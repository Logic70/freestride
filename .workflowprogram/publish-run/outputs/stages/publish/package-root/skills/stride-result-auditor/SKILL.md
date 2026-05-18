---
name: stride-result-auditor
description: 独立审计器 — 只做反证，不新增漏洞。检查 confirmed 合理性、must-detect 精确覆盖、PoC 证据级别、一致性。
version: "0.4.0"
---

# STRIDE Result Auditor Skill (v0.4)

## Purpose

独立的结果审计阶段。在执行完所有发现阶段（stride→verify→validation→poc）后运行。
**只打脸，不新增漏洞。** 职责是质疑 confirmed 的合理性、检查 must-detect 精确覆盖、验证 PoC 证据级别、交叉验证所有输出一致性。

## Hard Constraints

1. **不新增威胁** — 只审查已有威胁的分类质量
2. **不修改威胁内容** — 只做降级/标记，不编辑 name/source/mitigation
3. **硬失败即阻塞** — 任意 HARD_FAIL 规则触发 → 禁止输出报告
4. **最大 3 次重审迭代** — 超过迭代次数强制输出带警告注释的报告

## Audit Items

### A. Confirmed Gate Audit

对每条 `confirmed` 威胁检查：

```
1. preconditions 不含 [root, local_fs_write, system_partition_write]
   → 违规: 降级为 partial，说明原因

2. exploit_path_type == direct
   → 违规: 降级为 partial (conditional/simulated) 或 design (design_only)

3. 若 severity == HIGH, impact_observed == true
   → 违规: 降级为 MEDIUM 或标记 confidence 上限 5

4. attacker_control != none
   → 违规: 降级为 design

5. poc_type == runtime_target_poc 或 有显式 why_confirmed_without_poc
   → 违规: 不能写 "PoC 有效验证漏洞"，降级为 partial
```

### B. Must-Detect Precision Audit

对照 `config/regression-corpus-v2.yaml`：

```
For each must_detect entry:
  1. 在 threat_list 中搜索满足以下全部条件的 finding:
     - file ENDSWITH must_detect.matching.file_suffix
     - line IN must_detect.matching.line_range
     - 包含 must_detect.matching.sink_operation 或 bug_pattern

  2. 如找不到 → must_detect_miss → FAIL

  3. 如找到但 classification != correct_classification → MISMATCH → FAIL

  4. 如找到且分类正确 → PASS
```

### C. Must-Reject Enforcement Audit

```
For each must_reject pattern:
  1. 搜索所有 name/description 包含 trigger.finding_keywords 的 threat

  2. 对每个匹配项:
     - 验证 guard_location 在目标代码中存在
     - 若 guard 存在且 finding.classification != action.force_classification
       → 强制应用 action: 重新分类，添加 fp_code_ref, fp_rationale

  3. 检查是否有 confirmed threat 匹配 must_reject
     → 违规: FAIL (confirmed 不能是已知 FP 模式)
```

### D. PoC Evidence Tier Audit

```
For each PoC entry:
  1. poc_type 必须是 [runtime_target_poc, runtime_model_poc, static_evidence, design_scenario] 之一

  2. 检查 claims 是否与 tier 匹配:
     - runtime_model_poc 的 observation MUST NOT 包含 [fully verified, PoC有效验证漏洞, exploit confirmed]
     - static_evidence 的 observation MUST NOT 包含 [verified, confirmed, 有效验证]

  3. 检查 confirmed 威胁的 PoC 覆盖:
     - confirmed threat WITHOUT PoC → must have why_confirmed_without_poc
     - confirmed threat WITH static_evidence PoC → confidence <= 5
     - confirmed threat WITH runtime_model_poc → confidence <= 7
```

### E. Cross-File Consistency Audit

执行 `config/consistency-rules-v2.yaml` 中所有 `severity: HARD_FAIL` 规则：

```
1. CS-COUNT-POC: poc_summary.total_pocs == len(poc_results)
2. CS-COUNT-CLASSIFICATION: 分表计数一致
3. CS-COUNT-STANDARD: threat_list 计数分解正确
4. CS-MUST-DETECT-COVERAGE: 每个 must_detect 有精确匹配
5. CS-MUST-DETECT-MISMATCH: 匹配的分类正确
6. CS-MUST-REJECT-ENFORCED: 无 must_reject 违规
7. CS-CONFIRMED-GATES: 所有 confirmed 通过硬门禁
8. CS-ATTACKER-CAPABILITY: 无超模型威胁
9. CS-POC-EVIDENCE: PoC 证据一致
10. CS-POC-CLAIMS: PoC 声明准确
11. CS-SAST-REFERENCE: SAST 引用完整
12. CS-HTML-CONSISTENCY: HTML 数据一致
```

## Output

```json
{
  "audit_result": "PASS|FAIL",
  "hard_fails": [
    {"rule_id": "CS-xxx", "threat_id": "T-xxx", "reason": "..."}
  ],
  "soft_warns": [
    {"rule_id": "CS-xxx", "threat_id": "T-xxx", "reason": "..."}
  ],
  "downgrades_applied": [
    {"threat_id": "T-xxx", "from": "confirmed", "to": "partial", "reason": "..."}
  ],
  "must_detect_status": {
    "covered": 7,
    "missed": 0,
    "mismatched": 0
  },
  "must_reject_violations": 0,
  "iteration": 1,
  "max_iterations": 3
}
```

## Invocation

由 stride-audit 主工作流在 report 阶段之前自动调用：
```
parse → dfd → stride → verify → validation → poc → [result-auditor] → report
```
