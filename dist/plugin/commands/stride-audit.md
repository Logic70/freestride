<!-- AUTO-GENERATED FROM .claude/ - DO NOT EDIT DIRECTLY -->

---
description: Run STRIDE security threat analysis on a target (v0.5)
argument-hint: <target> [--no-sast] [--no-auto-install] [--no-poc-exec] [--mode chat] [--diff <run-id>] [--attacker-profile <profile>]
---

# /stride-audit (v0.5.0)

基于微软 STRIDE 框架的安全威胁分析工作流。
v0.4 新增：confirmed 硬门禁 schema、must-detect 精确匹配、must-reject 可执行模式、PoC 证据四级分级、独立 result-auditor 审计阶段、attacker_capabilities 威胁模型。
v0.5 新增：confirmed 两级分类（code_defect/exploitable）、static_evidence 不能支撑 HIGH、PIN 位数误读 FP 模式、DFD 自动化（yaml→mmd+index）、run_manifest 闭环、must-reject 扩展 9 项、DFD 文件存在性校验、PoC 类型与严重度绑定、双次审计（pre-report + post-report）。

## Usage

```text
/stride-audit <target> [options]
```

**参数：**
- `<target>`: 目标代码仓库路径或系统描述文本（必需）
- `--no-sast`: 完全跳过 SAST 验证阶段（含预检和安装尝试）
- `--no-auto-install`: 执行 SAST 预检但不尝试自动安装工具，仅使用已安装工具
- `--no-poc-exec`: 跳过 PoC 执行验证（仍生成 PoC 代码）
- `--mode chat`: 强制对话引导模式
- `--diff <run-id>`: 对比分析，与历史运行结果比较
- `--attacker-profile <profile>`: 指定攻击者能力模型（默认: mobile_device_remote_attacker）

## 工作流阶段

```
parse → dfd → stride → verify → validation → poc → result-auditor(pre) → report → result-auditor(post) → [diff]
```

| 阶段 | Agent | Goal | Verify |
|------|-------|------|--------|
| **parse** | stride-parse | 解析输入，定义威胁边界 | 输入有效性 + 语言检测 + threat_boundary 完整 |
| **dfd** | stride-dfd-inferrer | 代码阅读，DFD五要素推断 → 自动生成 dfd.yaml, dfd_mermaid.mmd, dfd_index.json | 5种元素类型 + DFD文件全部生成 |
| **stride** | stride-analyzer | STRIDE六维并行威胁识别 | 六维全覆盖 + 调用链追踪 + 可利用性评分 |
| **verify** | stride-attack-pattern-matcher→sast-verifier | 攻击模式匹配 + SAST预检 | 所有威胁完成攻击模式映射 |
| **validation** | stride-validator | 源码反证 + FP模式匹配 + 回归集精确匹配 | source_evidence + counter_evidence + mitigation + 五类分类 |
| **poc** | stride-poc-generator | PoC四级分层生成 | poc_plan含target_code_invoked/source_file/source_line/limitations/allowed_claim |
| **result-auditor (pre)** | stride-result-auditor | 独立反证：confirmed门禁、must-detect精确覆盖、PoC证据级别、attack model一致 | HARD_FAIL阻塞报告 |
| **report** | stride-report-assembler → `config/scripts/assemble-report.py` | 分表输出 + SVG DFD + 布局门禁(T1-T12) + HTML交互契约 + 语义一致性 + HTML | 统计自动生成, 0 inline onclick, STRIDE六维面板, 事件委托 |
| **result-auditor (post)** | stride-result-auditor **(v0.5 新增)** | HTML与JSON一致性、run_manifest终态 | HTML统计=分表统计 |
| **diff** | stride-diff-analyzer | 对比历史分析（可选） | diff正确计算 |

### Confirmed 两级分类（v0.5 新增）

```
confirmed_exploitable: 漏洞可被真实利用
  → 需要: exploit_path=direct + poc_type=runtime_target_poc + impact_observed=true
  → 最高 severity: HIGH

confirmed_code_defect: 代码缺陷确认，可利用性未在目标代码验证
  → 允许: exploit_path=direct|conditional, poc_type=runtime_model_poc|static_evidence
  → 最高 severity: MEDIUM
  → 不能声明 "漏洞已验证"
```

### 硬门禁（v0.5 升级）

| Gate | 规则 | v0.4 | v0.5 |
|------|------|------|------|
| GATE-PRECONDITION-PRIVILEGE | precondition含root/local_fs_write → 不能confirmed | HARD | HARD |
| GATE-EXPLOIT-PATH | design_only → 不能confirmed; conditional → 不能confirmed_exploitable | HARD | HARD |
| GATE-STATIC-EVIDENCE-HIGH | static_evidence + HIGH → 不能confirmed | SOFT_WARN | **HARD FAIL** |
| GATE-SIMULATION-CLAIMS | runtime_model_poc 不能写 "漏洞已验证" | HARD | HARD |
| GATE-POC-SEVERITY-CAP | runtime_model_poc最高MEDIUM; static_evidence最高MEDIUM | — | **新增** |
| GATE-CONFIRMED-TIER | confirmed_exploitable必须runtime_target_poc | — | **新增** |

### Attacker Capabilities 模型（v0.4 新增）

威胁分类必须遵守 `config/attacker-capabilities.yaml` 中定义的攻击者能力边界。
默认 profile: `mobile_device_remote_attacker`（无本地文件系统写入权限）。
超出能力边界的威胁 → design 或 out_of_scope。

### Must-Detect 精确匹配（v0.4 加强）

回归集匹配从模糊描述改为精确字段匹配（文件后缀 + 行号范围 + sink_function + bug_pattern），见 `config/regression-corpus-v2.yaml`。

**三个条件全部满足才算覆盖**：
1. `file ENDSWITH matching.file_suffix`
2. `line IN matching.line_range`
3. 包含 `matching.sink_operation` 或 `matching.bug_pattern`

不满足 → `must_detect_miss` → **HARD FAIL**

### Must-Reject 可执行（v0.4 新增）

当 finding 匹配 `must_reject` 触发词 AND 目标代码中存在 guard 时，**强制**应用分类（false_positive/design），并写入 `fp_code_ref` + `fp_rationale`。见 `config/regression-corpus-v2.yaml`。

### PoC 证据分级（v0.4 新增）

| Tier | 名称 | 允许的声明 | 可提 confirmed? |
|------|------|-----------|----------------|
| `runtime_target_poc` | 目标代码运行时验证 | "PoC有效验证漏洞" | **是** |
| `runtime_model_poc` | 独立机制模拟 | "机制成立" | 否（confidence≤7） |
| `static_evidence` | 静态代码证据 | "代码缺陷成立" | 否（confidence≤5） |
| `design_scenario` | 设计场景分析 | "设计风险存在" | **否（强制降级）** |

见 `config/poc-evidence-grading.yaml`。

### Result Auditor 独立审计（v0.4 新增）

独立审计阶段 `stride-result-auditor` 在 PoC 之后、Report 之前运行。职责：
- 检查 confirmed 是否通过硬门禁
- 检查 must-detect 精确覆盖（文件+行号+sink+bug_pattern）
- 检查 must-reject 模式是否被正确应用
- 检查 PoC 声明是否与证据级别匹配
- 检查跨文件一致性（语义级别，非仅计数）

**任意 HARD_FAIL → 禁止输出报告，修正后重试（max 3 迭代）**

### 语义一致性校验（v0.4 新增）

14 条语义一致性规则（见 `config/consistency-rules-v2.yaml`），覆盖：
- PoC 数量一致性（meta vs actual）
- 分类计数跨文件一致（threat_list ↔ 分表）
- must-detect 精确覆盖
- must-reject 强制应用
- confirmed 硬门禁
- PoC 证据级别一致性
- 攻击者能力边界一致性
- SAST 交叉引用
- HTML 数据一致性

## 输出

| 文件 | 内容 | 版本 |
|------|------|------|
| `run_manifest.json` | 运行清单：run_id、各阶段状态、产物列表、一致性结论 | **v0.5 新增** |
| `dfd.yaml` | 数据流图 YAML（canonical source） | — |
| `dfd_mermaid.mmd` | 从 dfd.yaml 自动生成的 Mermaid 图 | **v0.5 自动化** |
| `dfd_index.json` | DFD元素→威胁ID映射索引 | **v0.5 新增** |
| `confirmed_findings.json` | 确认漏洞（两级：code_defect / exploitable） | — |
| `candidate_findings.json` | 候选发现（部分证据） | — |
| `design_gaps.json` | 设计改进建议（含 attacker model 降级） | — |
| `out_of_scope.json` | 超出威胁边界 | — |
| `false_positives.json` | 误报（含 must_reject 自动匹配） | — |
| `result_audit.json` | 独立审计结果（pre-report + post-report） | v0.4→v0.5 升级 |
| `consistency_check_v3.json` | 语义一致性检查结果 | **v0.5 新增** |
| `stride-audit-report-{ts}.html` | HTML 主报告（嵌入 dfd_mermaid.mmd + dfd_index.json） | — |

### run_manifest.json 结构（v0.5 新增）

```json
{
  "run_id": "run-20260509-xxxxxx",
  "workflow_version": "0.5.0",
  "status": "COMPLETE|BLOCKED|INCOMPLETE",
  "stages": {"parse": "PASS", "dfd": "PASS", ...},
  "consistency": {"hard_fails": 0, "soft_warns": 0, "overall": "PASS"},
  "threat_stats": {...},
  "artifacts": [...]
}
```

任一阶段中断 → status = INCOMPLETE → 禁止生成最终报告。
验收以 run_manifest + consistency_check_v3 + result_audit 为准。

## 示例

```text
/stride-audit /path/to/cpp-project
/stride-audit . --no-auto-install        # 不尝试安装 SAST 工具
/stride-audit "一个处理用户支付的Web服务" --mode chat
/stride-audit src/ --scope src/auth --no-sast
/stride-audit . --diff run-20260501
```
