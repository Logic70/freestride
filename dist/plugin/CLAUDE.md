# FreeSTRIDE — STRIDE Security Audit Workspace

基于微软 STRIDE 框架的安全威胁分析工作区。

## 工作流

### `/stride-audit` v0.5

对目标代码仓库执行 STRIDE 六维度威胁分析：

```
/stride-audit <target> [--no-sast] [--no-auto-install] [--no-poc-exec] [--mode chat] [--diff <run-id>] [--attacker-profile <profile>]
```

**流程**: parse → dfd → stride → verify → validation → poc → result-auditor(pre) → report → result-auditor(post) → [diff]

**v0.5 新增**:
- confirmed 两级分类：`confirmed_code_defect` / `confirmed_exploitable`（`config/confirmed-gate-schema.yaml`）
- static_evidence 不能支撑 HIGH severity（SOFT_WARN → **HARD FAIL**）
- PoC 类型与最高严重度绑定（runtime_model_poc 最高 MEDIUM）
- PIN 位数误读 must-reject（REJECT-005: 6字符≠6bit）
- must-reject 扩展至 9 项（`config/regression-corpus-v2.yaml`）
- DFD 自动化：dfd.yaml → dfd_diagram.svg + dfd_mermaid.mmd + dfd_index.json（`config/scripts/assemble-report.py`）
- DFD 文件存在性 + SVG/Mermaid 一致性校验（`config/scripts/check-consistency-v3.py`）
- run_manifest.json：运行闭环、阶段状态、产物清单
- 双次审计：pre-report (阻塞) + post-report (HTML交叉验证)
- 技能文件统一命名为 SKILL.md

**输出**:
- `confirmed_findings.json` — 确认漏洞
- `candidate_findings.json` — 候选发现
- `design_gaps.json` — 设计建议
- `out_of_scope.json` — 超出范围
- `false_positives.json` — 误报记录
- `stride-audit-report-{ts}.html` — HTML 主报告

## 项目结构

```
.claude/           — Agent/Skill/Command 定义
config/            — 攻击模式库、FP模式库、SAST规则、威胁模板
templates/         — HTML 报告模板
.workflowprogram/  — 工作流运行时与设计文档
```

## 约束

- SAST 是验证工具（非发现工具），在攻击模式匹配后执行
- 威胁边界必须先于 DFD 推断
- HIGH/CRITICAL 需要源码行号 + 可达入口
- 输出分表：confirmed / candidate / design / oos / false_positive
- 统计必须自动生成，禁止手写
