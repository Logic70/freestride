# FreeSTRIDE — STRIDE Security Audit Plugin

基于微软 **STRIDE** 框架的安全威胁分析 Claude Code 插件。对目标代码仓库执行六维度威胁分析，自动推断数据流图，生成交互式 HTML 审计报告。

## 安装

```text
# 1. 先安装 WorkflowProgram 运行时
/plugin marketplace add logic70-plugins https://github.com/Logic70/WorkflowProgram.git
/plugin install workflowprogram-cn@logic70-plugins

# 2. 再安装 FreeSTRIDE
/plugin marketplace add target-workflow-plugins https://github.com/Logic70/freestride
/plugin install freestride@target-workflow-plugins
```

## 快速开始

```text
# 对本地代码仓库执行完整审计
/stride-audit /path/to/your/project

# 跳过 SAST 扫描（仅威胁建模）
/stride-audit /path/to/project --no-sast

# 对话引导模式
/stride-audit "一个处理用户支付的Web服务" --mode chat

# 指定攻击者模型
/stride-audit /path/to/project --attacker-profile internal_threat
```

## 工作流阶段

```
parse → dfd → stride → verify → validation → poc → result-auditor → report
```

| 阶段 | 功能 | 关键产出 |
|------|------|---------|
| **parse** | 语言检测、威胁边界定义 | `parse_result.json` |
| **dfd** | 代码阅读 → 数据流图五要素推断 | `dfd.yaml`, `dfd_mermaid.mmd`, `dfd_index.json` |
| **stride** | STRIDE 六维度并行威胁识别 | `threat_list.json` |
| **verify** | 攻击模式匹配 + SAST 验证 | `attack_pattern_map.json` |
| **validation** | 源码反证、FP 模式匹配、回归集精确匹配 | `validation_report.json` |
| **poc** | PoC 四级分层生成 | `poc_summary.json` |
| **result-auditor** | 独立审计：confirmed 门禁、must-detect 覆盖、PoC 证据级别 | `result_audit.json` |
| **report** | 分表输出 + 交互式 SVG DFD + HTML 报告 | `stride-audit-report-{ts}.html` |

## 输出文件

| 文件 | 说明 |
|------|------|
| `run_manifest.json` | 运行清单：run_id、各阶段状态、统计摘要 |
| `threat_list.json` | 全部威胁清单（含分类和严重度） |
| `confirmed_findings.json` | 确认漏洞（两级：code_defect / exploitable） |
| `candidate_findings.json` | 候选发现（证据不足） |
| `design_gaps.json` | 设计改进建议 |
| `false_positives.json` | 误报记录（含 must-reject 自动匹配） |
| `dfd.yaml` | 数据流图 YAML |
| `dfd_index.json` | DFD 元素 → 威胁映射索引 |
| `dfd_diagram.svg` | 交互式 SVG DFD（可点击元素查看 STRIDE 分析） |
| `poc_summary.json` | PoC 证据分级摘要 |
| `stride-audit-report-{ts}.html` | **HTML 主报告** |

## 功能特性

### Confirmed 两级分类

| 级别 | 要求 | 最高严重度 |
|------|------|-----------|
| `confirmed_exploitable` | exploit_path=direct + runtime_target_poc + impact_observed | HIGH |
| `confirmed_code_defect` | 代码缺陷确认，无需完整利用验证 | MEDIUM |

### PoC 证据四级分级

| 级别 | 名称 | 允许声明 | 可提 confirmed |
|------|------|---------|---------------|
| `runtime_target_poc` | 目标代码运行时验证 | "PoC有效验证漏洞" | 是 |
| `runtime_model_poc` | 独立机制模拟 | "机制成立" | 否 |
| `static_evidence` | 静态代码证据 | "代码缺陷成立" | 否 |
| `design_scenario` | 设计场景分析 | "设计风险存在" | 否（强制降级） |

### 硬门禁

- 静态证据不能支撑 HIGH severity
- runtime_model_poc 最高 MEDIUM
- design_only 不能 confirmed
- conditional 不能 confirmed_exploitable
- precondition 含 root/system_partition_write 不能 confirmed

### 交互式 DFD 报告

HTML 报告内嵌可点击的 SVG 数据流图，点击任意 DFD 元素即可查看其 STRIDE 六维安全分析。

## 项目配置

插件载入后会在目标项目下生成配置：

```
.claude/           — Agent/Skill/Command 定义
config/            — 攻击模式库、FP模式库、SAST规则、威胁模板
templates/         — HTML 报告模板
outputs/           — 审计运行输出
```

## 约束

- SAST 是**验证**工具（非发现工具），攻击模式匹配后执行
- 威胁边界必须先于 DFD 推断
- HIGH/CRITICAL 需要源码行号 + 可达入口
- 统计自动生成，禁止手写
- 默认 attacker profile: `mobile_device_remote_attacker`

## 许可

MIT
