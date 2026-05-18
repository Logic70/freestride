<!-- AUTO-GENERATED FROM .claude/ - DO NOT EDIT DIRECTLY -->

---
description: Run STRIDE security threat analysis on a target
argument-hint: <target> [--no-sast] [--no-poc-exec] [--mode chat] [--diff <run-id>]
---

# /stride-audit

基于微软 STRIDE 框架的安全威胁分析工作流。

## Usage

```text
/stride-audit <target> [options]
```

**参数：**
- `<target>`: 目标代码仓库路径或系统描述文本（必需）
- `--no-sast`: 跳过 SAST 工具验证
- `--no-poc-exec`: 跳过 PoC 执行验证（仍生成 PoC 代码）
- `--mode chat`: 强制对话引导模式
- `--diff <run-id>`: 对比分析，与历史运行结果比较
- `--scope <module>`: 限定分析范围（子目录/模块名）
- `--lang <language>`: 指定主语言，跳过自动检测

## 工作流阶段

```
parse → dfd → stride → verify → poc → report → [diff]
```

| 阶段 | Agent | 职责 |
|------|-------|------|
| parse | stride-parse | 输入解析、语言检测、威胁边界定义 |
| dfd | stride-dfd-inferrer | 代码阅读、调用链追踪、DFD推断（5要素） |
| stride | stride-analyzer | STRIDE六维度并行威胁识别+可利用性评分 |
| verify | stride-attack-pattern-matcher + stride-sast-verifier | 攻击模式匹配、漏洞分类、SAST验证 |
| poc | stride-poc-generator | 分层PoC生成+条件沙箱执行 |
| report | stride-report-assembler | HTML报告组装（DFD图+统计+详情） |
| diff | stride-diff-analyzer | 对比分析（可选，Phase 2） |

## 输出

- `outputs/stride-audit/stride-audit-report-{ts}.html` — 主报告
- `outputs/stride-audit/threat_list.json` — 威胁清单
- `outputs/stride-audit/dfd.yaml` — 数据流图
- `outputs/stride-audit/poc_files/` — PoC代码和执行日志

## 示例

```text
/stride-audit /path/to/cpp-project
/stride-audit "一个处理用户支付的Web服务，使用JWT认证，数据存储在PostgreSQL" --mode chat
/stride-audit src/ --scope src/auth --no-sast
/stride-audit . --diff run-20260501
```
