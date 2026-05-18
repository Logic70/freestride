# Workflow LowLevel Guide

_Generated at 2026-05-08T02:25:49Z from workflow-spec.yaml (spec_sha256=1af21ea9a2d0c6f2704eed91351ff8fa868347a8a2c70ace2be814a143c64e35)_

> 本文件用于维护与迭代指导，不得覆盖 workflow-spec.yaml 语义。

## Truth Hierarchy

- `workflow-spec.yaml`：唯一机器真源。任何影响执行、校验、阶段流转、输入输出边界的内容都必须先进入这里。
- `workflow-view.md`：从 YAML 单向渲染出的只读概览，便于快速审查，不允许反向改语义。
- `workflow-lowlevel.md`：维护与迭代指导文档，用于解释阶段职责、证据归属和修改方法；不得覆盖 YAML 语义。

## Workflow Identity

- name: `stride-security-audit`
- version: `0.2.0`
- target_platform: `claude-code`
- source_design: `outputs/stages/s3-design-highlevel.md`
- complexity: `L`

## Intent Flow Contract

- develop: required=`S1, S2, S3, S4, S5, S6` optional=`-`
- audit: required=`S5, S6` optional=`-`
- iterate: required=`S6` optional=`S5`
- validate: required=`S5` optional=`S6`

维护规则：修改某个意图的阶段流时，只能编辑 `workflow-spec.yaml.intent_flows`，再重新生成视图与 LowLevel 文档。

## Target Workflow Graph Contract

- schema_version: `1`
- templates_used: `agent, fan-out, sequential, loop`

维护规则：`workflow_graph` 是生成后目标工作流的业务图；`stages` 和 `intent_flows` 仍然只描述 WorkflowProgram 自身的开发/审计/迭代/验证控制面。
维护规则：任何会影响目标工作流入口、节点转移、输出资产或 gate 的调整，都必须先改 `workflow-spec.yaml.workflow_graph`，再重生成 view/lowlevel。
维护规则：目标资产输出必须能回到 `registry` 或 `test_contract.artifacts`，避免模型生成未声明文件。
维护规则：若节点声明 `loop_policy.enabled=true`，它只代表目标业务节点持续执行策略，不改变 WorkflowProgram 自身 S1-S6；成功必须由 verifier/test 证据支撑。

### Graph Nodes

- `parse` role=`input_parsing` owner=`stride-parse` loop=`disabled` outputs=`outputs/stride-audit/parse_result.json`
- `dfd` role=`data_flow_analysis` owner=`stride-dfd-inferrer` loop=`disabled` outputs=`outputs/stride-audit/dfd.yaml, outputs/stride-audit/code_reading_log.md`
- `stride` role=`threat_analysis` owner=`stride-analyzer` loop=`disabled` outputs=`outputs/stride-audit/threat_list.json, outputs/stride-audit/call_chain_map.json`
- `verify` role=`attack_pattern_verification` owner=`stride-attack-pattern-matcher` loop=`disabled` outputs=`outputs/stride-audit/attack_pattern_map.json, outputs/stride-audit/sast_verification.log`
- `validation` role=`source_evidence_validation` owner=`stride-validator` loop=`disabled` outputs=`outputs/stride-audit/validation_report.json`
- `poc` role=`poc_generation` owner=`stride-poc-generator` loop=`ralph` outputs=`outputs/stride-audit/poc_files/, outputs/stride-audit/sandbox_execution.log`
  - loop max_iterations=`3` goal_source=`user` evidence=`outputs/stages/loops/poc/poc_iteration_1.md, outputs/stages/loops/poc/poc_iteration_2.md, outputs/stages/loops/poc/poc_iteration_3.md`
- `report` role=`report_assembly_with_consistency_gate` owner=`stride-report-assembler` loop=`ralph` outputs=`outputs/stride-audit/confirmed_findings.json, outputs/stride-audit/candidate_findings.json, outputs/stride-audit/design_gaps.json, outputs/stride-audit/out_of_scope.json, outputs/stride-audit/false_positives.json, outputs/stride-audit/stride-audit-report.html`
  - loop max_iterations=`3` goal_source=`user` evidence=`outputs/stages/loops/report/report_snapshot_1.html, outputs/stages/loops/report/report_snapshot_2.html, outputs/stages/loops/report/report_snapshot_3.html`
- `diff` role=`comparative_analysis` owner=`stride-diff-analyzer` loop=`disabled` outputs=`outputs/stride-audit/diff-report.md`

## Stage Contracts

### `S1` · `research` · 需求澄清与规格生成

- pattern: `Explore`
- agent_ref: `stride-parse`
- input: `-`
- output: `outputs/stages/clarification-record.json, outputs/stages/clarification-handoff.json`
- gate: `-`
- on_approve: `-`
- on_reject: `-`
- max_retries: `-`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

### `S2` · `domain_research` · 领域研究与资产扫描

- pattern: `Explore`
- agent_ref: `-`
- input: `-`
- output: `outputs/stages/s2-domain-report.md`
- gate: `-`
- on_approve: `-`
- on_reject: `-`
- max_retries: `-`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

### `S3` · `design` · 模式选择与工作流设计

- pattern: `Specialized Agent`
- agent_ref: `stride-analyzer`
- input: `-`
- output: `workflow-spec.yaml, outputs/stages/s3-design-highlevel.md, outputs/stages/s3-design-lowlevel.md`
- gate: `user_approval`
- on_approve: `-`
- on_reject: `-`
- max_retries: `-`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

### `S4` · `generate` · 从YAML生成工作流文件

- pattern: `Sequential`
- agent_ref: `-`
- input: `-`
- output: `outputs/candidate/.workflowprogram/runtime, .workflowprogram/runtime/workflow-entry.py, .workflowprogram/runtime/workflow-runner.py, .workflowprogram/runtime/validate-run-state.py, .workflowprogram/runtime/runtime-manifest.json`
- gate: `-`
- on_approve: `-`
- on_reject: `-`
- max_retries: `3`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

### `S5` · `validate` · 运行时验证

- pattern: `Test-Driven`
- agent_ref: `-`
- input: `-`
- output: `outputs/stages/s5-validation-summary.json`
- gate: `-`
- on_approve: `-`
- on_reject: `-`
- max_retries: `-`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

### `S6` · `close` · 约束演进与流程闭环

- pattern: `Sequential`
- agent_ref: `-`
- input: `-`
- output: `outputs/stages/s6-lessons-delta.md`
- gate: `-`
- on_approve: `-`
- on_reject: `-`
- max_retries: `-`
- 维护说明：若某阶段的输入/输出/转移会影响执行或校验，必须先回写 `workflow-spec.yaml`，不得只改本文档。

## Runtime And Test Contract

- target_root_allow: `.claude/, .workflowprogram/, config/, templates/, outputs/stride-audit-*/`
- run_root_allow: `outputs/`
- required_evidence: `outputs/stride-audit/dfd.yaml, outputs/stride-audit/threat_list.json, outputs/stride-audit/call_chain_map.json, outputs/stride-audit/validation_report.json, outputs/stride-audit/attack_pattern_map.json, outputs/stride-audit/sast_verification.log, outputs/stride-audit/poc_files/, outputs/stride-audit/confirmed_findings.json, outputs/stride-audit/candidate_findings.json, outputs/stride-audit/design_gaps.json, outputs/stride-audit/out_of_scope.json, outputs/stride-audit/false_positives.json, outputs/stride-audit/stride-audit-report.html`
- failure_kinds: `none, design, implementation, environment, conflict`
- test_categories: `entry, boundary, flow, artifacts, failure`

维护规则：任何会改变 verdict、边界、证据或失败分类的调整，都必须更新 `workflow-spec.yaml.runtime_contract` 或 `workflow-spec.yaml.test_contract`，而不是只更新解释文字。

## Generated Runtime Contract

- runtime_root: `.workflowprogram/runtime/`
- entry_script: `.workflowprogram/runtime/workflow-entry.py`
- runner_script: `.workflowprogram/runtime/workflow-runner.py`
- state_validator_script: `.workflowprogram/runtime/validate-run-state.py`
- runtime_manifest: `.workflowprogram/runtime/runtime-manifest.json`
- run_root_dir: `.workflowprogram/runs/`
- runtime_capabilities: `state_transitions, run_state_validation, capability_discovery, host_capability_probe, node_loop_execution`

维护规则：若目标工作流声明了阶段流与 test_contract，则必须同时交付 `.workflowprogram/runtime/` 下的 deterministic runtime 资产，不得只保留命令和设计文档。

## Host Capability Contract

- `cppcheck` kind=`external_binary` required=`False` scope=`project_local` approval_required=`False` project_local_outputs=`.workflowprogram/bootstrap/install-sast-tools.sh` assets=`1`
- `flawfinder` kind=`external_binary` required=`False` scope=`project_local` approval_required=`False` project_local_outputs=`.workflowprogram/bootstrap/requirements.txt` assets=`1`
- `semgrep` kind=`external_binary` required=`False` scope=`project_local` approval_required=`False` project_local_outputs=`.workflowprogram/bootstrap/install-sast-tools.sh` assets=`0`
- `docker` kind=`external_binary` required=`False` scope=`host_global` approval_required=`True` project_local_outputs=`-` assets=`0`

维护规则：host capability 只影响宿主可用性，不是 TARGET_ROOT 业务资产。探测报告和 bootstrap plan 必须写入 RUN_ROOT，只有 project-local bootstrap 可以写入 `TARGET_ROOT/.workflowprogram/bootstrap/**`。
若声明 `bootstrap.assets`，则这些资产必须是可复用的配置、wrapper 或 marker 文件，并在 apply 证据与 target bootstrap manifest 中同时留下记录。

## Agent Team Contract

- None

维护规则：普通 subagent 并不等于 agent team。只有声明了 `agent_team_contract.enabled=true` 的 workflow 才应产出 team evidence。

## Persistent Design Assets

- develop 成功后，应把 `workflow-spec.yaml`、`workflow-view.md`、`workflow-lowlevel.md` 持久化到 `TARGET_ROOT/.workflowprogram/design/`。
- develop 成功后，应把 `workflow-entry.py`、`workflow-runner.py`、`validate-run-state.py`、`runtime-manifest.json` 持久化到 `TARGET_ROOT/.workflowprogram/runtime/`。
- 持久化副本属于 WorkflowProgram 托管资产，必须走 managed apply / manifest，而不是直接裸写目标目录。
- 目标侧副本用于后续 audit / iterate / 人工维护理解当前工作流；当前运行的控制面输入仍以 `RUN_ROOT/workflow-spec.yaml` 为准。

## Maintenance Rules

- 修改执行语义：先改 `workflow-spec.yaml`，再重新生成 `workflow-view.md` 与 `workflow-lowlevel.md`。
- 修改设计解释：可重生成 `workflow-lowlevel.md`，但不得引入与 YAML 冲突的新约束。
- 修改目标项目资产：必须通过 WorkflowProgram 的 develop / iterate 流程，避免手工破坏 manifest 与边界契约。
- 排查运行问题：先看 `TARGET_ROOT/.workflowprogram/design/`，再看 `RUN_ROOT/state.json`、`events.jsonl`、`validation-runtime-report.md`。
