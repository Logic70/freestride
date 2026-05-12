# Workflow View

_Generated at 2026-05-08T02:25:49Z from workflow-spec.yaml_

## Meta

- name: `stride-security-audit`
- version: `0.2.0`
- target_platform: `claude-code`
- source_design: `outputs/stages/s3-design-highlevel.md`
- complexity: `L`

## Stage Flow (ASCII)

`research(需求澄清与规格生成) -> domain_research(领域研究与资产扫描) -> design(模式选择与工作流设计) -> generate(从YAML生成工作流文件) -> validate(运行时验证) -> close(约束演进与流程闭环)`

## Intent Flows

- develop: required=`S1, S2, S3, S4, S5, S6` optional=`-`
- audit: required=`S5, S6` optional=`-`
- iterate: required=`S6` optional=`S5`
- validate: required=`S5` optional=`S6`

## Target Workflow Graph

- schema_version: `1`
- templates_used: `agent, fan-out, sequential, loop`
- entrypoints: `1`
- nodes: `8`
- transitions: `8`
- loop_enabled_nodes: `2`

### Graph Entrypoints

- `stride-audit` -> `parse`

### Graph Nodes

- `parse` role=`input_parsing` template=`agent` gate=`none` loop=`disabled` outputs=`outputs/stride-audit/parse_result.json`
- `dfd` role=`data_flow_analysis` template=`agent` gate=`auto_approval` loop=`disabled` outputs=`outputs/stride-audit/dfd.yaml, outputs/stride-audit/code_reading_log.md`
- `stride` role=`threat_analysis` template=`fan-out` gate=`auto_approval` loop=`disabled` outputs=`outputs/stride-audit/threat_list.json, outputs/stride-audit/call_chain_map.json`
- `verify` role=`attack_pattern_verification` template=`sequential` gate=`auto_approval` loop=`disabled` outputs=`outputs/stride-audit/attack_pattern_map.json, outputs/stride-audit/sast_verification.log`
- `validation` role=`source_evidence_validation` template=`agent` gate=`auto_approval` loop=`disabled` outputs=`outputs/stride-audit/validation_report.json`
- `poc` role=`poc_generation` template=`loop` gate=`auto_approval` loop=`ralph` outputs=`outputs/stride-audit/poc_files/, outputs/stride-audit/sandbox_execution.log`
- `report` role=`report_assembly_with_consistency_gate` template=`loop` gate=`auto_approval` loop=`ralph` outputs=`outputs/stride-audit/confirmed_findings.json, outputs/stride-audit/candidate_findings.json, outputs/stride-audit/design_gaps.json, outputs/stride-audit/out_of_scope.json, outputs/stride-audit/false_positives.json, outputs/stride-audit/stride-audit-report.html`
- `diff` role=`comparative_analysis` template=`agent` gate=`none` loop=`disabled` outputs=`outputs/stride-audit/diff-report.md`

## Stage Details

### 1. `research` · 需求澄清与规格生成

- pattern: `Explore`
- agent_ref: `stride-parse`
- gate: `-`
- max_retries: `-`
- input: `-`
- output: `outputs/stages/clarification-record.json, outputs/stages/clarification-handoff.json`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `parse_requirement`
  - `clarify_ambiguity`
  - `generate_spec`
  - `generate_clarification_package`
  - `confirm_readback`

### 2. `domain_research` · 领域研究与资产扫描

- pattern: `Explore`
- agent_ref: `-`
- gate: `-`
- max_retries: `-`
- input: `-`
- output: `outputs/stages/s2-domain-report.md`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `scan_claude_assets`
  - `probe_host_environment`
  - `analyze_existing_projects`
  - `generate_domain_report`

### 3. `design` · 模式选择与工作流设计

- pattern: `Specialized Agent`
- agent_ref: `stride-analyzer`
- gate: `user_approval`
- max_retries: `-`
- input: `-`
- output: `workflow-spec.yaml, outputs/stages/s3-design-highlevel.md, outputs/stages/s3-design-lowlevel.md`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `select_patterns`
  - `design_agent_team`
  - `create_workflow_spec_yaml`
  - `generate_view_docs`
  - `present_design_gate`

### 4. `generate` · 从YAML生成工作流文件

- pattern: `Sequential`
- agent_ref: `-`
- gate: `-`
- max_retries: `3`
- input: `-`
- output: `outputs/candidate/.workflowprogram/runtime, .workflowprogram/runtime/workflow-entry.py, .workflowprogram/runtime/workflow-runner.py, .workflowprogram/runtime/validate-run-state.py, .workflowprogram/runtime/runtime-manifest.json`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `generate_agents`
  - `generate_skills`
  - `generate_commands`
  - `generate_settings`
  - `generate_runtime`
  - `managed_apply`

### 5. `validate` · 运行时验证

- pattern: `Test-Driven`
- agent_ref: `-`
- gate: `-`
- max_retries: `-`
- input: `-`
- output: `outputs/stages/s5-validation-summary.json`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `read_test_contract`
  - `validate_entry`
  - `validate_boundary`
  - `validate_flow`
  - `validate_artifacts`
  - `validate_failure`
  - `generate_s5_summary`

### 6. `close` · 约束演进与流程闭环

- pattern: `Sequential`
- agent_ref: `-`
- gate: `-`
- max_retries: `-`
- input: `-`
- output: `outputs/stages/s6-lessons-delta.md`
- transitions: `on_approve=-, on_reject=-`
- steps:
  - `review_lessons`
  - `extract_constraints`
  - `cleanup_artifacts`

## Agent Refs

- `stride-parse`
- `stride-dfd-inferrer`
- `stride-analyzer`
- `stride-attack-pattern-matcher`
- `stride-sast-verifier`
- `stride-validator`
- `stride-poc-generator`
- `stride-report-assembler`
- `stride-diff-analyzer`

## Skills

- `stride-parse` (internal=False)
- `stride-dfd-renderer` (internal=False)
- `stride-attack-pattern-lookup` (internal=False)
- `stride-sast-runner` (internal=False)
- `stride-fp-pattern-lookup` (internal=False)
- `stride-consistency-check` (internal=False)
- `stride-poc-executor` (internal=False)
- `stride-html-reporter` (internal=False)

## Registry Summary

- commands: `1`
- skills: `8`
- agents: `9`
- hooks: `0`
- runtime_assets: `4`

## Constraints

- ALWAYS:
  - SAST tools must execute AFTER STRIDE analysis, driven by attack patterns (verification, not discovery)
  - Threat boundary must be explicitly defined before DFD inference
  - Every threat must be classified as confirmed/partial/design/oos/false_positive
  - All findings must include provenance tag (agent+tool+code_path)
  - {'DFD must identify 5 element types': 'Process, DataFlow, ExternalEntity, Store, TrustBoundary'}
  - PoC execution prefers Docker sandbox; fallback to other isolation methods (virtualenv, chroot) or user-approved local execution
  - Report must validate browser-compatible render
  - Every threat must have source_evidence AND counter_evidence_checked fields
  - {'HIGH/CRITICAL threats require': 'source line number, reachable entry point, explainable logic flaw, checked existing mitigations, no dependency on root/HUKS/same-process arbitrary write'}
  - {'Call chain reachability required': 'source entry -> handler -> validation -> vulnerable function -> impact; threats without full chain must be capped at candidate'}
  - summary.total_threats and severity counts must be auto-generated from threat list, never hand-written
  - HTML, JSON, DFD outputs must reference the same canonical threat list
  - Output must split into confirmed_findings.json, candidate_findings.json, design_gaps.json, out_of_scope.json, false_positives.json
  - {'Each threat must include poc_plan field': {'type': None, 'minimal_repro': None, 'expected_observation': None, 'limitations': None}}
- NEVER:
  - Never run SAST as a discovery tool before STRIDE analysis
  - Never skip threat boundary definition
  - Never modify target source code
  - Never exceed 4 parallel sub-agents in fan-out stages
  - Never execute PoC outside isolated environment without user approval
  - Never mark a finding HIGH/CRITICAL without source line number and reachable call chain
  - Never merge candidate/hypothesis findings with confirmed vulnerabilities in the same output list

## Host Capabilities

- `cppcheck` kind=`external_binary` required=`False` approval_required=`False` scope=`project_local` project_local_outputs=`.workflowprogram/bootstrap/install-sast-tools.sh` assets=`1`
- `flawfinder` kind=`external_binary` required=`False` approval_required=`False` scope=`project_local` project_local_outputs=`.workflowprogram/bootstrap/requirements.txt` assets=`1`
- `semgrep` kind=`external_binary` required=`False` approval_required=`False` scope=`project_local` project_local_outputs=`.workflowprogram/bootstrap/install-sast-tools.sh` assets=`0`
- `docker` kind=`external_binary` required=`False` approval_required=`True` scope=`host_global` project_local_outputs=`-` assets=`0`

## Agent Team Contract

- None

## Runtime Contract

```json
{
  "write_boundaries": {
    "target_root_allow": [
      ".claude/",
      ".workflowprogram/",
      "config/",
      "templates/",
      "outputs/stride-audit-*/"
    ],
    "run_root_allow": [
      "outputs/"
    ],
    "temp_root_allow": [
      "/tmp/stride-audit-*/"
    ],
    "deny": [
      "src/",
      ".git/"
    ]
  },
  "required_evidence": [
    "outputs/stride-audit/dfd.yaml",
    "outputs/stride-audit/threat_list.json",
    "outputs/stride-audit/call_chain_map.json",
    "outputs/stride-audit/validation_report.json",
    "outputs/stride-audit/attack_pattern_map.json",
    "outputs/stride-audit/sast_verification.log",
    "outputs/stride-audit/poc_files/",
    "outputs/stride-audit/confirmed_findings.json",
    "outputs/stride-audit/candidate_findings.json",
    "outputs/stride-audit/design_gaps.json",
    "outputs/stride-audit/out_of_scope.json",
    "outputs/stride-audit/false_positives.json",
    "outputs/stride-audit/stride-audit-report.html"
  ],
  "failure_kinds": [
    "none",
    "design",
    "implementation",
    "environment",
    "conflict"
  ],
  "environment_skip": [
    {
      "code": "SAST_UNAVAILABLE",
      "check": "runtime_host_available",
      "message": "SAST tools not found; degrade to LLM-only verification"
    },
    {
      "code": "DOCKER_UNAVAILABLE",
      "check": "runtime_host_ready",
      "message": "Docker not available; skip PoC sandbox execution"
    }
  ]
}
```

## Generated Runtime Contract

```json
{
  "runtime_root": ".workflowprogram/runtime/",
  "design_spec_path": ".workflowprogram/design/workflow-spec.yaml",
  "entry_script": ".workflowprogram/runtime/workflow-entry.py",
  "runner_script": ".workflowprogram/runtime/workflow-runner.py",
  "state_validator_script": ".workflowprogram/runtime/validate-run-state.py",
  "runtime_manifest": ".workflowprogram/runtime/runtime-manifest.json",
  "run_root_dir": ".workflowprogram/runs/",
  "mode": "shared-control-plane-wrapper",
  "runtime_capabilities": [
    "state_transitions",
    "run_state_validation",
    "capability_discovery",
    "host_capability_probe",
    "node_loop_execution"
  ]
}
```

## Test Contract (Judgment Only)

```json
{
  "entry": {
    "main_entry": "stride-audit",
    "entry_type": "slash_command",
    "required_args": [
      "target"
    ],
    "missing_arg_verdict": "FAIL",
    "invalid_entry_verdict": "FAIL"
  },
  "boundary": {
    "write_boundaries_ref": "runtime_contract.write_boundaries",
    "managed_overwrite_policy": "Managed files overwritable; user-owned files raise conflict",
    "conflict_expectation": "Conflicts must be preserved in RUN_ROOT/outputs/conflicts/",
    "external_write_policy": "Deny writes outside allowed boundaries"
  },
  "flow": {
    "required_stages": [
      "research",
      "domain_research",
      "design",
      "generate",
      "validate",
      "close"
    ],
    "skippable_stages": [],
    "failure_recovery": {
      "design": "design",
      "implementation": "generate",
      "environment": "generate",
      "conflict": "generate"
    },
    "terminal_conditions": {
      "PASS": "done",
      "WARN": "done",
      "FAIL": "failed",
      "ENVIRONMENT-SKIP": "done"
    }
  },
  "artifacts": {
    "deliverables": [
      ".workflowprogram/managed-files.json",
      ".workflowprogram/design/workflow-spec.yaml",
      ".workflowprogram/runtime/workflow-entry.py",
      ".workflowprogram/runtime/workflow-runner.py",
      ".workflowprogram/runtime/validate-run-state.py",
      ".workflowprogram/runtime/runtime-manifest.json",
      ".claude/commands/stride-audit.md",
      ".claude/agents/stride-parse.md",
      ".claude/agents/stride-dfd-inferrer.md",
      ".claude/agents/stride-analyzer.md",
      ".claude/agents/stride-attack-pattern-matcher.md",
      ".claude/agents/stride-sast-verifier.md",
      ".claude/agents/stride-poc-generator.md",
      ".claude/agents/stride-report-assembler.md",
      ".claude/agents/stride-diff-analyzer.md",
      ".claude/skills/stride-parse/SKILL.md",
      ".claude/skills/stride-dfd-renderer/SKILL.md",
      ".claude/skills/stride-attack-pattern-lookup/SKILL.md",
      ".claude/skills/stride-sast-runner/SKILL.md",
      ".claude/skills/stride-poc-executor/SKILL.md",
      ".claude/skills/stride-html-reporter/SKILL.md"
    ],
    "evidence_ref": "runtime_contract.required_evidence",
    "optional_outputs": [
      "outputs/stages/s3-design-highlevel.md",
      "outputs/stages/s3-design-lowlevel.md",
      "outputs/stages/node-designs/"
    ]
  },
  "failure": {
    "failure_kinds_ref": "runtime_contract.failure_kinds",
    "environment_skip_ref": "runtime_contract.environment_skip",
    "implemented_now": [
      "none",
      "design",
      "implementation",
      "environment"
    ]
  }
}
```
