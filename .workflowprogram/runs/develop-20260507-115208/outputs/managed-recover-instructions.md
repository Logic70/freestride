# Managed Asset Recovery Instructions

- Generated at: `2026-05-07T12:47:18Z`
- Rollback manifest: `outputs/managed-rollback-manifest.json`

## Safety Rules

- Created files may be deleted only when the current hash still equals `applied_sha256`.
- Updated files may be restored only when the current hash still equals `applied_sha256`.
- If the current hash differs, stop and manually merge because the user or another tool modified the file after apply.
- Conflict entries did not modify TARGET_ROOT; compare their `conflict_copy` with the target file before applying manually.

## Entries

- `.claude/agents/stride-analyzer.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-attack-pattern-matcher.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-dfd-inferrer.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-diff-analyzer.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-parse.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-poc-generator.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-report-assembler.md` action=`create` rollback=`delete_created_file`
- `.claude/agents/stride-sast-verifier.md` action=`create` rollback=`delete_created_file`
- `.claude/commands/stride-audit.md` action=`create` rollback=`delete_created_file`
- `.claude/settings.json` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-attack-pattern-lookup/SKILL.md` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-dfd-renderer/SKILL.md` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-html-reporter/SKILL.md` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-parse/SKILL.md` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-poc-executor/SKILL.md` action=`create` rollback=`delete_created_file`
- `.claude/skills/stride-sast-runner/SKILL.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/node-designs/attack-pattern-matcher.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/node-designs/dfd-inferrer.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/node-designs/poc-generator.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/node-designs/report-assembler.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/node-designs/stride-analyzer.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/s3-design-highlevel.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/workflow-lowlevel.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/workflow-spec.yaml` action=`create` rollback=`delete_created_file`
- `.workflowprogram/design/workflow-view.md` action=`create` rollback=`delete_created_file`
- `.workflowprogram/runtime/runtime-manifest.json` action=`create` rollback=`delete_created_file`
- `.workflowprogram/runtime/validate-run-state.py` action=`create` rollback=`delete_created_file`
- `.workflowprogram/runtime/workflow-entry.py` action=`create` rollback=`delete_created_file`
- `.workflowprogram/runtime/workflow-runner.py` action=`create` rollback=`delete_created_file`
