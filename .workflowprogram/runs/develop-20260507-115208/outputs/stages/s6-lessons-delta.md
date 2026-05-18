# S6 Lessons Delta — STRIDE Security Audit Workflow

> Session: 2026-05-07 `/develop 重新开发一个基于微软STRIDE威胁分析流程的安全测试工作流`
> Source: `workflowprogram-cn:develop`

## Lessons Extracted

### L1: SAST tool positioning is critical for methodology correctness
- **Problem**: Initial design placed SAST scan before DFD and STRIDE analysis (discovery role)
- **Root cause**: Default assumption that security scanning tools detect threats first, then model them
- **Fix**: SAST repositioned as verification tool — executed AFTER STRIDE analysis, driven by attack patterns
- **Severity**: HIGH (architectural)
- **Constraint candidate**: NEVER run SAST tools before STRIDE analysis in a threat modeling workflow

### L2: Threat boundary must be explicit before DFD inference
- **Problem**: STRIDEAnalyse had 16% out-of-scope threats due to undefined boundaries
- **Evidence**: 40% false positive rate in STRIDEAnalyse `security_device_auth` run
- **Fix**: Added explicit threat boundary definition to `parse` node output (scope_modules, trust_assumptions, out_of_scope)
- **Constraint candidate**: ALWAYS define threat boundary before DFD inference

### L3: Vulnerability classification taxonomy reduces noise
- **Problem**: Binary threat/no-threat output leads to 40% false positive rate
- **Fix**: [VULN]/[DESIGN]/[HARDENING]/[FP]/[OOS] 5-tag classification system
- **Evidence**: STRIDEAnalyse FP analysis identified need for multi-tag classification
- **Constraint candidate**: ALWAYS classify threats with multi-tag system before generating PoCs

### L4: PoC execution environment must be flexible
- **Problem**: Initial design required Docker exclusively
- **User correction**: Docker preferred but not required
- **Fix**: Fallback chain: Docker → virtualenv → chroot → user-approved local
- **Constraint candidate**: NEVER require exclusive isolation method for PoC execution

### L5: Agent-Skill naming overlap is by design, not conflict
- **Problem**: User questioned why `stride-parse` is both an agent and skill name
- **Resolution**: Agents orchestrate (reasoning), skills execute (tooling). Same base name indicates coupling.
- **Constraint candidate**: ALWAYS document agent-skill relationship in design docs when names overlap

### L6: Managed assets prefix-awareness is needed for apply
- **Problem**: managed-assets.py rejected `.workflowprogram/bootstrap/` and `config/` as non-managed prefixes
- **Workaround**: Filtered candidate files to managed prefixes only, manually copied non-managed files
- **Constraint candidate**: NEVER place workflow assets outside managed prefixes (`.claude/`, `.workflowprogram/design/`, `.workflowprogram/runtime/`)

## Constraints Candidates for constraints.md

```markdown
来源：2026-05-07 /develop stride-security-audit

- ALWAYS position SAST tools as verification (post-STRIDE), not discovery (pre-STRIDE)
- ALWAYS define explicit threat boundary before DFD inference
- ALWAYS classify threats with [VULN]/[DESIGN]/[HARDENING]/[FP]/[OOS] taxonomy
- ALWAYS support graceful degradation for optional tools (SAST, Docker, sandbox)
- ALWAYS verify managed-assets.py works with all candidate asset prefixes before apply
- NEVER skip the S2 domain research phase — STRIDEAnalyse lessons prevented major design errors
- NEVER require exclusive isolation method for PoC execution; provide fallback chain
```
