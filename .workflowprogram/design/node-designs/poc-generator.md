# Node Design: PoC Generator

**Node ID:** `poc`
**Agent:** `stride-poc-generator`
**Template:** loop
**Gate:** auto_approval
**Loop:** max 3 iterations, feedback on syntax/execution failure

## Design Overview

Tiered PoC generation with conditional sandbox execution. Docker preferred; virtualenv/chroot/user-approved local as fallback.

## PoC Tier Strategy

| Tier | Threat Classification | Severity | Output |
|------|----------------------|----------|--------|
| Tier 1 | [VULN] | Critical / High | Executable PoC code + sandbox execution attempt |
| Tier 2 | [VULN] | Medium / Low | Structured attack scenario document |
| Tier 3 | [DESIGN] / [HARDENING] | Any | Architectural attack scenario description |
| Skip | [FP] / [OOS] | Any | Nothing — excluded from PoC generation |

## Sandbox Execution Preference Chain

```
1. Docker (preferred)
   └─ Build image from config/poc-sandbox.dockerfile
   └─ docker run --rm --network none --memory 512m --cpus 1 -v ...
2. Python virtualenv
   └─ python3 -m venv /tmp/stride-sandbox-{threat_id}
   └─ Execute and capture output
3. chroot jail (Linux)
   └─ Minimal chroot setup, execute
4. User-approved local execution
   └─ Prompt: "No isolation method available. Execute PoC locally? [y/N]"
   └─ Only with explicit user approval
```

## Inner Loop Policy

```
for each PoC that needs execution:
  attempt 1: generate PoC → execute → capture result
  if syntax error: fix → attempt 2
  if execution error: fix → attempt 3
  if still fails: mark EXECUTION_FAILED, record all errors
  if all isolation unavailable: EXECUTION_SKIPPED
```

## Output Structure

```
poc_files/
  {threat_id}/
    poc.{py,c,rs,sh}    # Executable code (Tier 1)
    README.md           # Setup instructions (Tier 1)
    attack_scenario.md  # Attack description (Tier 2/3)
    execution_log.txt   # Sandbox results or SKIPPED/FAILED
```

## Safety Constraints

- Docker containers: `--network none`, `--memory 512m`, `--cpus 1`, non-root user
- Virtualenv/chroot: cleaned up after execution
- Timeout: 60 seconds per PoC
- Never execute outside isolation without explicit user confirmation
