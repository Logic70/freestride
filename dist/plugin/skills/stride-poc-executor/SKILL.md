---
name: stride-poc-executor
description: "Manage isolated sandbox lifecycle and execute PoC code. Docker preferred but not exclusive."
version: "0.1.0"
---

# STRIDE PoC Executor Skill

## Purpose

Called by `stride-poc-generator` agent. Provides a safe, isolated execution environment for PoC validation.

## Invocation

Triggered by: `stride-poc-generator` agent

## Isolation Methods (Preference Order)

### 1. Docker (Preferred)
```bash
docker build -t stride-sandbox -f config/poc-sandbox.dockerfile .
docker run --rm \
  --network none \
  --memory 512m \
  --cpus 1 \
  -v /path/to/poc_files:/poc:ro \
  -v /path/to/output:/output \
  stride-sandbox \
  /poc/run.sh
```

### 2. Python Virtualenv
```bash
python3 -m venv /tmp/stride-sandbox-{threat_id}
source /tmp/stride-sandbox-{threat_id}/bin/activate
# Install dependencies from PoC README
# Run PoC
deactivate
# Cleanup
```

### 3. chroot Jail (Linux)
```bash
mkdir -p /tmp/stride-chroot-{threat_id}
# Minimal chroot setup
chroot /tmp/stride-chroot-{threat_id} /poc/run.sh
```

### 4. User-Approved Local Execution
- Prompt user: "No isolation method available. Execute PoC locally? [y/N]"
- If approved, run with resource limits
- Record explicit approval in execution log

## Execution Template

Each PoC directory should contain a `run.sh`:
```bash
#!/bin/bash
set -e
echo "=== PoC Execution: {threat_id} ==="
echo "Target: {description}"
echo "Expected: {expected_behavior}"
# PoC commands
echo "=== RESULT: {outcome} ==="
```

## Output

```json
{
  "threat_id": "THREAT-001",
  "isolation_method": "docker",
  "command": "docker run --rm -v ...",
  "exit_code": 0,
  "stdout": "Vulnerability confirmed: buffer overflow at offset 128\n",
  "stderr": "",
  "status": "VERIFIED",
  "timestamp": "ISO8601"
}
```

Possible status values: `VERIFIED`, `NOT_VERIFIED`, `EXECUTION_SKIPPED`, `EXECUTION_FAILED`

## Constraints

- Docker preferred; if unavailable, try virtualenv → chroot → prompt user for local execution
- Never execute outside isolation without explicit user approval
- Resource limits enforced: max 512MB RAM, 1 CPU, 60s timeout, no network access
- Clean up sandbox after execution
