---
name: stride-sast-runner
description: "Execute targeted SAST tool scans with attack-pattern-driven rules"
version: "0.3.0"
---

# STRIDE SAST Runner Skill

## Purpose

Called by `stride-sast-verifier` agent. Encapsulates the execution of SAST tools (cppcheck, flawfinder, semgrep, cargo-clippy) with rules driven by attack pattern matching. Handles auto-installation of missing tools.

## Invocation

Triggered by: `stride-sast-verifier` agent

## Supported Tools

| Tool | Language | Command Pattern | Install Method |
|------|----------|----------------|---------------|
| cppcheck | C/C++ | `cppcheck --enable=warning,style --template=gcc <files>` | `apt-get install cppcheck` / `brew install cppcheck` |
| flawfinder | C/C++ | `flawfinder --context --minlevel=2 <path>` | `pip install flawfinder` |
| cargo clippy | Rust | `cargo clippy -- -W clippy::all` | (bundled with Rust toolchain) |
| semgrep | Multi | `semgrep --config=<rule_file> <target_path>` | `pip install semgrep` |

## Execution Flow (v0.3)

1. Receive: `{tool_name, target_files[], rule_config}`
2. **Check tool availability**: `which <tool>` or `command -v <tool>`
3. **If missing: attempt auto-install** via package manager (see install methods above)
4. **If install fails**: return `{status: "unavailable", install_attempted: true, install_error: "<error message>", tier: "T4"}`
5. **If available**: run tool with targeted rules on specific files only
6. Capture stdout, stderr, exit code
7. Parse output to extract finding locations and descriptions

## Output

```json
{
  "tool": "semgrep",
  "target_files": ["src/auth.c", "src/handler.c"],
  "rule": "missing-rate-limit",
  "available": true,
  "install_method": "pre-installed",
  "version": "1.50.0",
  "exit_code": 0,
  "findings": [
    {
      "file": "src/auth.c",
      "line": 42,
      "severity": "WARNING",
      "message": "No rate limiting detected in authentication handler",
      "rule_id": "custom.missing-rate-limit"
    }
  ],
  "raw_output": "..."
}
```

## Constraints

- Only scan the specific files identified by attack pattern matching (targeted, not full-project)
- Tool unavailability → attempt auto-install FIRST, then degrade if install fails
- Tool unavailability is non-blocking: return `{available: false, install_attempted: true}` for tiered degradation
- Respect tool-specific output formats for parsing
- Record install_method (pre-installed / auto-installed / unavailable) for report transparency
- **v0.3**: Always attempt auto-install before degrading; never silently skip
