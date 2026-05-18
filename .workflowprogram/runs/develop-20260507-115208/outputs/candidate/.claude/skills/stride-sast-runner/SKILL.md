---
name: stride-sast-runner
description: "Execute targeted SAST tool scans with attack-pattern-driven rules"
version: "0.1.0"
---

# STRIDE SAST Runner Skill

## Purpose

Called by `stride-sast-verifier` agent. Encapsulates the execution of SAST tools (cppcheck, flawfinder, semgrep, cargo-clippy) with rules driven by attack pattern matching.

## Invocation

Triggered by: `stride-sast-verifier` agent

## Supported Tools

| Tool | Language | Command Pattern |
|------|----------|----------------|
| cppcheck | C/C++ | `cppcheck --enable=warning,style --template=gcc <files>` |
| flawfinder | C/C++ | `flawfinder --context --minlevel=2 <path>` |
| cargo clippy | Rust | `cargo clippy -- -W clippy::all` |
| semgrep | Multi | `semgrep --config=<rule_file> <target_path>` |

## Execution Flow

1. Receive: `{tool_name, target_files[], rule_config}`
2. Check tool availability: `which <tool>` or equivalent
3. If available: run tool with targeted rules on specific files only
4. Capture stdout, stderr, exit code
5. Parse output to extract finding locations and descriptions
6. If unavailable: return `{status: "unavailable", tool: "<tool>"}`

## Output

```json
{
  "tool": "semgrep",
  "target_files": ["src/auth.c", "src/handler.c"],
  "rule": "missing-rate-limit",
  "available": true,
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
- Tool unavailability is non-blocking: return `{available: false}` for graceful degradation
- Respect tool-specific output formats for parsing
