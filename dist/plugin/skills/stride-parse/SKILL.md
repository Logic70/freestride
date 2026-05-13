---
name: stride-parse
description: "Language detection and input routing logic for /stride-audit workflow"
version: "0.1.0"
---

# STRIDE Parse Skill

## Purpose

Called by the `stride-parse` agent. Detects the primary programming language of a target code repository and determines the correct analysis mode.

## Invocation

Triggered by: `stride-parse` agent

## Steps

1. Scan the target directory for source files using file extension heuristics
2. Count file extensions: `.c/.h` → C, `.cpp/.hpp/.cc/.cxx` → C++, `.rs` → Rust, `.py` → Python, `.go` → Go, `.java` → Java, `.js/.ts/.tsx` → JS/TS
3. Check for build system files: `CMakeLists.txt`, `Makefile`, `Cargo.toml`, `go.mod`, `pom.xml`, `package.json`
4. Return the dominant language or `"unknown"` if no clear majority
5. If `--lang <lang>` specified, override detection

## Output

```json
{
  "detected_language": "c|cpp|rust|python|go|java|js|ts|unknown",
  "confidence": 0.95,
  "file_counts": {"c": 45, "h": 38},
  "build_system": "CMake",
  "overridden": false
}
```
