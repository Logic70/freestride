# Node Design: Parse

**Node ID:** `parse`
**Agent:** `stride-parse`
**Template:** agent
**Gate:** none

## Design Overview

Entry point for the STRIDE audit workflow. Parses user input, detects language, defines threat boundary, routes to auto or chat mode.

## Key Design Decisions

- Threat boundary MUST be explicitly defined before DFD inference (S2 lesson from STRIEAnalyse)
- Language detection supports C/C++/Rust as primary targets, fallback to general
- `--mode chat` bypasses all auto-analysis and enters guided STRIDE questionnaire

## Input
User provides: code repository path OR natural language system description

## Output
`outputs/stride-audit/parse_result.json` — {mode, language, code_path, threat_boundary, options}
