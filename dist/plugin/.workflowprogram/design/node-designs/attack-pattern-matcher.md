# Node Design: Attack Pattern Matcher + SAST Verifier

**Node ID:** `verify`
**Agents:** `stride-attack-pattern-matcher` → `stride-sast-verifier`
**Template:** sequential
**Gate:** auto_approval

## Design Overview

Two-phase sequential verification: first map threats to attack patterns and classify, then run targeted SAST verification on classified threats.

## Phase 1: Pattern Matching & Classification

```
threat_list.json
       ↓
  for each threat:
    1. Query attack-patterns.yaml (CAPEC + custom)
    2. Classify: [VULN] | [DESIGN] | [HARDENING] | [FP] | [OOS]
    3. Generate SAST rules for [VULN] + [DESIGN]
       ↓
  attack_pattern_map.json
```

### Classification Decision Tree

```
Is threat in threat_boundary.out_of_scope?
  YES → [OOS], skip
  NO ↓
Is reachability INTERNAL_ONLY (from dfd.yaml)?
  YES → [OOS], skip
  NO ↓
Is the threat based on code misunderstanding or impossible preconditions?
  YES → [FP], provide written justification, skip
  NO ↓
Is it directly exploitable from outside trust boundary with realistic preconditions?
  YES → [VULN], proceed to PoC
  NO → Is it a design-level weakness?
    YES → [DESIGN], scenario PoC only
    NO → [HARDENING], scenario PoC only
```

## Phase 2: SAST Verification

For [VULN] and [DESIGN] threats with generated SAST rules:

1. Select tools by language (cppcheck+flawfinder for C/C++, clippy for Rust, semgrep for general)
2. Run targeted scan on ONLY the specific files referenced in the threat
3. Correlate: `match` (confirmed), `no_finding` (tool silent), `tool_error` (degraded)
4. Tag with provenance: agent → tool → rule → file:line

## Attack Pattern Library Schema

`config/attack-patterns.yaml` organized as:
```yaml
{STRIDE_dimension}:
  {DFD_element_type}:
    - caped_id / custom: pattern_id
      name: "Pattern Name"
      indicators: [list of code-level indicators]
```

## SAST Rule Generation

For each attack pattern's indicators, generate tool-specific rules:
- semgrep: YAML rules targeting indicator patterns
- cppcheck: `--enable` flags + suppression lists
- flawfinder: `--minlevel` thresholding
