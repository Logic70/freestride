---
name: stride-consistency-check
description: "Run cross-output consistency validation: ID uniqueness, field completeness, statistics auto-generation"
version: "0.3.0"
---

# STRIDE Consistency Check Skill

## Purpose

Called by `stride-report-assembler` agent. Validates cross-output consistency across all generated files (HTML, JSON outputs, DFD) before finalizing the report. **This is a hard gate — FAIL blocks report output.**

## Validation Rules

### Rule 1: Statistics Auto-Generation
- `summary.total_threats` must equal `len(threats)` in each output file
- Severity counts (critical/high/medium/low) must be computed from the threat list, never hand-written
- Stride dimension counts must be auto-generated
- Classification counts must be auto-generated

### Rule 2: Field Completeness
Every threat in every output file MUST have:
- `id` (unique, non-empty)
- `name` (non-empty)
- `stride_category` (one of 6 values)
- `severity` (Critical/High/Medium/Low)
- `cwe` (valid CWE-ID)
- `file` (valid source path)
- `source_evidence` (non-empty)
- `counter_evidence_checked` (non-empty list, at least 1 entry)
- `mitigation` (non-empty string)
- `final_classification` (confirmed/partial/design/oos/false_positive)

### Rule 3: ID Uniqueness
- All threat IDs must be unique within and across output files
- Format: THREAT-NNN (zero-padded to 3 digits)

### Rule 4: Canonical Reference
- HTML report, confirmed_findings.json, candidate_findings.json, design_gaps.json, out_of_scope.json, false_positives.json must all reference the same canonical threat list
- No threat can appear in more than one output file
- The union of all split output threats must equal the original threat_list.json

### Rule 5: Severity Evidence Gate
- Any threat with severity HIGH/CRITICAL in confirmed_findings.json must have: source line number, complete call chain, confidence HIGH or MEDIUM, counter-evidence non-empty
- Any threat without these marked HIGH/CRITICAL → validation FAIL

### Rule 6: ID Cross-Reference (NEW v0.3)
- Every `threat_id` referenced in `sast_verification.log` and `attack_pattern_map.json` MUST exist in `threat_list.json`
- Any referenced ID that does not exist → FAIL
- This prevents ID drift between verification artifacts and the canonical threat list

### Rule 7: FP Rationale Match (NEW v0.3)
- For every threat with `final_classification == "false_positive"`:
  - `fp_rationale` MUST be non-empty
  - `fp_code_ref` MUST be non-empty and reference a valid source file:line
  - `fp_rationale` text MUST contain at least one keyword from the threat's `name` field
- Any violation → FAIL
- This prevents mismatches like "UDID anonymization" rationale on an HcMalloc threat

### Rule 8: JSON/HTML Count Consistency (NEW v0.3)
- The HTML report's rendered counts for confirmed/candidate/design/fp MUST equal the `count` fields in:
  - confirmed_findings.json
  - candidate_findings.json
  - design_gaps.json
  - false_positives.json
- If any count mismatches between HTML and JSON → FAIL

### Rule 9: Must-Reject Override (NEW v0.3.1)
- Load `config/regression-corpus.yaml` → `must_reject_patterns`
- For each pattern, check if ANY threat in `confirmed_findings.json` matches the pattern's `description` or `proof_location`
- If a confirmed threat matches a must_reject pattern → **auto-reclassify to false_positive** with the pattern's `proof_code` as `fp_code_ref` and `rationale` as `fp_rationale`
- Move the threat from `confirmed_findings.json` to `false_positives.json`
- Record the override in `auto_corrected.must_reject_overrides`
- This gate runs BEFORE any other output validation

### Rule 10: Must-Detect Check (NEW v0.3.1)
- Load `config/regression-corpus.yaml` → `must_detect_entries`
- For each entry, search `threat_list.json` for a threat whose `file:line` or `description` matches
- If found with correct `final_classification` → pass
- If found with WRONG `final_classification` → FAIL, flag as `must_detect_misclassified`
- If NOT found in threat list at all → flag as `must_detect_miss`, record in `known_misses`
- `must_detect_miss` is NOT a hard fail (does not block output), but MUST be listed in the report's "Known Misses" section
- `must_detect_misclassified` IS a hard fail

## Hard Fail Policy (NEW v0.3.1)

Any FAIL on Rules 1-9, or `must_detect_misclassified` → **hard_fail = true**. Report output is BLOCKED.

`must_detect_miss` (Rule 10 miss) is a SOFT fail — report MAY proceed but MUST include a "Known Misses" section.

Max 3 fix iterations. After 3 iterations with violations remaining, produce a partial report with explicit `validation_failures` section.

## Output

```json
{
  "consistency_status": "PASS|FAIL",
  "hard_fail": true|false,
  "checks": {
    "statistics_auto_generated": true,
    "fields_complete": true,
    "ids_unique": true,
    "canonical_reference": true,
    "evidence_gate": true,
    "id_cross_reference": true,
    "fp_rationale_match": true,
    "json_html_count_match": true,
    "must_reject_override": true,
    "must_detect_check": true
  },
  "violations": [
    {"rule": "Rule 9", "threat_id": "STRIDE-004", "pattern_id": "REJECT-001", "detail": "Confirmed threat matches must_reject pattern — auto-reclassified to false_positive"}
  ],
  "must_detect_misses": [
    {"entry_id": "MUST-003", "description": "Account-related group membership bypass", "detail": "No threat in list matches this known vulnerability"}
  ],
  "auto_corrected": {
    "summary_severity_counts": "recomputed from threat list",
    "must_reject_overrides": ["STRIDE-004 → false_positive via REJECT-001", "STRIDE-008 → false_positive via REJECT-002"]
  },
  "known_misses": [
    {"entry_id": "MUST-002", "description": "Seed value not zeroed before free in identity_group.c:542", "correct_classification": "confirmed"}
  ]
}
```
