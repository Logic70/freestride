# Node Design: Validation

**Node ID:** `validation`
**Agent:** `stride-validator`
**Template:** agent
**Gate:** auto_approval

## Design Overview (v0.2)

Source-code-level evidence validation on every threat before PoC/report stages.
This is the critical quality gate that distinguishes v0.2 from v0.1.

## Methodology

1. **Source Evidence Verification**: Read actual source code at claimed file:line, verify threat matches
2. **Counter-Evidence Check**: Search for guards, validations, error paths that could negate threat
3. **Call Chain Traceability**: Verify entry → handler → validation → vulnerable → impact chain
4. **FP Pattern Matching**: Query `config/fp-patterns.yaml` to detect known false positive patterns
5. **Final Classification**: Assign confirmed/partial/design/oos/false_positive

## Evidence Thresholds (P0)

- HIGH/CRITICAL requires: source line + reachable entry + explainable flaw + counter-evidence checked + no root/HUKS dependency
- Without source evidence → cap at candidate, max MEDIUM
- Without call chain → cap at partial

## Inputs
- `threat_list.json` from stride-analyzer
- `dfd.yaml` from dfd-inferrer
- `call_chain_map.json` from stride-analyzer
- `code_reading_log.md` from dfd-inferrer

## Output
`outputs/stride-audit/validation_report.json` — per-threat validation with source_evidence, counter_evidence_checked, call_chain, fp_patterns_matched, final_classification

## Design Source
- S2 lesson: STRIEAnalyse 40% FP rate → need source-level evidence gate
- S1 requirement: Q6-Q7 PoC evidence quality
- User feedback: HcFileRead false positive (readCount==0 guard missed)
