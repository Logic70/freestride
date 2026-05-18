# Report Render Iteration Loop

Iterating on HTML report generation for STRIDE analysis.

## Per-Iteration Instructions
1. Render report with current data context
2. Validate HTML5 syntax
3. Run consistency gate:
   - summary.total_threats == len(threats) in all outputs
   - All required fields: id, name, stride_category, severity, cwe, file, source_evidence
   - IDs unique; severity evidence gate for HIGH/CRITICAL
4. If validation fails: fix template/data, retry

## Stop Conditions
- success: HTML renders + all consistency checks pass + all sections populated
- max_iterations: reached (mark violations in report header)

## Evidence Output
Save each iteration to: outputs/stages/loops/report/report_snapshot_{n}.html
