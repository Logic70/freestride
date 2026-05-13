# PoC Iteration Loop

Iterating on PoC code for STRIDE threat validation.

## Per-Iteration Instructions
1. Review PoC code from previous attempt
2. Fix syntax or logic errors
3. Re-validate against source code at claimed file:line
4. If sandbox available: execute and capture results
5. If execution fails: analyze error, fix, retry

## Stop Conditions
- success: PoC syntax valid + sandbox execution passes
- max_iterations: reached (mark as EXECUTION_FAILED with error log)

## Evidence Output
Save each iteration to: outputs/stages/loops/poc/poc_iteration_{n}.md
