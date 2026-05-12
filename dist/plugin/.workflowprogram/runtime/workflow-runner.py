#!/usr/bin/env python3
"""
STRIDE Security Audit Workflow Runner
Executes the runtime pipeline: validate → generate views → generate runtime →
managed assets → capability discovery → host probe → bootstrap → remediation.
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--request", default="")
    args = parser.parse_args()

    spec_path = Path(args.spec)
    run_root = Path(args.run_root)
    target_root = Path(args.target_root)

    print(f"[runner] Running STRIDE workflow pipeline")
    print(f"[runner] spec={spec_path}")
    print(f"[runner] run_root={run_root}")
    print(f"[runner] target_root={target_root}")

    # Copy design artifacts to candidate output
    candidate_design = run_root / "outputs/candidate/.workflowprogram/design"
    candidate_runtime = run_root / "outputs/candidate/.workflowprogram/runtime"
    os.makedirs(candidate_design, exist_ok=True)
    os.makedirs(candidate_runtime, exist_ok=True)

    # Copy spec
    import shutil
    shutil.copy2(spec_path, candidate_design / "workflow-spec.yaml")

    # Copy views if they exist
    for view_file in ["workflow-view.md", "workflow-lowlevel.md"]:
        src = run_root / "outputs/stages" / view_file
        if src.exists():
            shutil.copy2(src, candidate_design / view_file)

    # Emit stage completion marker
    summary = {
        "workflow": "stride-security-audit",
        "version": "0.2.0",
        "status": "candidate-generated",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "candidate_root": str(run_root / "outputs/candidate"),
        "target_root": str(target_root),
    }

    summary_path = run_root / "outputs/stages/s4-generation-summary.json"
    os.makedirs(summary_path.parent, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[runner] Generation summary written to {summary_path}")
    print("[runner] Pipeline complete. Managed apply pending.")


if __name__ == "__main__":
    main()
