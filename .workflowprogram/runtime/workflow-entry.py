#!/usr/bin/env python3
"""
STRIDE Security Audit Workflow Entry Point v0.2
Deterministic control-plane orchestration for /stride-audit.

v0.2 stages: parse → dfd → stride → verify → validation → poc → report → [diff]
Key additions: call_chain_map.json, validation_report.json, split outputs (5 files),
FP pattern matching, consistency gate, poc_plan, evidence thresholds for HIGH/CRITICAL.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
TARGET_ROOT = Path.cwd()


def parse_args():
    parser = argparse.ArgumentParser(description="STRIDE Security Audit Workflow")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the STRIDE audit workflow")
    run_parser.add_argument("--spec", required=True, help="Path to workflow-spec.yaml")
    run_parser.add_argument("--run-root", required=True, help="Path to RUN_ROOT")
    run_parser.add_argument("--target-root", default=str(TARGET_ROOT), help="Target project root")
    run_parser.add_argument("--entry-skill", default="workflowprogram-develop")
    run_parser.add_argument("--request", required=True, help="Original request text")
    run_parser.add_argument("--auto-approve", action="store_true")
    run_parser.add_argument("--approval-status")

    return parser.parse_args()


def run_script(script_name, *args):
    script_path = SCRIPT_DIR / script_name
    cmd = [sys.executable, str(script_path)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


def main():
    args = parse_args()

    if args.command == "run":
        spec_path = Path(args.spec).resolve()
        run_root = Path(args.run_root).resolve()
        target_root = Path(args.target_root).resolve()

        os.makedirs(run_root / "outputs", exist_ok=True)

        print(f"[entry] spec={spec_path}")
        print(f"[entry] run_root={run_root}")
        print(f"[entry] target_root={target_root}")

        # Step 1: Validate workflow spec
        print("[entry] Step 1: validate-workflow-spec.py")
        result = run_script("validate-run-state.py", "--spec", str(spec_path))
        if result.returncode != 0:
            print(f"[entry] Spec validation failed:\n{result.stderr}")
            sys.exit(1)

        # Step 2: Generate workflow view
        print("[entry] Step 2: generate-workflow-view.py")
        # (delegated to workflow-runner.py for full pipeline)

        # Step 3: Generate lowlevel doc
        print("[entry] Step 3: generate-workflow-lowlevel.py")

        # Step 4-10: Delegated to workflow-runner
        print("[entry] Step 4-10: delegating to workflow-runner.py")
        result = run_script("workflow-runner.py",
                            "--spec", str(spec_path),
                            "--run-root", str(run_root),
                            "--target-root", str(target_root),
                            "--request", args.request)
        if result.returncode != 0:
            print(f"[entry] workflow-runner failed:\n{result.stderr}")
            sys.exit(result.returncode)

        print("[entry] STRIDE workflow completed successfully")
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
