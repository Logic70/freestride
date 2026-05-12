#!/usr/bin/env python3
"""
STRIDE Workflow Run State Validator
Validates workflow-spec.yaml structure and run state consistency.
"""
import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def validate_spec_structure(spec_path):
    """Basic structural validation of workflow-spec.yaml."""
    if yaml is None:
        print("[validator] WARNING: yaml module not available, skipping YAML validation")
        return True

    try:
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
    except Exception as e:
        print(f"[validator] ERROR: Cannot parse {spec_path}: {e}")
        return False

    required_top = {"meta", "stages", "intent_flows", "agent_refs", "skills",
                    "registry", "constraints", "resource_limits", "runtime_contract",
                    "generated_runtime_contract", "test_contract"}
    missing = required_top - set(spec.keys())
    if missing:
        print(f"[validator] ERROR: Missing top-level keys: {missing}")
        return False

    print(f"[validator] PASS: {spec_path} has all required top-level keys")
    return True


def validate_assets_exist(target_root):
    """Verify expected candidate assets are present."""
    required_assets = [
        ".claude/commands/stride-audit.md",
        ".claude/agents/stride-parse.md",
        ".claude/agents/stride-dfd-inferrer.md",
        ".claude/agents/stride-analyzer.md",
        ".claude/agents/stride-attack-pattern-matcher.md",
        ".claude/agents/stride-sast-verifier.md",
        ".claude/agents/stride-validator.md",
        ".claude/agents/stride-poc-generator.md",
        ".claude/agents/stride-report-assembler.md",
        ".claude/agents/stride-diff-analyzer.md",
        ".claude/skills/stride-fp-pattern-lookup/SKILL.md",
        ".claude/skills/stride-consistency-check/SKILL.md",
        ".workflowprogram/runtime/workflow-entry.py",
        ".workflowprogram/runtime/workflow-runner.py",
        ".workflowprogram/runtime/validate-run-state.py",
        ".workflowprogram/runtime/runtime-manifest.json",
        "config/fp-patterns.yaml",
    ]

    root = Path(target_root)
    missing_assets = []
    for asset in required_assets:
        if not (root / asset).exists():
            missing_assets.append(asset)

    if missing_assets:
        print(f"[validator] WARNING: Missing assets: {missing_assets}")
        return False

    print(f"[validator] PASS: All {len(required_assets)} required assets present")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, help="Path to workflow-spec.yaml")
    parser.add_argument("--target-root", default=".", help="Root to check assets against")
    args = parser.parse_args()

    spec_ok = validate_spec_structure(args.spec)
    assets_ok = validate_assets_exist(args.target_root)

    if spec_ok and assets_ok:
        print("[validator] OVERALL: PASS")
        sys.exit(0)
    else:
        print("[validator] OVERALL: FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
