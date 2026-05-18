#!/usr/bin/env python3
"""
STRIDE Consistency Check v2 (v0.4)
Machine-checkable semantic consistency — NOT just field counting.
Run: python3 check-consistency-v2.py <outputs/stride-audit/>
Exit code 0 = PASS, 1 = HARD_FAIL, 2 = SOFT_WARN
"""
import json, os, sys, yaml
from pathlib import Path
from collections import Counter

AUDIT_DIR = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('outputs/stride-audit').resolve()
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = SCRIPT_DIR.parent  # config/ directory

hard_fails = []
soft_warns = []

def load_json(name):
    with open(AUDIT_DIR / name) as f:
        return json.load(f)

def load_yaml(name):
    with open(CONFIG_DIR / name) as f:
        return yaml.safe_load(f)

# Load data
tl = load_json('threat_list.json')
threats = tl['threats']
cf = load_json('confirmed_findings.json')
cand = load_json('candidate_findings.json')
dg = load_json('design_gaps.json')
oos = load_json('out_of_scope.json')
fp = load_json('false_positives.json')
ps = load_json('poc_summary.json')

# ============================================================
# CS-COUNT-POC: PoC count internal consistency
# ============================================================
declared = ps['meta'].get('total_pocs', 0)
actual = len(ps.get('poc_results', []))
if declared != actual:
    hard_fails.append(f"CS-COUNT-POC: declared total_pocs={declared} != actual len(poc_results)={actual}")
else:
    print(f"  PASS CS-COUNT-POC: poc count consistent ({actual})")

# ============================================================
# CS-COUNT-CLASSIFICATION: cross-file classification consistency
# ============================================================
summary = tl.get('summary', {}).get('by_classification', {})
checks = [
    ('confirmed', len(cf.get('findings', []))),
    ('partial', len(cand.get('findings', []))),
    ('design', len(dg.get('findings', []))),
    ('false_positive', len(fp.get('findings', []))),
]
for cls, count in checks:
    if summary.get(cls) != count:
        hard_fails.append(f"CS-COUNT-CLASSIFICATION: summary.{cls}={summary.get(cls)} != {cls}_findings.json count={count}")
    else:
        print(f"  PASS CS-COUNT-CLASSIFICATION: {cls} count consistent ({count})")

# ============================================================
# CS-COUNT-STANDARD: total decomposition
# ============================================================
cat_total = sum(count for _, count in checks)
if len(threats) != cat_total:
    hard_fails.append(f"CS-COUNT-STANDARD: total threats={len(threats)} != sum(categories)={cat_total}")
else:
    print(f"  PASS CS-COUNT-STANDARD: total={len(threats)} decomposes correctly")

# ============================================================
# CS-CONFIRMED-GATES: confirmed hard gate enforcement
# ============================================================
confirmed_threats = [t for t in threats if t['final_classification'] == 'confirmed']
for t in confirmed_threats:
    tid = t['id']
    precond = t.get('preconditions', [])
    if any(p in precond for p in ['root', 'local_fs_write', 'system_partition_write']):
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} has elevated precondition in {precond}")

    if t.get('exploit_path_type', '') not in ('direct', ''):
        # '' means legacy threat without the field — warn, don't fail
        if t.get('exploit_path_type', 'direct') != 'direct':
            hard_fails.append(f"CS-CONFIRMED-GATES: {tid} exploit_path_type={t.get('exploit_path_type')} != direct")

    if t.get('severity') == 'HIGH' and not t.get('impact_observed', False):
        if t.get('impact_observed') is False:  # explicitly false
            hard_fails.append(f"CS-CONFIRMED-GATES: {tid} HIGH severity but impact_observed=false")

    if t.get('attacker_control') == 'none':
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} attacker_control=none")

print(f"  CS-CONFIRMED-GATES: {len(confirmed_threats)} confirmed, {len([h for h in hard_fails if 'CS-CONFIRMED-GATES' in h])} violations")

# ============================================================
# CS-POC-EVIDENCE: PoC evidence tier vs confirmed claims
# ============================================================
poc_by_threat = {p['threat_id']: p for p in ps.get('poc_results', [])}
for t in confirmed_threats:
    tid = t['id']
    poc = poc_by_threat.get(tid)
    if not poc:
        if 'why_confirmed_without_poc' not in t:
            soft_warns.append(f"CS-POC-EVIDENCE: {tid} confirmed but no PoC and no why_confirmed_without_poc")
        continue

    poc_type = poc.get('type', '')
    if poc_type == 'runtime_model_poc' and t.get('exploitability_score', 0) > 7:
        soft_warns.append(f"CS-POC-EVIDENCE: {tid} runtime_model_poc but confidence={t['exploitability_score']} (>7 cap)")
    if poc_type == 'static_evidence' and t.get('exploitability_score', 0) > 5:
        soft_warns.append(f"CS-POC-EVIDENCE: {tid} static_evidence but confidence={t['exploitability_score']} (>5 cap)")

print(f"  CS-POC-EVIDENCE: {len(soft_warns)} warnings")

# ============================================================
# CS-POC-CLAIMS: PoC claims must match evidence tier
# ============================================================
forbidden_claims = {
    'runtime_model_poc': ['fully verified', 'PoC 有效验证漏洞', 'PoC有效验证漏洞', 'exploit confirmed'],
    'static_evidence': ['verified', 'confirmed', '有效验证', 'PoC有效'],
}
for poc in ps.get('poc_results', []):
    poc_type = poc.get('type', '')
    obs = poc.get('observation', '') + ' ' + poc.get('execution_output', '')
    if poc_type in forbidden_claims:
        for claim in forbidden_claims[poc_type]:
            if claim.lower() in obs.lower():
                hard_fails.append(f"CS-POC-CLAIMS: {poc['threat_id']} type={poc_type} claims '{claim}' in observation")
print(f"  CS-POC-CLAIMS: {len([h for h in hard_fails if 'CS-POC-CLAIMS' in h])} violations")

# ============================================================
# CS-FP-RATIONALE: FP rationale must reference threat name
# ============================================================
fp_threats = [t for t in threats if t['final_classification'] == 'false_positive']
for t in fp_threats:
    rationale = t.get('fp_rationale', '')
    name_words = set(t['name'].lower().split())
    matching = [w for w in name_words if len(w) > 3 and w in rationale.lower()]
    if len(matching) < 2:
        soft_warns.append(f"CS-FP-RATIONALE: {t['id']} rationale has <2 name keywords match")
print(f"  CS-FP-RATIONALE: {len(soft_warns)} warnings")

# ============================================================
# CS-MUST-DETECT precise matching (v2 regression corpus)
# ============================================================
try:
    reg = load_yaml('regression-corpus-v2.yaml')
    for entry in reg.get('must_detect_entries', []):
        mid = entry['threat_id']
        matcher = entry['matching']
        file_suffix = matcher['file_suffix']
        lo, hi = matcher['line_range']

        found = None
        for t in threats:
            fname = t.get('file', '')
            # Strip line number suffix for endswith comparison
            fname_clean = fname.split(':')[0] if ':' in fname else fname
            if not fname_clean.endswith(file_suffix):
                continue

            # Extract line number from file field (e.g., "foo.c:123" or "foo.c:120-130")
            t_line = None
            if ':' in fname:
                line_part = fname.split(':')[-1]
                try:
                    t_line = int(line_part.split('-')[0])
                except ValueError:
                    pass

            if t_line is not None and lo <= t_line <= hi:
                found = t
                break

            # Also check if source_evidence mentions the right function
            se = t.get('source_evidence', '')
            if matcher.get('sink_operation', '') in se or matcher.get('bug_pattern', '') in se:
                found = t
                break

        if found is None:
            hard_fails.append(f"CS-MUST-DETECT-COVERAGE: {mid} NOT FOUND in threat_list (file_suffix={file_suffix}, line_range={lo}-{hi})")
        elif found['final_classification'] != entry['correct_classification']:
            hard_fails.append(f"CS-MUST-DETECT-MISMATCH: {mid} matched {found['id']} but classification={found['final_classification']} != expected={entry['correct_classification']}")
        else:
            print(f"  PASS CS-MUST-DETECT: {mid} → {found['id']} ({found['final_classification']})")

except FileNotFoundError:
    soft_warns.append("CS-MUST-DETECT: regression-corpus-v2.yaml not found, skipping precise match")
print(f"  CS-MUST-DETECT: {len([h for h in hard_fails if 'MUST-DETECT' in h])} violations")

# ============================================================
# CS-ATTACKER-CAPABILITY: threats must respect attacker model
# ============================================================
try:
    ac = load_yaml('attacker-capabilities.yaml')
    default_profile = ac.get('default_profile', 'mobile_device_remote_attacker')
    caps = ac['profiles'][default_profile]['capabilities']

    for t in threats:
        precond = t.get('preconditions', [])
        for p in precond:
            if p in caps and caps[p] is False:
                if t['final_classification'] in ('confirmed', 'partial'):
                    hard_fails.append(
                        f"CS-ATTACKER-CAPABILITY: {t['id']} requires {p} "
                        f"but attacker model '{default_profile}' has {p}=false "
                        f"(classification={t['final_classification']}, expect design/oos)"
                    )
    print(f"  CS-ATTACKER-CAPABILITY: {len([h for h in hard_fails if 'ATTACKER' in h])} violations")
except FileNotFoundError:
    soft_warns.append("CS-ATTACKER-CAPABILITY: attacker-capabilities.yaml not found")

# ============================================================
# CS-SAST-REFERENCE: SAST log cross-reference
# ============================================================
try:
    with open(AUDIT_DIR / 'sast_verification.log') as f:
        sast_log = f.read()
    with open(AUDIT_DIR / 'attack_pattern_map.json') as f:
        apm = json.load(f)

    threat_ids = {t['id'] for t in threats}
    for mapping in apm.get('mappings', []):
        if mapping['threat_id'] not in threat_ids:
            hard_fails.append(f"CS-SAST-REFERENCE: attack_pattern_map references unknown threat_id={mapping['threat_id']}")
    print(f"  CS-SAST-REFERENCE: {len([h for h in hard_fails if 'SAST' in h])} violations")
except FileNotFoundError:
    pass

# ============================================================
# CS-HTML-CONSISTENCY: HTML vs canonical data
# ============================================================
html_files = sorted(AUDIT_DIR.glob('stride-audit-report-*.html'))
if html_files:
    latest_html = html_files[-1]
    html_text = latest_html.read_text(encoding='utf-8', errors='ignore')
    # Quick check: total count appears in HTML
    total_str = str(len(threats))
    if total_str not in html_text:
        soft_warns.append(f"CS-HTML-CONSISTENCY: total_threats={total_str} not found in HTML report")
    print(f"  CS-HTML-CONSISTENCY: checked {latest_html.name}")
else:
    soft_warns.append("CS-HTML-CONSISTENCY: no HTML report found")

# ============================================================
# Summary
# ============================================================
print(f"\n{'='*60}")
print(f"Consistency Check v2 Results")
print(f"{'='*60}")
print(f"Hard fails: {len(hard_fails)}")
for f in hard_fails:
    print(f"  FAIL: {f}")
print(f"Soft warns: {len(soft_warns)}")
for w in soft_warns:
    print(f"  WARN: {w}")

# Write result
result = {
    'hard_fails': hard_fails,
    'soft_warns': soft_warns,
    'overall': 'FAIL' if hard_fails else ('WARN' if soft_warns else 'PASS')
}
with open(AUDIT_DIR / 'consistency_check_v2.json', 'w') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

if hard_fails:
    print(f"\n→ HARD_FAIL: Report blocked until {len(hard_fails)} issues fixed")
    sys.exit(1)
elif soft_warns:
    print(f"\n→ SOFT_WARN: Report allowed with {len(soft_warns)} warnings")
    sys.exit(2)
else:
    print(f"\n→ PASS: All consistency checks passed")
    sys.exit(0)
