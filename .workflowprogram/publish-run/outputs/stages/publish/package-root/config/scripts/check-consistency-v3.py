#!/usr/bin/env python3
"""
STRIDE Consistency Check v3 (v0.5)
Machine-checkable semantic consistency.
New in v0.5: two-tier confirmed, static_evidence HIGH → HARD FAIL,
DFD file presence, must-reject expanded, run_manifest generation.

Usage: python3 check-consistency-v3.py <outputs/stride-audit/> [--post-report]
Exit: 0=PASS, 1=HARD_FAIL, 2=SOFT_WARN
"""
import json, os, sys, yaml, uuid
from pathlib import Path
from datetime import datetime
from collections import Counter

AUDIT_DIR = Path(sys.argv[1]).resolve()
CONFIG_DIR = (Path(__file__).resolve().parent.parent)
POST_REPORT = '--post-report' in sys.argv

hard_fails = []
soft_warns = []

def load_json(name):
    with open(AUDIT_DIR / name) as f:
        return json.load(f)

# ============================================================
# CS-DFD-CHECK (v0.5 new): DFD files must exist and be consistent
# ============================================================
dfd_yaml = AUDIT_DIR / 'dfd.yaml'
dfd_mmd = AUDIT_DIR / 'dfd_mermaid.mmd'
dfd_index = AUDIT_DIR / 'dfd_index.json'

for f, name in [(dfd_yaml, 'dfd.yaml'), (dfd_mmd, 'dfd_mermaid.mmd'), (dfd_index, 'dfd_index.json')]:
    if not f.exists():
        hard_fails.append(f"CS-DFD-FILES: {name} MISSING — DFD automation requires this file")
    else:
        print(f"  PASS CS-DFD-FILES: {name} exists ({os.path.getsize(f)} bytes)")

# Cross-validate DFD
if dfd_yaml.exists() and dfd_mmd.exists():
    import yaml as _yaml
    with open(dfd_yaml) as f:
        dfd_data = _yaml.safe_load(f).get('dfd', _yaml.safe_load(f))
    mmd_text = dfd_mmd.read_text(encoding='utf-8', errors='ignore')

    # Count expected nodes from YAML
    ee_count = len(dfd_data.get('external_entities', []))
    p_count = len(dfd_data.get('processes', []))
    ds_count = len(dfd_data.get('data_stores', []))
    total_nodes = ee_count + p_count + ds_count
    total_flows = len(dfd_data.get('data_flows', []))

    # Count nodes in Mermaid
    mmd_nodes = sum(1 for l in mmd_text.split('\n') if '["' in l or '(("' in l or '[("' in l)
    mmd_edges = sum(1 for l in mmd_text.split('\n') if '-->|' in l)

    if abs(mmd_edges - total_flows) > total_flows * 0.5:
        soft_warns.append(f"CS-DFD-CONSISTENCY: Mermaid edges={mmd_edges} vs YAML flows={total_flows} — significant mismatch")
    else:
        print(f"  PASS CS-DFD-CONSISTENCY: YAML={total_nodes} nodes/{total_flows} flows, Mermaid≈{mmd_nodes} nodes/{mmd_edges} edges")

# CS-DFD-LAYOUT (v0.5 new): DFD 布局 10 项门禁
import subprocess
layout_script = CONFIG_DIR / 'scripts' / 'check-dfd-layout.py'
if layout_script.exists():
    layout_result = subprocess.run(
        ['python3', str(layout_script), str(AUDIT_DIR)],
        capture_output=True, text=True
    )
    if layout_result.returncode == 0:
        print(f"  PASS CS-DFD-LAYOUT: 10/10 layout tests passed")
    elif layout_result.returncode == 2:
        soft_warns.append("CS-DFD-LAYOUT: layout WARN (see dfd_layout_check.json)")
        print(f"  WARN CS-DFD-LAYOUT: check dfd_layout_check.json for details")
    else:
        hard_fails.append("CS-DFD-LAYOUT: layout HARD FAIL (see dfd_layout_check.json)")
        print(f"  FAIL CS-DFD-LAYOUT: see dfd_layout_check.json")

# Load data files that must exist
required_files = ['threat_list.json', 'confirmed_findings.json', 'candidate_findings.json',
                  'design_gaps.json', 'false_positives.json', 'out_of_scope.json',
                  'validation_report.json', 'poc_summary.json']
for rf in required_files:
    if not (AUDIT_DIR / rf).exists():
        hard_fails.append(f"CS-REQUIRED-FILE: {rf} MISSING")

if hard_fails:
    print(f"  Stopping early: {len(hard_fails)} file-level failures")
    # Write result and exit
    result = {'hard_fails': hard_fails, 'soft_warns': soft_warns, 'overall': 'FAIL'}
    with open(AUDIT_DIR / 'consistency_check_v3.json', 'w') as f:
        json.dump(result, f, indent=2)
    sys.exit(1)

# Load all data
tl = load_json('threat_list.json')
threats = tl['threats']
cf = load_json('confirmed_findings.json')
cand = load_json('candidate_findings.json')
dg = load_json('design_gaps.json')
fp = load_json('false_positives.json')
try:
    oos = load_json('out_of_scope.json')
except Exception:
    oos = {'findings': []}
ps = load_json('poc_summary.json')

# ============================================================
# CS-COUNT-POC
# ============================================================
declared = ps['meta'].get('total_pocs', 0)
actual = len(ps.get('poc_results', []))
if declared != actual:
    hard_fails.append(f"CS-COUNT-POC: declared={declared} != actual={actual}")
else:
    print(f"  PASS CS-COUNT-POC: {actual}")

# ============================================================
# CS-COUNT-CLASSIFICATION
# ============================================================
summary = tl.get('summary', {}).get('by_classification', {})
for cls, data in [('confirmed', cf), ('partial', cand), ('design', dg), ('false_positive', fp)]:
    sc = summary.get(cls, -1)
    dc = len(data.get('findings', []))
    if sc != dc:
        hard_fails.append(f"CS-COUNT-CLASSIFICATION: summary.{cls}={sc} != {cls}_findings count={dc}")
    else:
        print(f"  PASS CS-COUNT-CLASSIFICATION: {cls}={dc}")

# Total decomposition
clses = Counter(t['final_classification'] for t in threats)
total = len(threats)
if total != sum(clses.values()):
    hard_fails.append(f"CS-COUNT-STANDARD: {total} != sum({dict(clses)})")

# ============================================================
# CS-CONFIRMED-GATES-V05 (v0.5 upgraded)
# ============================================================
confirmed_t = [t for t in threats if t['final_classification'] in ('confirmed', 'confirmed_exploitable', 'confirmed_code_defect')]
for t in confirmed_t:
    tid = t['id']
    precond = t.get('preconditions', [])

    # GATE-PRECONDITION-PRIVILEGE
    if any(p in precond for p in ['root', 'local_fs_write', 'system_partition_write']):
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} elevated precondition {precond}")

    # GATE-EXPLOIT-PATH
    ept = t.get('exploit_path_type', '')
    if ept == 'design_only':
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} design_only cannot be confirmed")
    if ept == 'conditional' and t.get('confirmed_tier') == 'confirmed_exploitable':
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} conditional path cannot be confirmed_exploitable")

    # GATE-STATIC-EVIDENCE-HIGH (v0.5: HARD FAIL)
    if t.get('poc_type') == 'static_evidence' and t.get('severity') == 'HIGH':
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} static_evidence cannot support HIGH severity (v0.5 HARD FAIL)")

    # GATE-SIMULATION-CLAIMS
    if t.get('poc_type') == 'runtime_model_poc':
        obs = t.get('source_evidence', '').lower()
        for forbidden in ['fully verified', 'exploit confirmed', '漏洞已验证']:
            if forbidden.lower() in obs.lower():
                hard_fails.append(f"CS-CONFIRMED-GATES: {tid} simulation PoC claims '{forbidden}'")

    # GATE-ATTACKER-CONTROL
    if t.get('attacker_control') == 'none':
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} attacker_control=none")

    # GATE-CONFIRMED-WITHOUT-POC
    has_poc = any(p['threat_id'] == tid for p in ps.get('poc_results', []))
    if not has_poc and 'why_confirmed_without_poc' not in t:
        hard_fails.append(f"CS-CONFIRMED-GATES: {tid} no PoC and no why_confirmed_without_poc")

n_violations = len([h for h in hard_fails if 'CS-CONFIRMED-GATES' in h])
print(f"  CS-CONFIRMED-GATES: {len(confirmed_t)} confirmed, {n_violations} violations")

# ============================================================
# CS-POC-TIER (v0.5: max severity by PoC type)
# ============================================================
max_sev = {'runtime_target_poc': 'HIGH', 'runtime_model_poc': 'MEDIUM', 'static_evidence': 'MEDIUM', 'design_scenario': 'N/A'}
sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}

for t in threats:
    poc_type = t.get('poc_type', 'none')
    if poc_type in max_sev and max_sev[poc_type] != 'N/A':
        if sev_rank.get(t.get('severity', 'LOW'), 0) > sev_rank.get(max_sev[poc_type], 0):
            if t['final_classification'] in ('confirmed', 'confirmed_exploitable', 'confirmed_code_defect'):
                hard_fails.append(f"CS-POC-TIER: {t['id']} poc_type={poc_type} max severity={max_sev[poc_type]} but actual={t['severity']}")

# ============================================================
# CS-POC-CLAIMS
# ============================================================
for poc in ps.get('poc_results', []):
    pot = poc.get('type', '')
    obs = (poc.get('observation', '') + ' ' + poc.get('execution_output', '')).lower()
    if pot == 'runtime_model_poc':
        for forbidden in ['fully verified', 'exploit confirmed', '漏洞已验证', 'poc有效验证漏洞', 'poC有效验证漏洞']:
            if forbidden.lower() in obs:
                hard_fails.append(f"CS-POC-CLAIMS: {poc['threat_id']} simulation claims '{forbidden}'")
    if pot == 'static_evidence':
        for forbidden in ['verified', 'confirmed exploit', '有效验证漏洞']:
            if forbidden.lower() in obs:
                hard_fails.append(f"CS-POC-CLAIMS: {poc['threat_id']} static_evidence claims '{forbidden}'")

n_poc_violations = len([h for h in hard_fails if 'CS-POC-CLAIMS' in h])
print(f"  CS-POC-CLAIMS: {n_poc_violations} violations")

# ============================================================
# CS-MUST-REJECT-V05 (v0.5 expanded)
# ============================================================
try:
    reg_path = CONFIG_DIR / 'regression-corpus-v2.yaml'
    if reg_path.exists():
        import yaml as _yaml
        reg = _yaml.safe_load(open(reg_path))
        reject_applications = []

        for pattern in reg.get('must_reject_patterns', []):
            pid = pattern['pattern_id']
            keywords = pattern['trigger'].get('finding_keywords', [])
            action = pattern.get('action', {})

            for t in threats:
                text = (t.get('name', '') + ' ' + t.get('source_evidence', '') + ' ' +
                        t.get('description', '')).lower()

                if any(kw.lower() in text for kw in keywords):
                    ffc = action.get('force_classification')
                    fsv = action.get('new_severity')

                    if ffc and t['final_classification'] != ffc and t['final_classification'] != 'false_positive':
                        # Check guard or validation
                        validation = pattern.get('validation', {})
                        if validation.get('check_attacker_model'):
                            precond = t.get('preconditions', [])
                            required = validation.get('required_capability', '')
                            if any(r.strip() in precond for r in required.split('OR')):
                                hard_fails.append(
                                    f"CS-MUST-REJECT: {t['id']} matches {pid} — "
                                    f"should be {ffc}, currently {t['final_classification']}"
                                )
                        else:
                            hard_fails.append(
                                f"CS-MUST-REJECT: {t['id']} matches {pid} — "
                                f"should be {ffc}, currently {t['final_classification']}"
                            )

                    if fsv and t.get('severity') != fsv:
                        hard_fails.append(
                            f"CS-MUST-REJECT: {t['id']} matches {pid} — "
                            f"severity should be {fsv}, currently {t['severity']}"
                        )

        n_reject = len([h for h in hard_fails if 'CS-MUST-REJECT' in h])
        print(f"  CS-MUST-REJECT: {n_reject} violations")

except Exception as e:
    soft_warns.append(f"CS-MUST-REJECT: error loading regression corpus: {e}")

# ============================================================
# CS-MUST-DETECT (unchanged from v2)
# ============================================================
try:
    reg_path = CONFIG_DIR / 'regression-corpus-v2.yaml'
    if reg_path.exists():
        import yaml as _yaml
        reg = _yaml.safe_load(open(reg_path))
        for entry in reg.get('must_detect_entries', []):
            mid = entry['threat_id']
            matcher = entry['matching']
            file_suffix = matcher['file_suffix']
            lo, hi = matcher['line_range']
            found = None
            for t in threats:
                fname = t.get('file', '')
                fname_clean = fname.split(':')[0] if ':' in fname else fname
                if not fname_clean.endswith(file_suffix):
                    continue
                t_line = None
                if ':' in fname:
                    try:
                        t_line = int(fname.split(':')[-1].split('-')[0])
                    except ValueError:
                        pass
                if t_line is not None and lo <= t_line <= hi:
                    found = t
                    break
                se = t.get('source_evidence', '')
                if matcher.get('sink_operation', '') in se or matcher.get('bug_pattern', '') in se:
                    found = t
                    break

            if found is None:
                hard_fails.append(f"CS-MUST-DETECT-COVERAGE: {mid} NOT FOUND")
            else:
                expected = entry['correct_classification']
                actual = found['final_classification']
                # v0.5: confirmed maps to both confirmed_code_defect and confirmed_exploitable
                if expected.startswith('confirmed') and actual.startswith('confirmed'):
                    print(f"  PASS CS-MUST-DETECT: {mid} → {found['id']} ({actual})")
                elif actual != expected:
                    hard_fails.append(f"CS-MUST-DETECT-MISMATCH: {mid} matched {found['id']} classification={actual} != expected={expected}")
                else:
                    print(f"  PASS CS-MUST-DETECT: {mid} → {found['id']} ({actual})")
except Exception as e:
    soft_warns.append(f"CS-MUST-DETECT: error: {e}")

# ============================================================
# CS-ATTACKER-CAPABILITY (unchanged)
# ============================================================
try:
    ac_path = CONFIG_DIR / 'attacker-capabilities.yaml'
    if ac_path.exists():
        import yaml as _yaml
        ac = _yaml.safe_load(open(ac_path))
        default = ac.get('default_profile', 'mobile_device_remote_attacker')
        caps = ac['profiles'][default]['capabilities']
        for t in threats:
            for p in t.get('preconditions', []):
                if p in caps and caps[p] is False:
                    if t['final_classification'] in ('confirmed', 'confirmed_exploitable', 'confirmed_code_defect', 'partial'):
                        hard_fails.append(f"CS-ATTACKER-CAPABILITY: {t['id']} requires {p} but model has {p}=false")
    print(f"  CS-ATTACKER-CAPABILITY: {len([h for h in hard_fails if 'ATTACKER' in h])} violations")
except Exception:
    pass

# ============================================================
# CS-FP-RATIONALE (v2 rule restored in v3)
# ============================================================
for f in fp.get('findings', []):
    fid = f.get('id', '?')
    rationale = f.get('fp_rationale', f.get('reject_rationale', ''))
    name = f.get('name', '')
    if rationale and name:
        name_keywords = set(name.lower().split())
        rationale_lower = rationale.lower()
        matched = sum(1 for kw in name_keywords if len(kw) > 2 and kw in rationale_lower)
        if matched < 2:
            soft_warns.append(f"CS-FP-RATIONALE: {fid} rationale lacks keywords from threat name (matched={matched})")

# ============================================================
# CS-HIGH-CONFIRMED-POC (v2 rule restored in v3)
# ============================================================
for t in threats:
    if t.get('severity') == 'HIGH' and t['final_classification'] in ('confirmed', 'confirmed_exploitable', 'confirmed_code_defect'):
        if t.get('poc_type') != 'runtime_target_poc':
            soft_warns.append(f"CS-HIGH-CONFIRMED-POC: {t['id']} HIGH severity confirmed requires runtime_target_poc, got {t.get('poc_type','none')}")

# ============================================================
# CS-SAST-REFERENCE (v2 rule restored in v3)
# ============================================================
threat_ids = {t['id'] for t in threats}
sast_files = list(AUDIT_DIR.glob('sast_verification*.log')) + list(AUDIT_DIR.glob('sast_*.json'))
for sf in sast_files:
    try:
        content = sf.read_text(encoding='utf-8', errors='ignore')
        for tid_match in __import__('re').findall(r'T-\d+', content):
            if tid_match not in threat_ids:
                soft_warns.append(f"CS-SAST-REFERENCE: {tid_match} in {sf.name} not found in threat_list")
    except Exception:
        pass

# ============================================================
# CS-POC-EVIDENCE (v2 rule restored in v3)
# ============================================================
for t in threats:
    if t.get('confidence') is not None:
        try:
            conf = int(t.get('confidence'))
        except (ValueError, TypeError):
            conf = 5
        poc_type = t.get('poc_type', '')
        if poc_type == 'runtime_model_poc' and conf > 7:
            soft_warns.append(f"CS-POC-EVIDENCE: {t['id']} runtime_model_poc confidence={conf} exceeds max 7")
        if poc_type == 'static_evidence' and conf > 5:
            soft_warns.append(f"CS-POC-EVIDENCE: {t['id']} static_evidence confidence={conf} exceeds max 5")

# ============================================================
# CS-HTML-CONSISTENCY (post-report only)
# ============================================================
if POST_REPORT:
    html_files = sorted(AUDIT_DIR.glob('stride-audit-report-*.html'))
    if html_files:
        latest = html_files[-1]
        text = latest.read_text(encoding='utf-8', errors='ignore')
        # Check keywords
        expected_totals = [
            str(len(threats)),
            str(len(cf.get('findings', []))),
            str(len(cand.get('findings', []))),
            str(len(dg.get('findings', []))),
        ]
        missing = [e for e in expected_totals if e not in text]
        if missing:
            soft_warns.append(f"CS-HTML-CONSISTENCY: HTML may be stale — expected counts not found")
        else:
            print(f"  PASS CS-HTML-CONSISTENCY: counts match HTML ({latest.name})")
    else:
        soft_warns.append("CS-HTML-CONSISTENCY: no HTML report found")

# ============================================================
# RUN_MANIFEST (v0.5 new)
# ============================================================
run_id = f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
stages = {}
stage_files = {
    'parse': 'parse_result.json',
    'dfd': 'dfd.yaml',
    'stride': 'threat_list.json',
    'validation': 'validation_report.json',
    'poc': 'poc_summary.json',
    'result_audit': 'result_audit.json',
    'report': 'stride-audit-report-*.html'
}

for stage, glob_pattern in stage_files.items():
    if '*' in glob_pattern:
        matches = list(AUDIT_DIR.glob(glob_pattern))
        stages[stage] = 'PASS' if matches else 'PENDING'
    else:
        stages[stage] = 'PASS' if (AUDIT_DIR / glob_pattern).exists() else 'PENDING'

# Artifacts list
artifacts = [str(p.name) for p in AUDIT_DIR.glob('*') if p.is_file()]

manifest = {
    'run_id': run_id,
    'workflow_version': '0.5.0',
    'target': tl.get('meta', {}).get('target', 'unknown'),
    'attacker_profile': tl.get('meta', {}).get('attacker_profile', 'mobile_device_remote_attacker'),
    'timestamp': datetime.now().isoformat(),
    'status': 'COMPLETE' if not hard_fails else 'BLOCKED',
    'stages': stages,
    'consistency': {
        'hard_fails': len(hard_fails),
        'soft_warns': len(soft_warns),
        'overall': 'FAIL' if hard_fails else ('WARN' if soft_warns else 'PASS')
    },
    'threat_stats': tl.get('summary', {}),
    'artifacts': artifacts
}

with open(AUDIT_DIR / 'run_manifest.json', 'w') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)
print(f"  RUN_MANIFEST: {run_id} — status={manifest['status']}")

# ============================================================
# FINAL
# ============================================================
result = {
    'run_id': run_id,
    'workflow_version': '0.5.0',
    'hard_fails': hard_fails,
    'soft_warns': soft_warns,
    'overall': 'FAIL' if hard_fails else ('WARN' if soft_warns else 'PASS')
}

with open(AUDIT_DIR / 'consistency_check_v3.json', 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n{'='*60}")
print(f"Consistency Check v3 ({'post-report' if POST_REPORT else 'pre-report'})")
print(f"{'='*60}")
print(f"Hard fails: {len(hard_fails)}")
for f in hard_fails:
    print(f"  FAIL: {f}")
print(f"Soft warns: {len(soft_warns)}")
for w in soft_warns:
    print(f"  WARN: {w}")
print(f"Overall: {result['overall']}")

if hard_fails:
    print(f"\n→ HARD_FAIL: Report blocked")
    sys.exit(1)
elif soft_warns:
    print(f"\n→ SOFT_WARN: Report allowed with {len(soft_warns)} warnings")
    sys.exit(2)
else:
    print(f"\n→ PASS")
    sys.exit(0)
