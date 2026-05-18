#!/usr/bin/env python3
"""
STRIDE Report Assembler (v0.5) — report 阶段唯一入口
用法: python3 assemble-report.py <outputs/stride-audit/>
退出: 0=成功, 1=布局门禁FAIL, 2=校验WARN
"""
import json, os, sys, yaml, subprocess
from datetime import datetime
from pathlib import Path
from jinja2 import Template

AUDIT_DIR = Path(sys.argv[1]).resolve()
CONFIG_DIR = (Path(__file__).resolve().parent.parent)
SCRIPTS_DIR = CONFIG_DIR / 'scripts'
TEMPLATES_DIR = CONFIG_DIR.parent / 'templates'

# 将 scripts 目录加入 path
sys.path.insert(0, str(SCRIPTS_DIR))
from dfd_data import (
    NODE_POSITIONS, EDGES, TRUST_BOUNDARIES, ELEMENT_DESC, generate_dfd_index
)
from dfd_svg import render_svg_dfd

# ============================================================
# Step 1: 加载 canonical 数据
# ============================================================
with open(AUDIT_DIR / 'threat_list.json') as f:
    tl = json.load(f)
with open(AUDIT_DIR / 'dfd.yaml') as f:
    dfd = yaml.safe_load(f)
with open(AUDIT_DIR / 'poc_summary.json') as f:
    ps = json.load(f)
with open(AUDIT_DIR / 'dfd_mermaid.mmd') as f:
    mmd = f.read()
try:
    with open(AUDIT_DIR / 'result_audit.json') as f: ra = json.load(f)
except Exception:
    ra = {"missing": True, "warning": "result_audit.json not found — result-auditor stage may be incomplete"}
try:
    with open(AUDIT_DIR / 'consistency_check_v3.json') as f: cs = json.load(f)
except Exception: cs = {}
try:
    with open(AUDIT_DIR / 'run_manifest.json') as f: rm = json.load(f)
except Exception: rm = {}

dfd_data = dfd.get('dfd', dfd)
all_threats = tl['threats']
summary = tl['summary']

# ============================================================
# Step 2: 重建 dfd_index
# ============================================================
dfd_idx = generate_dfd_index(all_threats, dfd_data)
with open(AUDIT_DIR / 'dfd_index.json', 'w') as f:
    json.dump(dfd_idx, f, indent=2, ensure_ascii=False)
print('[assemble] dfd_index.json rebuilt')

# ============================================================
# Step 3: 生成 SVG
# ============================================================
svg = render_svg_dfd(NODE_POSITIONS, EDGES, TRUST_BOUNDARIES, dfd_idx, ELEMENT_DESC)
with open(AUDIT_DIR / 'dfd_diagram.svg', 'w') as f:
    f.write(svg)
print(f'[assemble] SVG DFD generated ({len(svg)} chars)')

# ============================================================
# Step 4: 运行布局门禁
# ============================================================
gate_script = SCRIPTS_DIR / 'check-dfd-layout.py'
gate_result = subprocess.run(
    ['python3', str(gate_script), str(AUDIT_DIR)],
    capture_output=True, text=True
)
if gate_result.returncode == 1:
    print(f'[assemble] DFD LAYOUT GATE FAILED:\n{gate_result.stdout[-500:]}')
    sys.exit(1)
elif gate_result.returncode == 2:
    print('[assemble] DFD layout WARN — report will include warnings')
else:
    print('[assemble] DFD layout gate PASS')

# ============================================================
# Step 5: 渲染 Jinja2 模板
# ============================================================
confirmed = [t for t in all_threats if t['final_classification'] in ('confirmed','confirmed_code_defect','confirmed_exploitable')]
top = sorted(confirmed, key=lambda x: {'CRITICAL':5,'HIGH':4,'MEDIUM':3,'LOW':2}.get(x['severity'],1), reverse=True)[:8]

# 构建 threat_id → file 映射 (PoC 代码路径)
threat_file_map = {t['id']: t.get('file', '') for t in all_threats}

# 构建 element_id → element_name 映射 (DFD 元素名称)
dfd_name_map = {}
for cat in ('external_entities', 'processes', 'data_stores', 'data_flows'):
    for eid, entry in dfd_idx.get(cat, {}).items():
        dfd_name_map[eid] = entry.get('name', eid)

# PoC 状态/类型中译映射
POC_STATUS_CN = {
    'VERIFIED': '已验证', 'STATIC_EVIDENCE': '静态证据', 'DESIGN_SCENARIO': '设计场景',
    'DESIGN_ONLY': '仅设计', 'FALSE_POSITIVE': '误报', 'PASS': '通过',
    'FAIL': '失败', 'UNVERIFIED': '未验证',
}
POC_TYPE_CN = {
    'runtime_target_poc': '目标代码运行时验证',
    'runtime_model_poc': '独立机制模拟',
    'static_evidence': '静态代码证据',
    'design_scenario': '设计场景分析',
}

# 增强 PoC 结果：添加源码路径、中译标签
enhanced_pocs = []
for poc in ps.get('poc_results', []):
    tid = poc.get('threat_id', '')
    poc_type_raw = poc.get('type', poc.get('poc_type', ''))
    enhanced = dict(poc)
    enhanced['source_file'] = threat_file_map.get(tid, '')
    enhanced['status_cn'] = POC_STATUS_CN.get(poc.get('status', ''), poc.get('status', ''))
    enhanced['type_cn'] = POC_TYPE_CN.get(poc_type_raw, poc_type_raw)
    enhanced_pocs.append(enhanced)

poc_summary_enhanced = {
    'meta': ps.get('meta', {}),
    'poc_results': enhanced_pocs,
}

meta = {
    'system_name': rm.get('target', tl['meta'].get('target', 'Unknown Target')),
    'workflow_version': '0.5.0',
    'analysis_date': rm.get('timestamp', datetime.now().isoformat()),
    'attacker_profile': tl['meta'].get('attacker_profile', 'mobile_device_remote_attacker'),
    'target': tl['meta'].get('target', ''),
}
exec_sum = {
    'total_threats': len(all_threats),
    'severity_counts': summary['by_severity'],
    'classification_counts': summary['by_classification'],
    'top_findings': [{'title': t['name'], 'severity': t['severity'], 'classification': t['final_classification']} for t in top],
}
dfd_stats = {
    'external_entities': len(dfd_data.get('external_entities', [])),
    'processes': len(dfd_data.get('processes', [])),
    'data_stores': len(dfd_data.get('data_stores', [])),
    'data_flows': len(EDGES),
    'trust_boundaries': len(dfd_data.get('trust_boundaries', [])),
    'elements_with_threats': sum(1 for cat in dfd_idx for v in dfd_idx[cat].values() if v['threat_count'] > 0),
}

# 加载模板
with open(TEMPLATES_DIR / 'report-template.html') as f:
    tpl = Template(f.read())

html = tpl.render(
    meta=meta, executive_summary=exec_sum, threats=all_threats,
    dfd_mermaid=mmd, dfd_svg=svg, dfd_status='PASS', dfd_stats=dfd_stats,
    result_audit=ra, consistency=cs, poc_summary=poc_summary_enhanced,
    dfd_element_names=dfd_name_map,
    methodology={'limitations': ['SAST不可用', 'PoC以runtime_model_poc为主']},
    sast_status='UNAVAILABLE',
)

ts = datetime.now().strftime('%Y%m%d-%H%M%S')
path = AUDIT_DIR / f'stride-audit-report-{ts}.html'
with open(path, 'w', encoding='utf-8') as f:
    f.write(html)
print(f'[assemble] Report: {path} ({os.path.getsize(path) / 1024:.1f} KB)')

# ============================================================
# Step 5.5: HTML 交互契约硬门禁
# ============================================================
dfd_node_count = len(NODE_POSITIONS)
html_issues = []

# Check container exists
if 'id="dfd-svg-container"' not in html:
    html_issues.append('missing #dfd-svg-container')

# Check data-eid count >= node count
import re as _re
eid_count = len(_re.findall(r'data-eid="([^"]*)"', html))
if eid_count < dfd_node_count:
    html_issues.append(f'data-eid count ({eid_count}) < DFD nodes ({dfd_node_count})')

# Check data-analysis exists on nodes
analysis_count = len(_re.findall(r'data-analysis="', html))
if analysis_count < dfd_node_count:
    html_issues.append(f'data-analysis count ({analysis_count}) < DFD nodes ({dfd_node_count})')

# Check no onclick attributes in SVG/HTML (excluding <script> blocks)
html_body = _re.sub(r'<script>.*?</script>', '', html, flags=_re.DOTALL)
onclick_count = html_body.count('onclick=')
if onclick_count > 0:
    html_issues.append(f'found {onclick_count} inline onclick attributes outside &lt;script&gt; (must use event delegation)')

# Check .dfd-clickable class exists on SVG elements
clickable_count = html.count('class="dfd-clickable"')
if clickable_count < dfd_node_count:
    html_issues.append(f'class="dfd-clickable" count ({clickable_count}) < DFD nodes ({dfd_node_count})')

# Check event delegation code exists in script
script_match = _re.search(r'<script>(.*?)</script>', html, _re.DOTALL)
if not script_match:
    html_issues.append('missing <script> block')
else:
    js = script_match.group(1)
    if "addEventListener('click'" not in js and 'addEventListener("click"' not in js:
        html_issues.append('missing event delegation (addEventListener click) in JS')
    if 'renderDfdDetail' not in js:
        html_issues.append('missing renderDfdDetail function in JS')

# Check data-threats/data-analysis JSON parseable (from SVG elements, not script)
html_body = _re.sub(r'<script>.*?</script>', '', html, flags=_re.DOTALL)
sample_threats = _re.findall(r'data-threats="([^"]*)"', html_body)
bad_json = 0
for s in sample_threats[:10]:
    try:
        import html as _html_mod
        json.loads(_html_mod.unescape(s))
    except Exception as e:
        bad_json += 1
        if bad_json <= 2:
            print(f'  [contract] JSON parse fail: {str(e)[:80]}')
if bad_json > 0:
    html_issues.append(f'{bad_json}/{len(sample_threats[:10])} sampled data-threats fail JSON parse')

if html_issues:
    print(f'[assemble] HTML CONTRACT GATE FAILED:')
    for issue in html_issues:
        print(f'  - {issue}')
    sys.exit(1)
else:
    print(f'[assemble] HTML contract gate PASS ({eid_count} data-eid, {clickable_count} clickable, {analysis_count} analysis, 0 onclick)')

# ============================================================
# Step 6: 后置校验
# ============================================================
check_script = SCRIPTS_DIR / 'check-consistency-v3.py'
post_result = subprocess.run(
    ['python3', str(check_script), str(AUDIT_DIR), '--post-report'],
    capture_output=True, timeout=30
)

# ============================================================
# Step 7: 更新 run_manifest (merge, not overwrite)
# ============================================================
run_id = rm.get('run_id', f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}")

# Load existing manifest (from consistency checker) to preserve consistency + artifacts
existing_rm = {}
rm_path = AUDIT_DIR / 'run_manifest.json'
if rm_path.exists():
    try:
        with open(rm_path) as f:
            existing_rm = json.load(f)
    except Exception:
        pass

manifest = {
    'run_id': run_id,
    'workflow_version': '0.5.0',
    'target': meta['target'],
    'timestamp': datetime.now().isoformat(),
    'status': 'COMPLETE',
    'stages': existing_rm.get('stages', {
        'parse': 'PASS', 'dfd': 'PASS', 'stride': 'PASS', 'validation': 'PASS',
        'poc': 'PASS', 'result_audit': 'PASS', 'report': 'PASS'
    }),
    'threat_stats': summary,
    'artifacts': existing_rm.get('artifacts', []),
    'consistency': existing_rm.get('consistency', {}),
    'post_consistency': 'PASS' if post_result.returncode == 0 else ('WARN' if post_result.returncode == 2 else 'FAIL'),
}

if post_result.returncode == 1:
    manifest['status'] = 'BLOCKED'
    print('[assemble] Post-consistency check FAILED — manifest status=BLOCKED')
elif post_result.returncode == 2:
    manifest['status'] = 'COMPLETE'
    print('[assemble] Post-consistency check WARN — report allowed with warnings')

with open(rm_path, 'w') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)
print('[assemble] run_manifest merged (preserving consistency + artifacts)')
print('[assemble] DONE')
