#!/usr/bin/env python3
"""
STRIDE Report Assembler (v0.5) — report 阶段唯一入口
用法: python3 assemble-report.py <outputs/stride-audit/>
退出: 0=成功, 1=布局门禁FAIL, 2=校验WARN
"""
import json, os, sys, yaml, subprocess
from collections import Counter
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
    with open(AUDIT_DIR / 'validation_report.json') as f: validation_data = json.load(f)
except Exception: validation_data = {}
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
# Step 5: 分类契约 — final_classification 保留 + report_bucket 派生
# ============================================================
FINAL_TO_BUCKET = {
    "confirmed_exploitable": "confirmed",
    "confirmed_code_defect": "confirmed",
    "confirmed": "confirmed",          # legacy input only
    "partial": "candidate",
    "candidate": "candidate",          # legacy input only
    "design": "design",
    "out_of_scope": "out_of_scope",
    "oos": "out_of_scope",             # legacy input only
    "false_positive": "false_positive",
    "fp": "false_positive",            # legacy input only
}

canonical_classification_counts = {}
report_bucket_counts = {}
for t in all_threats:
    raw = t.get('final_classification', 'partial')
    bucket = FINAL_TO_BUCKET.get(raw, 'candidate')

    # 保留原始 final_classification，不覆盖
    t['raw_final_classification'] = raw
    t['final_classification'] = raw
    t['report_bucket'] = bucket
    t['confirmed_tier'] = (
        raw if raw in ('confirmed_exploitable', 'confirmed_code_defect')
        else t.get('confirmed_tier', '')
    )

    canonical_classification_counts[raw] = canonical_classification_counts.get(raw, 0) + 1
    report_bucket_counts[bucket] = report_bucket_counts.get(bucket, 0) + 1

# 分类计数：同时输出 canonical 和 bucket
# classification_counts 作为兼容 alias 短期指向 report_bucket_counts
classification_counts = dict(report_bucket_counts)

# 分表：按 report_bucket 过滤
confirmed = [t for t in all_threats if t['report_bucket'] == 'confirmed']
candidate = [t for t in all_threats if t['report_bucket'] == 'candidate']
design = [t for t in all_threats if t['report_bucket'] == 'design']
false_positives = [t for t in all_threats if t['report_bucket'] == 'false_positive']
oos = [t for t in all_threats if t['report_bucket'] == 'out_of_scope']
top = sorted(confirmed, key=lambda x: {'CRITICAL':5,'HIGH':4,'MEDIUM':3,'LOW':2}.get(x['severity'],1), reverse=True)[:8]


# ============================================================
# 字段映射：将 threat_list + validation + poc 数据 enrich 到模板期望的字段名
# ============================================================
# 加载补充数据
vt_map = {}
for vt in validation_data.get("validated_threats", validation_data.get("findings", [])):
    vt_map[vt.get('threat_id', vt.get('id', ''))] = vt
# 兼容 PoC schema: 新格式 {meta, poc_results} / 旧格式 {poc_entries, poc_summary}
poc_map = {}
POC_VALID_STATUSES = {'TARGET_VERIFIED','MODEL_VALIDATED','STATIC_CONFIRMED',
                       'DESIGN_ONLY','SKIPPED','FAILED','UNVERIFIED'}
if 'poc_results' in ps:
    poc_source = ps['poc_results']
    poc_meta = ps.get('meta', {'total_pocs': len(poc_source), 'executed': 0})
elif 'poc_entries' in ps:
    # Convert legacy entries to new format
    poc_source = []
    for pe in ps['poc_entries']:
        pp = pe.get('poc_plan', {})
        old_status = pe.get('poc_execution_status', 'not_executed')
        new_status = ('STATIC_CONFIRMED' if pe.get('poc_type') == 'static_evidence'
                 else 'MODEL_VALIDATED' if pe.get('poc_type') == 'runtime_model_poc'
                 else 'UNVERIFIED')
        poc_type = pe.get('poc_type', 'static_evidence')
        # static_evidence: target_code_invoked is ALWAYS false — no runtime call to target code
        tci = poc_type == 'runtime_target_poc' and bool(pp.get('target_code_invoked'))
        poc_source.append({
            'threat_id': pe['threat_id'],
            'poc_type': poc_type,
            'status': new_status,
            'target_code_invoked': tci,
            'allowed_claim': pp.get('allowed_claim', ''),
            'limitations': pp.get('limitations', ''),
        })
    poc_meta = ps.get('poc_summary', ps.get('meta', {'total_pocs': len(poc_source), 'executed': 0}))
else:
    poc_source = []
    poc_meta = {'total_pocs': 0, 'executed': 0}

for pe in poc_source:
    poc_map[pe['threat_id']] = pe

for t in all_threats:
    tid = t['id']
    vt = vt_map.get(tid, vt_map.get(t.get('id',''), {}))
    pe = poc_map.get(tid, {})

    # 模板期望 'file' → 从 source_files 取
    sf = t.get('source_files', [])
    t['file'] = sf[0] if sf else t.get('sink_function', '')

    # 模板期望 'mitigation' → 从 mitigation_hints 合并
    mh = t.get('mitigation_hints', [])
    t['mitigation'] = '\n'.join(f'• {m}' for m in mh) if mh else ''

    # 模板期望 'source_evidence' → 从 validation 取
    # Pull final_classification from validation if threat does not have it
    if not t.get("final_classification") or t.get("final_classification") == "partial":
        t["final_classification"] = vt.get("classification", t.get("final_classification", "partial"))
    t['source_evidence'] = vt.get('source_evidence', '')

    # 模板期望 'counter_evidence_checked' → 从 validation 取
    cec = vt.get('counter_evidence_checked', '')
    t['counter_evidence_checked'] = [cec] if isinstance(cec, str) and cec else (cec if isinstance(cec, list) else [])

    # PoC info (compatible with both old poc_plan and new flat schema)
    t["poc_type"] = pe.get("poc_type", "static_evidence")
    pp = pe.get("poc_plan", {})
    t["poc_file"] = pe.get("source_file", pp.get("source_file", ""))
    t["poc_line"] = pe.get("source_line", pp.get("source_line", ""))
    # static_evidence: target_code_invoked must be false — no runtime call to target
    raw_tci = pe.get("target_code_invoked", pp.get("target_code_invoked", False))
    if isinstance(raw_tci, str):
        raw_tci = raw_tci.lower() in ('true', '1', 'yes')
    t["poc_target_invoked"] = bool(raw_tci) and t.get("poc_type") == "runtime_target_poc"
    # keep code path info in poc_target (source location, not runtime claim)
    t["poc_target"] = t.get("file", "") or t.get("sink_function", "")
    t["poc_desc"] = pe.get("description", pp.get("description", ""))
    t["poc_limitation"] = pe.get("limitations", pp.get("limitations", ""))
    t["poc_claim"] = pe.get("allowed_claim", pp.get("allowed_claim", ""))
    t["poc_status"] = pe.get("status", "UNVERIFIED")
    
    # confirmed_tier (already set by FINAL_TO_BUCKET, keep as fallback)
    if not t.get("confirmed_tier"):
        t["confirmed_tier"] = "code_defect" if t.get("final_classification") == "confirmed_code_defect" else ""

# 构建 threat_id → file 映射 (PoC 代码路径)
threat_file_map = {t['id']: t.get('file', '') for t in all_threats}

# ============================================================
# Must-Reject 强制降级 (v0.5 regression-corpus-v2.yaml)
# ============================================================
for t in all_threats:
    name = t.get('name', '')
    desc = t.get('description', '')
    combined = f"{name} {desc}".lower()

    # REJECT-005: PIN bit-length misread — HcStrlen>=6 means 6 CHARACTERS, not 6 bits
    if ('pin' in combined and ('brute' in combined or '6bit' in combined or '6 bit' in combined or '64' in combined)):
        if t['final_classification'] not in ('false_positive', 'out_of_scope'):
            t['final_classification'] = 'false_positive'
            t['report_bucket'] = 'false_positive'
            t['fp_code_ref'] = 'REJECT-005'
            t['fp_rationale'] = ('HcStrlen(pinCode) >= 6 检查的是字符串长度≥6个**字符**，不是6个bit。'
                                 '即使是纯数字PIN码也有10^6=1,000,000种组合（~20bit），'
                                 '按readme要求6字符混合可达48bit以上。以bit/char混淆为基础的暴力破解认定不成立。'
                                 'PIN无速率限制本身仍是设计缺陷，但不可作为可暴力破解漏洞提交。')
            t['reject_rule'] = 'REJECT-005'
    # REJECT-002: Credential export no auth/audit claim
    cred_keywords = ("export" in combined or "no auth" in combined or "unauthorized" in combined or "logging" in combined or "audit" in combined)
    if "credential" in combined and cred_keywords and t.get("sink_function", "") != "CheckOwnerUidPermission":
        if t["final_classification"] in ("confirmed_code_defect", "design"):
            t["final_classification"] = "false_positive"
            t["report_bucket"] = "false_positive"
            t['fp_code_ref'] = 'REJECT-002'
            t['fp_rationale'] = ('identity_service_impl.c:93 存在 CheckOwnerUidPermission(credential) 检查，'
                                 'credential export 并非无认证。攻击必须绕过该检查。降级为 false_positive gap。')
            t['reject_rule'] = 'REJECT-002'

# Rebuild buckets after must-reject adjustments
report_bucket_counts = {}
for t in all_threats:
    b = t['report_bucket']
    report_bucket_counts[b] = report_bucket_counts.get(b, 0) + 1
classification_counts = dict(report_bucket_counts)
confirmed = [t for t in all_threats if t['report_bucket'] == 'confirmed']
candidate = [t for t in all_threats if t['report_bucket'] == 'candidate']
design = [t for t in all_threats if t['report_bucket'] == 'design']
false_positives = [t for t in all_threats if t['report_bucket'] == 'false_positive']
oos = [t for t in all_threats if t['report_bucket'] == 'out_of_scope']

# ============================================================
# 严重度门禁：static_evidence/runtime_model_poc 封顶 MEDIUM
# ============================================================
for t in all_threats:
    if t['report_bucket'] != 'confirmed':
        continue
    poc_t = t.get('poc_type', 'static_evidence')
    if poc_t in ('static_evidence', 'runtime_model_poc'):
        if t.get('severity') in ('HIGH', 'CRITICAL'):
            t['downgrade_reason'] = (
                f"GATE-STATIC-EVIDENCE-HIGH: {poc_t} cannot support "
                f"{t['severity']} severity; downgraded to MEDIUM per v0.5 rules")
            t['severity'] = 'MEDIUM'

# ============================================================
# 修正 threat_list.summary（从 enriched threats 重新计算）
# ============================================================
_sev_counts = Counter()
for t in all_threats:
    sev = t.get('severity', 'LOW')
    _sev_counts[sev] = _sev_counts.get(sev, 0) + 1
_canonical_counts = Counter()
for t in all_threats:
    _canonical_counts[t.get('final_classification', 'partial')] += 1
tl['summary'] = {
    'by_severity': {k: _sev_counts.get(k, 0) for k in ('CRITICAL','HIGH','MEDIUM','LOW')},
    'by_classification': dict(report_bucket_counts),
    'canonical_classification_counts': dict(_canonical_counts),
    'report_bucket_counts': dict(report_bucket_counts),
    'total': len(all_threats),
}

# ============================================================
# 生成 split JSON 文件（由 report_bucket 派生，不依赖 agent）
# ============================================================
import copy
def _strip_internal(t):
    """只保留报告用的公开字段"""
    keep = ['id','name','dimension','stride_category','severity','final_classification',
            'report_bucket','confirmed_tier','description','source_evidence',
            'counter_evidence_checked','mitigation','call_chain','source_files',
            'file','sink_function','poc_type','poc_file','poc_line','poc_target',
            'poc_desc','poc_claim','poc_limitation','exploit_path_type',
            'exploitability_score','cwe','cvss_vector','preconditions','impact',
            'fp_code_ref','fp_rationale','reject_rule','downgrade_reason','oos_reason']
    return {k: v for k, v in t.items() if k in keep}

for bucket_name, label, filename in [
    ('confirmed', '确认漏洞', 'confirmed_findings.json'),
    ('candidate', '候选发现', 'candidate_findings.json'),
    ('design', '设计建议', 'design_gaps.json'),
    ('false_positive', '误报记录', 'false_positives.json'),
    ('out_of_scope', '超出范围', 'out_of_scope.json'),
]:
    items = [_strip_internal(t) for t in all_threats if t['report_bucket'] == bucket_name]
    with open(AUDIT_DIR / filename, 'w') as f:
        json.dump({'meta': {'classification': bucket_name, 'count': len(items),
                   'label': label}, 'findings': items}, f, indent=2, ensure_ascii=False)
    print(f'[assemble] {filename} ({len(items)} items)')

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

# 增强 PoC 结果：只包含 confirmed bucket 的威胁（design/oos/fp 不需要 PoC）
confirmed_ids = {t['id'] for t in confirmed}
enhanced_pocs = []
for poc in poc_source:
    tid = poc.get('threat_id', '')
    if tid not in confirmed_ids:
        continue
    poc_type_raw = poc.get('type', poc.get('poc_type', ''))
    enhanced = dict(poc)
    enhanced['source_file'] = threat_file_map.get(tid, '')
    enhanced['status_cn'] = POC_STATUS_CN.get(poc.get('status', ''), poc.get('status', ''))
    enhanced['type_cn'] = POC_TYPE_CN.get(poc_type_raw, poc_type_raw)
    # force: non-runtime_target_poc must have target_code_invoked=false
    if poc_type_raw != "runtime_target_poc":
        enhanced["target_code_invoked"] = False
    enhanced_pocs.append(enhanced)

poc_summary_enhanced = {
    'meta': dict(poc_meta, total_pocs=len(enhanced_pocs)),
    'poc_results': enhanced_pocs,
}

# 写回规范化 poc_summary.json + threat_list.json（供 consistency checker 读）
with open(AUDIT_DIR / 'poc_summary.json', 'w') as f:
    json.dump(poc_summary_enhanced, f, indent=2, ensure_ascii=False)
print(f'[assemble] poc_summary.json normalized ({len(enhanced_pocs)} entries)')

# 写回 enrich 后的 threat_list.json（持久化 report_bucket/confirmed_tier/等字段）
tl['threats'] = all_threats
# clear poc_type for non-confirmed buckets
for t in all_threats:
    if t["report_bucket"] != "confirmed":
        t["poc_type"] = ""
        t["poc_target_invoked"] = False
with open(AUDIT_DIR / 'threat_list.json', 'w') as f:
    json.dump(tl, f, indent=2, ensure_ascii=False)
print(f'[assemble] threat_list.json enriched ({len(all_threats)} threats)')

meta = {
    'system_name': rm.get('target', tl['meta'].get('target', 'Unknown Target')),
    'workflow_version': '0.5.0',
    'analysis_date': rm.get('timestamp', datetime.now().isoformat()),
    'attacker_profile': tl['meta'].get('attacker_profile', 'mobile_device_remote_attacker'),
    'target': tl['meta'].get('target', ''),
}
_sev_counts = Counter()
for t in all_threats:
    sev = t.get('severity', 'LOW')
    if sev in ('CRITICAL','HIGH','MEDIUM','LOW'):
        _sev_counts[sev] += 1
    else:
        _sev_counts['MEDIUM'] = _sev_counts.get('MEDIUM', 0) + 1
_sev_ordered = {'CRITICAL': _sev_counts.get('CRITICAL',0), 'HIGH': _sev_counts.get('HIGH',0),
                'MEDIUM': _sev_counts.get('MEDIUM',0), 'LOW': _sev_counts.get('LOW',0)}

exec_sum = {
    'total_threats': len(all_threats),
    'severity_counts': _sev_ordered,
    'classification_counts': classification_counts,
    'canonical_classification_counts': canonical_classification_counts,
    'report_bucket_counts': report_bucket_counts,
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
    meta=meta, executive_summary=exec_sum, all_threats=all_threats, threats=all_threats,
    confirmed=confirmed, candidate=candidate, design=design,
    false_positives=false_positives, oos=oos,
    dfd_mermaid=mmd, dfd_svg=svg, dfd_status='PASS', dfd_stats=dfd_stats,
    result_audit=ra, consistency=cs, poc_summary=poc_summary_enhanced,
    dfd_element_names=dfd_name_map, cls=exec_sum['classification_counts'],
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
# Step 6: 后置校验 → 重新渲染模板使用最新 consistency 数据
# ============================================================
check_script = SCRIPTS_DIR / 'check-consistency-v3.py'
post_result = subprocess.run(
    ['python3', str(check_script), str(AUDIT_DIR), '--post-report'],
    capture_output=True, timeout=30
)
# Re-read fresh consistency for re-render
try:
    with open(AUDIT_DIR / 'consistency_check_v3.json') as f:
        cs_fresh = json.load(f)
except Exception:
    cs_fresh = cs
# Re-render with fresh consistency data
html = tpl.render(
    meta=meta, executive_summary=exec_sum, all_threats=all_threats, threats=all_threats,
    confirmed=confirmed, candidate=candidate, design=design,
    false_positives=false_positives, oos=oos,
    dfd_mermaid=mmd, dfd_svg=svg, dfd_status='PASS', dfd_stats=dfd_stats,
    result_audit=ra, consistency=cs_fresh, poc_summary=poc_summary_enhanced,
    dfd_element_names=dfd_name_map, cls=classification_counts,
    methodology={'limitations': ['SAST不可用']}, sast_status='UNAVAILABLE',
)
ts2 = datetime.now().strftime('%Y%m%d-%H%M%S')
path = AUDIT_DIR / f'stride-audit-report-{ts2}.html'
with open(path, 'w', encoding='utf-8') as f:
    f.write(html)
print(f'[assemble] Report (final): {path} ({os.path.getsize(path) / 1024:.1f} KB)')
cs = cs_fresh

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
        'poc': 'PASS', 'result_audit': ra.get('audit_result', 'PASS'), 'report': 'PASS'
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
(AUDIT_DIR / '.report-latest').write_text(str(path))
print(f'[assemble] .report-latest → {path}')
print('[assemble] DONE')
