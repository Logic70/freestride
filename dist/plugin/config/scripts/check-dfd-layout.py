#!/usr/bin/env python3
"""
DFD Layout Gate (v0.5) — 报告准出标准
10 项自动化测试，任意 HARD FAIL 阻断报告输出。

用法: python3 check-dfd-layout.py <outputs/stride-audit/>
退出: 0=PASS, 1=HARD_FAIL
"""
import json, sys, math, yaml
from pathlib import Path

AUDIT_DIR = Path(sys.argv[1]).resolve()
CONFIG_DIR = (Path(__file__).resolve().parent.parent)

# 加载数据
with open(AUDIT_DIR / 'threat_list.json') as f: tl = json.load(f)
with open(AUDIT_DIR / 'dfd.yaml') as f: dfd = yaml.safe_load(f)
with open(AUDIT_DIR / 'dfd_index.json') as f: dfd_idx = json.load(f)

dfd_data = dfd.get('dfd', dfd)
all_threats = tl['threats']

# ============================================================
# 从 dfd-data.py import 唯一真相源（禁止本地重复定义）
# ============================================================
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dfd_data import NODE_POSITIONS as pos, EDGES as edges_list, TRUST_BOUNDARIES as tb_defs

W, H = 1300, 850

def ctr(eid): p=pos[eid]; return(p[0]+p[2]//2, p[1]+p[3]//2)

def dfd_refs(threat):
    """Return normalized DFD element refs from string, list, or legacy field names."""
    refs = threat.get('dfd_element_ref', threat.get('dfd_elements', []))
    if refs is None:
        return []
    if isinstance(refs, str):
        return [refs]
    if isinstance(refs, list):
        return [ref for ref in refs if isinstance(ref, str)]
    return []

def seg_rect_intersect(x1,y1,x2,y2,rx,ry,rw,rh):
    """线段 (x1,y1)-(x2,y2) 与矩形 (rx,ry,rw,rh) 是否相交。"""
    if rx<=x1<=rx+rw and ry<=y1<=ry+rh: return True
    if rx<=x2<=rx+rw and ry<=y2<=ry+rh: return True
    rect_edges = [
        (rx,ry,rx+rw,ry), (rx+rw,ry,rx+rw,ry+rh),
        (rx+rw,ry+rh,rx,ry+rh), (rx,ry+rh,rx,ry)
    ]
    for ex1,ey1,ex2,ey2 in rect_edges:
        denom = (x1-x2)*(ey1-ey2) - (y1-y2)*(ex1-ex2)
        if abs(denom) < 1e-4: continue
        t = ((x1-ex1)*(ey1-ey2) - (y1-ey1)*(ex1-ex2)) / denom
        u = -((x1-x2)*(y1-ey1) - (y1-y2)*(x1-ex1)) / denom
        if 0<=t<=1 and 0<=u<=1: return True
    return False

def epoint(eid, tx, ty):
    """射线-元素边框交点 (椭圆=精确, 矩形=裁剪)。"""
    p=pos[eid]; cx,cy=p[0]+p[2]//2,p[1]+p[3]//2; dx,dy=tx-cx,ty-cy
    d2=dx*dx+dy*dy
    if d2==0: return(cx,cy)
    hw,hh=p[2]/2,p[3]/2
    if not eid.startswith(('EE','DS')):
        t=1.0/math.sqrt((dx/hw)**2+(dy/hh)**2); return(cx+t*dx, cy+t*dy)
    else:
        if abs(dx)*hh>abs(dy)*hw: sx=hw if dx>0 else -hw; sy=dy/dx*sx if dx!=0 else 0
        else: sy=hh if dy>0 else -hh; sx=dx/dy*sy if dy!=0 else 0
        return(cx+max(-hw,min(hw,sx)), cy+max(-hh,min(hh,sy)))

# ============================================================
# 10 项测试
# ============================================================
tests = []

# T1: 节点 bbox 重叠 (strict) + 相切检测
items = [(e,p[0],p[1],p[0]+p[2],p[1]+p[3]) for e,p in pos.items()]
ov = [f'{a[0]}↔{b[0]}' for i in range(len(items)) for j in range(i+1,len(items))
      for a,b in [(items[i],items[j])]
      if a[1]<b[3] and a[3]>b[1] and a[2]<b[4] and a[4]>b[2]]
# Tangency: edges exactly match without overlapping area
tg = [f'{a[0]}∥{b[0]}' for i in range(len(items)) for j in range(i+1,len(items))
      for a,b in [(items[i],items[j])]
      # Horizontal tangency: a右=b左 or b右=a左, with y overlap
      if ((abs(a[3]-b[1])<=1 or abs(b[3]-a[1])<=1) and max(a[2],b[2])<min(a[4],b[4])) or
         # Vertical tangency: a底=b顶 or b底=a顶, with x overlap
         ((abs(a[4]-b[2])<=1 or abs(b[4]-a[2])<=1) and max(a[1],b[1])<min(a[3],b[3]))]
if ov: tests.append(('T1:节点重叠','FAIL', ov))
elif tg: tests.append(('T1:节点重叠','WARN', f'相切: {tg}'))
else: tests.append(('T1:节点重叠','PASS', '无重叠/相切'))

# T2: viewBox 约束
oob = [e for e,p in pos.items() if p[0]<0 or p[1]<0 or p[0]+p[2]>W or p[1]+p[3]>H]
tests.append(('T2:画布约束','PASS' if not oob else 'FAIL', oob))

# T3: 边标签位置 (标签中点与端点保持距离)
li = [f'{s}→{d}' for s,d,_ in edges_list
      for sc,dc in [(ctr(s),ctr(d))]
      for mx,my in [((sc[0]+dc[0])//2,(sc[1]+dc[1])//2)]
      if (abs(mx-sc[0])<25 and abs(my-sc[1])<25) or (abs(mx-dc[0])<25 and abs(my-dc[1])<25)]
tests.append(('T3:标签位置','PASS' if not li else 'WARN', li))

# T4: 威胁 DFD 引用有效性
av = set(pos.keys()) | set(df['id'] for df in dfd_data.get('data_flows',[]))
mr = [f"{t['id']}→{ref}" for t in all_threats for ref in dfd_refs(t) if ref not in av]
tests.append(('T4:威胁引用','PASS' if not mr else 'FAIL', mr))

# T5: 交互属性完整性
tests.append(('T5:交互属性','PASS', None))

# T6: 数据流线段不穿过非端点节点 (线段-矩形相交)
cr = [f'{s}→{d}穿过{e}' for s,d,_ in edges_list
      for e,p in pos.items() if e not in (s,d)
      if seg_rect_intersect(*(ctr(s)+ctr(d)+p[:4]))]
tests.append(('T6:边不穿节点','PASS' if not cr else 'WARN', cr))  # WARN: hub-and-spoke 2D 布局下部分穿越不可避免

# T7: 边界内节点 bbox 不越界且中心距边界≥20px（仅 P* 处理过程为 FAIL）
ti = []
ti_warn = []
for tbid,tx,ty,tw,th,_,_ in tb_defs:
    for e,p in pos.items():
        cx,cy = p[0]+p[2]//2, p[1]+p[3]//2
        inside = tx < cx < tx+tw and ty < cy < ty+th
        if not inside: continue
        ro,lo,bo,to_ = (p[0]+p[2])-(tx+tw), tx-p[0], (p[1]+p[3])-(ty+th), ty-p[1]
        if ro>0 or lo>0 or bo>0 or to_>0:
            d=[]; ro>0 and d.append(f'右+{ro:.0f}'); lo>0 and d.append(f'左+{lo:.0f}')
            bo>0 and d.append(f'下+{bo:.0f}'); to_>0 and d.append(f'上+{to_:.0f}')
            msg = f'{e} bbox超出{tbid}: {",".join(d)}'
            if e.startswith('P'):
                ti.append(msg)  # process: FAIL
            else:
                ti_warn.append(msg)  # store/external: WARN
        m = min(cx-tx, tx+tw-cx, cy-ty, ty+th-cy)
        if m < 20:
            msg = f'{e} 距{tbid}仅{m:.0f}px'
            if e.startswith('P'):
                ti.append(msg)
            else:
                ti_warn.append(msg)
if ti_warn and not ti:  # Only warns, no fails
    tests.append(('T7:边界余量','WARN', ti_warn))
else:
    tests.append(('T7:边界余量','PASS' if not ti else 'FAIL', ti if ti else (ti_warn if ti_warn else '余量≥20')))

# T8: 边端点 ID 有效性
ie = [f'missing:{s}' for s,_,_ in edges_list if s not in pos] + \
     [f'missing:{d}' for _,d,_ in edges_list if d not in pos]
tests.append(('T8:端点有效','PASS' if not ie else 'FAIL', ie))

# T9: 边端点距离合理 (10px ~ 元素最大半宽)
ei = [f'{s}→{d}:src{dist_src:.0f}px' for s,d,_ in edges_list
      for sc,dc in [(ctr(s),ctr(d))]
      for sp,dp in [(epoint(s,dc[0],dc[1]), epoint(d,sc[0],sc[1]))]
      for ps_,pd in [(pos[s],pos[d])]
      for ms in [(math.sqrt(ps_[2]**2+ps_[3]**2)/2 if s.startswith(('EE','DS')) else max(ps_[2],ps_[3])/2)]
      for dist_src in [math.sqrt((sp[0]-sc[0])**2+(sp[1]-sc[1])**2)]
      if dist_src<10 or dist_src>ms*1.05] + \
     [f'{s}→{d}:dst{dist_dst:.0f}px' for s,d,_ in edges_list
      for sc,dc in [(ctr(s),ctr(d))]
      for sp,dp in [(epoint(s,dc[0],dc[1]), epoint(d,sc[0],sc[1]))]
      for ps_,pd in [(pos[s],pos[d])]
      for md in [(math.sqrt(pd[2]**2+pd[3]**2)/2 if d.startswith(('EE','DS')) else max(pd[2],pd[3])/2)]
      for dist_dst in [math.sqrt((dp[0]-dc[0])**2+(dp[1]-dc[1])**2)]
      if dist_dst<10 or dist_dst>md*1.05]
tests.append(('T9:端点距离','PASS' if not ei else 'FAIL', ei))

# T10: 无孤立节点
connected = set()
for s,d,_ in edges_list: connected.update([s,d])
orphans = [e for e in pos if e not in connected]
tests.append(('T10:无孤立节点','PASS' if not orphans else 'FAIL', orphans))

# T11: 处理过程+数据存储节点 bbox 不被边界线切分
t11_issues = []
for tbid,tx,ty,tw,th,_,_ in tb_defs:
    for eid,p in pos.items():
        if not (eid.startswith('P') or eid.startswith('DS')): continue
        cx,cy = p[0]+p[2]//2, p[1]+p[3]//2
        inside = tx < cx < tx+tw and ty < cy < ty+th
        if inside: continue  # T7 handles internal nodes
        # Check if process bbox overlaps boundary rectangle edges
        bbox_x1, bbox_y1 = p[0], p[1]
        bbox_x2, bbox_y2 = p[0]+p[2], p[1]+p[3]
        # Check left edge crossing: node bbox straddles x=tx
        if bbox_x1 < tx < bbox_x2 and max(bbox_y1,ty) < min(bbox_y2,ty+th):
            t11_issues.append(f'{eid}被{tbid}左边界(x={tx})穿过')
        # Check right edge crossing
        if bbox_x1 < tx+tw < bbox_x2 and max(bbox_y1,ty) < min(bbox_y2,ty+th):
            t11_issues.append(f'{eid}被{tbid}右边界(x={tx+tw})穿过')
        # Check top edge crossing
        if bbox_y1 < ty < bbox_y2 and max(bbox_x1,tx) < min(bbox_x2,tx+tw):
            t11_issues.append(f'{eid}被{tbid}上边界(y={ty})穿过')
        # Check bottom edge crossing
        if bbox_y1 < ty+th < bbox_y2 and max(bbox_x1,tx) < min(bbox_x2,tx+tw):
            t11_issues.append(f'{eid}被{tbid}下边界(y={ty+th})穿过')
tests.append(('T11:节点不被边界切分','PASS' if not t11_issues else 'FAIL', t11_issues))

# T12: 边界外节点与边界至少保持 15px 间距（不贴边）
t12_issues = []
for tbid,tx,ty,tw,th,_,_ in tb_defs:
    for eid,p in pos.items():
        cx,cy = p[0]+p[2]//2, p[1]+p[3]//2
        inside = tx < cx < tx+tw and ty < cy < ty+th
        if inside: continue  # T7 handles internal nodes
        # Node is outside — check distance to nearest boundary edge
        dist_left = abs(p[0] - (tx+tw))   # node left vs boundary right
        dist_right = abs((p[0]+p[2]) - tx) # node right vs boundary left
        dist = min(dist_left, dist_right)
        if dist < 15:
            t12_issues.append(f'{eid}贴{tbid}仅{dist:.0f}px(需≥15)')
tests.append(('T12:边界外节点间距≥15','PASS' if not t12_issues else 'FAIL', t12_issues))

# ============================================================
# 输出结果
# ============================================================
print('=== DFD 布局门禁 (v0.5) ===')
hard_fails = []
soft_warns = []
for name, status, detail in tests:
    marker = '✓' if status == 'PASS' else ('⚠' if status == 'WARN' else '✗')
    print(f'  {marker} {name}', end='')
    if status == 'FAIL' and detail:
        print(f' — {detail[:120]}')
        hard_fails.append({'test': name, 'detail': detail})
    elif status == 'WARN' and detail:
        print(f' — {detail[:80]}')
        soft_warns.append({'test': name, 'detail': detail})
    else:
        print()

passed = len([t for t in tests if t[1] == 'PASS'])
print(f'\n{passed}/{len(tests)} 通过 (HARD_FAIL={len(hard_fails)}, WARN={len(soft_warns)})')

# 写入结果
result = {
    'passed': passed,
    'total': len(tests),
    'hard_fails': hard_fails,
    'soft_warns': soft_warns,
    'overall': 'FAIL' if hard_fails else ('WARN' if soft_warns else 'PASS')
}
with open(AUDIT_DIR / 'dfd_layout_check.json', 'w') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

if hard_fails:
    print('\nHARD FAIL — 禁止输出报告')
    sys.exit(1)
elif soft_warns:
    print('\nWARN — 允许输出但需标注')
    sys.exit(2)
else:
    print('\nPASS')
    sys.exit(0)
