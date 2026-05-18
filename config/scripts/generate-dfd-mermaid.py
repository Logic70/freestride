#!/usr/bin/env python3
"""
DFD Automation v0.5: dfd.yaml → dfd_mermaid.mmd + dfd_index.json
Generates proper Mermaid with: rectangles for external entities,
circles for processes, cylinders for stores, red-dashed for trust boundaries.

Also generates a DFD element index mapping each element to its threat IDs.

Usage: python3 generate-dfd-mermaid.py <dfd.yaml> <threat_list.json> <out_dir>
"""
import json, sys, yaml
from pathlib import Path

dfd_path = Path(sys.argv[1])
threat_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])

with open(dfd_path) as f:
    dfd = yaml.safe_load(f)

with open(threat_path) as f:
    tl = json.load(f)

dfd_data = dfd.get('dfd', dfd)

# Shape mappings
def ee_shape(eid, name):
    return f'{eid}["{name}"]'  # rectangle for external entities

def proc_shape(pid, name):
    return f'{pid}(("{name}"))'  # circle for processes

def store_shape(sid, name):
    return f'{sid}[("{name}")]'  # cylinder-like for stores

# Generate Mermaid
lines = ['graph TB', '']

# External entities
lines.append('  subgraph external["External Entities"]')
for ee in dfd_data.get('external_entities', []):
    lines.append(f'    {ee_shape(ee["id"], ee["name"])}')
lines.append('  end')
lines.append('')

# Processes
lines.append('  subgraph processes["Processes"]')
for p in dfd_data.get('processes', []):
    lines.append(f'    {proc_shape(p["id"], p["name"])}')
lines.append('  end')
lines.append('')

# Data stores
lines.append('  subgraph stores["Data Stores"]')
for ds in dfd_data.get('data_stores', []):
    lines.append(f'    {store_shape(ds["id"], ds["name"])}')
lines.append('  end')
lines.append('')

# Data flows (edges)
for df in dfd_data.get('data_flows', []):
    label = df.get('description', df['id'])[:40]
    lines.append(f'  {df["from"]} -->|"{label}"| {df["to"]}')

lines.append('')

# Trust boundaries (red dashed)
for i, tb in enumerate(dfd_data.get('trust_boundaries', [])):
    lines.append(f'  subgraph tb{i}["{tb["name"]}"]')
    for span in tb.get('spans', []):
        if span in [df.get('id', '') for df in dfd_data.get('data_flows', [])]:
            # Find the flow
            for df in dfd_data.get('data_flows', []):
                if df['id'] == span:
                    lines.append(f'    {df["from"]} -.- {df["to"]}')
        else:
            lines.append(f'    %% boundary spans flow: {span}')
    lines.append(f'    style tb{i} stroke:#ff0000,stroke-dasharray:5 5')
    lines.append('  end')
    lines.append('')

# Write Mermaid
mmd = '\n'.join(lines)
out_mmd = out_dir / 'dfd_mermaid.mmd'
out_mmd.write_text(mmd)
print(f'Wrote {out_mmd} ({len(mmd)} chars)')

# Build DFD index: element → threats
index = {'external_entities': {}, 'processes': {}, 'data_stores': {}, 'data_flows': {}, 'trust_boundaries': {}}

threats = tl.get('threats', [])
for elem_type, key in [('processes', 'P'), ('external_entities', 'EE'), ('data_stores', 'DS')]:
    for elem in dfd_data.get(elem_type, []):
        eid = elem['id']
        # Match threats that reference this element
        matched = []
        for t in threats:
            # Check call_chain and source_evidence for element references
            cc = str(t.get('call_chain', ''))
            se = str(t.get('source_evidence', ''))
            name = elem.get('name', '')
            path = elem.get('path', '')
            if name.lower() in cc.lower() or name.lower() in se.lower() or \
               (path and any(p.lower() in t.get('file', '').lower() for p in path if isinstance(path, list))):
                matched.append(t['id'])
        index[elem_type][eid] = {
            'name': elem.get('name', ''),
            'type': elem_type,
            'threats': matched,
            'threat_count': len(matched)
        }

out_index = out_dir / 'dfd_index.json'
with open(out_index, 'w') as f:
    json.dump(index, f, indent=2)
print(f'Wrote {out_index} ({sum(len(v) for v in index.values())} elements indexed)')

# Verify counts
ee_count = len(dfd_data.get('external_entities', []))
proc_count = len(dfd_data.get('processes', []))
store_count = len(dfd_data.get('data_stores', []))
flow_count = len(dfd_data.get('data_flows', []))
tb_count = len(dfd_data.get('trust_boundaries', []))

# Count Mermaid nodes/edges
mermaid_nodes = sum(1 for l in lines if l.strip().startswith(('EE', 'P', 'DS')) and ('["' in l or '(("' in l or '[("' in l))
mermaid_edges = sum(1 for l in lines if '-->|' in l)

print(f'DFD stats: EE={ee_count} P={proc_count} DS={store_count} DF={flow_count} TB={tb_count}')
print(f'Mermaid: nodes≈{mermaid_nodes} edges≈{mermaid_edges}')

# Quick validation
if mermaid_nodes < ee_count + proc_count + store_count:
    print('WARNING: Mermaid node count may be incomplete')
