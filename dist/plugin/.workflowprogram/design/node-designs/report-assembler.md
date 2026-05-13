# Node Design: Report Assembler

**Node ID:** `report`
**Agent:** `stride-report-assembler`
**Template:** loop
**Gate:** auto_approval
**Loop:** max 3 iterations, feedback on HTML render failure

## Design Overview

Assembles all upstream outputs into a self-contained HTML report with DFD visualization and multi-view vulnerability details.

## Input Assembly Pipeline

```
dfd.yaml ─────────────────────→ DFD Mermaid diagram
threat_list.json ─────────────→ statistics + threat cards
attack_pattern_map.json ──────→ classifications + attack references
sast_verification.log ────────→ verification evidence per threat
poc_files/ ───────────────────→ PoC appendix links
         ↓
   Jinja2 render (report-template.html)
         ↓
   stride-audit-report-{ts}.html
```

## Multi-View Organization

| View | Target User | Content Focus |
|------|------------|---------------|
| Security Engineer | Auditor/Analyst | Threat model, compliance mapping, PoC results, methodology |
| Developer | Engineer | Vulnerability checklist, fix guidance, SAST evidence, code locations |
| Architect | Designer | DFD diagram, STRIDE mapping, design recommendations, trust boundaries |

## DFD Rendering

Convert `dfd.yaml` to Mermaid syntax via `stride-dfd-renderer` skill:
- Processes → rounded rectangles with function names
- External Entities → rectangles with dashed borders
- Data Stores → cylinder shapes
- Trust Boundaries → colored subgraphs (red=untrusted, orange=DMZ, green=internal)
- Data Flows → labeled arrows with data descriptions

## Chart Generation

Embed SVG charts directly (no JS dependency):
- STRIDE dimension radar: hexagon with per-dimension threat counts
- Severity bar chart: horizontal bars color-coded Critical/High/Medium/Low
- Classification pie chart: VULN/DESIGN/HARDENING/FP/OOS distribution
- Exploitability heat map: severity vs score scatter

## Render Validation (Loop)

```
attempt 1: generate HTML → check template variables → validate HTML5
if issues: fix template → attempt 2
if browser render issues: fix CSS/JS → attempt 3
if still fails: mark with [RENDER_WARN] annotation, proceed
```

## Report Size Constraints

- <5MB total (no embedded base64 images)
- Self-contained (no external CDN for critical rendering)
- Print-friendly (CSS media queries)
