---
name: stride-html-reporter
description: "Render Jinja2 HTML templates with STRIDE threat analysis data for the final report"
version: "0.1.0"
---

# STRIDE HTML Reporter Skill

## Purpose

Called by `stride-report-assembler` agent. Renders `templates/report-template.html` with STRIDE analysis context into a self-contained HTML report.

## Data Context

```json
{
  "meta": {"system_name": "...", "analysis_date": "...", "workflow_version": "0.1.0"},
  "executive_summary": {"total_threats": 0, "severity_counts": {}, "classification_counts": {}, "top_findings": []},
  "dfd_mermaid": "<mermaid diagram string>",
  "threats": [],
  "charts": {"radar_data": [], "severity_data": {}, "classification_data": {}, "heatmap_data": []},
  "sast_tools_available": {},
  "poc_summary": {},
  "methodology": {}
}
```

## Constraints

- Self-contained HTML5, no external CDN
- SVG charts, embedded Mermaid.js
- Print-friendly CSS
- <5MB output
