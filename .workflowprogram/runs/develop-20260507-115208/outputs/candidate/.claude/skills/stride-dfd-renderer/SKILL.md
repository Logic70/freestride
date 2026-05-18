---
name: stride-dfd-renderer
description: "Render DFD YAML to Mermaid diagram for HTML embedding in STRIDE reports"
version: "0.1.0"
---

# STRIDE DFD Renderer Skill

## Purpose

Called by `stride-report-assembler` agent. Converts structured DFD YAML into an embedded Mermaid diagram suitable for HTML report inclusion.

## Invocation

Triggered by: `stride-report-assembler` agent

## DFD Element → Mermaid Mapping

| DFD Element | Mermaid Shape |
|-------------|--------------|
| Process | Rounded rectangle: `P1(auth_service)` |
| ExternalEntity | Normal rectangle: `E1[Web Client]` |
| Store | Cylinder: `S1[(Database)]` |
| TrustBoundary | Subgraph: `subgraph TB1[Internet→DMZ]...end` |
| DataFlow | Arrow: `E1 -->|credentials| P1` |

## Trust Boundary Styling

```mermaid
subgraph Internet[Internet - Untrusted]
  E1[Web Client]
end
subgraph DMZ[DMZ]
  P1[Auth Service]
end
subgraph Internal[Internal Network - Trusted]
  S1[(User DB)]
end
E1 -->|HTTPS POST| P1
P1 -->|SQL Query| S1
```

## Output

Returns a Mermaid diagram string ready for embedding in HTML `<div class="mermaid">...</div>`.

## Constraints

- Must handle partial DFDs (missing element types → render with placeholder notes)
- Trust boundaries color-coded: red=untrusted, orange=DMZ, green=internal
