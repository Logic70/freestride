---
name: stride-fp-pattern-lookup
description: "Query the false positive pattern repository and match threats against known FP patterns"
version: "0.2.0"
---

# STRIDE FP Pattern Lookup Skill

## Purpose

Called by `stride-validator` agent. Queries `config/fp-patterns.yaml` to check threats against known false positive patterns.

## Pattern Matching Logic

1. Receive threat: `{stride_category, description, file, line, source_evidence, call_chain}`
2. Apply each pattern's rule against the threat
3. Return matching patterns with actions

## Pattern Categories

| Pattern ID | Type | Action |
|-----------|------|--------|
| FP-AUTH-MIDSTEP | Auth chain incomplete | false_positive |
| FP-LOCAL-FS-CONTROL | Local attacker required | oos |
| FP-DESIGN-AS-VULN | Design preference | design |
| FP-PROTOCOL-INTEGRITY | Protocol boundary | false_positive |
| FP-PSK-LENGTH | PSK policy | design |
| FP-INTERNAL-GUARD | Existing guard present | false_positive |
| FP-INFERENCE-ONLY | No source evidence | hypothesis/partial |
| FP-UNREACHABLE-ENTRY | Dead code | false_positive |
| FP-ROOT-REQUIRED | Root equiv required | oos |
| FP-SAME-SEVERITY-REPEAT | Duplicate finding | merge |

## Output

```json
{
  "threat_id": "THREAT-001",
  "matched_patterns": [
    {
      "id": "FP-PROTOCOL-INTEGRITY",
      "name": "Protocol intermediate data mistaken for integrity boundary",
      "match_reason": "Threat targets JSON field but message is TLS-protected",
      "action": "downgrade to false_positive if protected by authenticated channel"
    }
  ],
  "suggested_reclassification": "false_positive"
}
```
