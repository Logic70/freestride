---
name: stride-attack-pattern-lookup
description: "Query the attack pattern library and map STRIDE threats to CAPEC references"
version: "0.1.0"
---

# STRIDE Attack Pattern Lookup Skill

## Purpose

Called by `stride-attack-pattern-matcher` agent. Queries `config/attack-patterns.yaml` to find matching CAPEC or custom attack patterns for a given STRIDE threat.

## Invocation

Triggered by: `stride-attack-pattern-matcher` agent

## Lookup Logic

1. Receive query: `{stride_dimension, dfd_element_type, threat_description}`
2. Search `config/attack-patterns.yaml` for matching entries:
   - Primary match: `stride_dimension` + `dfd_element_type`
   - Secondary match: keyword search in `detection_indicators`
3. Return top 3 matching patterns with relevance scores

## Output

```json
{
  "threat_id": "THREAT-001",
  "matches": [
    {
      "ref": "CAPEC-16",
      "name": "Dictionary-based Password Attack",
      "relevance": "high",
      "match_reason": "Threat describes credential attacks on external authentication entity",
      "detection_indicators": ["no rate limiting", "no MFA", "weak password policy"],
      "typical_mitigations": ["rate limiting", "MFA", "account lockout", "password complexity"]
    }
  ],
  "queried_library_version": "baseline-v1"
}
```

## Attack Pattern Library Location

`config/attack-patterns.yaml` — baseline ~50 patterns covering all 6 STRIDE dimensions:

- Spoofing: CAPEC-16, CAPEC-560, CAPEC-194, CAPEC-461, CAPEC-21
- Tampering: CAPEC-117, CAPEC-384, CAPEC-240, CAPEC-75, CAPEC-248
- Repudiation: CAPEC-93, CAPEC-268, CAPEC-272
- Information_Disclosure: CAPEC-37, CAPEC-545, CAPEC-169, CAPEC-497
- DoS: CAPEC-469, CAPEC-125, CAPEC-130, CAPEC-147
- Elevation_of_Privilege: CAPEC-233, CAPEC-122, CAPEC-69, CAPEC-81
