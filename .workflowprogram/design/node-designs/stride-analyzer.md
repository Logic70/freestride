# Node Design: STRIDE Analyzer

**Node ID:** `stride`
**Agent:** `stride-analyzer`
**Template:** fan-out
**Gate:** auto_approval
**Parallel sub-tasks:** 6 (one per STRIDE dimension)

## Design Overview

Six parallel analysis tasks, each examining all relevant DFD elements through one STRIDE lens. Results are merged and exploitability-scored.

## Fan-out Architecture

```
                    stride (coordinator)
                   /    |    |    |    \    \
                  S     T    R    I    D    E
                  ↓     ↓    ↓    ↓    ↓    ↓
               merge + scoring + output threat_list.json
```

## Dimension Focus Matrix

| Dimension | Primary DFD Targets | Key Questions |
|-----------|-------------------|---------------|
| S (Spoofing) | ExternalEntity, Process | Can identity be forged? Are auth tokens safe? |
| T (Tampering) | DataFlow, Store, Process | Can data be modified? Are inputs validated? |
| R (Repudiation) | Process, DataFlow | Are actions logged? Can users deny actions? |
| I (Info Disclosure) | DataFlow, Store, TrustBoundary | Is sensitive data exposed? Is encryption used? |
| D (DoS) | Process, ExternalEntity | Can resources be exhausted? Rate limits? |
| E (EoP) | Process, TrustBoundary | Can privileges be escalated? Auth bypass? |

## Exploitability Scoring Algorithm

```
Score = preconditions × 0.30 + access_vector × 0.25 + complexity × 0.20 + impact × 0.25

preconditions:  0=impossible,  5=rare state, 10=no prerequisites
access_vector:  0=physical,    5=local,     10=remote unauthenticated
complexity:     0=very high,   5=moderate,  10=trivial
impact:         0=none,        5=partial,   10=total compromise
```

Severity thresholds: >=8.0 Critical, >=6.0 High, >=4.0 Medium, <4.0 Low

## Per-Dimension Template

Each sub-task uses `config/stride-threats.yaml` templates as a starting point, then customizes to the specific DFD context. Templates provide pattern matching (e.g., "No authentication on {process_name}" → instantiate with actual process names from DFD).

## Dimension Completion Guarantee

Every dimension MUST output at least one of:
- A list of identified threats (≥1)
- `{"status": "no_threats_found", "rationale": "EXPLANATION"}`
