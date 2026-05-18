# Node Design: DFD Inferrer

**Node ID:** `dfd`
**Agent:** `stride-dfd-inferrer`
**Template:** agent
**Gate:** auto_approval

## Design Overview

The DFD Inferrer reads target source code and produces a structured data flow diagram. This is the bridge between raw code and threat modeling.

## Code Reading Strategy

1. **Entry point discovery**: scan for `main()`, HTTP route handlers, signal handlers, IPC listeners, public API exports
2. **Call chain tracing**: from each entry point, follow function calls recursively, building a call graph
3. **Reachability classification**:
   - `ENTRY_POINT`: functions callable from outside the process boundary
   - `EXTERNAL_CALL`: functions that invoke external systems (syscalls, HTTP clients, DB drivers)
   - `INTERNAL_ONLY`: functions only reachable through internal call chains

## DFD Element Identification Rules

| Element | How to Identify | Source Evidence |
|---------|----------------|-----------------|
| Process | Functions/methods that transform data; servers; daemons | Source file+line |
| ExternalEntity | Network clients; external APIs; user inputs; file descriptors from OS | Connection setup code |
| Store | Database write calls; file I/O; mmap; shared memory; caches | Persistence operations |
| DataFlow | Parameters passed between elements; return values; IPC messages; network packets | Inter-procedural data paths |
| TrustBoundary | Process boundary; network boundary; user/kernel boundary; privilege transitions | Context switch/API boundary |

## Reachability Analysis (Critical for FP Reduction)

Based on lessons from STRIDEAnalyse (40% FP rate, 11/64 FPs from internal-only functions):

1. Build call graph from all entry points
2. Mark each function: ENTRY_POINT / EXTERNAL_CALL / INTERNAL_ONLY
3. Filter: only DFD elements reachable from ENTRY_POINT or touching EXTERNAL_CALL are analyzed
4. INTERNAL_ONLY functions excluded from threat analysis scope

## Output Schema

```yaml
schema: stride-dfd-v1
entities: [...]
data_flows: [...]
stores: [...]
external_entities: [...]
trust_boundaries: [...]
reachability_summary:
  total_functions: N
  entry_points: N
  external_calls: N
  internal_only: N
  analyzed_functions: N
```

## DFD Validation Rules

1. Every DataFlow must connect defined source and target elements
2. Every TrustBoundary must cross at least one DataFlow
3. Every ExternalEntity must have at least one DataFlow to/from a Process
4. Every Store must be connected to at least one Process
