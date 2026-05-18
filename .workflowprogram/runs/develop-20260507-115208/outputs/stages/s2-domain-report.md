# Stage 2 Domain Research Report

## Summary of Findings

### Critical Discovery: STRIDEAnalyse Project

`/mnt/d/Code/STRIDEAnalyse/` is an **existing full STRIDE analysis workflow** (v2.0, event-driven architecture) that has been battle-tested on OpenHarmony's `security_device_auth` module (581 C source files). This is not just a reference—it's prior art with real outcomes.

**Key data from its last run:**
- 57 threats identified (10 Critical, 21 High)
- **40% false positive rate** (64 threats analyzed, all root causes documented)
- Only 2 VALID vulnerabilities found (3% yield)
- S1 (DFD) → S2 (STRIDE) → S3 (Test Gen) → S4 (Test Exec) → S5 (Report) → S6 (Lessons) structure

**False Positive Root Cause Taxonomy** (from their `stride_false_positive_analysis.md`):
1. Internal function mistaken for external entry point (most common)
2. Analysis stopping at intermediate steps without verification
3. Unrealistic attack preconditions
4. Design decisions incorrectly flagged as vulnerabilities
5. Misunderstanding of code context

### Host Environment Status

| Capability | Status | Action |
|-----------|--------|--------|
| Docker 29.3.0 | AVAILABLE | Ready for PoC sandbox |
| Python 3.13.12 | AVAILABLE | Satisfies >=3.10 req |
| Jinja2 3.1.6 | AVAILABLE | HTML report rendering |
| PyYAML 5.4.1 | AVAILABLE | Config parsing |
| **cppcheck** | MISSING | Must install |
| **flawfinder** | MISSING | Must install |
| **semgrep** | MISSING | Must install |
| **Rust/cargo-clippy** | MISSING | Must install rustup |
| **graphviz/pygraphviz** | MISSING | Must install for DFD viz |
| IDA Pro MCP | AVAILABLE | Optional binary analysis |

### Project State

- **No `CLAUDE.md`** at project root
- **No `.claude/` directory** (no project-level agents, skills, commands, or settings)
- Zero naming conflicts: `stride-` prefix clean against existing assets
- WorkflowProgram-CN plugin already configured in global settings

## Reusable Assets

### From STRIDEAnalyse
| Asset | Path | Value |
|-------|------|-------|
| False positive root cause taxonomy | `archive/.../stride_false_positive_analysis.md` | 5 patterns to prevent in new design |
| DFD entity schema | `outputs/s1/data-flow-diagram.json` | Reference schema for DFD YAML |
| Threat classification system | `archive/.../SESSION_CONTEXT_EXPORT.md` | [VULN]/[DESIGN]/[HARDENING]/[FP]/[OOS] taxonomy |
| Exploitability scoring framework | `archive/.../stride_false_positive_analysis.md` | Preconditions/Complexity/Impact/Detectability |
| Security reviewer agent | `WorkflowProgram-CN/dist/plugin/agents/security-reviewer.md` | CWE mapping, per-finding JSON output |

### From WorkflowProgram-CN
| Asset | Path |
|-------|------|
| Workflow validator agent | `dist/plugin/agents/workflow-validator.md` |
| Workflow verifier agent | `dist/plugin/agents/workflow-verifier.md` |
| Managed assets script | `dist/plugin/scripts/managed-assets.py` |
| Python runtime bootstrap | `dist/plugin/scripts/bootstrap-python-runtime.py` |

## Lessons Learned (from previous workflows)

### Must-Add to New Design
1. **Threat model boundary MUST be explicitly defined before analysis** — prevents 16% out-of-scope threats
2. **Function reachability verification** — filters 11 of 64 FPs
3. **Authentication endpoint verification** — required for Spoofing threats
4. **Multi-tag classification** — [VULN]/[DESIGN]/[HARDENING]/[FP]/[OOS] improves actionability
5. **Each finding must track provenance** — which agent/tool/code-path produced it

### Must-Prevent
1. SAST tools positioned before DFD (already corrected in our spec)
2. Missing threat boundary stage (not in STRIDEAnalyse S0)
3. No exploitability scoring step (not in STRIDEAnalyse pipeline)
4. No function reachability analysis
5. False positives diluting report value (40% rate unacceptable)

## Gap Analysis

Our spec vs STRIDEAnalyse reference:

| Feature | Our Spec | STRIDEAnalyse | Delta |
|---------|----------|---------------|-------|
| DFD stage | Yes (node-design) | Yes (S1) | Aligned |
| STRIDE 6-dim | Yes (fan-out) | Yes (S2 fan-out) | Aligned |
| Attack pattern mapping | Yes (NEW) | No | **Our advantage** |
| SAST verification | Yes (verify) | No | **Our advantage** |
| PoC generation | Yes (poc) | No (test gen instead) | Different approach |
| PoC execution | Yes (conditional) | Yes (Docker test exec) | Similar |
| HTML report | Yes | Yes | Aligned |
| Diff analysis | Yes (Phase 2) | No | **Our advantage** |
| Threat boundary def | In spec (implicit) | Missing → 40% FP | **Need to strengthen** |
| Reachability analysis | Not specified | Missing | **Need to add** |
| Exploitability scoring | Not specified | Missing | **Need to add** |
| FP classification | Not specified | Has taxonomy | **Need to add** |

## Recommendations for S3 Design

1. **Add threat boundary definition to the `parse` node** — when code input, explicitly identify attack surface scope before DFD
2. **Add exploitability scoring to `stride` node** — incorporate precondition/access/complexity/impact scoring
3. **Add vulnerability classification to `verify` node** — adopt [VULN]/[DESIGN]/[HARDENING]/[FP]/[OOS] taxonomy
4. **Add function reachability to `dfd` node** — filter internal-only functions from threat analysis
5. **Reuse STRIDEAnalyse DFD entity schema** — Process/DataFlow/ExternalEntity/Store/TrustBoundary
6. **For SAST tools** — generate bootstrap script, use auto-detection with graceful degradation
7. **For visualization** — Mermaid (npm) preferred over graphviz due to simpler rendering

## Bootstrap Plan (S3 → S4)

Required before workflow can execute:
```bash
# SAST tools
sudo apt install cppcheck
pip3 install flawfinder semgrep
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env && rustup component add clippy

# Visualization
pip3 install jinja2 graphviz networkx matplotlib

# Optional: Mermaid for DFD
npm install -g @mermaid-js/mermaid-cli
```
