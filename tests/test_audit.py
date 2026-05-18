"""
Test suite for FreeSTRIDE audit workflow.

Covers:
- Consistency checker (check-consistency-v3.py)
- Confirmed gate enforcement
- DFD generation (YAML → SVG + index)
- Regression corpus (must-detect, must-reject)
- HTML report rendering

Usage: pytest tests/ -v
"""

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = Path(__file__).parent.parent / "config"
SCRIPTS = CONFIG / "scripts"
TEMPLATES = Path(__file__).parent.parent / "templates"
sys.path.insert(0, str(SCRIPTS))


# ============================================================
# Fixture loading helpers
# ============================================================

def load_json(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def threat_list():
    return load_json("threat_list.json")


@pytest.fixture(scope="module")
def confirmed_findings():
    return load_json("confirmed_findings.json")


@pytest.fixture(scope="module")
def candidate_findings():
    return load_json("candidate_findings.json")


@pytest.fixture(scope="module")
def design_gaps():
    return load_json("design_gaps.json")


@pytest.fixture(scope="module")
def false_positives():
    return load_json("false_positives.json")


@pytest.fixture(scope="module")
def poc_summary():
    return load_json("poc_summary.json")


@pytest.fixture(scope="module")
def validation_report():
    return load_json("validation_report.json")


# ============================================================
# CS-COUNT: Classification count consistency
# ============================================================

class TestClassificationCounts:
    """CS-COUNT-CLASSIFICATION: threat_list summary must match output file counts."""

    def test_threat_list_total_matches_summary(self, threat_list):
        assert threat_list["meta"]["total_threats"] == len(threat_list["threats"])
        assert threat_list["summary"]["total_threats"] == len(threat_list["threats"])

    def test_confirmed_count_consistent(self, threat_list, confirmed_findings):
        expected = threat_list["summary"]["by_classification"]["confirmed"]
        actual = len(confirmed_findings["findings"])
        assert expected == actual, f"confirmed: summary={expected}, file={actual}"

    def test_partial_count_consistent(self, threat_list, candidate_findings):
        expected = threat_list["summary"]["by_classification"]["partial"]
        actual = len(candidate_findings["findings"])
        assert expected == actual, f"partial: summary={expected}, file={actual}"

    def test_design_count_consistent(self, threat_list, design_gaps):
        expected = threat_list["summary"]["by_classification"]["design"]
        actual = len(design_gaps["findings"])
        assert expected == actual, f"design: summary={expected}, file={actual}"

    def test_false_positive_count_consistent(self, threat_list, false_positives):
        expected = threat_list["summary"]["by_classification"]["false_positive"]
        actual = len(false_positives["findings"])
        assert expected == actual, f"false_positive: summary={expected}, file={actual}"

    def test_classifications_sum_to_total(self, threat_list):
        s = threat_list["summary"]["by_classification"]
        total = s["confirmed"] + s["partial"] + s["design"] + s["false_positive"]
        assert total == len(threat_list["threats"]), f"{total} != {len(threat_list['threats'])}"

    def test_every_threat_has_final_classification(self, threat_list):
        valid = {"confirmed_code_defect", "confirmed_exploitable", "partial", "design", "false_positive", "out_of_scope"}
        for t in threat_list["threats"]:
            assert t.get("final_classification") in valid, f"{t['id']}: {t.get('final_classification')}"


# ============================================================
# CS-CONFIRMED-GATES: Confirmed finding gates (v0.5)
# ============================================================

class TestConfirmedGates:
    """CS-CONFIRMED-GATES: confirmed findings must pass all hard gates."""

    def test_no_confirmed_with_root_precondition(self, threat_list):
        for t in threat_list["threats"]:
            if t["final_classification"] in ("confirmed_code_defect", "confirmed_exploitable"):
                precond = t.get("preconditions", [])
                assert "root" not in precond, f"{t['id']}: root precondition on confirmed"
                assert "system_partition_write" not in precond, f"{t['id']}: system_partition_write on confirmed"

    def test_no_design_only_confirmed(self, threat_list):
        for t in threat_list["threats"]:
            if t["final_classification"] in ("confirmed_code_defect", "confirmed_exploitable"):
                assert t.get("exploit_path_type") != "design_only", f"{t['id']}: design_only confirmed"

    def test_conditional_not_confirmed_exploitable(self, threat_list):
        for t in threat_list["threats"]:
            if t.get("exploit_path_type") == "conditional":
                assert t.get("confirmed_tier") != "confirmed_exploitable", f"{t['id']}: conditional→exploitable"

    def test_static_evidence_not_high_severity(self, threat_list):
        for t in threat_list["threats"]:
            if t.get("poc_type") == "static_evidence":
                assert t["severity"] != "HIGH", f"{t['id']}: static_evidence + HIGH"

    def test_runtime_model_poc_max_medium(self, threat_list):
        for t in threat_list["threats"]:
            if t.get("poc_type") == "runtime_model_poc" and t["final_classification"] in ("confirmed_code_defect", "confirmed_exploitable"):
                assert t["severity"] in ("MEDIUM", "LOW"), f"{t['id']}: runtime_model_poc severity={t['severity']}"

    def test_confirmed_exploitable_requires_runtime_target_poc(self, threat_list):
        for t in threat_list["threats"]:
            if t.get("confirmed_tier") == "confirmed_exploitable":
                assert t.get("poc_type") == "runtime_target_poc", f"{t['id']}: exploitable needs runtime_target_poc"

    def test_no_attacker_control_none_on_confirmed(self, threat_list):
        for t in threat_list["threats"]:
            if t["final_classification"] in ("confirmed_code_defect", "confirmed_exploitable"):
                assert t.get("attacker_control") != "none", f"{t['id']}: attacker_control=none on confirmed"

    def test_severity_values_valid(self, threat_list):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for t in threat_list["threats"]:
            assert t.get("severity") in valid, f"{t['id']}: invalid severity '{t.get('severity')}'"

    def test_confirmed_findings_have_source_evidence(self, confirmed_findings):
        for f in confirmed_findings["findings"]:
            assert f.get("source_evidence"), f"{f['id']}: confirmed without source_evidence"

    def test_confirmed_findings_have_mitigation(self, confirmed_findings):
        for f in confirmed_findings["findings"]:
            assert f.get("mitigation"), f"{f['id']}: confirmed without mitigation"


# ============================================================
# CS-MUST-DETECT: Regression corpus must-detect coverage
# ============================================================

class TestMustDetect:
    """CS-MUST-DETECT: regression corpus entries must be found in threat list."""

    @pytest.fixture(scope="class")
    def regression(self):
        import yaml
        with open(CONFIG / "regression-corpus-v2.yaml") as f:
            return yaml.safe_load(f)

    def test_all_must_detect_found(self, threat_list, regression):
        threats = threat_list["threats"]
        for entry in regression["must_detect_entries"]:
            mid = entry["threat_id"]
            matcher = entry["matching"]
            file_suffix = matcher["file_suffix"]
            lo, hi = matcher["line_range"]

            found = None
            for t in threats:
                fname = t.get("file", "")
                fname_clean = fname.split(":")[0] if ":" in fname else fname
                if not fname_clean.endswith(file_suffix):
                    continue
                t_line = None
                if ":" in fname:
                    try:
                        t_line = int(fname.split(":")[-1].split("-")[0])
                    except ValueError:
                        pass
                if t_line is not None and lo <= t_line <= hi:
                    found = t
                    break
                se = t.get("source_evidence", "")
                if matcher.get("sink_operation", "") in se or matcher.get("bug_pattern", "") in se:
                    found = t
                    break

            assert found is not None, f"{mid}: NOT FOUND (file_suffix={file_suffix}, line_range=[{lo},{hi}])"
            actual = found["final_classification"]
            expected = entry["correct_classification"]
            if expected.startswith("confirmed") and actual.startswith("confirmed"):
                pass  # confirmed maps to both confirmed_code_defect and confirmed_exploitable
            else:
                assert actual == expected, f"{mid}: classification={actual} != expected={expected}"


# ============================================================
# CS-MUST-REJECT: False positive rejection patterns
# ============================================================

class TestMustReject:
    """CS-MUST-REJECT: must-reject patterns must be applied to matching findings."""

    @pytest.fixture(scope="class")
    def regression(self):
        import yaml
        with open(CONFIG / "regression-corpus-v2.yaml") as f:
            return yaml.safe_load(f)

    def test_reject_005_pin_entropy_misread_applied(self, false_positives):
        """REJECT-005: PIN bit-length misread must be false_positive."""
        pin_fps = [f for f in false_positives["findings"] if "PIN" in f.get("name", "")]
        assert len(pin_fps) >= 1, "REJECT-005: no PIN-related false positive found"

    def test_reject_003_log_leak_applied(self, false_positives):
        """REJECT-003: PRINT_SENSITIVE_DATA log leak must be false_positive."""
        log_fps = [f for f in false_positives["findings"] if "PRINT_SENSITIVE_DATA" in f.get("name", "")]
        assert len(log_fps) >= 1, "REJECT-003: no PRINT_SENSITIVE_DATA false positive found"

    def test_false_positives_have_rationale(self, false_positives):
        for f in false_positives["findings"]:
            assert f.get("reject_rationale") or f.get("fp_rationale"), f"{f['id']}: false positive without rationale"


# ============================================================
# CS-POC: PoC evidence level consistency
# ============================================================

class TestPoC:
    """CS-POC: PoC count and evidence level consistency."""

    def test_poc_count_matches_meta(self, poc_summary):
        declared = poc_summary["meta"]["total_pocs"]
        actual = len(poc_summary["poc_results"])
        assert declared == actual, f"declared={declared} != actual={actual}"

    def test_poc_threat_ids_unique(self, poc_summary):
        ids = [p["threat_id"] for p in poc_summary["poc_results"]]
        assert len(ids) == len(set(ids)), f"Duplicate PoC threat_ids: {[i for i in ids if ids.count(i) > 1]}"

    def test_poc_status_valid(self, poc_summary):
        valid = {"STATIC_EVIDENCE", "DESIGN_ONLY", "FALSE_POSITIVE", "VERIFIED", "UNVERIFIED", "PASS", "FAIL"}
        for p in poc_summary["poc_results"]:
            assert p.get("status") in valid, f"{p['threat_id']}: invalid status '{p.get('status')}'"


# ============================================================
# CS-ATTACKER-CAPABILITY
# ============================================================

class TestAttackerCapability:
    """CS-ATTACKER-CAPABILITY: no confirmed finding needs capabilities attacker lacks."""

    @pytest.fixture(scope="class")
    def attacker_caps(self):
        import yaml
        with open(CONFIG / "attacker-capabilities.yaml") as f:
            return yaml.safe_load(f)

    def test_no_confirmed_violates_attacker_model(self, threat_list, attacker_caps):
        default = attacker_caps["default_profile"]
        caps = attacker_caps["profiles"][default]["capabilities"]
        for t in threat_list["threats"]:
            if t["final_classification"] in ("confirmed_code_defect", "confirmed_exploitable", "partial"):
                for p in t.get("preconditions", []):
                    if p in caps and caps[p] is False:
                        assert False, f"{t['id']}: needs {p} but attacker model has {p}=false"


# ============================================================
# DFD: Data flow diagram generation
# ============================================================

class TestDFD:
    """CS-DFD: DFD file generation and consistency."""

    def test_dfdyaml_exists(self):
        assert (FIXTURES / "dfd.yaml").exists(), "dfd.yaml missing"

    def test_dfd_index_exists(self):
        assert (FIXTURES / "dfd_index.json").exists(), "dfd_index.json missing"

    def test_dfd_interactive_svg_exists(self):
        assert (FIXTURES / "dfd_interactive.svg").exists(), "dfd_interactive.svg missing"

    def test_dfd_interactive_svg_has_nodes(self):
        svg = (FIXTURES / "dfd_interactive.svg").read_text()
        assert "dfd-clickable" in svg, "SVG missing clickable marker class"
        assert "data-eid=" in svg, "SVG missing data-eid attributes"
        assert "data-threats=" in svg, "SVG missing data-threats attributes"
        assert "data-analysis=" in svg, "SVG missing per-element STRIDE analysis"
        assert "onclick=" not in svg, "SVG should use template event delegation, not inline handlers"
        assert svg.count("data-eid=") >= 17, "SVG should expose all DFD nodes as click targets"

    def test_dfd_svg_renderer_emits_click_contract(self, threat_list):
        """The renderer, not a stale fixture, must emit the click contract used by the template."""
        import yaml
        from dfd_data import ELEMENT_DESC, EDGES, NODE_POSITIONS, TRUST_BOUNDARIES, generate_dfd_index
        from dfd_svg import render_svg_dfd

        with open(FIXTURES / "dfd.yaml") as f:
            dfd = yaml.safe_load(f)
        dfd_data = dfd.get("dfd", dfd)
        idx = generate_dfd_index(threat_list["threats"], dfd_data)
        svg = render_svg_dfd(NODE_POSITIONS, EDGES, TRUST_BOUNDARIES, idx, ELEMENT_DESC)

        assert "<svg " in svg
        assert "onclick=" not in svg
        assert svg.count('class="dfd-clickable') >= len(NODE_POSITIONS)
        assert svg.count("data-eid=") >= len(NODE_POSITIONS)
        assert svg.count("data-analysis=") >= len(NODE_POSITIONS)
        assert 'data-eid="P1"' in svg
        assert 'data-eid="DS1"' in svg
        assert 'data-eid="DF_EE1_P1"' in svg

    def test_dfd_index_maps_elements_to_threats(self):
        idx = load_json("dfd_index.json")
        for elem_type in ("external_entities", "processes", "data_stores"):
            for eid, entry in idx[elem_type].items():
                assert "name" in entry, f"{eid}: missing name"
                assert "type" in entry, f"{eid}: missing type"
                assert "threats" in entry, f"{eid}: missing threats list"
                assert "threat_count" in entry, f"{eid}: missing threat_count"

    def test_dfd_yaml_has_all_element_types(self):
        import yaml
        with open(FIXTURES / "dfd.yaml") as f:
            dfd = yaml.safe_load(f)
        dfd_data = dfd.get("dfd", dfd)
        for key in ("external_entities", "processes", "data_stores", "data_flows", "trust_boundaries"):
            assert key in dfd_data, f"dfd.yaml missing '{key}'"

    def test_element_name_not_description(self):
        """验证 ELEMENT_NAME 是短标签，不是长描述"""
        from dfd_data import ELEMENT_NAME, ELEMENT_DESC
        for eid, name in ELEMENT_NAME.items():
            desc = ELEMENT_DESC.get(eid, '')
            assert name != desc, (
                f"{eid}: ELEMENT_NAME equals ELEMENT_DESC — "
                f"name should be a short label, not a descriptive sentence"
            )


# ============================================================
# HTML Report: rendering and anchor validation
# ============================================================

class TestHTMLReport:
    """CS-HTML: report template rendering."""

    def test_template_exists(self):
        assert (TEMPLATES / "report-template.html").exists(), "template missing"

    def test_template_has_version_comment(self):
        tpl = (TEMPLATES / "report-template.html").read_text()
        assert "FreeSTRIDE report-template v2.0" in tpl, "template missing version comment"

    def test_template_has_no_mermaid_import(self):
        tpl = (TEMPLATES / "report-template.html").read_text()
        assert "mermaid" not in tpl.lower().split("import"), "template still imports Mermaid"

    def test_template_has_dfd_interaction_js(self):
        tpl = (TEMPLATES / "report-template.html").read_text()
        assert "renderDfdDetail" in tpl, "template missing DFD detail renderer"
        assert "function esc(v)" in tpl, "template must escape DFD sidebar HTML"
        assert "function safeThreatId(v)" in tpl, "template must sanitize threat anchors"
        assert "container.addEventListener('click'" in tpl, "template missing delegated DFD click listener"
        assert "target.getAttribute('data-eid')" in tpl, "template does not resolve clicked DFD element id"
        assert "window.selectDfdElement=renderDfdDetail" in tpl, "template missing legacy SVG click alias"
        assert "window.resetFilter=restoreSide" in tpl, "template missing legacy reset alias"
        assert "data-threat-link" in tpl, "template should use delegated threat links, not fragile inline onclick"
        assert "dfd-sidebar" in tpl, "template missing dfd-sidebar"

    @pytest.mark.slow
    def test_jinja2_render_smoke(self):
        """Verify the template renders without errors against fixtures."""
        try:
            from jinja2 import Template
        except ImportError:
            pytest.skip("Jinja2 not installed")

        threat_list = load_json("threat_list.json")
        confirmed = load_json("confirmed_findings.json")
        dfd_svg = (FIXTURES / "dfd_interactive.svg").read_text()

        tpl = (TEMPLATES / "report-template.html").read_text(encoding="utf-8")
        template = Template(tpl)

        html = template.render(
            meta={"system_name": "Test", "analysis_date": "2026-01-01",
                  "workflow_version": "0.5.0", "attacker_profile": "test",
                  "target": "test"},
            executive_summary={"total_threats": 20, "severity_counts": {"MEDIUM": 14, "LOW": 6},
                               "classification_counts": {"confirmed": 8, "partial": 4, "design": 6, "false_positive": 2},
                               "top_findings": confirmed["findings"][:3]},
            threats=threat_list["threats"],
            dfd_svg=dfd_svg,
            dfd_mermaid="graph TB\nA-->B",
            dfd_stats={"external_entities": 4, "processes": 11, "data_stores": 3, "data_flows": 21, "trust_boundaries": 4},
            dfd_status="WARN",
            result_audit={},
            consistency={"hard_fails": [], "soft_warns": ["layout WARN"], "overall": "WARN"},
            poc_summary=load_json("poc_summary.json"),
            confirmed=confirmed,
            candidate=load_json("candidate_findings.json"),
            design=load_json("design_gaps.json"),
            false_positives=load_json("false_positives.json"),
            methodology={"limitations": ["test limitation"]},
            sast_status="UNAVAILABLE",
            validation=load_json("validation_report.json")
        )

        # Verify anchors
        for anchor in ("overview", "quality", "dfd", "confirmed", "candidate", "design", "fp", "poc", "method"):
            assert f'id="{anchor}"' in html or f"id='{anchor}'" in html, f"Missing anchor: {anchor}"

        # Verify SVG embedded
        assert "<svg " in html, "SVG not embedded in HTML"

        # Verify interaction JS
        assert "renderDfdDetail" in html, "Missing DFD interaction JS"
        assert "function esc(v)" in html, "Missing DFD sidebar escaping"
        assert "container.addEventListener('click'" in html, "Missing delegated DFD click listener"
        assert "data-eid=" in html, "Rendered DFD has no clickable element ids"
        assert "data-analysis=" in html, "Rendered DFD has no STRIDE analysis payload"
        assert "dfd-sidebar" in html, "Rendered report missing DFD sidebar"

    @pytest.mark.slow
    def test_rendered_report_script_is_valid_javascript(self):
        """String-level checks are not enough; the browser must be able to parse the inline script."""
        node = shutil.which("node") or shutil.which("nodejs")
        if not node:
            pytest.skip("Node.js not installed")
        try:
            from jinja2 import Template
        except ImportError:
            pytest.skip("Jinja2 not installed")

        html = Template((TEMPLATES / "report-template.html").read_text(encoding="utf-8")).render(
            meta={"system_name": "Test", "analysis_date": "2026-01-01",
                  "workflow_version": "0.5.0", "attacker_profile": "test",
                  "target": "test"},
            executive_summary={"total_threats": 20, "severity_counts": {"MEDIUM": 14, "LOW": 6},
                               "classification_counts": {"confirmed": 8, "partial": 4, "design": 6, "false_positive": 2},
                               "top_findings": []},
            threats=load_json("threat_list.json")["threats"],
            dfd_svg=(FIXTURES / "dfd_interactive.svg").read_text(encoding="utf-8"),
            dfd_stats={"external_entities": 4, "processes": 11, "data_stores": 3, "data_flows": 16, "trust_boundaries": 1},
            result_audit={},
            consistency={"hard_fails": [], "soft_warns": [], "overall": "PASS"},
            poc_summary=load_json("poc_summary.json"),
            methodology={"limitations": []},
            sast_status="UNAVAILABLE",
        )
        scripts = re.findall(r"<script>\s*([\s\S]*?)\s*</script>", html)
        assert scripts, "Rendered report missing inline script"
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as f:
            f.write("\n\n".join(scripts))
            script_path = f.name
        result = subprocess.run([node, "--check", script_path], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    @pytest.mark.slow
    def test_rendered_html_has_clickable_dfd_contract(self):
        """Rendered report must contain all pieces needed for DFD element click behavior."""
        try:
            from jinja2 import Template
        except ImportError:
            pytest.skip("Jinja2 not installed")

        threat_list = load_json("threat_list.json")
        dfd_svg = (FIXTURES / "dfd_interactive.svg").read_text(encoding="utf-8")
        html = Template((TEMPLATES / "report-template.html").read_text(encoding="utf-8")).render(
            meta={"system_name": "Test", "analysis_date": "2026-01-01",
                  "workflow_version": "0.5.0", "attacker_profile": "test",
                  "target": "test"},
            executive_summary={"total_threats": 20, "severity_counts": {"MEDIUM": 14, "LOW": 6},
                               "classification_counts": {"confirmed": 8, "partial": 4, "design": 6, "false_positive": 2},
                               "top_findings": []},
            threats=threat_list["threats"],
            dfd_svg=dfd_svg,
            dfd_stats={"external_entities": 4, "processes": 11, "data_stores": 3, "data_flows": 16, "trust_boundaries": 1},
            result_audit={},
            consistency={"hard_fails": [], "soft_warns": [], "overall": "PASS"},
            poc_summary=load_json("poc_summary.json"),
            methodology={"limitations": []},
            sast_status="UNAVAILABLE",
        )

        container = re.search(r'<div class="dfd-box" id="dfd-svg-container"[\s\S]*?</section>', html)
        assert container, "DFD section/container missing"
        dfd_block = container.group(0)
        assert "<svg " in dfd_block, "DFD SVG not embedded in container"
        assert re.search(r'data-eid="(?:P1|DS1|EE1)"', dfd_block), "DFD nodes are not addressable"
        assert 'class="dfd-clickable' in dfd_block, "DFD click targets missing clickable class"
        assert "data-analysis=" in dfd_block, "DFD nodes lack analysis payload"
        assert "document.addEventListener('DOMContentLoaded'" in html, "DFD click binding is not initialized"
        assert "window.selectDfdElement=renderDfdDetail" in html, "Legacy inline SVG clicks would be broken"
        # No onclick in SVG/HTML body
        body_no_script = re.sub(r'<script>.*?</script>', '', html, flags=re.DOTALL)
        assert 'onclick="showDfdDetail' not in body_no_script, "SVG must not contain inline onclick"
        assert 'onclick="selectDfdElement' not in body_no_script, "SVG must not contain legacy onclick"

    @pytest.mark.slow
    def test_dfd_data_attributes_are_json_parseable(self):
        """All data-threats and data-analysis in SVG must parse as valid JSON."""
        dfd_svg = (FIXTURES / "dfd_interactive.svg").read_text(encoding="utf-8")
        threats_attrs = re.findall(r'data-threats="([^"]*)"', dfd_svg)
        analysis_attrs = re.findall(r'data-analysis="([^"]*)"', dfd_svg)
        assert len(threats_attrs) > 0, "No data-threats attributes found"
        for s in threats_attrs:
            assert len(s) > 2 or s == "[]", f"data-threats too short: '{s[:20]}'"
            if s == "[]": continue
            try:
                json.loads(__import__('html').unescape(s))
            except Exception as e:
                pytest.fail(f"data-threats not valid JSON: {e} — {s[:80]}")
        for s in analysis_attrs:
            if s == "{}" or s == "&#123;&#125;": continue
            try:
                json.loads(__import__('html').unescape(s))
            except Exception as e:
                pytest.fail(f"data-analysis not valid JSON: {e} — {s[:80]}")

    @pytest.mark.slow
    def test_dfd_svg_renderer_emits_click_contract(self):
        """dfd_svg.py renderer must output class=dfd-clickable, data-eid, data-analysis, and no onclick."""
        import yaml
        sys.path.insert(0, str(SCRIPTS))
        from dfd_data import NODE_POSITIONS, EDGES, TRUST_BOUNDARIES, ELEMENT_DESC, generate_dfd_index
        from dfd_svg import render_svg_dfd

        dfd_yaml = yaml.safe_load((CONFIG.parent / "outputs" / "stride-audit" / "dfd.yaml").read_text())
        dfd_data = dfd_yaml.get("dfd", dfd_yaml)
        idx = generate_dfd_index(load_json("threat_list.json")["threats"], dfd_data)
        svg = render_svg_dfd(NODE_POSITIONS, EDGES, TRUST_BOUNDARIES, idx, ELEMENT_DESC)

        assert 'class="dfd-clickable"' in svg, "SVG must contain clickable class"
        assert 'data-eid="P1"' in svg, "SVG must have data-eid on nodes"
        assert 'data-analysis="' in svg, "SVG must have data-analysis on nodes"
        assert 'onclick=' not in svg, "SVG must NOT contain inline onclick"
        assert 'onclick="selectDfdElement' not in svg, "SVG must NOT contain legacy onclick"
