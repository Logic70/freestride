"""Browser-based UI tests for STRIDE HTML report.

Requires Playwright + Chromium. Automatically skipped if unavailable.
"""
import pytest
import os
import tempfile
from pathlib import Path

os.environ.setdefault('LD_LIBRARY_PATH', os.path.expanduser('~/.local/lib'))

FIXTURES = Path(__file__).parent / 'fixtures'
TEMPLATES = Path(__file__).parent.parent / 'templates'
CHROME = os.path.expanduser(
    '~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome')


@pytest.fixture(scope='module')
def report_path():
    """Render the STRIDE report from fixtures to a temporary HTML file."""
    import json
    import yaml
    from jinja2 import Template

    tpl = Template((TEMPLATES / 'report-template.html').read_text(
        encoding='utf-8'))
    with open(FIXTURES / 'threat_list.json') as f:
        tl = json.load(f)
    with open(FIXTURES / 'dfd.yaml') as f:
        dfd = yaml.safe_load(f)

    html = tpl.render(
        meta={'system_name': 'Test', 'analysis_date': '2026-01-01',
              'workflow_version': '0.5.0', 'attacker_profile': 'test',
              'target': 'test'},
        executive_summary={
            'total_threats': 20,
            'severity_counts': {'MEDIUM': 14, 'LOW': 6},
            'classification_counts': {
                'confirmed': 8, 'partial': 4, 'design': 6,
                'false_positive': 2},
            'top_findings': []},
        threats=tl['threats'],
        summary=tl['summary'],
        dfd_svg=(FIXTURES / 'dfd_interactive.svg').read_text(
            encoding='utf-8'),
        dfd_mermaid='graph TB\nA-->B',
        dfd_stats={'external_entities': 4, 'processes': 11,
                   'data_stores': 3, 'data_flows': 21,
                   'trust_boundaries': 4},
        dfd_status='WARN',
        result_audit={},
        consistency={'hard_fails': [], 'soft_warns': ['layout WARN'],
                     'overall': 'WARN'},
        poc_summary={'total_pocs': 0},
        confirmed=[],
        candidate=[],
        design=[],
        false_positives=[],
        methodology={'limitations': ['test limitation']},
        sast_status='UNAVAILABLE',
        validation={},
        report_ts='test',
        threat_table_rows='',
    )

    with tempfile.NamedTemporaryFile(
            'w', suffix='.html', encoding='utf-8', delete=False) as f:
        f.write(html)
        path = f.name
    yield path
    os.unlink(path)


@pytest.fixture
def page(report_path):
    """Per-test fresh Playwright page with console error collection."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=CHROME, headless=True)
        pg = browser.new_page(viewport={'width': 1440, 'height': 900})
        errors = []
        pg.on('console', lambda msg: errors.append(msg.text)
              if msg.type == 'error' else None)
        pg.goto(f'file://{report_path}', wait_until='networkidle')
        pg._errors = errors
        yield pg
        browser.close()


@pytest.mark.browser
class TestReportLoad:
    """Page load, anchors, JS errors, DFD container."""

    def test_no_js_errors(self, page):
        real = [e for e in page._errors if 'favicon' not in e.lower()]
        assert len(real) == 0, f'JS console errors: {real[:5]}'

    def test_section_anchors_present(self, page):
        for a in ['overview', 'quality', 'dfd', 'confirmed', 'candidate',
                   'design', 'oos', 'fp', 'poc', 'method']:
            assert page.locator(f'#{a}').count() > 0, \
                f'Missing anchor #{a}'

    def test_dfd_container_has_interactive_elements(self, page):
        assert page.locator('#dfd-svg-container').count() > 0
        assert page.locator('#dfd-sidebar').count() > 0
        assert page.locator('[data-eid]').count() >= 10

    def test_dfd_elements_have_data_analysis(self, page):
        assert page.locator('[data-analysis]').count() > 0


@pytest.mark.browser
class TestDFDClickInteraction:
    """DFD SVG click interaction contract verification."""

    def test_click_node_updates_sidebar(self, page):
        before = page.locator('#dfd-sidebar').inner_html()
        page.locator('[data-eid]').first.click()
        page.wait_for_timeout(300)
        after = page.locator('#dfd-sidebar').inner_html()
        assert before != after, 'Sidebar HTML unchanged after DFD click'

    def test_sidebar_shows_stride_dimensions(self, page):
        page.locator('[data-eid]').first.click()
        page.wait_for_timeout(300)
        sidebar_text = page.locator('#dfd-sidebar').inner_text()
        for label in ['Spoofing', 'Tampering', 'Repudiation',
                      'Information Disclosure', 'Denial of Service',
                      'Elevation of Privilege']:
            assert label in sidebar_text, \
                f'STRIDE dimension "{label}" not in sidebar'

    def test_restore_link_created_after_click(self, page):
        page.locator('[data-eid]').first.click()
        page.wait_for_timeout(300)
        # restore-side is dynamically created by renderDfdDetail() JS
        assert page.locator(
            '[data-action="restore-side"]').count() > 0, \
            'Restore-side link not created after DFD click'

    def test_data_attributes_json_parseable(self, page):
        failures = page.evaluate("""() => {
            const nodes = document.querySelectorAll('[data-threats]');
            const fails = [];
            nodes.forEach(n => {
                try { JSON.parse(n.getAttribute('data-threats')); }
                catch(e) { fails.push(e.message); }
                try { JSON.parse(n.getAttribute('data-analysis')); }
                catch(e) { fails.push(e.message); }
            });
            return fails;
        }""")
        assert failures == [], f'JSON parse failures: {failures}'


@pytest.mark.browser
class TestLayoutIntegrity:
    """Layout checks: no inline onclick, no external CDN, version comment."""

    def test_no_inline_onclick_in_svg(self, page):
        svg = page.locator('#dfd-svg-container').inner_html()
        assert 'onclick="' not in svg, 'Inline onclick found in SVG'

    def test_no_external_cdn_requests(self, page):
        scripts = page.evaluate("""() => {
            return Array.from(
                document.querySelectorAll('script[src],link[href]'))
                .map(el => el.src || el.href);
        }""")
        external = [s for s in scripts if s and not s.startswith('file://')]
        assert external == [], f'External CDN requests: {external}'

    def test_footer_present(self, page):
        """Verify the FreeSTRIDE attribution footer is rendered."""
        assert page.locator('.footer').count() > 0, 'Footer missing'
        assert 'FreeSTRIDE' in page.locator('.footer').inner_text(), \
            'FreeSTRIDE attribution missing from footer'
