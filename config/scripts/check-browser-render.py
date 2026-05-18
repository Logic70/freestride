#!/usr/bin/env python3
"""Browser smoke test for STRIDE HTML report — shell feedback command."""
import sys, os, json, glob
from pathlib import Path

os.environ.setdefault('LD_LIBRARY_PATH', os.path.expanduser('~/.local/lib'))


def resolve_path(argv):
    if len(argv) > 1:
        return argv[1]
    marker = Path('outputs/stride-audit/.report-latest')
    if marker.exists():
        return marker.read_text().strip()
    reports = sorted(glob.glob('outputs/stride-audit/stride-audit-report-*.html'))
    if reports:
        return reports[-1]
    print('FATAL: no report found')
    sys.exit(1)


def smoke(report_path):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({'pass': True, 'skip': 'PLAYWRIGHT_UNAVAILABLE'}))
        return 0

    chrome = os.path.expanduser(
        '~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome')
    if not os.path.exists(chrome):
        print(json.dumps({'pass': True, 'skip': 'CHROMIUM_NOT_FOUND'}))
        return 0

    r = {'pass': True, 'checks': {}}
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=chrome, headless=True)
        page = browser.new_page(viewport={'width': 1440, 'height': 900})
        errors = []
        page.on('console', lambda msg: errors.append(msg.text)
                if msg.type == 'error' else None)
        page.goto(f'file://{report_path}', wait_until='networkidle')

        for a in ['overview', 'quality', 'dfd', 'confirmed', 'candidate',
                   'design', 'oos', 'fp', 'poc', 'method']:
            r['checks'][f'anchor_#{a}'] = page.locator(
                f'#{a}').count() > 0
        r['checks']['dfd_container'] = page.locator(
            '#dfd-svg-container').count() > 0
        r['checks']['dfd_sidebar'] = page.locator(
            '#dfd-sidebar').count() > 0
        r['checks']['interactive_elements'] = page.locator(
            '[data-eid]').count()
        r['checks']['has_data_analysis'] = page.locator(
            '[data-analysis]').count() > 0
        real = [e for e in errors if 'favicon' not in e.lower()]
        r['checks']['js_errors'] = len(real)
        if real:
            r['checks']['js_error_samples'] = real[:3]
        browser.close()

    for k, v in r['checks'].items():
        if isinstance(v, bool) and not v:
            r['pass'] = False
        if k == 'js_errors' and v > 0:
            r['pass'] = False
        if k == 'interactive_elements' and v < 10:
            r['pass'] = False
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r['pass'] else 1


if __name__ == '__main__':
    sys.exit(smoke(resolve_path(sys.argv)))
