"""pytest configuration for FreeSTRIDE audit tests."""
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "browser: marks tests requiring a headless browser (deselect with '-m \"not browser\"')")


def pytest_runtest_setup(item):
    """Skip browser tests when Playwright or Chromium is unavailable."""
    if "browser" in item.keywords:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            pytest.skip("playwright not installed")
        import os
        os.environ.setdefault('LD_LIBRARY_PATH',
                              os.path.expanduser('~/.local/lib'))
        chrome = os.path.expanduser(
            '~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome')
        if not os.path.exists(chrome):
            pytest.skip("chromium not found")
