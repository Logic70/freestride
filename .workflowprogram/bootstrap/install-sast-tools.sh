#!/bin/bash
# STRIDE Audit — SAST Tools Bootstrap
# Installs cppcheck, flawfinder, semgrep for C/C++/Rust security verification
set -e

echo "=== STRIDE SAST Tools Bootstrap ==="
echo "Target: $(uname -a)"

install_cppcheck() {
    if command -v cppcheck &>/dev/null; then
        echo "[OK] cppcheck $(cppcheck --version)"
        return
    fi
    echo "[INSTALL] cppcheck..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y cppcheck
    elif command -v brew &>/dev/null; then
        brew install cppcheck
    else
        echo "[WARN] Cannot auto-install cppcheck. Install manually."
    fi
}

install_flawfinder() {
    if command -v flawfinder &>/dev/null; then
        echo "[OK] flawfinder $(flawfinder --version 2>&1 | head -1)"
        return
    fi
    echo "[INSTALL] flawfinder via pip..."
    pip3 install --user flawfinder
}

install_semgrep() {
    if command -v semgrep &>/dev/null; then
        echo "[OK] semgrep $(semgrep --version)"
        return
    fi
    echo "[INSTALL] semgrep via pip..."
    pip3 install --user semgrep
}

install_rust_tools() {
    if command -v cargo &>/dev/null; then
        rustup component add clippy 2>/dev/null || true
        echo "[OK] cargo clippy available"
        return
    fi
    echo "[WARN] Rust toolchain not installed. Install via https://rustup.rs for Rust analysis"
}

echo ""
install_cppcheck
install_flawfinder
install_semgrep
install_rust_tools

echo ""
echo "=== Bootstrap Complete ==="
echo "cppcheck:  $(command -v cppcheck || echo 'NOT FOUND')"
echo "flawfinder: $(command -v flawfinder || echo 'NOT FOUND')"
echo "semgrep:   $(command -v semgrep || echo 'NOT FOUND')"
echo "cargo:     $(command -v cargo || echo 'NOT FOUND')"
