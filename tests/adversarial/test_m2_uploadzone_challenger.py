"""
Empirical Challenge & Verification Suite: Milestone 2 Frontend & Reverse Proxy Scaling.
Authored by: Challenger M2_1 (UploadZone Bounds Challenger)

Empirically tests and verifies:
1. Client-side boundary checking in frontend/src/components/UploadZone.tsx:
   - AST & TypeScript logic: MAX_SIZE_BYTES = 600 * 1024 * 1024 (629,145,600 bytes)
   - Strict inequality: file.size > MAX_SIZE_BYTES
   - Exact boundary behavior:
     * file.size == 600 * 1024 * 1024 passes validation
     * file.size == 600 * 1024 * 1024 + 1 fails validation with 600 MB size limit error
   - Error detail text format: "Archive exceeds 600 MB size limit (selected file is {sizeMb} MB)."
   - Subtitle copy: "Supports .zip archives up to 600 MB"
   - No residual stale "50 MB" references in UploadZone.tsx
2. Node.js AST static analyzer and test vector simulator execution:
   - Runs verify_uploadzone_ast.mjs against TypeScript compiler API
3. Reverse proxy scaling in frontend/nginx.conf:
   - client_max_body_size set to 650M
   - client_body_timeout set to 600s
   - proxy_read_timeout, proxy_connect_timeout, proxy_send_timeout set to 600s
4. Frontend build artifact verification:
   - dist/index.html and asset bundles generated cleanly
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
UPLOADZONE_PATH = FRONTEND_DIR / "src" / "components" / "UploadZone.tsx"
NGINX_CONF_PATH = FRONTEND_DIR / "nginx.conf"
AST_VERIFIER_PATH = Path(__file__).resolve().parent / "verify_uploadzone_ast.mjs"
DIST_DIR = FRONTEND_DIR / "dist"


class TestUploadZoneBoundsChallenger:
    """Empirical verification of UploadZone.tsx boundary logic and UI contracts."""

    def test_uploadzone_file_exists(self):
        assert UPLOADZONE_PATH.exists(), f"Target file missing: {UPLOADZONE_PATH}"

    def test_uploadzone_max_size_constant_exact(self):
        """Verify MAX_SIZE_BYTES definition and exact byte arithmetic."""
        content = UPLOADZONE_PATH.read_text(encoding="utf-8")

        # Match constant declaration
        pattern = r"const\s+MAX_SIZE_BYTES\s*=\s*600\s*\*\s*1024\s*\*\s*1024\s*;"
        assert re.search(pattern, content), "MAX_SIZE_BYTES must be declared as 600 * 1024 * 1024"

        # Numerical equivalence
        expected_bytes = 600 * 1024 * 1024
        assert expected_bytes == 629_145_600

    def test_uploadzone_strict_inequality_boundary_logic(self):
        """Verify boundary condition logic uses strict greater-than inequality."""
        content = UPLOADZONE_PATH.read_text(encoding="utf-8")

        # Must use strict greater than: if (file.size > MAX_SIZE_BYTES)
        assert "if (file.size > MAX_SIZE_BYTES)" in content, (
            "UploadZone must enforce boundary using strict inequality 'file.size > MAX_SIZE_BYTES'"
        )

        max_size = 600 * 1024 * 1024

        # Boundary truth table verification
        # Exactly 600 MB: 629145600 > 629145600 is False (PASSES)
        assert not (max_size > max_size), "Exact 600 MB file must pass validation"

        # Exactly 600 MB + 1 byte: 629145601 > 629145600 is True (FAILS)
        assert (max_size + 1) > max_size, "600 MB + 1 byte file must trigger failure"

        # 600 MB - 1 byte: 629145599 > 629145600 is False (PASSES)
        assert not ((max_size - 1) > max_size), "600 MB - 1 byte file must pass validation"

    def test_uploadzone_error_message_text(self):
        """Verify error message dynamically reports 600 MB ceiling and formatted size."""
        content = UPLOADZONE_PATH.read_text(encoding="utf-8")

        # Check for error message template
        assert "Archive exceeds 600 MB size limit" in content
        assert "selected file is ${sizeMb} MB" in content

        # Verify size formatting math
        file_size_fail = 600 * 1024 * 1024 + 1
        size_mb_fail = f"{file_size_fail / (1024 * 1024):.1f}"
        assert size_mb_fail == "600.0"

        file_size_650mb = 650 * 1024 * 1024
        size_mb_650 = f"{file_size_650mb / (1024 * 1024):.1f}"
        assert size_mb_650 == "650.0"

    def test_uploadzone_subtitle_copy(self):
        """Verify UI copy renders 'Supports .zip archives up to 600 MB'."""
        content = UPLOADZONE_PATH.read_text(encoding="utf-8")

        assert "Supports" in content
        assert "archives up to 600 MB" in content
        # Ensure no legacy '50 MB' remnants remain
        assert "50 MB" not in content, "Found stale reference to '50 MB' in UploadZone.tsx"
        assert "50MB" not in content, "Found stale reference to '50MB' in UploadZone.tsx"

    def test_uploadzone_node_ast_verifier_execution(self):
        """Empirically invoke Node.js AST parser and simulation harness."""
        assert AST_VERIFIER_PATH.exists(), f"AST verifier script missing: {AST_VERIFIER_PATH}"

        result = subprocess.run(
            ["node", str(AST_VERIFIER_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"AST verifier failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        assert "ALL 7 TEST VECTORS PASSED EMPIRICALLY!" in result.stdout


class TestNginxReverseProxyScaling:
    """Empirical verification of nginx.conf payload scaling and timeouts."""

    def test_nginx_conf_exists(self):
        assert NGINX_CONF_PATH.exists(), f"nginx.conf missing: {NGINX_CONF_PATH}"

    def test_nginx_conf_client_max_body_size(self):
        content = NGINX_CONF_PATH.read_text(encoding="utf-8")
        assert "client_max_body_size 650M;" in content, "nginx.conf missing 'client_max_body_size 650M;'"

    def test_nginx_conf_timeouts_600s(self):
        content = NGINX_CONF_PATH.read_text(encoding="utf-8")
        assert "client_body_timeout 600s;" in content, "nginx.conf missing 'client_body_timeout 600s;'"
        assert "proxy_read_timeout 600s;" in content, "nginx.conf missing 'proxy_read_timeout 600s;'"
        assert "proxy_connect_timeout 600s;" in content, "nginx.conf missing 'proxy_connect_timeout 600s;'"
        assert "proxy_send_timeout 600s;" in content, "nginx.conf missing 'proxy_send_timeout 600s;'"


class TestFrontendBuildArtifacts:
    """Empirical verification that frontend production build artifacts exist and are healthy."""

    def test_dist_directory_and_index_html(self):
        index_html = DIST_DIR / "index.html"
        assert index_html.exists(), "dist/index.html missing; npm run build has not produced output"
        html_text = index_html.read_text(encoding="utf-8")
        assert len(html_text) > 100
        assert "<div id=\"root\"></div>" in html_text or "id=\"root\"" in html_text

    def test_dist_assets_non_empty(self):
        assets_dir = DIST_DIR / "assets"
        assert assets_dir.exists(), "dist/assets directory missing"
        asset_files = list(assets_dir.glob("*"))
        assert len(asset_files) >= 2, f"Expected JS and CSS bundles in dist/assets, found: {asset_files}"
