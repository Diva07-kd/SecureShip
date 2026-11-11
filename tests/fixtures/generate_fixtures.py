#!/usr/bin/env python3
"""
Deterministic Synthetic Test Archive Generator for SecureScan E2E Test Suite.

Generates the 8 standard verification archives required by SecureScan specifications:
1. valid_clean.zip       - Clean codebase, passes safe extraction and scans with 0 findings.
2. valid_vulnerable.zip  - Vulnerable codebase with secrets, SQLi, command injection, and deserialization.
3. zip_slip.zip          - Archive containing path traversal entry ('../../evil.txt').
4. symlink_0xa1ed.zip    - Archive containing Unix symlink entry (external_attr 0xA1ED / S_IFLNK).
5. zip_bomb.zip          - High-ratio compression bomb (>100x ratio).
6. oversized_file.zip    - Single uncompressed file exceeding 10 MB (with ratio <= 100x).
7. oversized_archive.zip - Total uncompressed size exceeding 50 MB (with individual files <= 10 MB).
8. corrupt.zip           - Malformed / truncated zip archive.
"""

import io
import os
import random
import stat
import zipfile
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent

MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024      # 10 MB (10,485,760 bytes)
MAX_TOTAL_EXTRACT_BYTES = 50 * 1024 * 1024    # 50 MB (52,428,800 bytes)
MAX_COMPRESSION_RATIO = 100.0                 # 100x


def build_valid_clean(output_path: Path) -> None:
    """Creates a clean project archive with no security vulnerabilities."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # main.py
        main_py = (
            "import sys\n"
            "from math import sqrt\n\n"
            "def calculate_hypotenuse(a: float, b: float) -> float:\n"
            "    \"\"\"Calculates hypotenuse safely using standard math.\"\"\"\n"
            "    return sqrt(a**2 + b**2)\n\n"
            "def main():\n"
            "    print(f'Hypotenuse 3, 4 = {calculate_hypotenuse(3.0, 4.0)}')\n\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        )
        zf.writestr("src/main.py", main_py)

        # utils.py
        utils_py = (
            "def sanitize_string(text: str) -> str:\n"
            "    \"\"\"Removes non-alphanumeric characters cleanly.\"\"\"\n"
            "    return ''.join(ch for ch in text if ch.isalnum() or ch in ' -_')\n\n"
            "def safe_divide(numerator: float, denominator: float) -> float | None:\n"
            "    if denominator == 0:\n"
            "        return None\n"
            "    return numerator / denominator\n"
        )
        zf.writestr("src/utils.py", utils_py)

        # package.json
        pkg_json = (
            "{\n"
            "  \"name\": \"clean-service\",\n"
            "  \"version\": \"1.0.0\",\n"
            "  \"description\": \"Clean reference project for SecureScan testing\",\n"
            "  \"main\": \"src/main.py\",\n"
            "  \"scripts\": {\n"
            "    \"test\": \"pytest\"\n"
            "  }\n"
            "}\n"
        )
        zf.writestr("package.json", pkg_json)

        # README.md
        readme = (
            "# Clean Reference Service\n\n"
            "This repository contains clean, safe code with no hardcoded credentials,\n"
            "insecure deserialization, injection vulnerabilities, or dangerous dependencies.\n"
        )
        zf.writestr("README.md", readme)


def build_valid_vulnerable(output_path: Path) -> None:
    """
    Creates a vulnerable project archive with realistic flaws for SAST / Secret / SCA / IaC detection:
    - Hardcoded AWS credential (CWE-798, OWASP A02:2021)
    - SQL injection via raw f-string (CWE-89, OWASP A03:2021)
    - Command injection via os.system (CWE-78, OWASP A03:2021)
    - Insecure deserialization via pickle (CWE-502, OWASP A08:2021)
    - JS eval injection (CWE-95, OWASP A03:2021)
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Python vulnerable application
        app_py_lines = [
            "#!/usr/bin/env python3",
            "\"\"\"SecureScan Target: Deliberately Vulnerable Application.\"\"\"",
            "import os",
            "import sys",
            "import sqlite3",
            "import pickle",
            "import subprocess",
            "",
            "# Vulnerability 1: Hardcoded AWS Secret Key (CWE-798 / OWASP A02:2021)",
            "# Line 10 contains a hardcoded API token that secret scanners detect",
            "AWS_SECRET_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLEEXAMPLE\"",
            "AWS_DEFAULT_REGION = \"us-east-1\"",
            "",
            "def get_database_connection():",
            "    return sqlite3.connect(':memory:')",
            "",
            "def query_user_records(cursor, username: str):",
            "    \"\"\"",
            "    Vulnerability 2: SQL Injection (CWE-89 / OWASP A03:2021)",
            "    Unescaped f-string interpolation directly into SQL execute statement.",
            "    \"\"\"",
            "    # Context lines above vulnerable line (line 24)",
            "    if not username:",
            "        return None",
            "    # Line 24: SQL Injection target line",
            "    query = f\"SELECT id, username, email FROM users WHERE username = '{username}'\"",
            "    cursor.execute(query)",
            "    return cursor.fetchall()",
            "",
            "def execute_system_diagnostic(user_host: str):",
            "    \"\"\"",
            "    Vulnerability 3: Command Injection (CWE-78 / OWASP A03:2021)",
            "    Untrusted parameter concatenated directly into shell execution string.",
            "    \"\"\"",
            "    # Context lines above vulnerable line (line 36)",
            "    prefix = 'ping -c 1 '",
            "    # Line 36: Command Injection target line",
            "    command = prefix + user_host",
            "    return os.system(command)",
            "",
            "def restore_user_session(session_data: bytes):",
            "    \"\"\"",
            "    Vulnerability 4: Insecure Deserialization (CWE-502 / OWASP A08:2021)",
            "    Direct deserialization of untrusted byte payload using pickle.loads.",
            "    \"\"\"",
            "    if not session_data:",
            "        return {}",
            "    # Line 48: Insecure Deserialization target line",
            "    return pickle.loads(session_data)",
            "",
            "def audit_logging_helper(message: str) -> None:",
            "    \"\"\"Trailing context lines to ensure clean slicing.\"\"\"",
            "    formatted = f'[AUDIT] {message}'",
            "    sys.stdout.write(formatted + '\\n')",
            "",
            "def final_cleanup():",
            "    print('Cleanup complete')",
            "",
            "if __name__ == '__main__':",
            "    print('Vulnerable benchmark target ready')",
            ""
        ]
        zf.writestr("backend/app.py", "\n".join(app_py_lines))

        # Node.js vulnerable script
        server_js_lines = [
            "// Node.js target with eval code injection (CWE-95)",
            "const http = require('http');",
            "const url = require('url');",
            "",
            "const server = http.createServer((req, res) => {",
            "    const parsed = url.parse(req.url, true);",
            "    const userFormula = parsed.query.formula;",
            "    if (userFormula) {",
            "        // Line 9: Code Injection via eval()",
            "        const result = eval(userFormula);",
            "        res.end('Calculated: ' + result);",
            "    } else {",
            "        res.end('Provide ?formula=');",
            "    }",
            "});",
            "",
            "server.listen(3000, () => console.log('Listening on 3000'));",
            ""
        ]
        zf.writestr("frontend/server.js", "\n".join(server_js_lines))

        # Package manifest with outdated dependencies
        package_json = (
            "{\n"
            "  \"name\": \"vulnerable-project\",\n"
            "  \"version\": \"0.1.0\",\n"
            "  \"dependencies\": {\n"
            "    \"lodash\": \"4.17.15\"\n"
            "  }\n"
            "}\n"
        )
        zf.writestr("package.json", package_json)

        # Dockerfile with root execution misconfiguration
        dockerfile_content = (
            "FROM alpine:3.18\n"
            "USER root\n"
            "CMD [\"sh\", \"-c\", \"echo running as root\"]\n"
        )
        zf.writestr("Dockerfile", dockerfile_content)


def build_zip_slip(output_path: Path) -> None:
    """
    Creates a zip archive containing path traversal entries (Zip-Slip attack).
    Member filename uses '../' sequences to escape extraction boundaries.
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Legitimate benign entry
        zf.writestr("safe_file.txt", "This is inside the extraction directory.")

        # Path traversal entry 1: simple traversal
        info1 = zipfile.ZipInfo(filename="../../evil.txt")
        zf.writestr(info1, b"ATTACK: Path traversal escape via ../../evil.txt\n")

        # Path traversal entry 2: nested directory traversal
        info2 = zipfile.ZipInfo(filename="subfolder/../../../escaped_target.sh")
        zf.writestr(info2, b"#!/bin/sh\necho pwned\n")


def build_symlink_0xa1ed(output_path: Path) -> None:
    """
    Creates an archive containing a Unix symbolic link entry.
    External attributes are set to 0xA1ED << 16 (POSIX S_IFLNK | 0o755).
    """
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Legitimate file
        zf.writestr("normal_file.txt", "Normal content.\n")

        # Symlink entry pointing to sensitive system file
        symlink_info = zipfile.ZipInfo(filename="symlink_to_etc_passwd")
        # Standard Unix symlink external attribute: 0xA1ED << 16
        # Upper 16 bits = 0xA1ED (0o120755: S_IFLNK with 0755 permissions)
        symlink_info.external_attr = 0xA1ED << 16
        zf.writestr(symlink_info, b"/etc/passwd")


def build_zip_bomb(output_path: Path) -> None:
    """
    Creates a high-ratio compression bomb (> 100x ratio).
    Deflating 2,000,000 repetitive bytes yields ~2,000 compressed bytes (ratio ~1000x).
    """
    bomb_payload = b"\x00" * 2_000_000  # 2 MB uncompressed
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb_payload.dat", bomb_payload)


def build_oversized_file(output_path: Path) -> None:
    """
    Creates an archive containing a single uncompressed file exceeding 10 MB (10,485,760 bytes).
    Compression ratio is kept strictly <= 100x (around 10x) so it specifically trips the single-file limit
    without tripping the compression ratio check.
    """
    target_uncompressed = MAX_SINGLE_FILE_BYTES + 1024  # 10,486,784 bytes (~10.001 MB)
    rng = random.Random(1337)
    vocab = [f"word_{i:02d}_payload".encode() for i in range(10)]
    
    # Generate stream with controlled entropy: ratio ~10x
    chunks = []
    current_len = 0
    while current_len < target_uncompressed:
        chunk = b" ".join(rng.choice(vocab) for _ in range(2000))
        chunks.append(chunk)
        current_len += len(chunk)
    stream = b"".join(chunks)[:target_uncompressed]

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("oversized_single_file.bin", stream)


def build_oversized_archive(output_path: Path) -> None:
    """
    Creates an archive whose total uncompressed size exceeds 50 MB (52,428,800 bytes).
    Each individual file is 9.2 MB (<= 10 MB limit), so no single-file limit is breached.
    Total = 6 files * 9.2 MB = ~55.2 MB > 50 MB.
    Compression ratio is kept strictly <= 100x (around 10x) per file.
    """
    per_file_bytes = 9 * 1024 * 1024 + 200 * 1024  # ~9.2 MB each (well below 10 MB)
    file_count = 6                                  # 6 * 9.2 MB = 55.2 MB > 50 MB
    rng = random.Random(42)
    vocab = [f"part_token_{i:02d}".encode() for i in range(12)]
    
    chunks = []
    current_len = 0
    while current_len < per_file_bytes:
        chunk = b" ".join(rng.choice(vocab) for _ in range(2000))
        chunks.append(chunk)
        current_len += len(chunk)
    stream = b"".join(chunks)[:per_file_bytes]

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for idx in range(file_count):
            zf.writestr(f"module_part_{idx + 1}.bin", stream)


def build_corrupt(output_path: Path) -> None:
    """
    Creates a malformed / corrupted zip file.
    Writes ZIP header signature followed by random truncated garbage bytes.
    """
    # Standard ZIP local file header signature PK\x03\x04 followed by truncated invalid payload
    corrupt_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00CORRUPT_HEADER_TRUNCATED_STREAM"
    output_path.write_bytes(corrupt_bytes)


def generate_all_fixtures(target_dir: Path = FIXTURES_DIR) -> dict[str, Path]:
    """Generates all 8 fixtures in target_dir and returns mapping of name to path."""
    target_dir.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "valid_clean.zip": target_dir / "valid_clean.zip",
        "valid_vulnerable.zip": target_dir / "valid_vulnerable.zip",
        "zip_slip.zip": target_dir / "zip_slip.zip",
        "symlink_0xa1ed.zip": target_dir / "symlink_0xa1ed.zip",
        "zip_bomb.zip": target_dir / "zip_bomb.zip",
        "oversized_file.zip": target_dir / "oversized_file.zip",
        "oversized_archive.zip": target_dir / "oversized_archive.zip",
        "corrupt.zip": target_dir / "corrupt.zip",
    }

    print(f"Generating synthetic test archives in: {target_dir}")
    build_valid_clean(fixtures["valid_clean.zip"])
    build_valid_vulnerable(fixtures["valid_vulnerable.zip"])
    build_zip_slip(fixtures["zip_slip.zip"])
    build_symlink_0xa1ed(fixtures["symlink_0xa1ed.zip"])
    build_zip_bomb(fixtures["zip_bomb.zip"])
    build_oversized_file(fixtures["oversized_file.zip"])
    build_oversized_archive(fixtures["oversized_archive.zip"])
    build_corrupt(fixtures["corrupt.zip"])

    return fixtures


def audit_fixture(path: Path) -> dict:
    """Inspects a zip fixture and returns metadata and safety audit results."""
    result = {
        "path": str(path.name),
        "file_size": path.stat().st_size,
        "is_valid_zip": False,
        "has_path_traversal": False,
        "has_symlink": False,
        "max_compression_ratio": 0.0,
        "max_single_file_size": 0,
        "total_uncompressed_size": 0,
        "entries": []
    }

    try:
        with zipfile.ZipFile(path, "r") as zf:
            result["is_valid_zip"] = True
            for info in zf.infolist():
                mode = info.external_attr >> 16
                is_sym = (mode & 0o170000) == 0o120000 or mode == 0xA1ED
                ratio = info.file_size / max(info.compress_size, 1)
                
                parts = Path(info.filename).parts
                is_traversal = ".." in parts or info.filename.startswith(("/", "\\"))

                if is_traversal:
                    result["has_path_traversal"] = True
                if is_sym:
                    result["has_symlink"] = True
                if ratio > result["max_compression_ratio"]:
                    result["max_compression_ratio"] = ratio
                if info.file_size > result["max_single_file_size"]:
                    result["max_single_file_size"] = info.file_size
                result["total_uncompressed_size"] += info.file_size

                result["entries"].append({
                    "filename": info.filename,
                    "file_size": info.file_size,
                    "compress_size": info.compress_size,
                    "ratio": round(ratio, 2),
                    "external_attr_hex": f"0x{info.external_attr:08X}",
                    "is_symlink": is_sym,
                    "is_traversal": is_traversal
                })
    except Exception as exc:
        result["error"] = str(exc)

    return result


if __name__ == "__main__":
    generated = generate_all_fixtures()
    print("\n--- Synthetic Test Fixtures Verification Summary ---")
    for name, p in generated.items():
        audit = audit_fixture(p)
        print(f"\n[{name}]")
        print(f"  Archive Size on Disk : {audit['file_size']} bytes")
        print(f"  Valid Zip Format     : {audit['is_valid_zip']}")
        if audit.get("error"):
            print(f"  Load Error           : {audit['error']}")
        else:
            print(f"  Has Path Traversal   : {audit['has_path_traversal']}")
            print(f"  Has Symlink (0xA1ED) : {audit['has_symlink']}")
            print(f"  Max Compress Ratio   : {audit['max_compression_ratio']:.1f}x (limit <= 100x)")
            print(f"  Max Single File Size : {audit['max_single_file_size']} bytes (limit <= 10MB = {MAX_SINGLE_FILE_BYTES})")
            print(f"  Total Extracted Size : {audit['total_uncompressed_size']} bytes (limit <= 50MB = {MAX_TOTAL_EXTRACT_BYTES})")
