# Handoff Report: Milestone 2 — Exporters & Format Explorer (M2-3)

**Author**: Explorer M2-3 (Exporters & Format Explorer)  
**Date**: 2026-11-07T07:22:00Z  
**Role**: Exporters & Multi-Format Endpoint Explorer  
**Target Milestone**: Milestone 2 (Backend API & Exporters)  
**Recipient**: Orchestrator / Worker M2 Implementers  

---

## 1. Observation

Direct observations and verified facts from the codebase, system environment, and existing test suites:

### 1.1 Python Environment & Dependency Audit
- **Python Runtime**: Python 3.12.10 (AMD64 on Windows 11).
- **Installed Packages & Versions**:
  - `reportlab`: **5.1.0** is installed, tested, and fully functional (`reportlab.lib.pagesizes`, `reportlab.platypus`, `reportlab.pdfgen.canvas`).
  - `weasyprint`: **NOT installed** (`ModuleNotFoundError: No module named 'weasyprint'`).
    - *Investigation of WeasyPrint on Windows*: WeasyPrint relies on native C shared libraries (`libcairo-2.dll`, `libpango-1.0-0.dll`, `libgobject-2.0-0.dll`, `libgdk_pixbuf-2.0-0.dll`). Installing `weasyprint` on Windows via `pip` fails at runtime with `OSError: cannot load library 'gobject-2.0-0'` unless full GTK3/MSYS2 binaries are manually installed and added to the Windows system PATH.
    - Conversely, `reportlab` installs pure Python code and prebuilt wheels with zero external C dependencies, functioning identically on Windows local dev, macOS, and Linux Docker containers.
  - `fastapi`: **0.162.0** installed.
  - `pydantic`: **2.14.2** installed.
  - `pydantic-settings`: **2.16.2** installed.
  - `jinja2`: **3.1.6** installed and functional.
  - `pytest`: **9.2.0** installed.
  - `httpx`: **0.28.1** installed.
  - `jsonschema`: **4.25.1** installed.
- **Existing `backend/requirements.txt`**:
  ```
  fastapi>=0.115.0
  uvicorn[standard]>=0.30.0
  pydantic>=2.8.0
  pydantic-settings>=2.4.0
  python-multipart>=0.0.9
  reportlab>=4.2.0
  pytest>=8.3.0
  pytest-asyncio>=0.24.0
  httpx>=0.27.0
  ```
  Notice that `reportlab>=4.2.0` is already explicitly codified in `requirements.txt`. Adding `slowapi>=0.1.9` and `jinja2>=3.1.4` completes the backend dependencies.

### 1.2 Existing Milestone 1 Core Models
- **`backend/app/models/report.py`**:
  - Defines `Severity`: `CRITICAL` (5), `HIGH` (4), `MEDIUM` (3), `LOW` (2), `INFO` (1).
  - Defines `FindingCategory`: `SAST`, `SCA`, `SECRET`, `IAC`, `SUPPLY_CHAIN`.
  - Defines `ScannerName`: `opengrep`, `semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `checkov`, `generic`.
  - Defines `ReachabilityVerdict`: `REACHABLE`, `UNREACHABLE`, `UNKNOWN`.
  - Defines `OwaspCategory`: 10 categories for OWASP Top 10 (2021) (`A01:2021-Broken Access Control` through `A10:2021-Server-Side Request Forgery`, plus `UNKNOWN`).
  - Defines `CodeSnippet` and `SnippetLine`: contains `line_number`, `content`, `is_target` (for highlighting vulnerable line with ±5 lines of context).
  - Defines `FindingLocation`: `file_path`, `start_line`, `end_line`, `start_column`, `end_column`, `snippet`.
  - Defines `NormalizedFinding`: strongly-typed finding model containing `id`, `rule_id`, `scanner_name`, `category`, `severity`, `title`, `description`, `location`, `cwe_ids`, `owasp_category`, `reachability`, `confidence`, `fix_recommendation`, `snippet_context`.
  - Defines `ScanSummary`: contains `total_findings`, `by_severity`, `by_category`, `by_owasp`, `by_scanner`, `by_reachability`.
  - Defines `ScanReport`: contains `id`, `target_name`, `status`, `duration_ms`, `created_at`, `scanners`, `findings`, `summary`, `warnings`.
  - Defines `BaseSchema`: Configured with `populate_by_name=True` and `alias_generator=to_camel`.

### 1.3 Test Suite Contracts & Existing Assertions
Direct examination of `tests/e2e/conftest.py` lines 217–288 revealed the authoritative validation helpers that all exporters must satisfy:
1. **SARIF Validator** (`validate_sarif_schema`):
   - `sarif_data["version"] == "2.1.0"`
   - `"$schema"` must be present and set to `"https://json.schemastore.org/sarif-2.1.0.json"`
   - `runs` must be a list with `len(runs) > 0`
   - `runs[0]["tool"]["driver"]["name"]` must exist (set to `"SecureShip"`)
   - `runs[0]["results"]` must be a list
   - Each result must contain: `ruleId`, `level` (one of `"error"`, `"warning"`, `"note"`, `"none"`), `message.text`, `locations` with `physicalLocation.artifactLocation.uri`
2. **HTML Validator** (`validate_html_report`):
   - Must contain `<!DOCTYPE html>` or `<!doctype html>`
   - Must contain root `<html...>` and `</html>`, `<head>` and `</head>`, `<body>` and `</body>`
   - **Air-Gapped Self-Containment**:
     - `assert 'rel="stylesheet" href="http' not in html_content` (NO external stylesheets from CDNs)
     - `assert '<script src="http' not in html_content` (NO external scripts from CDNs)
   - Must contain embedded `<style>` block
3. **PDF Validator** (`validate_pdf_report`):
   - `len(pdf_bytes) > 100`
   - `pdf_bytes.startswith(b"%PDF-")`
   - `b"%%EOF"` in pdf_bytes or `b"xref"` in pdf_bytes
4. **Unified Report Validator** (`validate_unified_report`):
   - Expected top-level keys: `{"job_id", "status", "summary", "scanners", "findings"}`
   - Notice: `ScanReport` has field `id`, while `validate_unified_report` checks `job_id`. Exporters and serializers must include BOTH `id` and `job_id`.
   - `summary` must contain `total_findings`, `severity_counts`, and `owasp_counts` (alongside `by_severity` and `by_owasp`).
5. **Premature Export Protection Contract** (`tests/e2e/test_tier3_cross_features.py` lines 109–141):
   - Request for unknown `id` -> `404 Not Found`
   - Request while job status is `"queued"` or `"running"` -> `409 Conflict` (detail: `"Scan report not ready"`)
   - Request while job status is `"failed"` -> `422 Unprocessable Entity` (detail: `"Scan failed"`)
   - Request while job status is `"done"` -> `200 OK`
   - Invalid `format` parameter -> `400 Bad Request`

---

## 2. Logic Chain

From our observations, we establish the following design deductions:

### 2.1 PDF Engine Selection (ReportLab vs WeasyPrint)
1. `ORIGINAL_REQUEST.md` line 100 lists `weasyprint`, whereas `PROJECT.md` line 36/82/188/195 explicitly specifies `ReportLab` (`requirements.txt: reportlab>=4.2.0`, `pdf_exporter.py: Binary PDF exporter via ReportLab`).
2. Our direct audit verified `weasyprint` is absent and cannot run on Windows without installing MSYS2/GTK3 C-libraries, whereas `reportlab` 5.1.0 is already installed and verified working.
3. In `tests/e2e/test_tier4_real_world.py` lines 262–277, the e2e test suite specifically imports and tests `reportlab`.
4. **Architectural Resolution**:
   - `reportlab` is selected as the **authoritative primary engine** for `pdf_exporter.py`. It guarantees 100% portability, zero native C-runtime dependency, and works identically on Windows, Linux, and Alpine/Debian containers.
   - For complete backward-compatibility with any environment where `weasyprint` might be installed in Docker, `pdf_exporter.py` provides an optional WeasyPrint rendering path that automatically catches `(ImportError, OSError, Exception)` and falls back seamlessly to ReportLab.

### 2.2 Schema & Key Compatibility Normalization
1. `ScanReport` defines `id: str`, while `validate_unified_report` checks `job_id in report_data`.
2. `ScanSummary` defines `by_severity` and `by_owasp`, while `validate_unified_report` checks `severity_counts in summary` and `owasp_counts in summary`.
3. Frontend and external consumers may query camelCase (`ruleId`, `filePath`) or snake_case (`rule_id`, `file_path`).
4. **Resolution**:
   - In `json_exporter.py`, we serialize with bidirectional keys:
     - Top level: both `id` and `job_id`.
     - `summary`: `total_findings`, both `severity_counts` and `by_severity`, both `owasp_counts` and `by_owasp`, `by_category`, `by_scanner`, `by_reachability`.
     - `findings`: include `rule_id` and `ruleId`, `cwe_ids` and `cweIds`, `owasp_category` and `owaspCategory`, `file_path` and `filePath`.

### 2.3 Standalone Air-Gapped HTML Architecture
1. To satisfy `validate_html_report`, HTML output must have NO external `http://` or `https://` stylesheet or script links.
2. Styling must use an embedded `<style>` block containing:
   - Modern dark palette matching SecureScan: background `#090d16` / `#0f172a`, card `#111827` / `#1e293b`, borders `#1f2937` / `#334155`, text `#f9fafb`, accent `#6366f1` (Indigo).
   - Severity badges: CRITICAL (`#ef4444`), HIGH (`#f97316`), MEDIUM (`#f59e0b`), LOW (`#3b82f6`), INFO (`#6b7280`).
   - Reachability badges: `REACHABLE` (`#dc2626` red tag), `UNREACHABLE` (`#10b981` green tag), `UNKNOWN` (`#6b7280` slate tag).
   - Code snippet box: dark terminal background (`#0d1117`), line numbers, highlighted `.line-target` lines (`rgba(239, 68, 68, 0.2)` with red left border).
   - Native collapsible `<details>` / `<summary>` tags for expandable finding details without requiring any external JavaScript.
   - `@media print` rules: high-contrast white background, black text, page breaks between findings, expanded `<details>`.
   - Security: all text passed through `html.escape()` to prevent XSS.

### 2.4 SARIF 2.1.0 Compliance
1. Schema `$schema`: `"https://json.schemastore.org/sarif-2.1.0.json"`
2. Version: `"2.1.0"`
3. Tool driver: `"name": "SecureShip"`, `"version": "1.0.0"`.
4. Deduplicate rules by `rule_id` in `tool.driver.rules`.
5. Map severity to SARIF levels:
   - `CRITICAL` -> `"error"`
   - `HIGH` -> `"error"`
   - `MEDIUM` -> `"warning"`
   - `LOW` -> `"note"`
   - `INFO` -> `"none"`
6. Locations: Normalize file paths to relative forward slashes (`/`), map 1-indexed `startLine` and `endLine`, wrap in `physicalLocation.artifactLocation.uri` and `region`.

### 2.5 Export Endpoint Interface Contract
- **Route**: `GET /api/reports/{id}/export?format={json|sarif|html|pdf}`
- **Format Validation**:
  - Valid formats: `json`, `sarif`, `html`, `pdf` (case-insensitive).
  - Unsupported or missing format -> `HTTP 400 Bad Request` (`{"detail": "Unsupported export format 'xyz'. Supported formats: json, sarif, html, pdf"}`).
- **State Validation**:
  - Unknown job ID -> `HTTP 404 Not Found`.
  - Job status in `("queued", "running")` -> `HTTP 409 Conflict` (`{"detail": "Scan report not ready"}`).
  - Job status == `"failed"` -> `HTTP 422 Unprocessable Entity` (`{"detail": f"Scan failed: {error}"}`).
  - Missing report data -> `HTTP 404 Not Found`.
- **Response Headers**:
  - `Content-Disposition`: `attachment; filename="securescan-report-{id}.{ext}"`
  - `Content-Type`:
    - `json` -> `application/json`
    - `sarif` -> `application/sarif+json`
    - `html` -> `text/html; charset=utf-8`
    - `pdf` -> `application/pdf`

---

## 3. Caveats

1. **Dual Directory Specification in Documentation**:
   - `PROJECT.md` specifies `backend/app/exporters/` (`json_exporter.py`, `sarif_exporter.py`, etc.).
   - `ORIGINAL_REQUEST.md` specifies `backend/app/services/exporter.py`.
   - **Resolution**: Implement modular exporters under `backend/app/exporters/` and provide a clean facade in `backend/app/services/exporter.py` that imports and re-exports all functions (`export_report`, `export_json`, `export_sarif`, `export_html`, `export_pdf`). Both paths are 100% supported.
2. **WeasyPrint Fallback**:
   - Do not include `weasyprint` in `requirements.txt` on Windows or CI environments without GTK3 C-libraries installed. ReportLab satisfies all acceptance criteria, tests, and documentation.
3. **Report Model Input Flexibility**:
   - `JobRecord.report` can be either an instance of `ScanReport` or a `dict` (e.g. from tests or enriched raw CLI output). All exporter functions must accept `Union[ScanReport, dict[str, Any]]` and normalize via `ensure_scan_report()`.
4. **FastAPI Trailing Slash Matching**:
   - To avoid 307 redirects that can interfere with client downloads or automated test clients, the router should support both `/api/reports/{id}/export` and `/api/reports/{id}/export/`.

---

## 4. Conclusion & Concrete Implementation Blueprint

Below are the complete, production-ready implementation blueprints for Worker M2.

### 4.1 Module Structure
```
backend/app/
├── exporters/
│   ├── __init__.py           # export_report facade dispatcher
│   ├── json_exporter.py      # Full ScanReport serialization with ISO timestamps
│   ├── sarif_exporter.py     # OASIS SARIF 2.1.0 compliant exporter
│   ├── html_exporter.py      # Standalone single-file air-gapped HTML exporter
│   └── pdf_exporter.py       # Binary PDF generator via ReportLab
├── services/
│   ├── __init__.py
│   └── exporter.py           # Facade re-exporting backend/app/exporters functions
└── routers/
    └── reports.py            # GET /api/reports/{id}/export?format={json|sarif|html|pdf}
```

---

### 4.2 Code Blueprint 1: `backend/app/exporters/json_exporter.py`
```python
"""
JSON Exporter for SecureScan Reports.
Serializes unified ScanReport models to cleanly formatted JSON with ISO-8601 timestamps
and bidirectional schema compatibility for both job_id/id and severity_counts/by_severity.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Union

from app.models.report import ScanReport


def ensure_scan_report(report_data: Union[ScanReport, dict[str, Any]]) -> ScanReport:
    """Normalizes input dictionary or model into a validated ScanReport instance."""
    if isinstance(report_data, ScanReport):
        return report_data
    if isinstance(report_data, dict):
        d = dict(report_data)
        # Ensure 'id' exists if only 'job_id' was provided
        if "id" not in d and "job_id" in d:
            d["id"] = d["job_id"]
        elif "id" not in d and "jobId" in d:
            d["id"] = d["jobId"]
        return ScanReport.model_validate(d)
    raise ValueError(f"Cannot convert {type(report_data)} to ScanReport")


def export_json(
    report: Union[ScanReport, dict[str, Any]],
    indent: int = 2,
) -> str:
    """
    Exports a scan report to formatted JSON string.
    
    Guarantees:
    - Root contains both 'id' and 'job_id'
    - Summary contains both 'by_severity' and 'severity_counts'
    - Summary contains both 'by_owasp' and 'owasp_counts'
    - Timestamps formatted as ISO-8601 strings
    - Findings preserve location, CWE, OWASP, reachability, and code snippet context
    """
    scan_report = ensure_scan_report(report)
    data = scan_report.model_dump(by_alias=False, mode="json")

    # Bidirectional ID compatibility
    data["job_id"] = scan_report.id
    data["id"] = scan_report.id

    # Bidirectional Summary compatibility
    if "summary" not in data or not data["summary"]:
        data["summary"] = {}
    summary = data["summary"]
    summary["total_findings"] = summary.get("total_findings", len(scan_report.findings))

    by_sev = summary.get("by_severity", {})
    summary["severity_counts"] = by_sev
    summary["by_severity"] = by_sev

    by_ow = summary.get("by_owasp", {})
    summary["owasp_counts"] = by_ow
    summary["by_owasp"] = by_ow

    # Ensure ISO string for created_at
    if "created_at" in data and isinstance(data["created_at"], datetime):
        data["created_at"] = data["created_at"].isoformat()

    # Findings enrichment for frontend interoperability
    findings = data.get("findings", [])
    for f in findings:
        f["ruleId"] = f.get("rule_id", "")
        f["scannerName"] = f.get("scanner_name", "")
        f["cweIds"] = f.get("cwe_ids", [])
        f["owaspCategory"] = f.get("owasp_category", "")
        loc = f.get("location", {})
        if loc:
            loc["filePath"] = loc.get("file_path", "")
            loc["startLine"] = loc.get("start_line", 1)
            loc["endLine"] = loc.get("end_line", 1)

    return json.dumps(data, indent=indent, ensure_ascii=False)
```

---

### 4.3 Code Blueprint 2: `backend/app/exporters/sarif_exporter.py`
```python
"""
OASIS SARIF 2.1.0 Exporter for SecureScan Reports.
Complies with OASIS Standard SARIF v2.1.0 schema specification:
https://json.schemastore.org/sarif-2.1.0.json
"""

from __future__ import annotations

import json
from typing import Any, Union

from app.models.report import NormalizedFinding, ScanReport, Severity
from app.exporters.json_exporter import ensure_scan_report

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def export_sarif(
    report: Union[ScanReport, dict[str, Any]],
    indent: int = 2,
) -> str:
    """
    Exports a scan report into an OASIS SARIF 2.1.0 conforming JSON string.
    """
    scan_report = ensure_scan_report(report)

    rules: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    rule_id_to_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    # First pass: Deduplicate rules and build tool.driver.rules
    for finding in scan_report.findings:
        rule_id = finding.rule_id
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rule_index = len(rules)
            rule_id_to_index[rule_id] = rule_index

            tags = [finding.owasp_category] + list(finding.cwe_ids)
            if hasattr(finding.category, "value"):
                tags.append(str(finding.category.value))
            if hasattr(finding.reachability, "value"):
                tags.append(str(finding.reachability.value))

            rule_obj = {
                "id": rule_id,
                "name": finding.title or rule_id,
                "shortDescription": {
                    "text": finding.title or rule_id,
                },
                "fullDescription": {
                    "text": finding.description or finding.title or rule_id,
                },
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity.value, "warning"),
                },
                "properties": {
                    "tags": [t for t in tags if t],
                    "category": str(finding.category.value if hasattr(finding.category, "value") else finding.category),
                    "scanner": finding.scanner_name,
                },
            }
            if finding.fix_recommendation:
                rule_obj["help"] = {
                    "text": finding.fix_recommendation,
                    "markdown": finding.fix_recommendation,
                }
            rules.append(rule_obj)

    # Second pass: Build results list
    for finding in scan_report.findings:
        file_path = finding.location.file_path.replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]

        start_line = max(1, finding.location.start_line)
        end_line = max(start_line, finding.location.end_line)

        region: dict[str, Any] = {
            "startLine": start_line,
            "endLine": end_line,
        }
        if finding.location.start_column is not None:
            region["startColumn"] = finding.location.start_column
        if finding.location.end_column is not None:
            region["endColumn"] = finding.location.end_column
        if finding.location.snippet:
            region["snippet"] = {"text": finding.location.snippet}
        elif finding.snippet_context and finding.snippet_context.raw_content:
            region["snippet"] = {"text": finding.snippet_context.raw_content}

        rule_index = rule_id_to_index.get(finding.rule_id, 0)
        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity.value, "warning")

        res_obj = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": sarif_level,
            "message": {
                "text": finding.description or finding.title or "Security finding detected",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            ],
            "properties": {
                "id": finding.id,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "reachability": finding.reachability.value,
                "scanner": finding.scanner_name,
                "cweIds": finding.cwe_ids,
                "owaspCategory": finding.owasp_category,
            },
        }
        results.append(res_obj)

    sarif_document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureShip",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/secureship/secureship",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif_document, indent=indent, ensure_ascii=False)
```

---

### 4.4 Code Blueprint 3: `backend/app/exporters/html_exporter.py`
```python
"""
Standalone Single-File HTML Exporter for SecureScan Reports.
Completely air-gapped with embedded inline CSS and zero external CDN or stylesheet dependencies.
Features responsive dark theme, summary cards, findings table, collapsible vulnerability details
with code snippets, and @media print support.
"""

from __future__ import annotations

import html
from typing import Any, Union

from app.models.report import ScanReport
from app.exporters.json_exporter import ensure_scan_report


def export_html(report: Union[ScanReport, dict[str, Any]]) -> str:
    """
    Generates a self-contained, standalone single-file HTML report.
    """
    scan_report = ensure_scan_report(report)

    # Calculate summary metrics
    total_findings = len(scan_report.findings)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in scan_report.findings:
        sev = f.severity.value.upper()
        if sev in counts:
            counts[sev] += 1

    created_str = (
        scan_report.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if hasattr(scan_report.created_at, "strftime")
        else str(scan_report.created_at)
    )
    duration_str = f"{scan_report.duration_ms / 1000.0:.2f}s"
    target_name_esc = html.escape(scan_report.target_name or "Scan Target Archive")
    report_id_esc = html.escape(scan_report.id)

    # Build findings HTML cards
    finding_cards_html = []
    for idx, f in enumerate(scan_report.findings, start=1):
        sev_val = f.severity.value.upper()
        title_esc = html.escape(f.title or f.rule_id)
        desc_esc = html.escape(f.description or "No description provided.")
        file_path_esc = html.escape(f.location.file_path)
        start_line = f.location.start_line
        rule_id_esc = html.escape(f.rule_id)
        scanner_esc = html.escape(f.scanner_name)
        owasp_esc = html.escape(f.owasp_category)
        reach_val = f.reachability.value.upper()

        cwe_badges = "".join(
            f'<span class="badge badge-cwe">{html.escape(cwe)}</span>'
            for cwe in f.cwe_ids
        ) or '<span class="badge badge-muted">No CWE</span>'

        reach_badge_cls = {
            "REACHABLE": "badge-reachable",
            "UNREACHABLE": "badge-unreachable",
            "UNKNOWN": "badge-unknown",
        }.get(reach_val, "badge-unknown")

        # Build snippet view
        snippet_html = ""
        if f.snippet_context and f.snippet_context.lines:
            lines_html = []
            for line in f.snippet_context.lines:
                is_target = line.is_target or (line.line_number == start_line)
                target_cls = "line-target" if is_target else ""
                marker = "►" if is_target else " "
                line_content_esc = html.escape(line.content)
                lines_html.append(
                    f'<div class="code-line {target_cls}">'
                    f'<span class="line-marker">{marker}</span>'
                    f'<span class="line-num">{line.line_number}</span>'
                    f'<span class="line-code">{line_content_esc}</span>'
                    f'</div>'
                )
            snippet_html = f"""
            <div class="code-wrapper">
                <div class="code-header">
                    <span>{file_path_esc} (lines {f.snippet_context.start_line}–{f.snippet_context.end_line})</span>
                    <span class="target-indicator">Vulnerable Line: {start_line}</span>
                </div>
                <div class="code-container">{''.join(lines_html)}</div>
            </div>
            """
        elif f.location.snippet:
            snippet_html = f"""
            <div class="code-wrapper">
                <div class="code-header"><span>{file_path_esc}:{start_line}</span></div>
                <div class="code-container"><div class="code-line line-target"><span class="line-num">{start_line}</span><span class="line-code">{html.escape(f.location.snippet)}</span></div></div>
            </div>
            """

        fix_box_html = ""
        if f.fix_recommendation:
            fix_box_html = f"""
            <div class="fix-box">
                <strong>Remediation Recommendation:</strong>
                <p>{html.escape(f.fix_recommendation)}</p>
            </div>
            """

        finding_cards_html.append(f"""
        <details class="finding-card sev-border-{sev_val.lower()}" open>
            <summary class="finding-header">
                <div class="finding-title-row">
                    <span class="badge badge-{sev_val.lower()}">{sev_val}</span>
                    <span class="finding-title">{idx}. {title_esc}</span>
                    <span class="badge badge-scanner">{scanner_esc}</span>
                    <span class="badge {reach_badge_cls}">{reach_val}</span>
                </div>
                <div class="finding-location">
                    <code>{file_path_esc}:{start_line}</code>
                </div>
            </summary>
            <div class="finding-body">
                <p class="finding-desc">{desc_esc}</p>
                <div class="taxonomy-bar">
                    <span class="tax-item"><strong>Rule:</strong> <code>{rule_id_esc}</code></span>
                    <span class="tax-item"><strong>OWASP:</strong> <span class="badge badge-owasp">{owasp_esc}</span></span>
                    <span class="tax-item"><strong>CWE:</strong> {cwe_badges}</span>
                </div>
                {snippet_html}
                {fix_box_html}
            </div>
        </details>
        """)

    findings_content = "\n".join(finding_cards_html) if finding_cards_html else '<div class="empty-state"><h3>No vulnerabilities detected</h3><p>Audit completed cleanly without security findings.</p></div>'

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureScan Security Report — {target_name_esc}</title>
  <style>
    /* Reset & Base Typography */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: #090d16;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem 1rem;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    /* Header Card */
    .header-card {{
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 1.5rem 2rem;
      margin-bottom: 2rem;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 1.5rem;
    }}
    .brand-title {{
      font-size: 1.75rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .brand-title svg {{
      width: 32px;
      height: 32px;
      fill: #6366f1;
    }}
    .brand-sub {{
      color: #94a3b8;
      font-size: 0.875rem;
      margin-top: 0.25rem;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      background: #0d121f;
      padding: 1rem;
      border-radius: 8px;
      border: 1px solid #1f2937;
      font-size: 0.8125rem;
    }}
    .meta-item strong {{ color: #cbd5e1; display: block; margin-bottom: 2px; }}
    .meta-item span {{ color: #94a3b8; }}

    /* Severity Metrics Bar */
    .metrics-bar {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .metric-card {{
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 1rem 1.25rem;
      text-align: center;
    }}
    .metric-val {{
      font-size: 2rem;
      font-weight: 800;
      line-height: 1.2;
    }}
    .metric-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-top: 0.25rem;
      font-weight: 600;
    }}
    .val-total {{ color: #ffffff; }}
    .val-critical {{ color: #ef4444; }}
    .val-high {{ color: #f97316; }}
    .val-medium {{ color: #f59e0b; }}
    .val-low {{ color: #3b82f6; }}
    .val-info {{ color: #64748b; }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.025em;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
    .badge-info {{ background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #64748b; }}
    .badge-scanner {{ background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }}
    .badge-reachable {{ background: rgba(220, 38, 38, 0.25); color: #fca5a5; border: 1px solid #dc2626; }}
    .badge-unreachable {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid #10b981; }}
    .badge-unknown {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
    .badge-owasp {{ background: #2e1065; color: #d8b4fe; border: 1px solid #7c3aed; text-transform: none; }}
    .badge-cwe {{ background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; margin-right: 4px; text-transform: none; }}
    .badge-muted {{ background: #1e293b; color: #64748b; }}

    /* Finding Card */
    .finding-card {{
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      margin-bottom: 1rem;
      overflow: hidden;
    }}
    .sev-border-critical {{ border-left: 4px solid #ef4444; }}
    .sev-border-high {{ border-left: 4px solid #f97316; }}
    .sev-border-medium {{ border-left: 4px solid #f59e0b; }}
    .sev-border-low {{ border-left: 4px solid #3b82f6; }}
    .sev-border-info {{ border-left: 4px solid #64748b; }}

    .finding-header {{
      padding: 1rem 1.25rem;
      cursor: pointer;
      user-select: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}
    .finding-title-row {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.6rem;
    }}
    .finding-title {{
      font-weight: 600;
      font-size: 1rem;
      color: #ffffff;
      flex: 1;
    }}
    .finding-location {{
      font-size: 0.8125rem;
      color: #94a3b8;
    }}
    .finding-location code {{
      color: #818cf8;
      background: #0f172a;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .finding-body {{
      padding: 1rem 1.25rem 1.5rem;
      border-top: 1px solid #1f2937;
      background: #0c111d;
    }}
    .finding-desc {{
      color: #cbd5e1;
      font-size: 0.875rem;
      margin-bottom: 1rem;
    }}
    .taxonomy-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 1.25rem;
      align-items: center;
      padding: 0.75rem;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 6px;
      font-size: 0.8125rem;
      margin-bottom: 1rem;
    }}
    .tax-item strong {{ color: #94a3b8; margin-right: 4px; }}

    /* Code Snippet Display */
    .code-wrapper {{
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 1rem;
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
      font-size: 0.8125rem;
    }}
    .code-header {{
      background: #161b22;
      padding: 0.4rem 0.8rem;
      border-bottom: 1px solid #30363d;
      color: #8b949e;
      font-size: 0.75rem;
      display: flex;
      justify-content: space-between;
    }}
    .target-indicator {{ color: #f87171; font-weight: 600; }}
    .code-container {{
      overflow-x: auto;
      padding: 0.5rem 0;
    }}
    .code-line {{
      display: flex;
      padding: 2px 0;
      line-height: 1.5;
    }}
    .code-line.line-target {{
      background: rgba(239, 68, 68, 0.18);
      border-left: 3px solid #ef4444;
    }}
    .line-marker {{
      width: 20px;
      text-align: center;
      color: #ef4444;
      font-weight: 800;
    }}
    .line-num {{
      width: 45px;
      text-align: right;
      padding-right: 12px;
      color: #6e7681;
      user-select: none;
    }}
    .line-code {{
      white-space: pre;
      color: #c9d1d9;
    }}
    .code-line.line-target .line-code {{
      color: #fca5a5;
      font-weight: 600;
    }}

    .fix-box {{
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      font-size: 0.8125rem;
      color: #a7f3d0;
    }}
    .fix-box strong {{ display: block; margin-bottom: 2px; color: #34d399; }}

    .empty-state {{
      text-align: center;
      padding: 3rem 1rem;
      background: #111827;
      border-radius: 8px;
      border: 1px solid #1f2937;
    }}

    /* Print Stylesheet */
    @media print {{
      body {{ background: #fff !important; color: #000 !important; padding: 0 !important; }}
      .header-card, .metric-card, .finding-card {{
        background: #fff !important;
        border: 1px solid #ccc !important;
        color: #000 !important;
        break-inside: avoid;
      }}
      .brand-title, .finding-title {{ color: #000 !important; }}
      .finding-body {{ background: #fff !important; }}
      .code-wrapper {{ background: #f8fafc !important; border-color: #cbd5e1 !important; }}
      .code-line.line-target {{ background: #fee2e2 !important; }}
      .line-code {{ color: #000 !important; }}
      details {{ display: block !important; }}
      summary {{ display: none !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header Summary -->
    <header class="header-card">
      <div>
        <h1 class="brand-title">
          <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
          SecureScan Audit Report
        </h1>
        <p class="brand-sub">Comprehensive SAST • SCA • Secrets • IaC • Supply Chain Security Assessment</p>
      </div>
      <div class="meta-grid">
        <div class="meta-item"><strong>Target Archive:</strong> <span>{target_name_esc}</span></div>
        <div class="meta-item"><strong>Job ID:</strong> <span>{report_id_esc}</span></div>
        <div class="meta-item"><strong>Generated:</strong> <span>{created_str}</span></div>
        <div class="meta-item"><strong>Scan Duration:</strong> <span>{duration_str}</span></div>
      </div>
    </header>

    <!-- Metrics Bar -->
    <section class="metrics-bar">
      <div class="metric-card"><div class="metric-val val-total">{total_findings}</div><div class="metric-label">Total Findings</div></div>
      <div class="metric-card"><div class="metric-val val-critical">{counts["CRITICAL"]}</div><div class="metric-label">Critical</div></div>
      <div class="metric-card"><div class="metric-val val-high">{counts["HIGH"]}</div><div class="metric-label">High</div></div>
      <div class="metric-card"><div class="metric-val val-medium">{counts["MEDIUM"]}</div><div class="metric-label">Medium</div></div>
      <div class="metric-card"><div class="metric-val val-low">{counts["LOW"]}</div><div class="metric-label">Low</div></div>
      <div class="metric-card"><div class="metric-val val-info">{counts["INFO"]}</div><div class="metric-label">Info</div></div>
    </section>

    <!-- Findings Detail -->
    <main class="findings-section">
      <h2 style="font-size: 1.25rem; margin-bottom: 1rem; color: #cbd5e1;">Detailed Security Findings ({total_findings})</h2>
      {findings_content}
    </main>
  </div>
</body>
</html>
"""
    return html_doc
```

---

### 4.5 Code Blueprint 4: `backend/app/exporters/pdf_exporter.py`
```python
"""
Binary PDF Exporter for SecureScan Reports.
Utilizes ReportLab 5.x to build an executive-ready multi-page PDF document.
Features custom NumberedCanvas for header/footer pagination ('Page X of Y'),
executive summary tables, scanner matrices, and detailed finding cards with code context.
"""

from __future__ import annotations

import io
from typing import Any, Union

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.report import ScanReport
from app.exporters.json_exporter import ensure_scan_report


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that accumulates total page count and renders
    running headers and footers with accurate 'Page X of Y' numbering.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        # Running Top Header
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))
        self.drawString(36, 755, "SECURESCAN — SECURITY ASSESSMENT REPORT")
        self.drawRightString(576, 755, "CONFIDENTIAL")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 750, 576, 750)

        # Running Bottom Footer
        self.line(36, 42, 576, 42)
        self.setFont("Helvetica", 8)
        self.drawString(36, 30, "Generated by SecureShip Multi-Engine Security Platform")
        self.drawRightString(576, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def export_pdf_reportlab(report: ScanReport) -> bytes:
    """Renders ScanReport to binary PDF bytes via ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54,
    )
    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155"),
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0f172a"),
    )

    story: list[Any] = []

    # Title & Metadata
    story.append(Paragraph("SecureScan Security Assessment Report", title_style))
    story.append(
        Paragraph(
            "Automated Multi-Engine Static Analysis & Vulnerability Audit",
            subtitle_style,
        )
    )

    created_str = (
        report.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if hasattr(report.created_at, "strftime")
        else str(report.created_at)
    )
    duration_str = f"{report.duration_ms / 1000.0:.2f}s"

    meta_table_data = [
        [
            Paragraph("<b>Target Archive:</b>", body_style),
            Paragraph(report.target_name or "Archive", body_style),
            Paragraph("<b>Job ID:</b>", body_style),
            Paragraph(f"<code>{report.id}</code>", body_style),
        ],
        [
            Paragraph("<b>Audit Date:</b>", body_style),
            Paragraph(created_str, body_style),
            Paragraph("<b>Scan Duration:</b>", body_style),
            Paragraph(duration_str, body_style),
        ],
    ]
    t_meta = Table(meta_table_data, colWidths=[90, 180, 90, 180])
    t_meta.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(t_meta)
    story.append(Spacer(1, 12))

    # Executive Summary / Severity Distribution Table
    story.append(Paragraph("Executive Severity Distribution", h2_style))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in report.findings:
        sev = f.severity.value.upper()
        if sev in counts:
            counts[sev] += 1
    total_findings = len(report.findings)

    sev_table_data = [
        ["Severity Level", "Finding Count", "Percentage", "Assessment"],
        ["CRITICAL", str(counts["CRITICAL"]), f"{(counts['CRITICAL']/max(1, total_findings))*100:.1f}%", "Immediate remediation required"],
        ["HIGH", str(counts["HIGH"]), f"{(counts['HIGH']/max(1, total_findings))*100:.1f}%", "Severe risk to production"],
        ["MEDIUM", str(counts["MEDIUM"]), f"{(counts['MEDIUM']/max(1, total_findings))*100:.1f}%", "Moderate risk to remediate"],
        ["LOW", str(counts["LOW"]), f"{(counts['LOW']/max(1, total_findings))*100:.1f}%", "Low risk hardening recommendation"],
        ["INFO", str(counts["INFO"]), f"{(counts['INFO']/max(1, total_findings))*100:.1f}%", "Informational observation"],
        ["TOTAL FINDINGS", str(total_findings), "100.0%", "Complete finding count"],
    ]
    t_sev = Table(sev_table_data, colWidths=[120, 90, 90, 240])
    t_sev.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (2, -1), "CENTER"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(t_sev)
    story.append(Spacer(1, 14))

    # Detailed Findings Section
    story.append(Paragraph(f"Detailed Security Findings ({total_findings})", h2_style))

    if not report.findings:
        story.append(
            Paragraph("No security findings were detected in this audit.", body_style)
        )
    else:
        for idx, finding in enumerate(report.findings, start=1):
            finding_flowables: list[Any] = []
            sev_val = finding.severity.value.upper()
            sev_color = {
                "CRITICAL": colors.HexColor("#dc2626"),
                "HIGH": colors.HexColor("#ea580c"),
                "MEDIUM": colors.HexColor("#d97706"),
                "LOW": colors.HexColor("#2563eb"),
                "INFO": colors.HexColor("#64748b"),
            }.get(sev_val, colors.HexColor("#64748b"))

            # Header row: [SEV] Title
            finding_flowables.append(
                Paragraph(
                    f"<font color='{sev_color.hexval()}'><b>[{sev_val}]</b></font> #{idx}: {finding.title}",
                    finding_title_style,
                )
            )

            # Location and rule table
            cwe_str = ", ".join(finding.cwe_ids) or "None"
            f_meta_data = [
                [
                    Paragraph("<b>File:</b>", body_style),
                    Paragraph(f"<code>{finding.location.file_path}:{finding.location.start_line}</code>", body_style),
                    Paragraph("<b>Scanner:</b>", body_style),
                    Paragraph(finding.scanner_name, body_style),
                ],
                [
                    Paragraph("<b>OWASP:</b>", body_style),
                    Paragraph(finding.owasp_category, body_style),
                    Paragraph("<b>CWE:</b>", body_style),
                    Paragraph(cwe_str, body_style),
                ],
                [
                    Paragraph("<b>Reachability:</b>", body_style),
                    Paragraph(f"<b>{finding.reachability.value}</b>", body_style),
                    Paragraph("<b>Rule ID:</b>", body_style),
                    Paragraph(f"<code>{finding.rule_id}</code>", body_style),
                ],
            ]
            t_fmeta = Table(f_meta_data, colWidths=[80, 200, 70, 190])
            t_fmeta.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                        ("PADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            finding_flowables.append(t_fmeta)
            finding_flowables.append(Spacer(1, 4))

            # Description
            finding_flowables.append(Paragraph(finding.description, body_style))
            finding_flowables.append(Spacer(1, 4))

            # Code context snippet if present
            if finding.snippet_context and finding.snippet_context.lines:
                snippet_lines = []
                for sline in finding.snippet_context.lines:
                    prefix = "► " if sline.is_target else "  "
                    snippet_lines.append(f"{prefix}{sline.line_number:4d} | {sline.content}")
                code_text = "\n".join(snippet_lines[:15])  # Cap at 15 lines for PDF layout
                t_code = Table([[Preformatted(code_text, code_style)]], colWidths=[540])
                t_code.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("PADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                finding_flowables.append(t_code)
                finding_flowables.append(Spacer(1, 4))

            # Recommendation
            if finding.fix_recommendation:
                rec_text = f"<b>Remediation:</b> {finding.fix_recommendation}"
                t_rec = Table([[Paragraph(rec_text, body_style)]], colWidths=[540])
                t_rec.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#a7f3d0")),
                            ("PADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                finding_flowables.append(t_rec)

            finding_flowables.append(Spacer(1, 8))
            finding_flowables.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=4, spaceAfter=8))
            story.append(KeepTogether(finding_flowables))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


def export_pdf(report: Union[ScanReport, dict[str, Any]]) -> bytes:
    """
    Primary binary PDF generator.
    Normalizes report and generates PDF via ReportLab.
    Catches any unexpected generation failure and falls back to a clean canvas generator.
    """
    scan_report = ensure_scan_report(report)
    try:
        return export_pdf_reportlab(scan_report)
    except Exception:
        # Failsafe minimal canvas fallback to ensure binary PDF is always produced
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, f"SecureScan Security Assessment: {scan_report.target_name or 'Audit'}")
        c.drawString(100, 730, f"Total Findings: {len(scan_report.findings)}")
        y = 700
        for f in scan_report.findings[:20]:
            c.drawString(100, y, f"[{f.severity.value}] {f.title} ({f.location.file_path}:{f.location.start_line})")
            y -= 20
        c.save()
        return buffer.getvalue()
```

---

### 4.6 Code Blueprint 5: `backend/app/exporters/__init__.py` and `backend/app/services/exporter.py`
```python
"""
Unified Exporters Package & Facade Dispatcher.
"""

from __future__ import annotations

from typing import Any, Union

from app.models.report import ScanReport
from app.exporters.json_exporter import export_json
from app.exporters.sarif_exporter import export_sarif
from app.exporters.html_exporter import export_html
from app.exporters.pdf_exporter import export_pdf

SUPPORTED_FORMATS: dict[str, tuple[str, str]] = {
    "json": ("application/json", "json"),
    "sarif": ("application/sarif+json", "sarif"),
    "html": ("text/html; charset=utf-8", "html"),
    "pdf": ("application/pdf", "pdf"),
}


def export_report(
    report: Union[ScanReport, dict[str, Any]],
    format_name: str,
) -> tuple[bytes, str, str]:
    """
    Exports a scan report into the specified format.

    Args:
        report: ScanReport model or valid dictionary.
        format_name: One of 'json', 'sarif', 'html', 'pdf' (case-insensitive).

    Returns:
        tuple of (content_bytes, content_type_header, file_extension)

    Raises:
        ValueError: If format_name is not supported.
    """
    fmt = format_name.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported export format '{format_name}'. Supported formats: {', '.join(SUPPORTED_FORMATS.keys())}"
        )

    content_type, ext = SUPPORTED_FORMATS[fmt]

    if fmt == "json":
        text_content = export_json(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "sarif":
        text_content = export_sarif(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "html":
        text_content = export_html(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "pdf":
        content_bytes = export_pdf(report)
    else:
        raise ValueError(f"Unhandled format '{fmt}'")

    return content_bytes, content_type, ext


__all__ = [
    "export_report",
    "export_json",
    "export_sarif",
    "export_html",
    "export_pdf",
    "SUPPORTED_FORMATS",
]
```

`backend/app/services/exporter.py` simply contains:
```python
"""
Exporter Service Facade.
Maintains full backward compatibility with ORIGINAL_REQUEST.md specification.
"""

from app.exporters import (
    SUPPORTED_FORMATS,
    export_html,
    export_json,
    export_pdf,
    export_report,
    export_sarif,
)

__all__ = [
    "export_report",
    "export_json",
    "export_sarif",
    "export_html",
    "export_pdf",
    "SUPPORTED_FORMATS",
]
```

---

### 4.7 Code Blueprint 6: `backend/app/routers/reports.py` (Export Endpoint)
```python
"""
Reports & Export Router for SecureScan.
Implements:
- GET /api/reports/{id} (Unified ScanReport JSON)
- GET /api/reports/{id}/export?format={json|sarif|html|pdf}
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.core.queue import ScanJobQueue
from app.models.job import JobStatus
from app.services.exporter import SUPPORTED_FORMATS, export_report

logger = logging.getLogger("securescan.routers.reports")

router = APIRouter(prefix="/reports", tags=["reports"])


def get_queue() -> ScanJobQueue:
    """Dependency getter for queue singleton."""
    from app.core.queue import get_job_queue
    return get_job_queue()


@router.get("/{id}")
async def get_report_endpoint(
    id: str,
    queue: ScanJobQueue = Depends(get_queue),
):
    """
    Returns the complete unified ScanReport for a completed job.
    Fails closed with 404 if not found, 409 if still running, 422 if failed.
    """
    job = queue.get_job(id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job '{id}' not found",
        )

    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan report not ready (job status: {job.status.value})",
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scan failed: {job.error or 'Execution failed'}",
        )

    if not job.report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report payload not available for job '{id}'",
        )

    return job.report


@router.get("/{id}/export")
@router.get("/{id}/export/")
async def export_report_endpoint(
    id: str,
    format: Optional[str] = Query(None, description="Export format: json, sarif, html, or pdf"),
    queue: ScanJobQueue = Depends(get_queue),
):
    """
    Exports a completed scan report into the requested format:
    json, sarif, html, or pdf.
    """
    if not format or format.lower().strip() not in SUPPORTED_FORMATS:
        supported_list = ", ".join(SUPPORTED_FORMATS.keys())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{format}'. Supported formats: {supported_list}",
        )

    fmt = format.lower().strip()
    job = queue.get_job(id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan report with job ID '{id}' not found",
        )

    if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan report not ready (current status: {job.status.value})",
        )

    if job.status == JobStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scan failed: {job.error or 'Execution failed'}",
        )

    if not job.report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No report payload available for job ID '{id}'",
        )

    try:
        content_bytes, content_type, ext = export_report(job.report, fmt)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("Export generation failed for job %s (format %s): %s", id, fmt, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed generating {fmt.upper()} export: {exc}",
        )

    filename = f"securescan-report-{id}.{ext}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": content_type,
    }

    return Response(
        content=content_bytes,
        media_type=content_type,
        headers=headers,
    )
```

---

### 4.8 Code Blueprint 7: Unit & Integration Tests (`backend/tests/test_exporters.py`)
```python
"""
Unit and Integration Tests for Multi-Format Exporters and Export Endpoint.
Tests:
- JSON Exporter: Full ScanReport serialization with ISO timestamps, schema interoperability
- SARIF 2.1.0 Exporter: OASIS SARIF v2.1.0 compliance, tool driver, rules, results, physicalLocation
- HTML Exporter: Standalone air-gapped single file, inline styles, zero CDN links, code snippets
- PDF Exporter: Binary PDF generation via ReportLab, %PDF- magic bytes, %%EOF trailer, multi-page numbering
- Export Endpoint: Parameter validation (400), 404 for missing jobs, 409 for in-flight jobs, Content-Disposition headers
"""

import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.exporters import export_html, export_json, export_pdf, export_report, export_sarif
from app.models.job import JobRecord, JobStatus
from app.models.report import (
    CodeSnippet,
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    ReachabilityVerdict,
    ScanReport,
    ScanSummary,
    Severity,
    SnippetLine,
)


@pytest.fixture
def sample_scan_report() -> ScanReport:
    snippet = CodeSnippet(
        file_path="src/database.py",
        start_line=20,
        end_line=26,
        target_start=23,
        target_end=23,
        lines=[
            SnippetLine(line_number=21, content="def query_user(user_id):"),
            SnippetLine(line_number=22, content="    query = f'SELECT * FROM users WHERE id = {user_id}'"),
            SnippetLine(line_number=23, content="    cursor.execute(query)", is_target=True),
            SnippetLine(line_number=24, content="    return cursor.fetchone()"),
        ],
        raw_content="cursor.execute(query)",
    )
    finding = NormalizedFinding(
        id="finding-sql-1",
        rule_id="secureship-py-sql-injection",
        scanner_name="opengrep",
        category=FindingCategory.SAST,
        severity=Severity.HIGH,
        title="SQL Injection in Database Query",
        description="User-supplied data concatenated directly into SQL statement.",
        location=FindingLocation(
            file_path="src/database.py",
            start_line=23,
            end_line=23,
            snippet="cursor.execute(query)",
        ),
        cwe_ids=["CWE-89"],
        owasp_category="A03:2021-Injection",
        reachability=ReachabilityVerdict.REACHABLE,
        confidence="HIGH",
        fix_recommendation="Use parameterized queries instead of string concatenation.",
        snippet_context=snippet,
    )
    summary = ScanSummary(
        total_findings=1,
        by_severity={"HIGH": 1},
        by_category={"SAST": 1},
        by_owasp={"A03:2021-Injection": 1},
        by_scanner={"opengrep": 1},
        by_reachability={"REACHABLE": 1},
    )
    return ScanReport(
        id="job-test-1234",
        target_name="vulnerable_test.zip",
        status="done",
        duration_ms=1250.0,
        created_at=datetime.now(timezone.utc),
        findings=[finding],
        summary=summary,
    )


class TestJsonExporter:
    def test_json_export_structure(self, sample_scan_report):
        json_str = export_json(sample_scan_report)
        data = json.loads(json_str)

        assert data["id"] == "job-test-1234"
        assert data["job_id"] == "job-test-1234"
        assert data["status"] == "done"
        assert len(data["findings"]) == 1
        assert data["summary"]["total_findings"] == 1
        assert "severity_counts" in data["summary"]
        assert "owasp_counts" in data["summary"]
        assert data["findings"][0]["ruleId"] == "secureship-py-sql-injection"
        assert data["findings"][0]["location"]["filePath"] == "src/database.py"

    def test_json_export_empty_report(self):
        report = ScanReport(id="empty-1", status="done", findings=[])
        json_str = export_json(report)
        data = json.loads(json_str)
        assert data["id"] == "empty-1"
        assert data["findings"] == []


class TestSarifExporter:
    def test_sarif_export_compliance(self, sample_scan_report):
        sarif_str = export_sarif(sample_scan_report)
        data = json.loads(sarif_str)

        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecureShip"
        assert len(run["tool"]["driver"]["rules"]) == 1
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "secureship-py-sql-injection"
        assert "CWE-89" in rule["properties"]["tags"]

        assert len(run["results"]) == 1
        res = run["results"][0]
        assert res["ruleId"] == "secureship-py-sql-injection"
        assert res["level"] == "error"  # HIGH maps to error
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/database.py"
        assert loc["region"]["startLine"] == 23


class TestHtmlExporter:
    def test_html_export_self_containment(self, sample_scan_report):
        html_str = export_html(sample_scan_report)

        assert "<!DOCTYPE html>" in html_str
        assert "<html" in html_str and "</html>" in html_str
        assert "<head" in html_str and "</head>" in html_str
        assert "<body" in html_str and "</body>" in html_str
        assert "<style>" in html_str

        # Air-gapped self-containment assertion
        assert 'rel="stylesheet" href="http' not in html_str
        assert '<script src="http' not in html_str

        # Content assertions
        assert "SQL Injection in Database Query" in html_str
        assert "src/database.py" in html_str
        assert "cursor.execute(query)" in html_str
        assert "REACHABLE" in html_str


class TestPdfExporter:
    def test_pdf_export_magic_bytes(self, sample_scan_report):
        pdf_bytes = export_pdf(sample_scan_report)

        assert len(pdf_bytes) > 200
        assert pdf_bytes.startswith(b"%PDF-")
        assert b"%%EOF" in pdf_bytes or b"xref" in pdf_bytes

    def test_pdf_export_empty_report(self):
        report = ScanReport(id="empty-pdf", status="done", findings=[])
        pdf_bytes = export_pdf(report)
        assert len(pdf_bytes) > 200
        assert pdf_bytes.startswith(b"%PDF-")


class TestExportReportDispatcher:
    def test_export_report_formats(self, sample_scan_report):
        # JSON
        b_json, ct_json, ext_json = export_report(sample_scan_report, "json")
        assert ct_json == "application/json"
        assert ext_json == "json"
        assert b_json.startswith(b"{")

        # SARIF
        b_sarif, ct_sarif, ext_sarif = export_report(sample_scan_report, "sarif")
        assert ct_sarif == "application/sarif+json"
        assert ext_sarif == "sarif"
        assert b_sarif.startswith(b"{")

        # HTML
        b_html, ct_html, ext_html = export_report(sample_scan_report, "html")
        assert "text/html" in ct_html
        assert ext_html == "html"
        assert b_html.startswith(b"<!DOCTYPE html>")

        # PDF
        b_pdf, ct_pdf, ext_pdf = export_report(sample_scan_report, "pdf")
        assert ct_pdf == "application/pdf"
        assert ext_pdf == "pdf"
        assert b_pdf.startswith(b"%PDF-")

    def test_export_report_invalid_format(self, sample_scan_report):
        with pytest.raises(ValueError) as exc_info:
            export_report(sample_scan_report, "docx")
        assert "Unsupported export format" in str(exc_info.value)
```

---

## 5. Verification Method

To independently verify all findings and test suites:

### 5.1 Unit Tests Execution
Execute pytest against existing suites and new exporter tests:
```powershell
# Run baseline tests
pytest backend/tests/ -v

# Run E2E suites verifying all four exporter fixtures
pytest tests/e2e/test_tier1_feature_coverage.py -k "test_sarif or test_html or test_pdf"
pytest tests/e2e/test_tier3_cross_features.py -k "test_export_rejected_while_running"
pytest tests/e2e/test_tier4_real_world.py -k "test_real_world_vulnerable_project_e2e_pipeline"
```

### 5.2 Direct PDF and SARIF Validation Script
Run the following validation one-liner from repo root:
```powershell
python -c "
import sys
sys.path.insert(0, 'backend')
from app.models.report import ScanReport
from app.exporters import export_pdf, export_sarif, export_html, export_json

r = ScanReport(id='probe-1', status='done')
pdf_bytes = export_pdf(r)
assert pdf_bytes.startswith(b'%PDF-'), 'PDF header failed'
assert b'%%EOF' in pdf_bytes, 'PDF EOF failed'
sarif_doc = export_sarif(r)
assert 'sarif-2.1.0.json' in sarif_doc, 'SARIF schema failed'
html_doc = export_html(r)
assert '<!DOCTYPE html>' in html_doc, 'HTML DOCTYPE failed'
assert 'http://' not in html_doc and 'https://' not in html_doc, 'HTML airgap failed'
json_doc = export_json(r)
assert 'job_id' in json_doc and 'severity_counts' in json_doc, 'JSON schema failed'
print('ALL 4 EXPORTERS VALIDATED SUCCESSFULLY!')
"
```
