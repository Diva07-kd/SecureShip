"""
OASIS SARIF 2.1.0 Exporter for SecureScan.
Transforms unified ScanReport into valid OASIS SARIF v2.1.0 schema format.
Specification: https://json.schemastore.org/sarif-2.1.0.json
"""

from __future__ import annotations

import json
from typing import Any

from app.exporters.json_exporter import normalize_report_dict
from app.models.report import ScanReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _map_severity_to_sarif_level(severity: Any) -> str:
    if hasattr(severity, "value"):
        sev = str(severity.value).upper()
    else:
        sev = str(severity).replace("Severity.", "").upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    if sev in ("LOW", "INFO"):
        return "note"
    return "note"


def _safe_int(val: Any, default: int = 1) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default


def generate_sarif_dict(report: ScanReport | dict[str, Any]) -> dict[str, Any]:
    """
    Generates a dictionary compliant with OASIS SARIF 2.1.0 JSON Schema.
    """
    norm = normalize_report_dict(report)
    findings = norm.get("findings", [])

    rules_dict: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for f in findings:
        rule_id = f.get("rule_id") or f.get("ruleId") or f.get("id") or "UNKNOWN_RULE"
        title = f.get("title") or rule_id
        desc = f.get("description") or title
        sev = f.get("severity", "MEDIUM")
        level = _map_severity_to_sarif_level(sev)

        # Build rule entry if not present
        if rule_id not in rules_dict:
            tags: list[str] = []
            for cwe in (f.get("cwe_ids") or []):
                if cwe is not None and str(cwe).strip():
                    tags.append(str(cwe).strip())
            owasp = f.get("owasp_category")
            if owasp and owasp != "A00:2021-Other/Unknown":
                tags.append(str(owasp))
            cat = f.get("category")
            if cat:
                tags.append(str(cat.value if hasattr(cat, "value") else cat))

            rules_dict[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": tags,
                    "precision": "high",
                },
            }
            fix_rec = f.get("fix_recommendation")
            if fix_rec:
                rules_dict[rule_id]["help"] = {
                    "text": fix_rec,
                    "markdown": fix_rec,
                }

        # Build location
        loc = f.get("location") or {}
        if not isinstance(loc, dict):
            loc = {}
        file_path = loc.get("file_path") or loc.get("filePath") or "unknown"
        start_line = max(1, _safe_int(loc.get("start_line") or loc.get("startLine"), default=1))
        end_line = max(start_line, _safe_int(loc.get("end_line") or loc.get("endLine"), default=start_line))
        start_col = max(1, _safe_int(loc.get("start_column") or loc.get("startColumn"), default=1))
        end_col_raw = loc.get("end_column") or loc.get("endColumn")
        end_col = _safe_int(end_col_raw, default=0) if end_col_raw is not None else None

        # OASIS SARIF 2.1.0 §3.30.2: When startLine == endLine, endColumn SHALL be >= startColumn
        if start_line == end_line and end_col is not None and end_col > 0:
            end_col = max(start_col, end_col)

        region: dict[str, Any] = {
            "startLine": start_line,
            "endLine": end_line,
            "startColumn": start_col,
        }
        if end_col and end_col > 0:
            region["endColumn"] = end_col

        snippet_data = f.get("snippet") or f.get("snippet_context")
        if snippet_data and isinstance(snippet_data, dict):
            raw = snippet_data.get("raw_content") or snippet_data.get("rawContent")
            if raw:
                region["snippet"] = {"text": raw}

        physical_loc = {
            "artifactLocation": {
                "uri": file_path.replace("\\", "/").lstrip("/"),
                "uriBaseId": "%SRCROOT%",
            },
            "region": region,
        }

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": desc},
            "locations": [{"physicalLocation": physical_loc}],
            "properties": {
                "id": f.get("id"),
                "severity": str(sev),
                "confidence": f.get("confidence", "HIGH"),
                "reachability": str(f.get("reachability", "UNKNOWN")),
                "scanner": f.get("scanner_name", "secureship"),
                "cweIds": [str(c) for c in (f.get("cwe_ids") or []) if c is not None and str(c).strip()],
                "owaspCategory": f.get("owasp_category", ""),
            },
        }
        results_list.append(result_entry)

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureShip",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/secureship/secureship",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list,
            }
        ],
    }

    return sarif_doc


def export_sarif(report: ScanReport | dict[str, Any], indent: int = 2) -> str:
    """
    Exports a scan report to formatted SARIF 2.1.0 JSON string.
    """
    sarif_data = generate_sarif_dict(report)
    return json.dumps(sarif_data, indent=indent, default=str)
