"""
Native JSON Report Exporter for SecureScan.
Serializes unified scan reports to standardized JSON format with bidirectional
compatibility for job_id/id and severity_counts/by_severity.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.models.report import ScanReport


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        f = float(val)
        if f != f or f == float("inf") or f == float("-inf"):
            return default
        return f
    except (ValueError, TypeError, OverflowError):
        return default


def normalize_report_dict(report: ScanReport | dict[str, Any]) -> dict[str, Any]:
    """
    Normalizes report into a dictionary conforming to both project and e2e schema requirements.
    Ensures bidirectional camelCase (for frontend) and snake_case (for python tests)
    property aliases exist on all report, summary, finding, location, and snippet objects.
    """
    if report is None:
        data: dict[str, Any] = {}
    elif isinstance(report, ScanReport):
        data = report.model_dump(mode="json", by_alias=False)
    elif hasattr(report, "model_dump"):
        data = report.model_dump(mode="json", by_alias=False)
    elif hasattr(report, "dict") and callable(report.dict):
        data = report.dict()
    elif isinstance(report, dict):
        data = dict(report)
    else:
        try:
            data = dict(report)
        except Exception:
            data = {}

    # Ensure job_id and id interoperability
    report_id = data.get("job_id") or data.get("id") or "scan-report"
    data["job_id"] = str(report_id)
    data["id"] = str(report_id)

    # Root report bidirectional aliases: durationMs, targetName, createdAt, completedAt
    duration_ms = _safe_float(
        data.get("duration_ms") if data.get("duration_ms") is not None else data.get("durationMs", 0.0),
        0.0,
    )
    data["duration_ms"] = duration_ms
    data["durationMs"] = duration_ms

    target_name = data.get("target_name") if data.get("target_name") is not None else data.get("targetName")
    data["target_name"] = str(target_name) if target_name is not None else None
    data["targetName"] = str(target_name) if target_name is not None else None

    created_at = data.get("created_at") if data.get("created_at") is not None else data.get("createdAt")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    data["created_at"] = created_at
    data["createdAt"] = created_at

    completed_at = data.get("completed_at") if data.get("completed_at") is not None else data.get("completedAt")
    if isinstance(completed_at, datetime):
        completed_at = completed_at.isoformat()
    data["completed_at"] = completed_at
    data["completedAt"] = completed_at

    finished_at = data.get("finished_at") if data.get("finished_at") is not None else data.get("finishedAt")
    if finished_at is None and completed_at is not None:
        finished_at = completed_at
    if isinstance(finished_at, datetime):
        finished_at = finished_at.isoformat()
    if finished_at is not None:
        data["finished_at"] = finished_at
        data["finishedAt"] = finished_at

    # Normalize summary fields
    raw_summary = data.get("summary")
    if raw_summary is None:
        summary: dict[str, Any] = {}
    elif hasattr(raw_summary, "model_dump"):
        summary = raw_summary.model_dump(mode="json", by_alias=False)
    elif hasattr(raw_summary, "dict") and callable(raw_summary.dict):
        summary = raw_summary.dict()
    elif isinstance(raw_summary, dict):
        summary = dict(raw_summary)
    else:
        try:
            summary = dict(raw_summary)
        except Exception:
            summary = {}

    raw_by_sev = (
        summary.get("by_severity")
        or summary.get("bySeverity")
        or summary.get("severity_counts")
        or summary.get("severityCounts")
        or {}
    )
    if not isinstance(raw_by_sev, dict):
        try:
            raw_by_sev = dict(raw_by_sev)
        except Exception:
            raw_by_sev = {}

    by_sev: dict[str, int] = {}
    for k, v in raw_by_sev.items():
        k_str = str(k).upper()
        by_sev[k_str] = _safe_int(v, 0)
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if s not in by_sev:
            by_sev[s] = 0

    by_owasp = (
        summary.get("by_owasp")
        or summary.get("byOwasp")
        or summary.get("owasp_counts")
        or summary.get("owaspCounts")
        or {}
    )
    if not isinstance(by_owasp, dict):
        try:
            by_owasp = dict(by_owasp)
        except Exception:
            by_owasp = {}

    by_scanner = (
        summary.get("by_scanner")
        or summary.get("byScanner")
        or summary.get("scanner_counts")
        or summary.get("scannerCounts")
        or {}
    )
    if not isinstance(by_scanner, dict):
        try:
            by_scanner = dict(by_scanner)
        except Exception:
            by_scanner = {}

    by_reachability = (
        summary.get("by_reachability")
        or summary.get("byReachability")
        or summary.get("reachability_counts")
        or summary.get("reachabilityCounts")
        or {}
    )
    if not isinstance(by_reachability, dict):
        try:
            by_reachability = dict(by_reachability)
        except Exception:
            by_reachability = {}

    by_category = (
        summary.get("by_category")
        or summary.get("byCategory")
        or summary.get("category_counts")
        or summary.get("categoryCounts")
        or {}
    )
    if not isinstance(by_category, dict):
        try:
            by_category = dict(by_category)
        except Exception:
            by_category = {}

    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []

    raw_total = summary.get("total_findings")
    if raw_total is None:
        raw_total = summary.get("totalFindings")
    total = _safe_int(raw_total, default=len(findings))
    if total == 0 and len(findings) > 0:
        total = len(findings)

    # Backfill missing summary breakdowns from findings if needed
    if all(v == 0 for v in by_sev.values()) and findings:
        for f in findings:
            sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev or "INFO").upper()
            if sev_val in by_sev:
                by_sev[sev_val] += 1
            else:
                by_sev[sev_val] = 1

    if not by_owasp and findings:
        for f in findings:
            ow = (
                f.get("owasp_category") or f.get("owaspCategory")
                if isinstance(f, dict)
                else getattr(f, "owasp_category", None)
            )
            if ow:
                ow_str = str(ow)
                by_owasp[ow_str] = by_owasp.get(ow_str, 0) + 1

    if not by_scanner and findings:
        for f in findings:
            sc = (
                f.get("scanner_name") or f.get("scannerName")
                if isinstance(f, dict)
                else getattr(f, "scanner_name", None)
            )
            if sc:
                sc_str = str(sc)
                by_scanner[sc_str] = by_scanner.get(sc_str, 0) + 1

    if not by_reachability and findings:
        for f in findings:
            r = (
                f.get("reachability")
                if isinstance(f, dict)
                else getattr(f, "reachability", None)
            )
            r_val = r.value if hasattr(r, "value") else str(r or "UNKNOWN").upper()
            by_reachability[r_val] = by_reachability.get(r_val, 0) + 1

    if not by_category and findings:
        for f in findings:
            c = (
                f.get("category")
                if isinstance(f, dict)
                else getattr(f, "category", None)
            )
            c_val = c.value if hasattr(c, "value") else str(c or "SAST").upper()
            by_category[c_val] = by_category.get(c_val, 0) + 1

    summary["total_findings"] = total
    summary["totalFindings"] = total
    summary["severity_counts"] = by_sev
    summary["severityCounts"] = by_sev
    summary["by_severity"] = by_sev
    summary["bySeverity"] = by_sev
    summary["owasp_counts"] = by_owasp
    summary["owaspCounts"] = by_owasp
    summary["by_owasp"] = by_owasp
    summary["byOwasp"] = by_owasp
    summary["by_scanner"] = by_scanner
    summary["byScanner"] = by_scanner
    summary["scanner_counts"] = by_scanner
    summary["scannerCounts"] = by_scanner
    summary["by_reachability"] = by_reachability
    summary["byReachability"] = by_reachability
    summary["reachability_counts"] = by_reachability
    summary["reachabilityCounts"] = by_reachability
    summary["by_category"] = by_category
    summary["byCategory"] = by_category
    summary["category_counts"] = by_category
    summary["categoryCounts"] = by_category
    data["summary"] = summary

    # Normalize scanners list
    scanners = data.get("scanners") or []
    normalized_scanners = []
    for sc in scanners:
        if isinstance(sc, dict):
            sc_dict = dict(sc)
        elif hasattr(sc, "model_dump"):
            sc_dict = sc.model_dump(mode="json", by_alias=False)
        elif hasattr(sc, "dict") and callable(sc.dict):
            sc_dict = sc.dict()
        else:
            try:
                sc_dict = dict(sc)
            except Exception:
                sc_dict = {}

        s_dur = _safe_float(
            sc_dict.get("duration_ms") if sc_dict.get("duration_ms") is not None else sc_dict.get("durationMs", 0.0),
            0.0,
        )
        sc_dict["duration_ms"] = s_dur
        sc_dict["durationMs"] = s_dur

        raw_cnt = sc_dict.get("raw_finding_count")
        if raw_cnt is None:
            raw_cnt = sc_dict.get("rawFindingCount")
        if raw_cnt is None:
            raw_cnt = sc_dict.get("findings_count")
        if raw_cnt is None:
            raw_cnt = sc_dict.get("findingsCount", 0)
        s_cnt = _safe_int(raw_cnt, 0)

        sc_dict["raw_finding_count"] = s_cnt
        sc_dict["rawFindingCount"] = s_cnt
        sc_dict["findings_count"] = s_cnt
        sc_dict["findingsCount"] = s_cnt

        s_err = sc_dict.get("error_message") if sc_dict.get("error_message") is not None else sc_dict.get("errorMessage")
        sc_dict["error_message"] = s_err
        sc_dict["errorMessage"] = s_err
        normalized_scanners.append(sc_dict)
    data["scanners"] = normalized_scanners

    # Normalize findings locations and snippets
    normalized_findings = []
    for f in findings:
        if isinstance(f, dict):
            f_dict = dict(f)
        elif hasattr(f, "model_dump"):
            f_dict = f.model_dump(mode="json", by_alias=False)
        elif hasattr(f, "dict") and callable(f.dict):
            f_dict = f.dict()
        else:
            try:
                f_dict = dict(f)
            except Exception:
                continue

        # 1. Location
        raw_loc = f_dict.get("location") or {}
        if hasattr(raw_loc, "model_dump"):
            loc = raw_loc.model_dump(mode="json", by_alias=False)
        elif hasattr(raw_loc, "dict") and callable(raw_loc.dict):
            loc = raw_loc.dict()
        elif isinstance(raw_loc, dict):
            loc = dict(raw_loc)
        else:
            loc = {}

        file_p = str(loc.get("file_path") or loc.get("filePath") or "")
        start_l = max(1, _safe_int(loc.get("start_line") or loc.get("startLine"), default=1))
        end_l_raw = loc.get("end_line") if loc.get("end_line") is not None else loc.get("endLine")
        end_l = max(start_l, _safe_int(end_l_raw, default=start_l))

        loc["file_path"] = file_p
        loc["filePath"] = file_p
        loc["start_line"] = start_l
        loc["startLine"] = start_l
        loc["end_line"] = end_l
        loc["endLine"] = end_l
        f_dict["location"] = loc

        # 2. Snippet normalization
        snippet = (
            f_dict.get("snippet_context")
            or f_dict.get("snippetContext")
            or f_dict.get("snippet")
        )
        if snippet:
            if hasattr(snippet, "model_dump"):
                s_dict = snippet.model_dump(mode="json", by_alias=False)
            elif hasattr(snippet, "dict") and callable(snippet.dict):
                s_dict = snippet.dict()
            elif isinstance(snippet, dict):
                s_dict = dict(snippet)
            elif isinstance(snippet, str):
                s_dict = {
                    "file_path": file_p,
                    "filePath": file_p,
                    "start_line": start_l,
                    "startLine": start_l,
                    "end_line": end_l,
                    "endLine": end_l,
                    "raw_content": snippet,
                    "rawContent": snippet,
                    "lines": [snippet],
                }
            else:
                s_dict = {
                    "file_path": file_p,
                    "filePath": file_p,
                    "start_line": start_l,
                    "startLine": start_l,
                    "end_line": end_l,
                    "endLine": end_l,
                    "raw_content": str(snippet),
                    "rawContent": str(snippet),
                    "lines": [str(snippet)],
                }

            snip_fp = str(s_dict.get("file_path") or s_dict.get("filePath") or file_p)
            snip_sl = max(1, _safe_int(s_dict.get("start_line") or s_dict.get("startLine"), default=start_l))
            snip_el_raw = s_dict.get("end_line") if s_dict.get("end_line") is not None else s_dict.get("endLine")
            snip_el = max(snip_sl, _safe_int(snip_el_raw, default=end_l))

            snip_ts_raw = s_dict.get("target_start") if s_dict.get("target_start") is not None else s_dict.get("targetStart")
            snip_ts = max(1, _safe_int(snip_ts_raw, default=start_l))
            snip_te_raw = s_dict.get("target_end") if s_dict.get("target_end") is not None else s_dict.get("targetEnd")
            snip_te = max(snip_ts, _safe_int(snip_te_raw, default=end_l))

            snip_raw = str(
                s_dict.get("raw_content")
                if s_dict.get("raw_content") is not None
                else s_dict.get("rawContent", "")
            )

            s_dict["file_path"] = snip_fp
            s_dict["filePath"] = snip_fp
            s_dict["start_line"] = snip_sl
            s_dict["startLine"] = snip_sl
            s_dict["end_line"] = snip_el
            s_dict["endLine"] = snip_el
            s_dict["target_start"] = snip_ts
            s_dict["targetStart"] = snip_ts
            s_dict["target_end"] = snip_te
            s_dict["targetEnd"] = snip_te
            s_dict["raw_content"] = snip_raw
            s_dict["rawContent"] = snip_raw

            raw_lines = s_dict.get("lines")
            if raw_lines is None:
                raw_lines = []
            elif isinstance(raw_lines, (str, bytes)):
                raw_lines = str(raw_lines).splitlines()
            elif isinstance(raw_lines, dict):
                raw_lines = [raw_lines]
            elif not isinstance(raw_lines, (list, tuple)):
                try:
                    raw_lines = list(raw_lines)
                except Exception:
                    raw_lines = [raw_lines]

            if not raw_lines and snip_raw:
                raw_lines = snip_raw.splitlines()

            normalized_lines = []
            for idx, ln in enumerate(raw_lines):
                default_lno = snip_sl + idx

                if hasattr(ln, "model_dump"):
                    ln_dict = ln.model_dump(mode="json", by_alias=False)
                elif hasattr(ln, "dict") and callable(ln.dict):
                    ln_dict = ln.dict()
                elif isinstance(ln, dict):
                    ln_dict = dict(ln)
                elif isinstance(ln, str):
                    ln_dict = {
                        "line_number": default_lno,
                        "lineNumber": default_lno,
                        "content": ln,
                        "is_target": (snip_ts <= default_lno <= snip_te),
                        "isTarget": (snip_ts <= default_lno <= snip_te),
                        "is_vulnerable": (snip_ts <= default_lno <= snip_te),
                        "isVulnerable": (snip_ts <= default_lno <= snip_te),
                    }
                elif isinstance(ln, int) and not isinstance(ln, bool):
                    ln_dict = {
                        "line_number": default_lno,
                        "lineNumber": default_lno,
                        "content": str(ln),
                        "is_target": (snip_ts <= default_lno <= snip_te),
                        "isTarget": (snip_ts <= default_lno <= snip_te),
                        "is_vulnerable": (snip_ts <= default_lno <= snip_te),
                        "isVulnerable": (snip_ts <= default_lno <= snip_te),
                    }
                elif ln is None:
                    ln_dict = {
                        "line_number": default_lno,
                        "lineNumber": default_lno,
                        "content": "",
                        "is_target": False,
                        "isTarget": False,
                        "is_vulnerable": False,
                        "isVulnerable": False,
                    }
                else:
                    ln_dict = {
                        "line_number": default_lno,
                        "lineNumber": default_lno,
                        "content": str(ln),
                        "is_target": (snip_ts <= default_lno <= snip_te),
                        "isTarget": (snip_ts <= default_lno <= snip_te),
                        "is_vulnerable": (snip_ts <= default_lno <= snip_te),
                        "isVulnerable": (snip_ts <= default_lno <= snip_te),
                    }

                raw_lno = (
                    ln_dict.get("line_number")
                    if ln_dict.get("line_number") is not None
                    else (
                        ln_dict.get("lineNumber")
                        if ln_dict.get("lineNumber") is not None
                        else (
                            ln_dict.get("line")
                            if ln_dict.get("line") is not None
                            else ln_dict.get("lno")
                        )
                    )
                )
                if raw_lno is None and ("line_number" not in ln_dict and "lineNumber" not in ln_dict):
                    raw_lno = default_lno

                raw_cnt = (
                    ln_dict.get("content")
                    if ln_dict.get("content") is not None
                    else (
                        ln_dict.get("text")
                        if ln_dict.get("text") is not None
                        else ln_dict.get("code")
                    )
                )
                if raw_cnt is None:
                    raw_cnt = ""

                raw_tgt = (
                    ln_dict.get("is_target")
                    if ln_dict.get("is_target") is not None
                    else (
                        ln_dict.get("isTarget")
                        if ln_dict.get("isTarget") is not None
                        else (
                            ln_dict.get("is_vulnerable")
                            if ln_dict.get("is_vulnerable") is not None
                            else ln_dict.get("isVulnerable")
                        )
                    )
                )
                if raw_tgt is None:
                    parsed_lno = _safe_int(raw_lno, default=0)
                    is_tgt_bool = (snip_ts <= parsed_lno <= snip_te) if (parsed_lno > 0 and snip_ts > 0) else False
                else:
                    is_tgt_bool = bool(raw_tgt)

                ln_dict["line_number"] = raw_lno
                ln_dict["lineNumber"] = raw_lno
                ln_dict["content"] = str(raw_cnt)
                ln_dict["is_target"] = is_tgt_bool
                ln_dict["isTarget"] = is_tgt_bool
                ln_dict["is_vulnerable"] = is_tgt_bool
                ln_dict["isVulnerable"] = is_tgt_bool

                normalized_lines.append(ln_dict)

            s_dict["lines"] = normalized_lines
            f_dict["snippet"] = s_dict
            f_dict["snippet_context"] = s_dict
            f_dict["snippetContext"] = s_dict

        # 3. CWEs and OWASP category null-safety
        raw_cwes = f_dict.get("cwe_ids") if f_dict.get("cwe_ids") is not None else f_dict.get("cweIds")
        clean_cwes: list[str] = []
        if isinstance(raw_cwes, list):
            for cwe in raw_cwes:
                if cwe is not None and str(cwe).strip():
                    clean_cwes.append(str(cwe).strip())
        elif raw_cwes is not None and str(raw_cwes).strip():
            clean_cwes.append(str(raw_cwes).strip())

        raw_owasp = f_dict.get("owasp_category") if f_dict.get("owasp_category") is not None else f_dict.get("owaspCategory")
        clean_owasp = str(raw_owasp or "")

        f_dict["cwe_ids"] = clean_cwes
        f_dict["cweIds"] = clean_cwes
        f_dict["owasp_category"] = clean_owasp
        f_dict["owaspCategory"] = clean_owasp

        # 4. Rule ID and Scanner Name
        rule_id = str(f_dict.get("rule_id") or f_dict.get("ruleId") or "")
        scanner_name = str(f_dict.get("scanner_name") or f_dict.get("scannerName") or "")
        f_dict["rule_id"] = rule_id
        f_dict["ruleId"] = rule_id
        f_dict["scanner_name"] = scanner_name
        f_dict["scannerName"] = scanner_name

        # 5. Fix Recommendation
        fix_rec = f_dict.get("fix_recommendation") if f_dict.get("fix_recommendation") is not None else f_dict.get("fixRecommendation")
        f_dict["fix_recommendation"] = fix_rec
        f_dict["fixRecommendation"] = fix_rec

        # 6. AI Triage
        ai_tr = f_dict.get("ai_triage") if f_dict.get("ai_triage") is not None else f_dict.get("aiTriage")
        f_dict["ai_triage"] = ai_tr
        f_dict["aiTriage"] = ai_tr

        # 7. Created At
        f_created = f_dict.get("created_at") if f_dict.get("created_at") is not None else f_dict.get("createdAt")
        if isinstance(f_created, datetime):
            f_created = f_created.isoformat()
        if f_created is not None:
            f_dict["created_at"] = f_created
            f_dict["createdAt"] = f_created

        normalized_findings.append(f_dict)

    data["findings"] = normalized_findings
    return data


def export_json(report: ScanReport | dict[str, Any], indent: int = 2) -> str:
    """
    Exports a scan report to formatted JSON string.
    """
    normalized = normalize_report_dict(report)
    return json.dumps(normalized, indent=indent, default=str)
