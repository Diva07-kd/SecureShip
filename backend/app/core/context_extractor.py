"""
Code Context Extractor for SecureScan.
Extracts code snippets (±5 lines around vulnerable lines) from target repositories safely.
Enforces path traversal defense, boundary clamping, UTF-8/Latin-1 encoding fallback,
binary file rejection, and target line tagging.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional, Union

from app.models.report import (
    CodeSnippet,
    NormalizedFinding,
    SnippetLine,
    extract_cwe_ids,
    map_cwe_to_owasp,
    normalize_reachability_verdict,
)

logger = logging.getLogger("securescan.context")


def extract_code_snippet(
    target_dir: Union[str, Path],
    file_path: str,
    start_line: int,
    end_line: int,
    context_lines: int = 5,
) -> Optional[CodeSnippet]:
    """
    Extracts ±context_lines around [start_line, end_line] safely from target_dir.
    Returns CodeSnippet with tagged target lines, or None if extraction is impossible or unsafe.
    """
    if not file_path:
        return None

    try:
        resolved_base = Path(target_dir).resolve()

        # Clean leading slashes and Windows/POSIX separators
        clean_rel = file_path.replace("\\", "/").lstrip("/")
        resolved_file = (resolved_base / clean_rel).resolve()

        # Invariant 1: Path Traversal Defense
        if not resolved_file.is_relative_to(resolved_base):
            return None

        # Invariant 2: File must exist and be a regular file
        if not resolved_file.is_file():
            return None

        # Invariant 3: Multi-encoding safe reading
        try:
            content = resolved_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, UnicodeError):
            try:
                content = resolved_file.read_text(encoding="latin-1")
            except Exception:
                return None

        # Invariant 4: Binary file defense (null byte in first 4096 bytes)
        if "\x00" in content[:4096]:
            return None

        raw_lines = content.splitlines()
        total_lines = len(raw_lines)
        if total_lines == 0:
            return None

        # Invariant 5: Boundary Clamping
        safe_start = max(1, min(start_line if start_line > 0 else 1, total_lines))
        safe_end = max(safe_start, min(end_line if end_line > 0 else safe_start, total_lines))

        window_start = max(1, safe_start - context_lines)
        window_end = min(total_lines, safe_end + context_lines)

        lines: List[SnippetLine] = []
        for lno in range(window_start, window_end + 1):
            lines.append(
                SnippetLine(
                    line_number=lno,
                    content=raw_lines[lno - 1],
                    is_target=(safe_start <= lno <= safe_end),
                )
            )

        return CodeSnippet(
            file_path=clean_rel,
            start_line=window_start,
            end_line=window_end,
            target_start=safe_start,
            target_end=safe_end,
            lines=lines,
            raw_content="\n".join([line.content for line in lines]),
        )
    except Exception as exc:
        logger.debug("Failed extracting snippet for %s: %s", file_path, exc)
        return None


def enrich_findings_with_context(
    findings: List[NormalizedFinding],
    target_dir: Union[str, Path],
    context_lines: int = 5,
) -> List[NormalizedFinding]:
    """
    Enriches each NormalizedFinding with a sliced CodeSnippet from target_dir.
    Mutates finding.snippet_context and returns the list.
    """
    for finding in findings:
        if finding.location and finding.location.file_path:
            finding.snippet_context = extract_code_snippet(
                target_dir=target_dir,
                file_path=finding.location.file_path,
                start_line=finding.location.start_line,
                end_line=finding.location.end_line,
                context_lines=context_lines,
            )
    return findings


def enrich_report_with_snippets(
    report: Union[dict[str, Any], Any],
    target_dir: Union[str, Path],
    context_lines: int = 5,
) -> Union[dict[str, Any], Any]:
    """
    Enriches raw or normalized scan report dictionary or model with code snippets,
    CWE IDs, OWASP Top 10 categories, and reachability verdicts.
    """
    if isinstance(report, dict):
        findings = report.get("findings", [])
        for f in findings:
            if not isinstance(f, dict):
                continue

            loc = f.get("location") or {}
            file_path = loc.get("filePath") or loc.get("file_path") or ""
            start_line = loc.get("startLine") or loc.get("start_line") or 1
            end_line = loc.get("endLine") or loc.get("end_line") or start_line

            snippet = extract_code_snippet(
                target_dir=target_dir,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                context_lines=context_lines,
            )
            if snippet:
                f["snippetContext"] = snippet.model_dump(by_alias=True)
                f["snippet_context"] = snippet.model_dump(by_alias=False)

            # Enrich CWE IDs
            raw_cwes = f.get("cweIds") or f.get("cwe_ids") or []
            normalized_cwes = extract_cwe_ids(raw_cwes)
            f["cweIds"] = normalized_cwes
            f["cwe_ids"] = normalized_cwes

            # Enrich OWASP Category
            rule_id = f.get("ruleId") or f.get("rule_id") or ""
            desc = f.get("description") or f.get("title") or ""
            cat = f.get("category") or ""
            owasp = map_cwe_to_owasp(
                cwe_ids=normalized_cwes,
                category=cat,
                rule_id=rule_id,
                description=desc,
            )
            f["owaspCategory"] = owasp
            f["owasp_category"] = owasp

            # Enrich Reachability
            raw_reach = f.get("reachability")
            verdict = normalize_reachability_verdict(raw_reach).value
            f["reachability"] = verdict

        return report

    if hasattr(report, "findings"):
        enrich_findings_with_context(report.findings, target_dir, context_lines=context_lines)
        return report

    return report
