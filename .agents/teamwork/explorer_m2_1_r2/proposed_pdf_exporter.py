"""
Binary PDF Report Exporter for SecureScan using ReportLab.
Generates an executive-ready, beautifully styled PDF document with vulnerability details.
"""

from __future__ import annotations

import html
import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.exporters.json_exporter import normalize_report_dict
from app.models.report import ScanReport


def _escape_pdf(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _export_pdf_reportlab(report: ScanReport | dict[str, Any]) -> bytes:
    """
    Exports a scan report to binary PDF bytes via ReportLab.
    """
    norm = normalize_report_dict(report)
    job_id = norm.get("job_id", "unknown")
    target_name = norm.get("target_name", "Target Archive")
    created_at = str(norm.get("created_at", ""))[:19]
    summary = norm.get("summary") or {}
    findings = norm.get("findings") or []
    total = _safe_int(summary.get("total_findings"), default=len(findings))
    by_sev = summary.get("by_severity") or {}
    by_owasp = summary.get("by_owasp") or {}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1e1b4b"),
        fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )
    body_bold = ParagraphStyle(
        "BodyBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Code"],
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a"),
        fontName="Courier",
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("SecureScan Security Audit Report", title_style))
    elements.append(
        Paragraph(
            f"<b>Job ID:</b> {_escape_pdf(job_id)} &nbsp;|&nbsp; <b>Target:</b> {_escape_pdf(target_name)} &nbsp;|&nbsp; <b>Scan Date:</b> {_escape_pdf(created_at)}",
            subtitle_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#6366f1"), spaceAfter=12))

    # Summary Statistics Table
    crit = _safe_int(by_sev.get("CRITICAL", 0))
    high = _safe_int(by_sev.get("HIGH", 0))
    med = _safe_int(by_sev.get("MEDIUM", 0))
    low = _safe_int(by_sev.get("LOW", 0))
    info = _safe_int(by_sev.get("INFO", 0))

    summary_data = [
        [
            Paragraph("<b>Total Findings</b>", body_bold),
            Paragraph("<b>Critical</b>", body_bold),
            Paragraph("<b>High</b>", body_bold),
            Paragraph("<b>Medium</b>", body_bold),
            Paragraph("<b>Low / Info</b>", body_bold),
        ],
        [
            Paragraph(f"<font size=14><b>{total}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#dc2626'><b>{crit}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#ea580c'><b>{high}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#ca8a04'><b>{med}</b></font>", body_style),
            Paragraph(f"<font size=14 color='#2563eb'><b>{low + info}</b></font>", body_style),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[1.4 * inch, 1.4 * inch, 1.4 * inch, 1.4 * inch, 1.4 * inch])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 14))

    # OWASP Breakdown
    active_owasp: list[tuple[str, int]] = []
    if isinstance(by_owasp, dict):
        for cat, cnt in by_owasp.items():
            cnt_int = _safe_int(cnt)
            if cnt_int > 0:
                active_owasp.append((str(cat), cnt_int))
    if active_owasp:
        elements.append(Paragraph("OWASP Top 10 (2021) Classification", h2_style))
        owasp_table_data = [[Paragraph("<b>OWASP Category</b>", body_bold), Paragraph("<b>Count</b>", body_bold)]]
        for cat, cnt in sorted(active_owasp, key=lambda x: -x[1]):
            owasp_table_data.append([
                Paragraph(_escape_pdf(cat), body_style),
                Paragraph(str(cnt), body_bold),
            ])
        owasp_table = Table(owasp_table_data, colWidths=[5.5 * inch, 1.5 * inch])
        owasp_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(owasp_table)
        elements.append(Spacer(1, 14))

    # Findings Details
    elements.append(Paragraph(f"Detailed Vulnerability Findings ({total})", h2_style))
    if not findings:
        elements.append(Paragraph("<i>No security vulnerabilities detected in the analyzed target.</i>", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            severity = str(f.get("severity") or "MEDIUM").upper()
            title = f.get("title") or f.get("rule_id") or f"Finding {idx}"
            rule_id = f.get("rule_id") or "N/A"
            desc = f.get("description") or "No description provided."
            loc = f.get("location") or {}
            file_path = loc.get("file_path") or "unknown"
            start_line = loc.get("start_line", 1)
            start_line_display = _safe_int(start_line, default=1) if isinstance(start_line, (int, str)) and str(start_line).isdigit() else _escape_pdf(start_line)
            owasp = f.get("owasp_category") or "Unknown"

            raw_cwes = f.get("cwe_ids")
            if isinstance(raw_cwes, list):
                cwes = ", ".join(str(c) for c in raw_cwes if c is not None) or "None"
            elif raw_cwes is not None:
                cwes = str(raw_cwes) or "None"
            else:
                cwes = "None"

            reach = f.get("reachability") or "UNKNOWN"

            sev_color_hex = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#ca8a04",
                "LOW": "#2563eb",
                "INFO": "#64748b",
            }.get(severity, "#64748b")

            finding_flowables = []
            f_header = (
                f"<font color='{sev_color_hex}'><b>[{_escape_pdf(severity)}]</b></font> &nbsp; "
                f"<b>{_escape_pdf(title)}</b> &nbsp; <font color='#64748b'>({_escape_pdf(rule_id)})</font>"
            )
            finding_flowables.append(Paragraph(f_header, body_style))

            f_meta = (
                f"<b>File:</b> {_escape_pdf(file_path)}:{start_line_display} &nbsp;|&nbsp; "
                f"<b>CWE:</b> {_escape_pdf(cwes)} &nbsp;|&nbsp; <b>OWASP:</b> {_escape_pdf(owasp)} &nbsp;|&nbsp; "
                f"<b>Reachability:</b> {_escape_pdf(reach)}"
            )
            finding_flowables.append(Paragraph(f_meta, subtitle_style))
            safe_desc = _escape_pdf(desc).replace("\n", "<br/>")
            finding_flowables.append(Paragraph(safe_desc, body_style))

            # Code Snippet if present
            snippet_data = f.get("snippet") or f.get("snippet_context")
            if snippet_data and isinstance(snippet_data, dict):
                lines = snippet_data.get("lines")
                if not lines and snippet_data.get("raw_content"):
                    raw_lines = str(snippet_data["raw_content"]).splitlines()
                    start_lno = _safe_int(snippet_data.get("start_line"), default=1)
                    lines = [
                        {"line_number": start_lno + i, "content": l, "is_target": False}
                        for i, l in enumerate(raw_lines[:12])
                    ]
                if lines and isinstance(lines, list):
                    snippet_text = []
                    for ln in lines[:12]:  # cap lines to fit page cleanly
                        if isinstance(ln, dict):
                            lno = _safe_int(ln.get("line_number"), default=0)
                            cnt = _escape_pdf(str(ln.get("content") or "").expandtabs(4))
                            is_tgt = bool(ln.get("is_target") or ln.get("is_vulnerable", False))
                        else:
                            lno = 0
                            cnt = _escape_pdf(str(ln).expandtabs(4))
                            is_tgt = False
                        marker = "&gt;&gt;" if is_tgt else "  "
                        snippet_text.append(f"{lno:4d} | {marker} {cnt}")
                    snippet_para = Paragraph("<br/>".join(snippet_text).replace(" ", "&nbsp;"), code_style)
                    s_table = Table([[snippet_para]], colWidths=[7.0 * inch])
                    s_table.setStyle(
                        TableStyle([
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("TOPPADDING", (0, 0), (-1, -1), 4),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ])
                    )
                    finding_flowables.append(Spacer(1, 3))
                    finding_flowables.append(s_table)

            finding_flowables.append(Spacer(1, 8))
            elements.append(KeepTogether(finding_flowables))

    doc.build(elements)
    return buffer.getvalue()


def export_pdf(report: ScanReport | dict[str, Any]) -> bytes:
    """
    Exports a scan report to binary PDF bytes conforming to PDF-1.4+ standard.
    Prefers WeasyPrint HTML-to-PDF rendering when native libraries (pango/cairo) are available;
    automatically falls back to ReportLab for air-gapped / pure-Python environments.
    """
    try:
        import weasyprint
        from app.exporters.html_exporter import export_html
        html_str = export_html(report)
        return weasyprint.HTML(string=html_str).write_pdf()
    except (Exception, OSError):
        return _export_pdf_reportlab(report)
