import html
import io
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
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

def _escape_pdf(val):
    if val is None:
        return ""
    return html.escape(str(val))

def _safe_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default

def test_render(report):
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
    title_style = ParagraphStyle("DocTitle", parent=styles["Heading1"], fontSize=20, leading=24, textColor=colors.HexColor("#1e1b4b"), fontName="Helvetica-Bold")
    subtitle_style = ParagraphStyle("DocSubtitle", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#64748b"))
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, leading=16, textColor=colors.HexColor("#0f172a"), fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=6)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#334155"))
    body_bold = ParagraphStyle("BodyBold", parent=body_style, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("CodeText", parent=styles["Code"], fontSize=7, leading=9, textColor=colors.HexColor("#0f172a"), fontName="Courier")

    findings = report.get("findings", [])
    summary = report.get("summary", {})
    total = _safe_int(summary.get("total_findings", len(findings)))
    by_sev = summary.get("by_severity", {})
    by_owasp = summary.get("by_owasp", {})

    elements = []
    # Title
    job_id = report.get("job_id", "unknown")
    target_name = report.get("target_name", "Target Archive")
    created_at = str(report.get("created_at", ""))[:19]
    elements.append(Paragraph("SecureScan Security Audit Report", title_style))
    elements.append(
        Paragraph(
            f"<b>Job ID:</b> {_escape_pdf(job_id)} &nbsp;|&nbsp; <b>Target:</b> {_escape_pdf(target_name)} &nbsp;|&nbsp; <b>Scan Date:</b> {_escape_pdf(created_at)}",
            subtitle_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#6366f1"), spaceAfter=12))

    # Summary
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
    summary_table = Table(summary_data, colWidths=[1.4 * inch] * 5)
    elements.append(summary_table)

    # OWASP
    active_owasp = []
    if isinstance(by_owasp, dict):
        for cat, cnt in by_owasp.items():
            c_int = _safe_int(cnt)
            if c_int > 0:
                active_owasp.append((str(cat), c_int))
    if active_owasp:
        elements.append(Paragraph("OWASP Top 10 (2021) Classification", h2_style))
        owasp_table_data = [[Paragraph("<b>OWASP Category</b>", body_bold), Paragraph("<b>Count</b>", body_bold)]]
        for cat, cnt in sorted(active_owasp, key=lambda x: -x[1]):
            owasp_table_data.append([
                Paragraph(_escape_pdf(cat), body_style),
                Paragraph(str(cnt), body_bold),
            ])
        owasp_table = Table(owasp_table_data, colWidths=[5.5 * inch, 1.5 * inch])
        elements.append(owasp_table)

    # Findings
    elements.append(Paragraph(f"Detailed Vulnerability Findings ({total})", h2_style))
    for idx, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "MEDIUM").upper()
        title = f.get("title") or f.get("rule_id") or f"Finding {idx}"
        rule_id = f.get("rule_id") or "N/A"
        desc = f.get("description") or "No description provided."
        loc = f.get("location") or {}
        file_path = loc.get("file_path") or "unknown"
        start_line = loc.get("start_line", 1)
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
        }.get(sev, "#64748b")

        finding_flowables = []
        f_header = (
            f"<font color='{sev_color_hex}'><b>[{_escape_pdf(sev)}]</b></font> &nbsp; "
            f"<b>{_escape_pdf(title)}</b> &nbsp; <font color='#64748b'>({_escape_pdf(rule_id)})</font>"
        )
        finding_flowables.append(Paragraph(f_header, body_style))
        f_meta = (
            f"<b>File:</b> {_escape_pdf(file_path)}:{_escape_pdf(start_line)} &nbsp;|&nbsp; "
            f"<b>CWE:</b> {_escape_pdf(cwes)} &nbsp;|&nbsp; <b>OWASP:</b> {_escape_pdf(owasp)} &nbsp;|&nbsp; "
            f"<b>Reachability:</b> {_escape_pdf(reach)}"
        )
        finding_flowables.append(Paragraph(f_meta, subtitle_style))
        safe_desc = _escape_pdf(desc).replace("\n", "<br/>")
        finding_flowables.append(Paragraph(safe_desc, body_style))

        snippet_data = f.get("snippet") or f.get("snippet_context")
        if snippet_data and isinstance(snippet_data, dict):
            lines = snippet_data.get("lines", [])
            if not lines and snippet_data.get("raw_content"):
                lines = [{"line_number": i + 1, "content": l, "is_target": False} for i, l in enumerate(str(snippet_data["raw_content"]).splitlines()[:12])]
            if lines and isinstance(lines, list):
                s_lines = []
                for ln in lines[:12]:
                    if isinstance(ln, dict):
                        lno = _safe_int(ln.get("line_number", 0))
                        cnt = _escape_pdf(str(ln.get("content") or "").expandtabs(4))
                        tgt = bool(ln.get("is_target") or ln.get("is_vulnerable", False))
                    else:
                        lno = 0
                        cnt = _escape_pdf(str(ln).expandtabs(4))
                        tgt = False
                    marker = "&gt;&gt;" if tgt else "  "
                    s_lines.append(f"{lno:4d} | {marker} {cnt}")
                s_para = Paragraph("<br/>".join(s_lines).replace(" ", "&nbsp;"), code_style)
                s_table = Table([[s_para]], colWidths=[7.0 * inch])
                finding_flowables.append(s_table)
        elements.append(KeepTogether(finding_flowables))

    doc.build(elements)
    return buffer.getvalue()

test_cases = [
    {"job_id": "job<1>", "findings": [{"title": "C++ Vector<int> & std::map<string, void*>", "rule_id": "rule<123>", "description": "Unclosed <tag and & ampersand", "severity": "CRITICAL", "location": {"file_path": "dir/<file>.cpp", "start_line": "<script>"}, "cwe_ids": ["CWE-79<tag>", "CWE-89"], "snippet": {"lines": [{"line_number": "10", "content": "int x = a < b && c > d;", "is_target": True}]}}]},
    {"findings": [{"title": None, "rule_id": None, "description": None, "severity": "unknown", "location": None, "cwe_ids": None, "snippet": None}]},
    {"findings": [{"title": "Normal", "snippet": {"lines": [{"line_number": None, "content": None}]}}]},
    {"summary": {"total_findings": "<unclosed", "by_severity": {"CRITICAL": "5<tag>"}, "by_owasp": {"A01<tag>": "2<tag>"}}, "findings": []},
    {"findings": [{"title": "Raw snippet", "snippet": {"raw_content": "if (a < b && c > d) {\n    return <xml>foo</xml>;\n}"}}]},
    {"findings": [{"title": "Broken cwe_ids", "cwe_ids": None, "location": {"start_line": "<unclosed"}}]},
    {"findings": [{"title": "Integer cwe_ids", "cwe_ids": [79, 89, None]}]},
    {"findings": [{"title": "Special chars &<>\"'", "description": "AT&T & Co <bold>not closed\nSecond line"}]}
]

for i, tc in enumerate(test_cases):
    out = test_render(tc)
    assert out.startswith(b"%PDF-")
    assert b"%%EOF" in out[-1024:]
    print(f"Test case {i}: OK, length {len(out)} bytes")

print("ALL 8 ADVERSARIAL CASES PASSED!")
