"""
Standalone HTML Report Exporter for SecureScan.
Generates an air-gapped, self-contained single-file HTML report with embedded inline styling.
"""

from __future__ import annotations

import html
import re
from typing import Any
from app.models.report import ScanReport
from app.exporters.json_exporter import normalize_report_dict

KNOWN_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


def _escape(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def export_html(report: ScanReport | dict[str, Any]) -> str:
    """
    Exports a scan report to a single-file, self-contained HTML document.
    """
    norm = normalize_report_dict(report)
    job_id = norm.get("job_id", "unknown")
    target_name = norm.get("target_name", "Target Archive")
    created_at = norm.get("created_at", "")
    summary = norm.get("summary", {})
    total = summary.get("total_findings", 0)
    by_sev = summary.get("by_severity", {})
    by_owasp = summary.get("by_owasp", {})
    scanners = norm.get("scanners", [])
    findings = norm.get("findings", [])

    crit = by_sev.get("CRITICAL", 0)
    high = by_sev.get("HIGH", 0)
    med = by_sev.get("MEDIUM", 0)
    low = by_sev.get("LOW", 0)
    info = by_sev.get("INFO", 0)

    # Build findings HTML rows and code snippets
    findings_rows = []
    for idx, f in enumerate(findings, 1):
        fid = f.get("id", f"finding-{idx}")
        rule_id = f.get("rule_id", "UNKNOWN")
        scanner = f.get("scanner_name", "generic")
        category = f.get("category", "SAST")

        # Whitelist known severities and normalize invalid/unrecognized values to INFO
        raw_sev = str(f.get("severity") or "MEDIUM").strip().upper()
        severity = raw_sev if raw_sev in KNOWN_SEVERITIES else "INFO"
        sev_badge_cls = _escape(f"badge-{severity.lower()}")

        title = f.get("title", rule_id)
        desc = f.get("description", "")
        owasp = f.get("owasp_category", "Unknown")
        reach = f.get("reachability", "UNKNOWN")
        cwes = ", ".join(f.get("cwe_ids", [])) or "None"

        loc = f.get("location", {})
        file_path = loc.get("file_path", "")
        start_line = loc.get("start_line", 1)
        end_line = loc.get("end_line", start_line)

        # Snippet rendering
        snippet_html = ""
        snippet_data = f.get("snippet") or f.get("snippet_context")
        if snippet_data and isinstance(snippet_data, dict):
            lines = snippet_data.get("lines", [])
            if lines:
                snippet_lines = []
                for ln in lines:
                    lno = ln.get("line_number")
                    cnt = ln.get("content", "")
                    is_tgt = ln.get("is_target") or ln.get("is_vulnerable", False)
                    cls = "line-highlight" if is_tgt else "line-normal"
                    marker = ">> " if is_tgt else "   "
                    snippet_lines.append(
                        f'<div class="{cls}"><span class="line-num">{lno:4d} | {marker}</span>{_escape(cnt)}</div>'
                    )
                snippet_html = (
                    f'<div class="code-box">'
                    f'<div class="code-header">{_escape(file_path)} : lines {start_line}-{end_line}</div>'
                    f'<pre class="code-pre">{"".join(snippet_lines)}</pre>'
                    f'</div>'
                )

        row = f"""
        <div class="finding-card">
          <div class="finding-header">
            <span class="badge {sev_badge_cls}">{_escape(severity)}</span>
            <span class="finding-title">{_escape(title)}</span>
            <span class="finding-rule">{_escape(rule_id)}</span>
          </div>
          <div class="finding-meta">
            <span><strong>Scanner:</strong> {_escape(scanner)}</span>
            <span><strong>Category:</strong> {_escape(category)}</span>
            <span><strong>Location:</strong> <code>{_escape(file_path)}:{start_line}</code></span>
            <span><strong>Reachability:</strong> {_escape(reach)}</span>
            <span><strong>CWE:</strong> {_escape(cwes)}</span>
            <span><strong>OWASP:</strong> {_escape(owasp)}</span>
          </div>
          <div class="finding-desc">{_escape(desc)}</div>
          {snippet_html}
        </div>
        """
        findings_rows.append(row)

    findings_content = "".join(findings_rows) if findings_rows else "<p class='no-findings'>No security vulnerabilities detected.</p>"

    # Scanners HTML
    scanner_badges = []
    for sc in scanners:
        s_name = sc.get("name", "scanner")
        s_status = sc.get("status", "READY")
        scanner_badges.append(
            f'<div class="scanner-chip"><span class="chip-name">{_escape(s_name)}</span><span class="chip-status">{_escape(s_status)}</span></div>'
        )
    scanner_content = "".join(scanner_badges)

    # OWASP Table Rows
    owasp_rows = []
    for cat, cnt in sorted(by_owasp.items(), key=lambda x: -x[1]):
        if cnt > 0:
            owasp_rows.append(f"<tr><td>{_escape(cat)}</td><td style='text-align: right; font-weight: bold;'>{cnt}</td></tr>")
    owasp_content = "".join(owasp_rows) or "<tr><td colspan='2'>No vulnerabilities recorded</td></tr>"

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureScan Security Report - {_escape(job_id)}</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #64748b;
      --indigo: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding: 2rem 1.5rem;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }}
    h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .brand-shield {{
      color: var(--indigo);
      font-size: 2rem;
    }}
    .subtext {{
      color: var(--text-muted);
      font-size: 0.875rem;
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }}
    .stat-title {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}
    .stat-value {{
      font-size: 2rem;
      font-weight: 700;
      margin-top: 0.25rem;
    }}
    .two-col {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}
    @media (max-width: 800px) {{
      .two-col {{ grid-template-columns: 1fr; }}
    }}
    .panel {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }}
    .panel h2 {{
      font-size: 1.1rem;
      margin-bottom: 1rem;
      color: #fff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }}
    th, td {{
      padding: 0.6rem 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      color: var(--text-muted);
      font-weight: 600;
    }}
    .scanner-grid {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
    .scanner-chip {{
      display: inline-flex;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 6px;
      overflow: hidden;
      font-size: 0.75rem;
    }}
    .chip-name {{
      padding: 0.25rem 0.5rem;
      color: #cbd5e1;
    }}
    .chip-status {{
      background: #0f766e;
      color: #fff;
      padding: 0.25rem 0.5rem;
      font-weight: 600;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    .badge-info {{ background: rgba(100, 116, 139, 0.2); color: var(--info); border: 1px solid var(--info); }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }}
    .finding-title {{
      font-weight: 600;
      font-size: 1rem;
      color: #fff;
    }}
    .finding-rule {{
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-left: auto;
      font-family: monospace;
    }}
    .finding-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }}
    .finding-desc {{
      font-size: 0.875rem;
      color: #d1d5db;
      margin-bottom: 0.75rem;
    }}
    .code-box {{
      background: #030712;
      border: 1px solid #1f2937;
      border-radius: 6px;
      overflow: hidden;
      margin-top: 0.5rem;
    }}
    .code-header {{
      background: #111827;
      padding: 0.35rem 0.75rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: monospace;
      border-bottom: 1px solid #1f2937;
    }}
    .code-pre {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      padding: 0.5rem 0;
      overflow-x: auto;
    }}
    .line-normal {{
      padding: 0.1rem 0.75rem;
      color: #94a3b8;
    }}
    .line-highlight {{
      padding: 0.1rem 0.75rem;
      background: rgba(239, 68, 68, 0.15);
      color: #fca5a5;
      font-weight: 600;
      border-left: 3px solid var(--critical);
    }}
    .line-num {{
      color: #475569;
      user-select: none;
      margin-right: 0.5rem;
    }}
    .no-findings {{
      padding: 2rem;
      text-align: center;
      color: #10b981;
      font-size: 1.1rem;
    }}
    footer {{
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
    }}

    @media print {{
      @page {{
        margin: 0.5in;
        size: auto;
      }}
      *, *:before, *:after {{
        box-shadow: none !important;
        text-shadow: none !important;
      }}
      body {{
        background: #ffffff !important;
        background-color: #ffffff !important;
        color: #111827 !important;
        padding: 0 !important;
        font-size: 10pt !important;
        line-height: 1.4 !important;
      }}
      .container {{
        max-width: 100% !important;
        width: 100% !important;
        margin: 0 !important;
        padding: 0 !important;
      }}
      header {{
        padding-bottom: 0.75rem !important;
        margin-bottom: 1rem !important;
        border-bottom: 2px solid #111827 !important;
      }}
      h1 {{
        color: #111827 !important;
        font-size: 1.5rem !important;
      }}
      .brand-shield {{
        color: #4338ca !important;
        font-size: 1.5rem !important;
      }}
      .subtext {{
        color: #4b5563 !important;
      }}
      .stat-grid {{
        gap: 0.75rem !important;
        margin-bottom: 1rem !important;
      }}
      .stat-card, .panel, .finding-card {{
        background: #ffffff !important;
        background-color: #ffffff !important;
        border: 1px solid #d1d5db !important;
        color: #111827 !important;
        page-break-inside: avoid !important;
        break-inside: avoid !important;
      }}
      .stat-card {{
        padding: 0.75rem !important;
      }}
      .stat-title {{
        color: #6b7280 !important;
      }}
      .stat-value {{
        font-size: 1.5rem !important;
        color: #111827 !important;
      }}
      .panel {{
        margin-bottom: 1rem !important;
        padding: 1rem !important;
      }}
      .panel h2 {{
        color: #111827 !important;
        border-bottom: 1px solid #e5e7eb !important;
        padding-bottom: 0.5rem !important;
        margin-bottom: 0.75rem !important;
      }}
      .two-col {{
        gap: 1rem !important;
        margin-bottom: 1rem !important;
      }}
      table {{
        border: 1px solid #e5e7eb !important;
      }}
      th, td {{
        border-bottom: 1px solid #e5e7eb !important;
        color: #111827 !important;
        padding: 0.4rem 0.5rem !important;
      }}
      th {{
        background: #f9fafb !important;
        color: #4b5563 !important;
        font-weight: 700 !important;
      }}
      .scanner-chip {{
        background: #f3f4f6 !important;
        border: 1px solid #d1d5db !important;
      }}
      .chip-name {{
        color: #1f2937 !important;
      }}
      .chip-status {{
        background: #0d9488 !important;
        color: #ffffff !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .badge {{
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .badge-critical {{
        background: #fee2e2 !important;
        color: #991b1b !important;
        border: 1px solid #ef4444 !important;
      }}
      .badge-high {{
        background: #ffedd5 !important;
        color: #9a3412 !important;
        border: 1px solid #f97316 !important;
      }}
      .badge-medium {{
        background: #fef9c3 !important;
        color: #854d0e !important;
        border: 1px solid #eab308 !important;
      }}
      .badge-low {{
        background: #dbeafe !important;
        color: #1e40af !important;
        border: 1px solid #3b82f6 !important;
      }}
      .badge-info {{
        background: #f1f5f9 !important;
        color: #334155 !important;
        border: 1px solid #94a3b8 !important;
      }}
      .finding-card {{
        padding: 1rem !important;
        margin-bottom: 0.75rem !important;
      }}
      .finding-title {{
        color: #111827 !important;
      }}
      .finding-rule {{
        color: #4b5563 !important;
      }}
      .finding-meta {{
        color: #4b5563 !important;
        border-bottom: 1px solid #e5e7eb !important;
      }}
      .finding-desc {{
        color: #1f2937 !important;
      }}
      .code-box {{
        background: #f8fafc !important;
        border: 1px solid #cbd5e1 !important;
        page-break-inside: avoid !important;
        break-inside: avoid !important;
      }}
      .code-header {{
        background: #f1f5f9 !important;
        color: #334155 !important;
        border-bottom: 1px solid #cbd5e1 !important;
      }}
      .line-normal {{
        color: #334155 !important;
      }}
      .line-highlight {{
        background: #fee2e2 !important;
        color: #991b1b !important;
        border-left: 3px solid #ef4444 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .line-num {{
        color: #64748b !important;
      }}
      footer {{
        color: #6b7280 !important;
        border-top: 1px solid #e5e7eb !important;
        margin-top: 1.5rem !important;
        padding-top: 1rem !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1><span class="brand-shield">&#x1F6E1;</span> SecureScan Audit Report</h1>
        <div class="subtext">Job ID: {_escape(job_id)} &bull; Target: {_escape(target_name)}</div>
      </div>
      <div class="subtext" style="text-align: right;">
        Generated: {_escape(created_at)}<br>
        Engine: SecureShip Multi-Scanner Suite
      </div>
    </header>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-title">Total Findings</div>
        <div class="stat-value">{total}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Critical Severity</div>
        <div class="stat-value" style="color: var(--critical);">{crit}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">High Severity</div>
        <div class="stat-value" style="color: var(--high);">{high}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Medium Severity</div>
        <div class="stat-value" style="color: var(--medium);">{med}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Low / Info</div>
        <div class="stat-value" style="color: var(--low);">{low + info}</div>
      </div>
    </div>

    <div class="two-col">
      <div class="panel">
        <h2>OWASP Top 10 (2021) Classification</h2>
        <table>
          <thead>
            <tr><th>Category</th><th style="text-align: right;">Count</th></tr>
          </thead>
          <tbody>
            {owasp_content}
          </tbody>
        </table>
      </div>

      <div class="panel">
        <h2>Pre-baked Scanner Engines</h2>
        <div class="scanner-grid">
          {scanner_content}
        </div>
      </div>
    </div>

    <div class="panel">
      <h2>Vulnerability Findings ({total})</h2>
      {findings_content}
    </div>

    <footer>
      Produced by SecureScan Security Platform &bull; Powered by SecureShip CLI &bull; OASIS SARIF & OWASP Top 10 Compliant
    </footer>
  </div>
</body>
</html>
"""
    return html_template
