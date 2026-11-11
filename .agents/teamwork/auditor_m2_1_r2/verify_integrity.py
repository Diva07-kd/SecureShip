import sys
import re
sys.path.insert(0, "backend")
from app.models.report import ScanReport
from app.exporters.html_exporter import export_html
from app.exporters.pdf_exporter import _export_pdf_reportlab

malicious_report = {
    "job_id": "<script>alert(1)</script>",
    "target_name": 'target<img src=x onerror=alert(2)>',
    "created_at": "2026-11-07<script>",
    "summary": {
        "total_findings": 1,
        "by_severity": {"CRITICAL": 1},
        "by_owasp": {"A01<script>": 1}
    },
    "findings": [
        {
            "id": "f-malicious",
            "rule_id": "rule<tag>&more",
            "title": "C++ Template Vector<std::pair<int, float>> & Special <script>",
            "description": 'Description with <bold> and & and "quotes" and <iframe src="evil.com">',
            "severity": 'CRITICAL"><script>alert(3)</script>',
            "scanner_name": "scanner<script>",
            "category": "SAST<tag>",
            "owasp_category": "A03<script>",
            "cwe_ids": ["CWE-79<script>", "CWE-80"],
            "reachability": "REACHABLE<tag>",
            "location": {
                "file_path": "src/<script>/test.cpp",
                "start_line": 42,
                "end_line": 45
            },
            "snippet": {
                "file_path": "src/<script>/test.cpp",
                "start_line": 40,
                "lines": [
                    {"line_number": 42, "content": "std::vector<int> v; // & <script>", "is_target": True}
                ]
            }
        }
    ]
}

html_out = export_html(malicious_report)
# Check for unescaped HTML tags
assert "<script" not in html_out, "Unescaped script tag found in HTML!"
assert "<iframe" not in html_out, "Unescaped iframe found in HTML!"
assert "<img" not in html_out, "Unescaped img tag found in HTML!"
assert "<bold>" not in html_out, "Unescaped bold tag found in HTML!"

# Check that entity-escaped versions are safely rendered as text
assert "&lt;img" in html_out, "Entity-escaped img tag not found!"
assert "&lt;script" in html_out, "Entity-escaped script tag not found!"

# Verify finding badge class and text in DOM
badges = re.findall(r'<span class="badge ([^"]+)">([^<]+)</span>', html_out)
assert len(badges) >= 1, "No finding badge rendered"
finding_badge_cls, finding_badge_text = badges[0]
assert finding_badge_cls == "badge-info", f"Expected badge-info but got {finding_badge_cls}"
assert finding_badge_text == "INFO", f"Expected text INFO but got {finding_badge_text}"

# Verify media print stylesheet
assert "@media print" in html_out, "@media print missing!"
assert "page-break-inside: avoid" in html_out or "break-inside: avoid" in html_out
assert "#ffffff" in html_out

# Verify PDF generation with malicious payloads
pdf_bytes = _export_pdf_reportlab(malicious_report)
assert pdf_bytes.startswith(b"%PDF-"), "PDF header missing"
assert b"%%EOF" in pdf_bytes[-1024:], "PDF EOF missing"
assert len(pdf_bytes) > 2000, "PDF appears truncated"

print("INDEPENDENT DEEP ADVERSARIAL INTEGRITY VERIFICATION: PASSED")
