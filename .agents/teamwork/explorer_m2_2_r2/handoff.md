# Explorer Report: HTML Exporter Sanitization & Print Stylesheet (Defects 2 & 3)

**Agent**: Explorer M2-2-r2 (`explorer`)  
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_2_r2`  
**Milestone**: Milestone 2 Iteration 2 (M2-2-r2)  
**Date**: 2026-11-07T07:50:00Z  

---

## 1. Observation

### 1.1 Direct Inspection of `backend/app/exporters/html_exporter.py`
In `backend/app/exporters/html_exporter.py`:
- **Line 49**:
  ```python
  severity = str(f.get("severity", "MEDIUM")).upper()
  ```
- **Lines 84–89**:
  ```python
  clean_sev = re.sub(r"[^a-zA-Z0-9_-]", "", severity.lower())
  sev_badge_cls = _escape(f"badge-{clean_sev}")
  row = f"""
  <div class="finding-card">
    <div class="finding-header">
      <span class="badge {sev_badge_cls}">{_escape(severity)}</span>
  ```
- **Lines 132–365 (`<style>` block)**:
  Contains responsive layout rule at lines 211–213 (`@media (max-width: 800px)`), but contains **zero** `@media print` rules.

### 1.2 Test Results in `backend/tests/test_adversarial_exporters.py`
Command executed:
```powershell
python -m pytest backend/tests/test_adversarial_exporters.py -v
```
Verbatim test output:
```
backend\tests\test_adversarial_exporters.py::TestHtmlExporterAdversarial::test_html_air_gapped_self_contained PASSED [ 41%]
backend\tests\test_adversarial_exporters.py::TestHtmlExporterAdversarial::test_html_xss_escaping_in_all_fields PASSED [ 45%]
backend\tests\test_adversarial_exporters.py::TestHtmlExporterAdversarial::test_html_xss_in_severity_attribute PASSED [ 50%]
backend\tests\test_adversarial_exporters.py::TestHtmlExporterAdversarial::test_html_responsive_layout PASSED [ 54%]
backend\tests\test_adversarial_exporters.py::TestHtmlExporterAdversarial::test_html_print_stylesheet_rules XFAIL [ 58%]

================== 23 passed, 1 xfailed, 2 warnings in 3.67s ==================
```

### 1.3 Verbatim Challenger M2-2 Failure Details
From `.agents/teamwork/challenger_m2_2/handoff.md`:
- **Defect 2**: Unescaped / unwhitelisted severity attribute breakout:
  When a finding presents an adversarial severity payload such as `CRITICAL"><script>alert("xss-in-sev")</script>`, regex stripping produces `badge-criticalscriptalert1script`. This fails to normalize invalid severities to `INFO` per specification and results in broken CSS class styling.
- **Defect 3**: Missing Print Stylesheet Rules:
  `TestHtmlExporterAdversarial::test_html_print_stylesheet_rules` at lines 506–512 resulted in `XFAIL` because `@media print` was completely absent from `html_exporter.py`.

### 1.4 Architectural Synergy with PDF Exporter
In `backend/app/exporters/pdf_exporter.py`:
- **Lines 262–266**:
  ```python
  try:
      import weasyprint
      from app.exporters.html_exporter import export_html
      html_str = export_html(report)
      return weasyprint.HTML(string=html_str).write_pdf()
  except (Exception, OSError):
      return _export_pdf_reportlab(report)
  ```
  `export_pdf()` uses `export_html()` when `weasyprint` is present. Therefore, CSS rules defining page break avoidance (`page-break-inside: avoid; break-inside: avoid;`) and white background in `html_exporter.py` directly control and enhance WeasyPrint PDF layout.

---

## 2. Logic Chain

1. **Premise 1 (Severity Whitelisting & Normalization)**: The SecureScan domain model (`backend/app/models/report.py:Severity`) strictly defines five severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. (Observation 1.1)
2. **Premise 2**: In `html_exporter.py`, input findings can be raw dictionaries from arbitrary external sources or scanners with values like `"MODERATE"`, `"BLOCKER"`, `"informational"`, `None`, or malicious payloads `CRITICAL"><script>...`. (Observation 1.1, 1.3)
3. **Premise 3**: Stripping characters via regex `re.sub(r"[^a-zA-Z0-9_-]", "", severity.lower())` produces non-standard class names like `badge-criticalscriptalert1script` or `badge-moderate` that have no matching CSS rules in `html_exporter.py`, yielding unstyled, broken badges. (Observation 1.1, 1.3)
4. **Inference 1**: Whitelisting against `KNOWN_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})` and normalizing any unrecognized or invalid severity value to `"INFO"` guarantees that:
   - Every badge class strictly matches a defined CSS class (`badge-critical`, `badge-high`, `badge-medium`, `badge-low`, `badge-info`).
   - XSS attribute breakouts are impossible by design.
   - Dual-layer defense is achieved by keeping `_escape()` on both the badge class and the inner severity text.
5. **Premise 4 (Missing Print Stylesheet Specification Requirement)**: The Milestone 2 specification mandates a standalone, air-gapped HTML report equipped with responsive design and print stylesheet rules. (Observation 1.1, 1.3)
6. **Premise 5**: Without `@media print` rules, printing an air-gapped HTML report or converting it via browser print-to-PDF renders a dark `#090d16` background (wasting toner) and breaks finding cards and code blocks across page margins. (Observation 1.1)
7. **Premise 6**: In addition, WeasyPrint uses the HTML document generated by `export_html` to render PDF reports. (Observation 1.4)
8. **Inference 2**: Adding comprehensive `@media print` rules with white backgrounds (`#ffffff`), dark high-contrast text (`#111827`), page-break avoidance (`page-break-inside: avoid; break-inside: avoid;`), exact color retention for badges (`-webkit-print-color-adjust: exact; print-color-adjust: exact;`), and clean code boxes resolves the `XFAIL` in `test_html_print_stylesheet_rules` and produces professional printable audit documents.
9. **Conclusion**: Remediating `backend/app/exporters/html_exporter.py` with severity whitelisting and an embedded `@media print` block fully resolves Defects 2 and 3, bringing the adversarial test suite to 100% pass (24/24).

---

## 3. Caveats

1. **Python F-String Escaping**: `html_template` in `html_exporter.py` is a Python f-string. All literal curly braces in CSS rules MUST be doubled (`{{` and `}}`). Using single braces `{` or `}` will trigger a runtime `KeyError` or `ValueError`.
2. **WeasyPrint Environment Variability**: On Windows hosts lacking native Pango/Cairo libraries, `export_pdf` falls back to ReportLab. The `@media print` CSS rules are primarily active for standalone HTML browser viewing/printing and in Linux container environments (Milestone 4) where WeasyPrint is available.
3. **No Caveats on Other Files**: Zero changes are required in `backend/app/routers/` or other exporters for these two defects.

---

## 4. Conclusion & Actionable Recommendations

### 4.1 Summary of Deliverables for Worker M2
Explorer M2-2-r2 has authored and verified the following artifacts in `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_2_r2\`:
- `proposed_html_exporter.py`: Full drop-in replacement file.
- `html_exporter.patch`: Unified diff patch.
- `test_html_exporter_fix.py`: Standalone verification test verifying all severity cases, attribute breakouts, and `@media print` rules.

### 4.2 Exact Code Remediations in `backend/app/exporters/html_exporter.py`

#### Change 1: Define `KNOWN_SEVERITIES` Whitelist
Add at top of `backend/app/exporters/html_exporter.py` (after line 13):
```python
KNOWN_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
```

#### Change 2: Whitelist, Normalize, and Sanitize Severity Badge
Replace lines 49 and 84–85 with:
```python
        # Whitelist known severities and normalize invalid/unrecognized values to INFO
        raw_sev = str(f.get("severity") or "MEDIUM").strip().upper()
        severity = raw_sev if raw_sev in KNOWN_SEVERITIES else "INFO"
        sev_badge_cls = _escape(f"badge-{severity.lower()}")
```
Remove `clean_sev = re.sub(...)` and `import re` if not needed.

#### Change 3: Insert `@media print` Stylesheet Block
Insert before `</style>` (at line 365):
```css
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
```

---

## 5. Verification Method

Once Worker M2 applies the changes to `backend/app/exporters/html_exporter.py`:

### Verification Command 1: Standalone Proposed Fix Verification
```powershell
python .agents/teamwork/explorer_m2_2_r2/test_html_exporter_fix.py
```
Expected output:
```
ALL VERIFICATIONS PASSED SUCCESSFULLY!
```

### Verification Command 2: Adversarial Exporter Test Suite
```powershell
python -m pytest backend/tests/test_adversarial_exporters.py -v
```
Expected output:
- **Total Tests**: 24
- **Passed**: 24 (100%)
- **Failed**: 0
- **XFailed**: 0 (`test_html_print_stylesheet_rules` will now transition from XFAIL to PASSED)

### Verification Command 3: Full Exporter & API Regression Suites
```powershell
python -m pytest backend/tests/test_exporters.py backend/tests/test_api.py -v
```
Expected output:
- **Total Tests**: 34
- **Passed**: 34 (100%)
- Zero regressions across JSON, SARIF, HTML, and PDF exporters.

### Invalidation Conditions:
1. If any `<script>` or unescaped HTML tag appears in the output HTML string when an adversarial severity is provided.
2. If `test_html_print_stylesheet_rules` is xfailed or fails.
3. If Python raises a `KeyError` or `ValueError` due to un-doubled f-string braces in CSS rules.
