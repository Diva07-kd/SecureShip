# Investigation & Test Strategy Handoff Report — Explorer M2-3-r2

**Milestone**: Milestone 2 Iteration 2 — Multi-Format Exporters, Test Suite Analysis & Regression Strategy  
**Agent**: Explorer M2-3-r2 (`Teamwork explorer`, roles: `investigator`, `synthesizer`)  
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_3_r2`  
**Date**: 2026-11-07T07:55:00Z  

---

## 1. Observation

Direct empirical observations, file inspections, and execution evidence across all test suites and exporter modules:

### 1.1 Complete Test Suite Inventory & Baseline
The repository currently maintains **385 automated tests** distributed across three major test directory structures:

| Test Directory / Module | Test Count | Scope / Purpose |
|-------------------------|------------|-----------------|
| `backend/tests/test_adversarial_exporters.py` | 24 | Exporters & export route adversarial stress suite |
| `backend/tests/test_adversarial_m1.py` | 20 | Concurrency, context extractor boundary & OWASP mapping |
| `backend/tests/test_adversarial_m2.py` | 68 | Malformed payloads, 50MB boundary, rate limits, queue stress |
| `backend/tests/test_api.py` | 21 | FastAPI routes integration (`/api/scan`, `/api/jobs`, `/api/reports`, `/api/health`) |
| `backend/tests/test_context.py` | 10 | Context extractor unit tests (±5 line slicing) |
| `backend/tests/test_exporters.py` | 13 | Core unit tests for JSON, SARIF, HTML, PDF exporters |
| `backend/tests/test_extraction.py` | 30 | Safe extraction defenses (zip-slip, symlinks, zip-bombs, quotas) |
| `backend/tests/test_models.py` | 13 | Pydantic model schemas, CWE normalization, OWASP mappings |
| `backend/tests/test_queue.py` | 9 | Job queue lifecycle, concurrency=1, timeout semantics |
| `backend/tests/test_runner.py` | 9 | Subprocess runner argument lists, exit code 0/1 handling |
| **Subtotal `backend/tests/`** | **217** | **Backend Unit, Integration, & Adversarial Suite** |
| `tests/adversarial/test_m1_adversarial.py` | 72 | Core security & defense stress suite (Tier 5) |
| `tests/adversarial/test_m2_adversarial.py` | 68 | API and upload stress test suite (Tier 5 mirror) |
| **Subtotal `tests/adversarial/`** | **140** | **Adversarial Hardening Track Suite** |
| `tests/e2e/test_tier1_feature_coverage.py` | 12 | Opaque-box Tier 1 feature contracts |
| `tests/e2e/test_tier2_boundaries.py` | 9 | Opaque-box Tier 2 security boundaries & timeouts |
| `tests/e2e/test_tier3_cross_features.py` | 5 | Opaque-box Tier 3 queue, state machine & lifecycle cleanup |
| `tests/e2e/test_tier4_real_world.py` | 2 | Opaque-box Tier 4 real-world clean and vulnerable scan runs |
| **Subtotal `tests/e2e/`** | **28** | **E2E Acceptance Gate Suite** |
| **Grand Total Across Codebase** | **385** | **Repository Automated Test Inventory** |

---

### 1.2 Deep Analysis of `backend/tests/test_adversarial_exporters.py` (24 Tests)
Command executed:
```powershell
python -m pytest backend/tests/test_adversarial_exporters.py -v
```
Result: **23 passed, 1 xfailed, 0 failed in 5.61s**.

Breakdown of the 24 tests:
- **JSON Exporter Adversarial (4 tests)**:
  - `test_json_bidirectional_field_presence` -> `PASSED`
  - `test_json_round_trip_empty_and_zero_findings` -> `PASSED`
  - `test_json_scale_1000_findings` -> `PASSED` (1,200 findings serialized in 0.045s)
  - `test_json_unicode_and_adversarial_payloads` -> `PASSED`
- **SARIF 2.1.0 Exporter Adversarial (5 tests)**:
  - `test_sarif_oasis_schema_conformance` -> `PASSED` (validated against OASIS SARIF JSON schema)
  - `test_sarif_clean_report_schema_conformance` -> `PASSED`
  - `test_sarif_missing_line_numbers_and_missing_location` -> `PASSED`
  - `test_sarif_extreme_line_numbers` -> `PASSED` (handles integer limits and clamped negatives)
  - `test_sarif_empty_snippet_contexts` -> `PASSED`
- **HTML Exporter Adversarial (5 tests)**:
  - `test_html_air_gapped_self_contained` -> `PASSED` (zero external HTTP/HTTPS CDN references)
  - `test_html_xss_escaping_in_all_fields` -> `PASSED` (escapes script/img/svg in titles, descriptions, code snippets)
  - `test_html_xss_in_severity_attribute` -> `PASSED` (defended via sanitization)
  - `test_html_responsive_layout` -> `PASSED`
  - `test_html_print_stylesheet_rules` -> **`XFAIL`** (missing `@media print`)
- **PDF Exporter Adversarial (4 tests)**:
  - `test_pdf_binary_structure_and_eof` -> `PASSED` (`%PDF-` header and `%%EOF` marker)
  - `test_pdf_zero_findings_clean_report` -> `PASSED`
  - `test_pdf_adversarial_special_characters_and_xml_tags` -> `PASSED` (defended via `_escape_pdf`)
  - `test_pdf_extreme_text_lengths_and_no_wrap_overflow` -> `PASSED`
- **Export Endpoint Adversarial (6 tests)**:
  - `test_export_unknown_format_returns_400` -> `PASSED`
  - `test_export_case_insensitivity_and_whitespace` -> `PASSED`
  - `test_export_in_flight_job_returns_409` -> `PASSED`
  - `test_export_non_existent_job_returns_404` -> `PASSED`
  - `test_export_failed_job_returns_422` -> `PASSED`
  - `test_content_disposition_header_specification` -> `PASSED`

---

### 1.3 Detailed Failure Trace 1: `test_pdf_adversarial_special_characters_and_xml_tags`
- **Test Location**: `backend/tests/test_adversarial_exporters.py:556-605`
- **Target File**: `backend/app/exporters/pdf_exporter.py`
- **Verbatim Error from Challenger M2-2 Failure Run**:
  ```
  Failed: ReportLab CRASHED on string 'Vector<int> buffer overflow': 
  paragraph text "<para><font color='#ea580c'><b>[HIGH]</b></font> &nbsp; <b>Title with Vector<int> buffer overflow</b> &nbsp; <font color='#64748b'>(rule-Vector<int)</font></para>" caused exception Parse error: saw </para> instead of expected </font>. ReportLab Paragraph strings must escape '<', '>', '&' XML characters.
  C:\Users\kdiva\AppData\Local\Programs\Python\Python312\Lib\site-packages\reportlab\platypus\paraparser.py:3066: ValueError
  ```
- **Root Cause**:
  ReportLab's `Paragraph` class is an XML flowable parser. Dynamic strings containing `<`, `>`, or `&` (such as C++ template instantiations `Vector<int>`, HTML tags `<script>`, or boolean conditions `a < b && c > d`) were interpolated directly into `f_header`, `f_meta`, `desc`, and snippet lines without XML entity escaping. When `paraparser.py` encountered `<int>`, it expected a corresponding closing tag `</int>` before the closing `</font>` or `</para>`.
- **Current State in `pdf_exporter.py`**:
  Lines 30-34:
  ```python
  def _escape_pdf(val: Any) -> str:
      if val is None:
          return ""
      return html.escape(str(val))
  ```
  And lines 208-234: `_escape_pdf` wraps `severity`, `title`, `rule_id`, `file_path`, `cwes`, `owasp`, `reach`, `desc`, and `cnt = _escape_pdf(...)`.
- **Status**: The test currently **passes** (`PASSED [70%]`). However, review by Explorer M2-1-r2 ensures that all table cells (e.g. summary table, OWASP table) and header labels maintain strict escaping and do not suffer double-escaping if `_escape_pdf` is applied repeatedly.

---

### 1.4 Detailed Failure Trace 2: `test_html_xss_in_severity_attribute`
- **Test Location**: `backend/tests/test_adversarial_exporters.py:475-498`
- **Target File**: `backend/app/exporters/html_exporter.py`
- **Verbatim Error from Challenger M2-2 Failure Run**:
  ```
  Failed: XSS injection detected via unescaped finding severity: 
  html_exporter.py injects sev_badge_cls directly into class attribute without escaping.
  ```
- **Root Cause**:
  In `html_exporter.py`, `sev_badge_cls` was originally computed as:
  ```python
  sev_badge_cls = f"badge-{severity.lower()}"
  ```
  and injected into:
  ```html
  <span class="badge {sev_badge_cls}">{_escape(severity)}</span>
  ```
  When an adversary or malicious repository scan output supplied:
  `severity='CRITICAL"><script>alert("xss-in-sev")</script>'`, the string broke out of the class attribute:
  `<span class="badge badge-critical"><script>alert("xss-in-sev")</script>">...` executing the script payload in any browser viewing the exported HTML file.
- **Current State in `html_exporter.py`**:
  Lines 84-85:
  ```python
  clean_sev = re.sub(r"[^a-zA-Z0-9_-]", "", severity.lower())
  sev_badge_cls = _escape(f"badge-{clean_sev}")
  ```
  While this regular expression removes `<` and `"` and prevents attribute breakout (allowing the test to pass), it still allows non-standard severity strings (e.g., `badge-foobar`), which fail to style according to the defined CSS classes (`badge-critical`, `badge-high`, `badge-medium`, `badge-low`, `badge-info`).
- **Remediation Recommendation**:
  Adopt strict enum whitelisting per Challenger M2-2 and Explorer M2-2:
  ```python
  KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
  sev_upper = str(severity).upper()
  normalized_sev = sev_upper if sev_upper in KNOWN_SEVERITIES else "INFO"
  sev_badge_cls = f"badge-{normalized_sev.lower()}"
  ```

---

### 1.5 Detailed Failure Trace 3: `test_html_print_stylesheet_rules`
- **Test Location**: `backend/tests/test_adversarial_exporters.py:505-512`
- **Target File**: `backend/app/exporters/html_exporter.py`
- **Test Implementation**:
  ```python
  def test_html_print_stylesheet_rules(self):
      """Check for print stylesheet rules (@media print) for printable security audit reports."""
      html_str = export_html({"job_id": "print-test", "status": "done", "findings": []})
      has_print_media = "@media print" in html_str
      # Note: We record this as an empirical finding
      if not has_print_media:
          pytest.xfail("Print stylesheet rules (@media print) are currently missing from html_exporter.py")
  ```
- **Root Cause**:
  `backend/app/exporters/html_exporter.py` lines 132-365 includes responsive layout queries (`@media (max-width: 800px)`), but includes **zero** `@media print` rules. As a result, `has_print_media` evaluates to `False`, invoking `pytest.xfail(...)`.
- **Behavior Upon Fix**:
  When `@media print` rules are inserted into the inline `<style>` block in `html_exporter.py`, `has_print_media` evaluates to `True`. The function skips `pytest.xfail(...)` and completes normally, flipping the test from **XFAIL** to **PASSED**.
- **Test Strengthening Required**:
  Currently, `test_html_print_stylesheet_rules` does not assert the presence of critical print declarations (such as page break prevention). The test should be updated to assert:
  1. `"@media print"` is in `html_str`
  2. `"page-break-inside: avoid"` or `"break-inside: avoid"` is present for cards
  3. Body background is reset to `#ffffff`

---

### 1.6 Full Test Suite Batch Execution Observations
During our multi-suite verification run across all 217 backend tests, we observed an asynchronous lifecycle artifact:
1. When running tests in isolation:
   - `python -m pytest backend/tests/test_adversarial_m2.py -k test_upload_corrupt_zip_body_fails_at_worker_stage -v` -> **PASSED** (1.49s).
   - `python -m pytest tests/adversarial/test_m2_adversarial.py -k test_upload_streaming_cleanup_on_413 -v` -> **PASSED** (3.74s).
2. When running all 217 tests in a single process without resetting the queue:
   - `test_upload_corrupt_zip_body_fails_at_worker_stage` flaked with `assert <JobStatus.QUEUED: 'queued'> == <JobStatus.FAILED: 'failed'>` because prior tests left the singleton queue's worker in a busy or stopped state, and the polling loop (40 * 0.05s = 2.0s) timed out under heavy CPU load.
   - `test_upload_streaming_cleanup_on_413` flaked when lingering files from other tests in the shared `%TEMP%` directory were counted in the delta set.

---

## 2. Logic Chain

1. **Premise 1 (Adversarial Exporters Gate Failure)**: Challenger M2-2 issued `REQUEST_CHANGES` due to 2 failures (`test_pdf_adversarial_special_characters_and_xml_tags`, `test_html_xss_in_severity_attribute`) and 1 xfail (`test_html_print_stylesheet_rules`). (Observation 1.1, 1.2)
2. **Premise 2 (PDF Exporter XML Parsing)**: ReportLab's `Paragraph` interprets text as XML. Any unescaped `<`, `>`, or `&` triggers an unhandled `ValueError` in `paraparser.py`. (Observation 1.3)
3. **Inference 1**: Escaping dynamic text via `html.escape` while preserving ReportLab's styling tags (`<b>`, `</b>`, `<font>`, `<br/>`) completely eliminates the `ValueError` crash and allows `test_pdf_adversarial_special_characters_and_xml_tags` to pass reliably.
4. **Premise 3 (HTML Exporter Stored XSS)**: In `html_exporter.py`, interpolating `severity` directly into `<span class="badge {sev_badge_cls}">` creates a DOM breakout vulnerability. (Observation 1.4)
5. **Inference 2**: Whitelisting severity against `{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}` and normalizing unrecognized values to `"INFO"` neutralizes the breakout payload, guarantees that only valid CSS badge classes are emitted, and ensures `test_html_xss_in_severity_attribute` passes.
6. **Premise 4 (Missing Print Stylesheet Specification Requirement)**: The Milestone 2 specification mandates that standalone HTML reports include print stylesheet rules. The test `test_html_print_stylesheet_rules` is designed to xfail when `@media print` is absent and pass when present. (Observation 1.5)
7. **Inference 3**: Injecting a clean print stylesheet block with white background, black typography, border contrast, and `break-inside: avoid` / `page-break-inside: avoid` satisfies the specification and converts `test_html_print_stylesheet_rules` from XFAIL to PASSED.
8. **Premise 5 (Test Suite Health & Regression Isolation)**: Running 385 tests across multiple suites requires clear tier boundaries so that fast unit/exporter checks can be run rapidly without queue contention. (Observation 1.6)
9. **Conclusion**: By implementing the three exporter fixes and executing a structured regression checklist across the 4 test tiers, Milestone 2 will achieve a 100% pass rate with zero test failures and zero xfails.

---

## 3. Caveats

1. **WeasyPrint Fallback on Windows**:
   On Windows development environments lacking native GTK/Pango/Cairo DLLs, `export_pdf()` automatically falls back to `_export_pdf_reportlab()`. In Linux containers (Milestone 4), WeasyPrint will execute directly. Both paths must remain verified and crash-free.
2. **Pytest XFAIL Semantics**:
   `test_html_print_stylesheet_rules` uses imperative `pytest.xfail(...)` inside the function body rather than the `@pytest.mark.xfail` decorator. Once `@media print` is present, the test executes to completion without invoking `pytest.xfail` and is reported as `PASSED`.
3. **Queue Singleton Concurrency in Batch Pytest Runs**:
   The process-wide `_global_job_queue` singleton maintains state across tests in a single pytest process. When running end-to-end integration tests that submit jobs to the queue, tests should ensure the queue worker is cleanly started and drained to avoid timeout flakes.

---

## 4. Conclusion & Test Execution Strategy

### 4.1 Recommended Fixes to be Applied by Worker M2
1. **In `backend/app/exporters/html_exporter.py`**:
   - Add `@media print` stylesheet block inside `<style>` (around line 363):
     ```css
     @media print {
       body { background: #ffffff !important; color: #000000 !important; padding: 0.5in !important; }
       .container { max-width: 100% !important; margin: 0 !important; }
       .finding-card, .stat-card, .panel {
         background: #ffffff !important;
         border: 1px solid #d1d5db !important;
         color: #111827 !important;
         page-break-inside: avoid;
         break-inside: avoid;
       }
       .finding-title, .panel h2, h1 { color: #111827 !important; }
       .code-box { background: #f8fafc !important; border: 1px solid #cbd5e1 !important; }
       .code-header { background: #f1f5f9 !important; color: #334155 !important; }
       .line-normal { color: #334155 !important; }
       .line-highlight { background: #fee2e2 !important; color: #991b1b !important; }
       footer { color: #6b7280 !important; border-top: 1px solid #e5e7eb !important; }
     }
     ```
   - Standardize severity whitelisting (around line 84):
     ```python
     KNOWN_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
     normalized_sev = severity if severity in KNOWN_SEVERITIES else "INFO"
     sev_badge_cls = f"badge-{normalized_sev.lower()}"
     ```

2. **In `backend/app/exporters/pdf_exporter.py`**:
   - Maintain `_escape_pdf(val)` across all dynamic text fields (`job_id`, `target_name`, `created_at`, `cat`, `severity`, `title`, `rule_id`, `file_path`, `cwes`, `owasp`, `reach`, `desc`, snippet content `cnt`).
   - Ensure header labels and table cells are cleanly escaped without double escaping.

3. **In `backend/tests/test_adversarial_exporters.py`**:
   - Strengthen `test_html_print_stylesheet_rules` to assert print rules directly:
     ```python
     def test_html_print_stylesheet_rules(self):
         """Check for print stylesheet rules (@media print) for printable security audit reports."""
         html_str = export_html({"job_id": "print-test", "status": "done", "findings": []})
         assert "@media print" in html_str, "Print stylesheet rules (@media print) are missing from html_exporter.py"
         assert "page-break-inside: avoid" in html_str or "break-inside: avoid" in html_str
         assert "#ffffff" in html_str
     ```

---

### 4.2 Comprehensive Regression Test Execution Strategy

We define a 4-tier regression execution strategy designed to guarantee fast verification loops and zero regressions before gate sign-off:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Exporter & API Fast Verification (Targeted Milestone 2)       │
│ • backend/tests/test_adversarial_exporters.py (24 tests)               │
│ • backend/tests/test_exporters.py (13 tests)                           │
│ • backend/tests/test_api.py (21 tests)                                 │
│ Expected: 58 passed in < 8s                                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ PASS
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Core Backend Engine & Pipeline Suites                          │
│ • backend/tests/test_extraction.py (30 tests)                          │
│ • backend/tests/test_runner.py (9 tests)                               │
│ • backend/tests/test_queue.py (9 tests)                                │
│ • backend/tests/test_context.py (10 tests)                             │
│ • backend/tests/test_models.py (13 tests)                              │
│ Expected: 71 passed in < 6s                                            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ PASS
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Full Adversarial Stress Track Suites (Tier 5 Hardening)        │
│ • backend/tests/test_adversarial_m1.py (20 tests)                      │
│ • backend/tests/test_adversarial_m2.py (68 tests)                      │
│ • tests/adversarial/ (140 tests)                                       │
│ Expected: All passed                                                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ PASS
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 4: Opaque-Box E2E Acceptance Gates                                │
│ • tests/e2e/ (28 tests across Tiers 1-4)                               │
│ Expected: 28 passed in < 2s                                            │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 4.3 Regression Test Checklist

| Step | Scope | Command | Target Pass Count | Success Criteria |
|:----:|-------|---------|:-----------------:|------------------|
| **1** | Exporters Adversarial Suite | `python -m pytest backend/tests/test_adversarial_exporters.py -v` | **24 / 24 PASSED** | Zero failures, zero xfails. `test_html_print_stylesheet_rules` PASSED. |
| **2** | Standard Exporters Suite | `python -m pytest backend/tests/test_exporters.py -v` | **13 / 13 PASSED** | All 4 formats (JSON, SARIF, HTML, PDF) pass validation. |
| **3** | FastAPI Endpoints Suite | `python -m pytest backend/tests/test_api.py -v` | **21 / 21 PASSED** | Upload, status polling, report retrieval, and export endpoints pass. |
| **4** | Combined Tier 1 Suite | `python -m pytest backend/tests/test_adversarial_exporters.py backend/tests/test_exporters.py backend/tests/test_api.py -v` | **58 / 58 PASSED** | 100% pass across all exporter and route tests in < 10s. |
| **5** | Core Backend Unit Suites | `python -m pytest backend/tests/test_extraction.py backend/tests/test_runner.py backend/tests/test_queue.py backend/tests/test_context.py backend/tests/test_models.py -v` | **71 / 71 PASSED** | Zero regressions in safe extraction, CLI runner, queue, context extractor, models. |
| **6** | Adversarial Hardening Suite | `python -m pytest tests/adversarial/ -v` | **140 / 140 PASSED** | All Zip Slip, decompression bomb, and upload stress tests pass. |
| **7** | E2E Acceptance Gate Suite | `python -m pytest tests/e2e/ -v` | **28 / 28 PASSED** | Tiers 1-4 opaque-box acceptance tests pass cleanly. |
| **8** | Full Repository Smoke Test | `python -c "import sys; sys.path.insert(0, 'backend'); from app.models.report import ScanReport; from app.services.exporter import export_report; r=ScanReport(id='chk', status='done'); [export_report(r, f) for f in ['json', 'sarif', 'html', 'pdf']]; print('ALL 4 EXPORTERS FUNCTIONAL')"` | Prints `ALL 4 EXPORTERS FUNCTIONAL` | Smoke test confirms no import errors, syntax issues, or runtime exceptions. |

---

## 5. Verification Method

To independently verify all findings and test suite behavior:

### 5.1 Verification Commands
```powershell
# 1. Run the specific adversarial exporter test suite
python -m pytest backend/tests/test_adversarial_exporters.py -v

# 2. Run the combined exporter and API test suite (Tier 1)
python -m pytest backend/tests/test_adversarial_exporters.py backend/tests/test_exporters.py backend/tests/test_api.py -v

# 3. Run the core backend tests (Tier 2)
python -m pytest backend/tests/test_extraction.py backend/tests/test_runner.py backend/tests/test_queue.py backend/tests/test_context.py backend/tests/test_models.py -v

# 4. Run the E2E acceptance test suite (Tier 4)
python -m pytest tests/e2e/ -v
```

### 5.2 Files to Inspect
- `backend/tests/test_adversarial_exporters.py` (lines 475-605)
- `backend/app/exporters/pdf_exporter.py` (lines 30-34, 208-234)
- `backend/app/exporters/html_exporter.py` (lines 83-87, 132-365)

### 5.3 Invalidation Conditions
- If `test_pdf_adversarial_special_characters_and_xml_tags` raises `ValueError: paraparser: syntax error` on strings containing `<` or `&`.
- If `test_html_xss_in_severity_attribute` allows attribute breakout (`<script>` in HTML output).
- If `test_html_print_stylesheet_rules` fails or xfails due to missing `@media print` rules.
- If any test in `backend/tests/test_exporters.py`, `backend/tests/test_api.py`, or `tests/e2e/` regresses.
