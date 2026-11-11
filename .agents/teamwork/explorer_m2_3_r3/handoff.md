# Explorer Handoff Report: Adversarial Exporter Test Suite Expansion (M2-r3)

**Explorer**: Explorer M2-3-r3 (`explorer`, roles: `explorer`)  
**Target**: Worker M2-r3  
**Milestone**: SecureScan Milestone 2 Iteration 3  
**Date**: 2026-11-07T08:38:00Z  
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_3_r3`

---

## Executive Summary

This investigation resolves Reviewer M2-2-r2 Finding 4 ("Missing Adversarial Assertions in `test_adversarial_exporters.py`"). Empirical reproduction verified that the current exporter codebase fails on all three edge cases:
1. `location.start_line` with `<script>alert(1)</script>` is emitted raw into the HTML export output (`AssertionError`).
2. `cwe_ids: None` raises `TypeError: 'NoneType' object is not iterable` in SARIF export and `TypeError: can only join an iterable` in HTML export.
3. String line numbers (e.g. `'42'`) in `snippet.lines` raise `ValueError: Unknown format code 'd' for object of type 'str'`, while `None` line numbers raise `TypeError`.

This report provides the exact implementation of **three new adversarial test methods** to add to `backend/tests/test_adversarial_exporters.py`, along with the exact code diffs required in `html_exporter.py`, `sarif_exporter.py`, and `json_exporter.py` for Worker M2-r3 to achieve clean execution.

---

## 1. Observation

### 1.1 Current Test Suite Status
- File: `backend/tests/test_adversarial_exporters.py` (756 lines, 24 test methods across 5 classes).
- Current execution passes (`24 passed in 6.80s`), but lacks coverage for line number XSS, null CWE lists, and non-integer snippet line numbers.

### 1.2 Empirical Defect Reproduction on Current Codebase

1. **Defect 1: Stored XSS in `start_line` and `end_line`** (`html_exporter.py:86, 101`):
   ```python
   # Reproduction command:
   r = {'job_id': 'xss', 'status': 'done', 'findings': [{'id': '1', 'rule_id': 'r', 'location': {'file_path': 'a.py', 'start_line': '<script>alert(1)</script>', 'end_line': '<script>alert(2)</script>'}}]}
   html = export_html(r)
   assert '<script>alert(1)</script>' not in html
   ```
   **Empirical Result**: Fails with `AssertionError`. Unescaped output observed:
   - Line 101: `<span><strong>Location:</strong> <code>a.py:<script>alert(1)</script></code></span>`
   - Line 86: `<div class="code-header">a.py : lines <script>alert(1)</script>-<script>alert(2)</script></div>`

2. **Defect 2: Crash on `cwe_ids: None`** (`sarif_exporter.py:54`, `html_exporter.py:61`):
   ```python
   # Reproduction command:
   r = {'job_id': 'x', 'status': 'done', 'findings': [{'id': '1', 'rule_id': 'r', 'cwe_ids': None, 'location': {'file_path': 'a.py', 'start_line': 10}}]}
   export_sarif(r)
   export_html(r)
   ```
   **Empirical Result**:
   - `export_sarif(r)` raises `TypeError: 'NoneType' object is not iterable` at `sarif_exporter.py:54`.
   - `export_html(r)` raises `TypeError: can only join an iterable` at `html_exporter.py:61`.

3. **Defect 3: Crash on String or None Line Numbers** (`html_exporter.py:76`):
   ```python
   # Reproduction command:
   r1 = {'job_id': 'x', 'status': 'done', 'findings': [{'id': '1', 'rule_id': 'r', 'location': {'file_path': 'a.py', 'start_line': 1}, 'snippet': {'lines': [{'line_number': '42', 'content': 'x=1'}]}}]}
   r2 = {'job_id': 'y', 'status': 'done', 'findings': [{'id': '2', 'rule_id': 'r', 'location': {'file_path': 'a.py', 'start_line': 1}, 'snippet': {'lines': [{'line_number': None, 'content': 'y=1'}]}}]}
   export_html(r1)
   export_html(r2)
   ```
   **Empirical Result**:
   - `export_html(r1)` raises `ValueError: Unknown format code 'd' for object of type 'str'`.
   - `export_html(r2)` raises `TypeError: unsupported format string passed to NoneType.__format__`.

---

## 2. Logic Chain

1. **Premise 1**: Security reports frequently render code and finding metadata extracted from third-party repositories. Malicious actors can craft synthetic code or file paths designed to compromise security dashboards and reports.
2. **Premise 2**: In `html_exporter.py`, `start_line` and `end_line` are taken directly from `finding["location"]` without escaping or numeric coercion.
3. **Inference 1**: Direct string interpolation into HTML templates creates a Stored XSS vulnerability (`test_html_xss_in_start_and_end_line` proves and guards against this).
4. **Premise 3**: Upstream tools (scanners, parsers, or normalization layers) may emit `cwe_ids` as `None` or omitted rather than an empty list `[]`.
5. **Inference 2**: Exporters that assume `cwe_ids` is always a list crash on null inputs (`test_exporters_cwe_ids_none_handled_safely` validates that all 4 exporters handle `cwe_ids: None` gracefully).
6. **Premise 4**: Snippet extraction tools may serialize line numbers as strings (e.g. `'42'`) or `None` for unanchored context lines.
7. **Inference 3**: Formatting line numbers with `{lno:4d}` without defensive type coercion causes fatal crashes (`test_html_snippet_string_line_numbers` enforces defensive integer coercion via `_safe_int`).

---

## 3. Caveats

- `test_adversarial_exporters.py` uses `jsonschema.validate` with the `sarif_schema` fixture (defined on line 47). The cross-exporter test `test_exporters_cwe_ids_none_handled_safely` takes `sarif_schema` to validate OASIS SARIF 2.1.0 conformance.
- PDF generation in environments without WeasyPrint relies on the ReportLab fallback implemented in `pdf_exporter.py`. The PDF assertions in `test_exporters_cwe_ids_none_handled_safely` verify binary header `%PDF-`.
- Coercing string line numbers using `_safe_int` or formatting with `_escape` are both safe: numeric lines format as integers, while non-numeric payloads are sanitized against HTML tag injection.

---

## 4. Conclusion & Actionable Test Formulations for Worker M2-r3

Worker M2-r3 must add the following **3 test methods** to `backend/tests/test_adversarial_exporters.py`:

### 4.1 Test Method 1: `test_html_xss_in_start_and_end_line`
**Target Location**: Inside `class TestHtmlExporterAdversarial` (after line 512).

```python
    def test_html_xss_in_start_and_end_line(self):
        """Adversarial challenge: verify malicious HTML/script tags in start_line and end_line are escaped."""
        xss_start = "<script>alert(1)</script>"
        xss_end = '"><svg onload=alert(2)>'
        report = {
            "job_id": "xss-lines-job",
            "status": "done",
            "findings": [
                {
                    "id": "f-xss-line",
                    "rule_id": "r-line-xss",
                    "title": "Clean Title",
                    "description": "Clean Description",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "app/core/vuln.py",
                        "start_line": xss_start,
                        "end_line": xss_end,
                    },
                    "snippet": {
                        "file_path": "app/core/vuln.py",
                        "start_line": xss_start,
                        "end_line": xss_end,
                        "lines": [
                            {"line_number": 1, "content": "x = untrusted_input()", "is_target": True}
                        ],
                    },
                }
            ],
        }

        html_str = export_html(report)

        # Raw executable payloads must never appear unescaped in HTML output
        assert "<script>alert(1)</script>" not in html_str
        assert "<svg onload=alert(2)>" not in html_str
        assert "<script>" not in html_str
        assert "<svg" not in html_str

        # Either properly escaped entity or numeric coercion fallback must be present
        assert ("&lt;script&gt;alert(1)&lt;/script&gt;" in html_str or "1" in html_str)
```

### 4.2 Test Method 2: `test_html_snippet_string_line_numbers`
**Target Location**: Inside `class TestHtmlExporterAdversarial` (after line 512).

```python
    def test_html_snippet_string_line_numbers(self):
        """Verify snippet line numbers as strings (e.g. '42') or None do not crash the HTML exporter."""
        report = {
            "job_id": "snippet-line-types-job",
            "status": "done",
            "findings": [
                {
                    "id": "f-str-lno",
                    "rule_id": "r-str-lno",
                    "title": "String Line Number Finding",
                    "severity": "HIGH",
                    "location": {"file_path": "test.py", "start_line": "42"},
                    "snippet": {
                        "file_path": "test.py",
                        "start_line": "40",
                        "end_line": "45",
                        "lines": [
                            {"line_number": "42", "content": "vuln_call()", "is_target": True},
                            {"line_number": None, "content": "# line number is None", "is_target": False},
                            {"line_number": "N/A", "content": "# non-numeric string", "is_target": False},
                        ],
                    },
                },
                {
                    "id": "f-raw-lines",
                    "rule_id": "r-raw-lines",
                    "title": "Raw String Line Finding",
                    "severity": "MEDIUM",
                    "location": {"file_path": "plain.py", "start_line": 1},
                    "snippet": {
                        "file_path": "plain.py",
                        "lines": [
                            "raw string line without dict structure",
                        ],
                        "raw_content": "raw string line without dict structure",
                    },
                },
            ],
        }

        # Must generate valid HTML string without raising ValueError or TypeError
        html_str = export_html(report)
        assert isinstance(html_str, str)
        assert len(html_str) > 500
        assert "vuln_call()" in html_str
        assert "String Line Number Finding" in html_str
```

### 4.3 Test Method 3: `test_exporters_cwe_ids_none_handled_safely`
**Target Location**: Added inside a new class `class TestMultiFormatExportersAdversarial` at the end of `backend/tests/test_adversarial_exporters.py` (line 757+).

```python
# =========================================================================
# 6. Multi-Format Cross-Cutting Exporters Adversarial Tests
# =========================================================================

class TestMultiFormatExportersAdversarial:
    def test_exporters_cwe_ids_none_handled_safely(self, sarif_schema: dict[str, Any]):
        """Verify all 4 exporters (JSON, SARIF, HTML, PDF) survive findings with cwe_ids=None."""
        report = {
            "job_id": "none-cwe-job",
            "status": "done",
            "summary": {
                "total_findings": 2,
                "by_severity": {"HIGH": 1, "MEDIUM": 1},
            },
            "findings": [
                {
                    "id": "f-none-cwe",
                    "rule_id": "r-null-cwe",
                    "title": "Finding with None CWE",
                    "description": "Vulnerability without mapped CWE IDs.",
                    "severity": "HIGH",
                    "cwe_ids": None,
                    "location": {"file_path": "src/app.py", "start_line": 15},
                },
                {
                    "id": "f-empty-cwe",
                    "rule_id": "r-empty-cwe",
                    "title": "Finding with Empty CWE List",
                    "severity": "MEDIUM",
                    "cwe_ids": [],
                    "location": {"file_path": "src/util.py", "start_line": 20},
                },
            ],
        }

        # 1. JSON Exporter
        json_str = export_json(report)
        json_data = json.loads(json_str)
        assert json_data["job_id"] == "none-cwe-job"
        assert len(json_data["findings"]) == 2

        # 2. SARIF Exporter
        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        sarif_str = export_sarif(report)
        assert "r-null-cwe" in sarif_str
        assert len(sarif_doc["runs"][0]["results"]) == 2

        # 3. HTML Exporter
        html_str = export_html(report)
        assert isinstance(html_str, str)
        assert "Finding with None CWE" in html_str

        # 4. PDF Exporter
        pdf_bytes = export_pdf(report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")
```

---

### 4.4 Companion Production Code Fixes Required for Worker M2-r3

For the new tests to pass, Worker M2-r3 must apply the following targeted fixes:

1. **`backend/app/exporters/html_exporter.py`**:
   - Add `_safe_int` helper:
     ```python
     def _safe_int(val: Any, default: int = 0) -> int:
         try:
             return int(val)
         except (ValueError, TypeError):
             return default
     ```
   - Lines 32, 38-42, 567-583: Wrap counts (`total`, `crit`, `high`, `med`, `low`, `info`, and OWASP `cnt`) with `_safe_int`.
   - Line 61: Coerce `cwe_ids` safely:
     ```python
     raw_cwes = f.get("cwe_ids")
     if isinstance(raw_cwes, list):
         cwes = ", ".join(str(c) for c in raw_cwes if c is not None) or "None"
     elif raw_cwes is not None:
         cwes = str(raw_cwes) or "None"
     else:
         cwes = "None"
     ```
   - Lines 75-84: Defensively format snippet lines:
     ```python
     for ln in lines:
         if isinstance(ln, dict):
             lno = _safe_int(ln.get("line_number"), default=0)
             cnt = ln.get("content", "")
             is_tgt = bool(ln.get("is_target") or ln.get("is_vulnerable", False))
         else:
             lno = 0
             cnt = str(ln)
             is_tgt = False
         cls = "line-highlight" if is_tgt else "line-normal"
         marker = ">> " if is_tgt else "   "
         lno_str = f"{lno:4d}" if lno > 0 else "    "
         snippet_lines.append(
             f'<div class="{cls}"><span class="line-num">{lno_str} | {marker}</span>{_escape(cnt)}</div>'
         )
     ```
   - Line 86: Escape start and end lines:
     ```python
     f'<div class="code-header">{_escape(file_path)} : lines {_escape(start_line)}-{_escape(end_line)}</div>'
     ```
   - Line 101: Escape start line:
     ```python
     <span><strong>Location:</strong> <code>{_escape(file_path)}:{_escape(start_line)}</code></span>
     ```

2. **`backend/app/exporters/sarif_exporter.py`**:
   - Line 54:
     ```python
     for cwe in (f.get("cwe_ids") or []):
         if cwe is not None:
             tags.append(str(cwe))
     ```

3. **`backend/app/exporters/json_exporter.py`**:
   - In `normalize_report_dict` (lines 88-100):
     ```python
     raw_cwe = f_dict.get("cwe_ids")
     if raw_cwe is None and "cweIds" in f_dict:
         raw_cwe = f_dict.get("cweIds")
     if isinstance(raw_cwe, list):
         f_dict["cwe_ids"] = [str(c) for c in raw_cwe if c is not None]
     elif raw_cwe is not None:
         f_dict["cwe_ids"] = [str(raw_cwe)]
     else:
         f_dict["cwe_ids"] = []
     f_dict["cweIds"] = f_dict["cwe_ids"]
     ```

---

## 5. Verification Method

Once Worker M2-r3 implements the code fixes and test methods, independently verify:

```powershell
# 1. Run all 27 adversarial exporter tests (24 existing + 3 new)
python -m pytest backend/tests/test_adversarial_exporters.py -v

# 2. Run specifically the 3 new adversarial test methods
python -m pytest backend/tests/test_adversarial_exporters.py -k "test_html_xss_in_start_and_end_line or test_exporters_cwe_ids_none_handled_safely or test_html_snippet_string_line_numbers" -v

# 3. Run full backend regression suite
python -m pytest backend/tests/ -v

# 4. Run e2e and adversarial suites
python -m pytest tests/e2e/ tests/adversarial/ -v
```

### Invalidation Conditions:
- If `<script>alert(1)</script>` or any unescaped `<script>` / `<svg>` tag is present in the output of `export_html`.
- If `cwe_ids: None` raises `TypeError` in any of the four exporters.
- If snippet string or null line numbers raise `ValueError` or `TypeError`.
- If `pytest backend/tests/test_adversarial_exporters.py` reports any failures.
