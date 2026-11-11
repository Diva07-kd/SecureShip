# Handoff Report: Explorer M2-1-r3 — HTML Exporter Type Coercion & Escaping

**Agent**: Explorer M2-1-r3 (`explorer`)  
**Role**: HTML Exporter Type Coercion & Escaping Explorer  
**Milestone**: Milestone 2 Iteration 3 (M2-r3)  
**Recipient**: Orchestrator (`bd6ab654-c7e3-4745-8e5f-2ab6c9ba48f5`) / Worker M2-r3  
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_1_r3`  
**Patch Artifact**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_1_r3\proposed_fixes.patch`  

---

## 1. Observation

Direct empirical observations, file paths, line numbers, and verbatim reproduction outputs:

### 1.1 Empirical Defect Reproductions

1. **Stored XSS via `start_line` in `backend/app/exporters/html_exporter.py` (lines 86, 101)**:
   - Command:
     ```powershell
     python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','location':{'file_path':'a.py','start_line':'<script>alert(1)</script>'}}]}; html=export_html(r); assert '<script>alert(1)</script>' not in html, 'Stored XSS in start_line!'"
     ```
   - Verbatim Output:
     ```
     Traceback (most recent call last):
       File "<string>", line 1, in <module>
     AssertionError: Stored XSS in start_line!
     ```
   - Observation: `start_line` was extracted via `loc.get("start_line", 1)` and directly interpolated into `<div class="code-header">{_escape(file_path)} : lines {start_line}-{end_line}</div>` (line 86) and `<span><strong>Location:</strong> <code>{_escape(file_path)}:{start_line}</code></span>` (line 101) without integer coercion or HTML escaping.

2. **Stored XSS via Summary Counts in `html_exporter.py` (lines 567, 571, 575, 579, 583)**:
   - Command:
     ```powershell
     python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','summary':{'by_severity':{'CRITICAL':'<script>alert(2)</script>'}},'findings':[]}; html=export_html(r); assert '<script>alert(2)</script>' not in html, 'Stored XSS in by_severity!'"
     ```
   - Verbatim Output:
     ```
     Traceback (most recent call last):
       File "<string>", line 1, in <module>
     AssertionError: Stored XSS in by_severity!
     ```
   - Observation: `crit = by_sev.get("CRITICAL", 0)` directly interpolated string/malicious payloads into `<div class="stat-value" style="color: var(--critical);">{crit}</div>`.

3. **Unhandled `TypeError` on `cwe_ids: None` in `html_exporter.py` (line 61)**:
   - Command:
     ```powershell
     python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','cwe_ids':None,'location':{'file_path':'a.py','start_line':1}}]}; export_html(r)"
     ```
   - Verbatim Output:
     ```
     Traceback (most recent call last):
       File "<string>", line 1, in <module>
       File "C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\backend\app\exporters\html_exporter.py", line 61, in export_html
         cwes = ", ".join(f.get("cwe_ids", [])) or "None"
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     TypeError: can only join an iterable
     ```
   - Observation: `dict.get("cwe_ids", [])` returns `None` when `"cwe_ids"` key exists with value `None`, causing `", ".join(None)` to raise fatal `TypeError`.

4. **Unhandled `ValueError` on string line numbers in snippet rendering in `html_exporter.py` (line 82)**:
   - Command:
     ```powershell
     python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','location':{'file_path':'a.py','start_line':1},'snippet':{'lines':[{'line_number':'1','content':'x'}]}}]}; export_html(r)"
     ```
   - Verbatim Output:
     ```
     Traceback (most recent call last):
       File "<string>", line 1, in <module>
       File "C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\backend\app\exporters\html_exporter.py", line 82, in export_html
         f'<div class="{cls}"><span class="line-num">{lno:4d} | {marker}</span>{_escape(cnt)}</div>'
                                                     ^^^^^^^^
     ValueError: Unknown format code 'd' for object of type 'str'
     ```
   - Observation: Line 76 extracted `lno = ln.get("line_number")` without type coercion. Python format specifier `4d` requires an integer and throws `ValueError` on strings and `TypeError` on `None`.

5. **Unhandled `TypeError` on `cwe_ids: None` in `backend/app/exporters/sarif_exporter.py` (line 54)**:
   - Command:
     ```powershell
     python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.sarif_exporter import generate_sarif_dict; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','cwe_ids':None,'location':{'file_path':'a.py','start_line':1}}]}; generate_sarif_dict(r)"
     ```
   - Verbatim Output:
     ```
     Traceback (most recent call last):
       File "<string>", line 1, in <module>
       File "C:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\backend\app\exporters\sarif_exporter.py", line 54, in generate_sarif_dict
         for cwe in f.get("cwe_ids", []):
                    ^^^^^^^^^^^^^^^^^^^^
     TypeError: 'NoneType' object is not iterable
     ```

6. **Prior Successful Pattern in `pdf_exporter.py`**:
   - Inspected `backend/app/exporters/pdf_exporter.py` lines 36-40:
     ```python
     def _safe_int(val: Any, default: int = 0) -> int:
         try:
             return int(val)
         except (ValueError, TypeError):
             return default
     ```
   - In `pdf_exporter.py` lines 206-207, 259-267, all line numbers and summary counts are passed through `_safe_int`, which completely eliminated paraparser crashes and type errors in PDF export.

---

## 2. Logic Chain

1. **Step 1 (Root Cause of XSS)**: In `html_exporter.py`, the exporter assumed that `start_line`, `end_line`, and summary count fields would always be primitive integers supplied by trustworthy scanners. However, reports can be parsed from untrusted archives or arbitrary scanner outputs. Direct string interpolation `{start_line}` into HTML attributes and content allows arbitrary `<script>` injection.
2. **Step 2 (Root Cause of Unhandled Exceptions)**: In both Python 3.11/3.12, `dict.get(k, default)` returns the value associated with key `k` if the key exists, even if its value is `None`. Therefore, `{ "cwe_ids": None }.get("cwe_ids", [])` evaluates to `None`. Any subsequent operation assuming an iterable (`", ".join(...)` or `for c in ...`) fails with `TypeError`.
3. **Step 3 (Root Cause of Snippet Format Crash)**: Line numbers in snippet dictionaries may be extracted as string tokens from scanners or raw files (e.g., `"42"` or `None`). Formatting string `f"{lno:4d}"` strictly requires `int`.
4. **Step 4 (Remediation Strategy)**:
   - Implement `_safe_int(val, default)` helper in `html_exporter.py` and `sarif_exporter.py`.
   - Coerce all summary statistics (`total`, `crit`, `high`, `med`, `low`, `info`, and OWASP counts) using `_safe_int`.
   - Coerce finding locations:
     `start_line = max(1, _safe_int(loc.get("start_line"), default=1))`
     `end_line = max(start_line, _safe_int(loc.get("end_line"), default=start_line))`
     This guarantees both integer safety against XSS and structural invariants (`end_line >= start_line >= 1`).
   - Coerce snippet line numbers:
     `lno = _safe_int(ln.get("line_number"), default=0)` if `isinstance(ln, dict)` else `0`.
   - Guard `cwe_ids` at three layers (defense in depth):
     1. In `normalize_report_dict` (`json_exporter.py`), normalize `cwe_ids` to `[str(c) for c in raw if c is not None]`.
     2. In `html_exporter.py`, check `isinstance(raw_cwes, list)` and filter `None` elements.
     3. In `sarif_exporter.py`, iterate `(f.get("cwe_ids") or [])` and filter `None` elements.
   - Guard against non-dict elements in `findings` and `snippet.lines`.
   - Add snippet fallback: if `lines` is empty but `raw_content` exists, split lines and generate synthesized snippet lines, matching `pdf_exporter.py`.

---

## 3. Caveats

- **No Caveats on Core Exporters**: The proposed type coercion and escaping patterns are identical to those already proven in `pdf_exporter.py`.
- **Air-Gapped Constraint**: The changes introduce zero third-party dependencies, preserving pure-Python offline air-gap execution.
- **Backward Compatibility**: Valid reports containing standard integer line numbers and list-of-strings `cwe_ids` produce identical, schema-compliant outputs.

---

## 4. Conclusion & Concrete Recommendations

The four issues reported by Reviewer M2-2-r2 are fully understood, empirically reproduced, and addressed by a minimal, robust patch (`proposed_fixes.patch`).

### Summary of Required Changes for Worker M2-r3:

1. **`backend/app/exporters/html_exporter.py`**:
   - Define `_safe_int(val: Any, default: int = 0) -> int`.
   - In `export_html`:
     - Coerce `total`, `crit`, `high`, `med`, `low`, `info` using `_safe_int`.
     - In OWASP loop: sort using `key=lambda x: -_safe_int(x[1])`, cast `cnt_int = _safe_int(cnt)`, and interpolate `{cnt_int}`.
     - In findings loop:
       - Handle `cwe_ids`: support `None`, scalar strings/integers, and lists with `None` items.
       - Calculate `start_line = max(1, _safe_int(loc.get("start_line"), default=1))` and `end_line = max(start_line, _safe_int(loc.get("end_line"), default=start_line))`.
       - In snippet rendering: coerce `lno = _safe_int(ln.get("line_number"), default=0)` (preventing `{lno:4d}` format crash), handle non-dict lines, and support `raw_content` fallback.

2. **`backend/app/exporters/sarif_exporter.py`**:
   - Define `_safe_int(val: Any, default: int = 0) -> int`.
   - Change `for cwe in f.get("cwe_ids", []):` to `for cwe in (f.get("cwe_ids") or []): if cwe is not None: tags.append(str(cwe))`.
   - Coerce `startLine`, `endLine`, `startColumn`, `endColumn` through `_safe_int` with minimum bounds.

3. **`backend/app/exporters/json_exporter.py`**:
   - In `normalize_report_dict`: guarantee `f_dict["cwe_ids"]` and `f_dict["cweIds"]` are clean `list[str]`.

4. **`backend/tests/test_adversarial_exporters.py`**:
   - Add `test_html_xss_in_start_line_and_summary_counts`.
   - Add `test_html_malformed_cwe_and_snippet_lines`.
   - Add `test_sarif_null_cwe_and_malformed_location`.

---

## 5. Verification Method

Worker M2-r3 and Reviewer M2-2-r3 can verify all fixes using the following commands:

```powershell
# 1. Verify start_line XSS rejection in html_exporter
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','location':{'file_path':'a.py','start_line':'<script>alert(1)</script>'}}]}; html=export_html(r); assert '<script>alert(1)</script>' not in html; print('PASS: start_line XSS blocked')"

# 2. Verify summary count XSS rejection in html_exporter
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','summary':{'by_severity':{'CRITICAL':'<script>alert(2)</script>'}},'findings':[]}; html=export_html(r); assert '<script>alert(2)</script>' not in html; print('PASS: by_severity XSS blocked')"

# 3. Verify cwe_ids: None handling in html_exporter and sarif_exporter
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; from app.exporters.sarif_exporter import generate_sarif_dict; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','cwe_ids':None,'location':{'file_path':'a.py','start_line':1}}]}; export_html(r); generate_sarif_dict(r); print('PASS: cwe_ids None handled')"

# 4. Verify string line numbers in snippet rendering
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; r={'job_id':'x','status':'done','findings':[{'id':'1','rule_id':'r','location':{'file_path':'a.py','start_line':1},'snippet':{'lines':[{'line_number':'1','content':'x'}]}}]}; export_html(r); print('PASS: string line numbers handled')"

# 5. Run adversarial exporters suite
python -m pytest backend/tests/test_adversarial_exporters.py -v

# 6. Run full backend suite
python -m pytest backend/tests/ -v
```

**Invalidation Conditions**:
- Any `<script>` tag appearing unescaped anywhere in `export_html(report)` when malicious payloads are injected.
- Any unhandled `TypeError` or `ValueError` when `cwe_ids` is `None` or line numbers are strings.
- Any regression in SARIF 2.1.0 JSON Schema compliance.
