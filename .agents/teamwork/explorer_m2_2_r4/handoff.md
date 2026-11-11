# Investigation Report & Implementation Blueprint: Exporter `_safe_int` Robustness & Edge Cases

**Author**: Explorer M2-2-r4 (`explorer`)  
**Target Milestone**: SecureScan Milestone 2 Iteration 4  
**Recipient**: Orchestrator (`bd6ab654-c7e3-4745-8e5f-2ab6c9ba48f5`)  
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_2_r4`  
**Date**: 2026-11-07T09:10:00Z  

---

## 1. Observation

### 1.1 Current Definitions of `_safe_int`
Investigation across `backend/app/exporters/*.py` revealed three distinct definitions of `_safe_int`:

1. **`backend/app/exporters/html_exporter.py`** (lines 23-27):
   ```python
   def _safe_int(val: Any, default: int = 0) -> int:
       try:
           return int(val)
       except (ValueError, TypeError):
           return default
   ```

2. **`backend/app/exporters/sarif_exporter.py`** (lines 33-37):
   ```python
   def _safe_int(val: Any, default: int = 1) -> int:
       try:
           return int(val)
       except (ValueError, TypeError):
           return default
   ```

3. **`backend/app/exporters/pdf_exporter.py`** (lines 36-40):
   ```python
   def _safe_int(val: Any, default: int = 0) -> int:
       try:
           return int(val)
       except (ValueError, TypeError):
           return default
   ```

*Note*: `backend/app/exporters/json_exporter.py` does not define or invoke `_safe_int`. Its snippet line normalization uses index-based line numbering `idx + 1` for string inputs and preserves incoming dictionary structure.

---

### 1.2 Complete Inventory of All `_safe_int` Call Sites (19 Total)

| File | Line | Call Site | Context / Field Protected |
|---|---|---|---|
| `html_exporter.py` | 42 | `_safe_int(summary.get("total_findings"), default=len(findings))` | Summary total findings count |
| `html_exporter.py` | 53 | `_safe_int(by_sev.get("CRITICAL"), default=0)` | Summary CRITICAL count |
| `html_exporter.py` | 54 | `_safe_int(by_sev.get("HIGH"), default=0)` | Summary HIGH count |
| `html_exporter.py` | 55 | `_safe_int(by_sev.get("MEDIUM"), default=0)` | Summary MEDIUM count |
| `html_exporter.py` | 56 | `_safe_int(by_sev.get("LOW"), default=0)` | Summary LOW count |
| `html_exporter.py` | 57 | `_safe_int(by_sev.get("INFO"), default=0)` | Summary INFO count |
| `html_exporter.py` | 91 | `max(1, _safe_int(loc.get("start_line"), default=1))` | Location start line number |
| `html_exporter.py` | 92 | `max(start_line, _safe_int(loc.get("end_line"), default=start_line))` | Location end line number |
| `html_exporter.py` | 101 | `_safe_int(snippet_data.get("start_line"), default=start_line)` | Snippet context start line |
| `html_exporter.py` | 110 | `_safe_int(ln.get("line_number"), default=0)` | Snippet line item number |
| `html_exporter.py` | 166 | `sorted(by_owasp.items(), key=lambda x: -_safe_int(x[1]))` | OWASP breakdown sort key |
| `html_exporter.py` | 167 | `_safe_int(cnt)` | OWASP breakdown category count |
| `sarif_exporter.py` | 93 | `max(1, _safe_int(loc.get("start_line") or loc.get("startLine"), default=1))` | SARIF `region.startLine` |
| `sarif_exporter.py` | 94 | `max(start_line, _safe_int(loc.get("end_line") or loc.get("endLine"), default=start_line))` | SARIF `region.endLine` |
| `sarif_exporter.py` | 95 | `max(1, _safe_int(loc.get("start_column") or loc.get("startColumn"), default=1))` | SARIF `region.startColumn` |
| `sarif_exporter.py` | 97 | `_safe_int(end_col_raw, default=0)` | SARIF `region.endColumn` |
| `pdf_exporter.py` | 53 | `_safe_int(summary.get("total_findings"), default=len(findings))` | PDF Summary total findings |
| `pdf_exporter.py` | 130-134 | `_safe_int(by_sev.get("CRITICAL", 0))` ... `by_sev.get("INFO", 0)` | PDF Severity counts |
| `pdf_exporter.py` | 171 | `_safe_int(cnt)` | PDF OWASP table count |
| `pdf_exporter.py` | 207 | `_safe_int(start_line, default=1)` | PDF Finding header line number |
| `pdf_exporter.py` | 250 | `_safe_int(snippet_data.get("start_line"), default=1)` | PDF Snippet context start line |
| `pdf_exporter.py` | 259 | `_safe_int(ln.get("line_number"), default=0)` | PDF Snippet line item number |

---

### 1.3 Empirical Reproduction of `OverflowError` on Float Infinity

Direct execution against the current codebase:
```python
# Command:
python -c "
import sys; sys.path.insert(0, 'backend')
from app.exporters.html_exporter import export_html
from app.exporters.sarif_exporter import generate_sarif_dict
from app.exporters.pdf_exporter import _export_pdf_reportlab

r_inf = {'job_id': 'inf-job', 'status': 'done', 'findings': [{'id': '1', 'rule_id': 'r', 'location': {'file_path': 'a.py', 'start_line': float('inf')}}]}

try: export_html(r_inf)
except Exception as e: print(f'export_html: {type(e).__name__}: {e}')

try: generate_sarif_dict(r_inf)
except Exception as e: print(f'generate_sarif_dict: {type(e).__name__}: {e}')

r_pdf_inf = {'job_id': 'pdf-inf', 'status': 'done', 'summary': {'total_findings': float('inf')}}
try: _export_pdf_reportlab(r_pdf_inf)
except Exception as e: print(f'pdf_exporter: {type(e).__name__}: {e}')
"
```

**Verbatim Output**:
```
export_html: OverflowError: cannot convert float infinity to integer
generate_sarif_dict: OverflowError: cannot convert float infinity to integer
pdf_exporter: OverflowError: cannot convert float infinity to integer
```

---

### 1.4 Empirical Behavior of Python `int()` on Float & Numeric Representations

Empirical evaluation of Python 3.12 conversion behavior across various numeric edge cases:

| Input Expression | Type | `int(val)` Result / Exception | Exception Type | Caught by `(ValueError, TypeError)`? | Caught by `(ValueError, TypeError, OverflowError)`? |
|---|---|---|---|---|---|
| `float('inf')` | `float` | `OverflowError: cannot convert float infinity to integer` | `OverflowError` | **NO (CRASH)** | **YES (returns default)** |
| `float('-inf')` | `float` | `OverflowError: cannot convert float infinity to integer` | `OverflowError` | **NO (CRASH)** | **YES (returns default)** |
| `float('nan')` | `float` | `ValueError: cannot convert float NaN to integer` | `ValueError` | YES | YES |
| `'inf'` / `'-inf'` | `str` | `ValueError: invalid literal for int() with base 10: 'inf'` | `ValueError` | YES | YES |
| `'nan'` / `'NaN'` | `str` | `ValueError: invalid literal for int() with base 10: 'nan'` | `ValueError` | YES | YES |
| `1e500` | `float` | Evaluates to `inf` -> `OverflowError` | `OverflowError` | **NO (CRASH)** | **YES (returns default)** |
| `'1e500'` | `str` | `ValueError: invalid literal for int() with base 10: '1e500'` | `ValueError` | YES | YES |
| `1e308` | `float` | Produces 309-digit integer (arbitrary precision) | None (Success) | N/A | N/A |
| `'42.0'` | `str` | `ValueError: invalid literal for int() with base 10: '42.0'` | `ValueError` | YES (returns default) | YES (returns default) |
| `Decimal('Infinity')` | `Decimal` | `OverflowError: cannot convert Infinity to integer` | `OverflowError` | **NO (CRASH)** | **YES (returns default)** |
| `Decimal('NaN')` | `Decimal` | `ValueError: cannot convert NaN to integer` | `ValueError` | YES | YES |
| `None` | `NoneType` | `TypeError: int() argument must be... not 'NoneType'` | `TypeError` | YES | YES |
| `[1, 2]` / `{'a': 1}` | `list`/`dict` | `TypeError: int() argument must be...` | `TypeError` | YES | YES |
| `complex(1, 2)` | `complex` | `TypeError: int() argument must be... not 'complex'` | `TypeError` | YES | YES |
| `'9' * 5000` | `str` | `ValueError: Exceeds the limit (4300 digits)...` | `ValueError` | YES | YES |

---

### 1.5 Empirical Reproduction of SARIF Column Invariant Defect
In `backend/app/exporters/sarif_exporter.py` lines 95-106:
```python
start_col = max(1, _safe_int(loc.get("start_column") or loc.get("startColumn"), default=1))
end_col_raw = loc.get("end_column") or loc.get("endColumn")
end_col = _safe_int(end_col_raw, default=0) if end_col_raw is not None else None

region: dict[str, Any] = {
    "startLine": start_line,
    "endLine": end_line,
    "startColumn": start_col,
}
if end_col and end_col > 0:
    region["endColumn"] = end_col
```
When `start_line == 1`, `end_line == 1`, `start_column == 10`, `end_column == 5`:
- **Current Output**: `{'startLine': 1, 'endLine': 1, 'startColumn': 10, 'endColumn': 5}`
- **Specification**: OASIS SARIF 2.1.0 §3.30.2 mandates: `When startLine equals endLine, endColumn MUST be greater than or equal to startColumn`.

---

## 2. Logic Chain

1. **Observation 1.1 & 1.3**: All three exporters (`html_exporter.py:23`, `sarif_exporter.py:33`, `pdf_exporter.py:36`) define `_safe_int` with `except (ValueError, TypeError): return default`.
2. **Observation 1.4**: In Python's exception hierarchy:
   ```
   BaseException
    └── Exception
         ├── ArithmeticError
         │    └── OverflowError  <-- Inherits from ArithmeticError, NOT ValueError or TypeError
         ├── TypeError
         └── ValueError
   ```
3. **Deduction 1**: Calling `int(float('inf'))`, `int(float('-inf'))`, or `int(Decimal('Infinity'))` raises `OverflowError`. Because `OverflowError` is not a subclass of `ValueError` or `TypeError`, the exception escapes `_safe_int` and propagates up the call stack, aborting report export and producing HTTP 500 crashes.
4. **Observation 1.2**: `_safe_int` is invoked on all location coordinates (`start_line`, `end_line`, `start_column`, `end_column`), snippet line numbers, and summary statistic aggregations (`total_findings`, severity counts, OWASP counts). A single float infinity in any scanner output or crafted report payload triggers this crash.
5. **Observation 1.4**: Catching `OverflowError` alongside `(ValueError, TypeError)` handles 100% of non-finite float instances (`float('inf')`, `float('-inf')`, `float('nan')`), string infinities, string NaNs, incompatible collections, complex numbers, and integer string length overflows (`sys.set_int_max_str_digits`).
6. **Observation 1.5**: In `sarif_exporter.py`, if `start_line == end_line`, `endColumn` must be clamped to `max(start_col, end_col)` to adhere to the OASIS SARIF 2.1.0 standard.
7. **Conclusion**: Hardening `_safe_int` across `html_exporter.py`, `sarif_exporter.py`, and `pdf_exporter.py` with `except (ValueError, TypeError, OverflowError): return default`, and adding the column clamp in `sarif_exporter.py`, completely resolves both issues with zero overhead and zero added dependencies.

---

## 3. Caveats

1. **String Floats (e.g., `"42.0"`)**:
   - In standard Python, `int("42.0")` raises `ValueError: invalid literal for int() with base 10: '42.0'`.
   - With `except (ValueError, TypeError, OverflowError): return default`, passing `"42.0"` returns `default`.
   - In JSON-parsed reports (`json.loads`), numbers are parsed as either `int` (e.g. `42`) or `float` (e.g. `42.0`), NOT float strings. For native `float` values like `42.0`, `int(42.0)` succeeds and returns `42`.
   - If upstream scanners emit float strings like `"42.0"`, an optional two-stage fallback (Blueprint Option B) can be used. However, Blueprint Option A matches Reviewer M2-1-r3's specification and preserves exact integer conversion semantics without introducing extra parsing overhead or importing `math`. Both options are documented below.
2. **Arbitrary Precision Ints**:
   - `1e308` is a finite float. `int(1e308)` creates a 309-digit integer.
   - In downstream HTML and PDF exporters, line numbers are rendered in string templates. In SARIF, `region.startLine` is validated as a positive integer. Downstream bounds checks (`max(1, ...)`) handle finite large integers safely without exceptions.
3. **Read-Only Invariant**:
   - As an Explorer, no source files were modified. All blueprints and verification scripts are staged for the Worker agent.

---

## 4. Conclusion & Exact Blueprints

### 4.1 Blueprint Option A: Recommended Universal Hardened `_safe_int` (Direct & Idiomatic)

This is the primary recommended fix. It directly catches `OverflowError`, requires no new module imports, introduces no runtime overhead, and matches Reviewer M2-1-r3's finding.

#### 1. File: `backend/app/exporters/html_exporter.py`
**Target lines 23-28**:
```python
<<<<
def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
====
def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default
>>>>
```

#### 2. File: `backend/app/exporters/sarif_exporter.py`
**Target lines 33-38**:
```python
<<<<
def _safe_int(val: Any, default: int = 1) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
====
def _safe_int(val: Any, default: int = 1) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default
>>>>
```

**Target lines 99-106 (SARIF Column Invariant Fix)**:
```python
<<<<
        region: dict[str, Any] = {
            "startLine": start_line,
            "endLine": end_line,
            "startColumn": start_col,
        }
        if end_col and end_col > 0:
            region["endColumn"] = end_col
====
        region: dict[str, Any] = {
            "startLine": start_line,
            "endLine": end_line,
            "startColumn": start_col,
        }
        if end_col and end_col > 0:
            if start_line == end_line:
                end_col = max(start_col, end_col)
            region["endColumn"] = end_col
>>>>
```

#### 3. File: `backend/app/exporters/pdf_exporter.py`
**Target lines 36-41**:
```python
<<<<
def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
====
def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default
>>>>
```

---

### 4.2 Blueprint Option B: Enhanced Two-Stage Fallback Variant (Optional Extension)

If the team also wishes to gracefully recover float strings (e.g. `"42.0"` -> `42` or scientific `"1e5"` -> `100000`), the following definition can be used:

```python
import math

def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        pass
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return default
        return int(f)
    except (ValueError, TypeError, OverflowError):
        return default
```
*Assessment*: Option A is preferred because standard JSON scanner inputs represent numbers natively as integers or floats (which `int(42.0)` already handles directly without `float()`). Option A is cleaner, faster, and does not require importing `math`.

---

### 4.3 Blueprint for Test Suite Extension: `backend/tests/test_adversarial_exporters.py`

To ensure automated regression coverage, Worker M2-r4 should add the following two test methods to `backend/tests/test_adversarial_exporters.py` in `TestMultiFormatExportersAdversarial` and `TestSarifExporterAdversarial`:

```python
    def test_exporters_float_infinity_and_nan_overflow(self, sarif_schema: dict[str, Any]):
        """Verify all exporters handle float infinity, -infinity, and NaN without OverflowError."""
        adv_report = {
            "job_id": "float-infinity-test",
            "status": "done",
            "summary": {
                "total_findings": float("inf"),
                "by_severity": {
                    "CRITICAL": float("inf"),
                    "HIGH": float("-inf"),
                    "MEDIUM": float("nan"),
                    "LOW": "inf",
                    "INFO": 0,
                },
                "by_owasp": {"A01:2021": float("inf")},
            },
            "findings": [
                {
                    "id": "f-inf",
                    "rule_id": "r-inf",
                    "title": "Float Infinity Finding",
                    "severity": "HIGH",
                    "location": {
                        "file_path": "infinity.py",
                        "start_line": float("inf"),
                        "end_line": float("-inf"),
                        "start_column": float("inf"),
                        "end_column": float("-inf"),
                    },
                    "snippet": {
                        "file_path": "infinity.py",
                        "start_line": float("inf"),
                        "lines": [
                            {"line_number": float("inf"), "content": "x = 1", "is_target": True},
                            {"line_number": float("-inf"), "content": "y = 2", "is_target": False},
                            {"line_number": float("nan"), "content": "z = 3", "is_target": False},
                        ],
                    },
                }
            ],
        }

        # 1. HTML Exporter must not crash with OverflowError
        html_out = export_html(adv_report)
        assert isinstance(html_out, str)
        assert len(html_out) > 0

        # 2. SARIF Exporter must not crash and validate against schema
        sarif_doc = generate_sarif_dict(adv_report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        region = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["endLine"] >= region["startLine"]

        # 3. PDF Exporter must not crash with OverflowError
        pdf_bytes = export_pdf(adv_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")

    def test_sarif_same_line_column_ordering_invariant(self, sarif_schema: dict[str, Any]):
        """Verify SARIF clamps endColumn >= startColumn when startLine == endLine per OASIS §3.30.2."""
        report = {
            "job_id": "sarif-col-order",
            "status": "done",
            "findings": [
                {
                    "id": "f-col",
                    "rule_id": "r-col",
                    "severity": "MEDIUM",
                    "location": {
                        "file_path": "col.py",
                        "start_line": 10,
                        "end_line": 10,
                        "start_column": 25,
                        "end_column": 12,  # inverted: end < start
                    },
                }
            ],
        }
        sarif_doc = generate_sarif_dict(report)
        jsonschema.validate(instance=sarif_doc, schema=sarif_schema)
        region = sarif_doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["endLine"] == 10
        assert region["startColumn"] == 25
        assert region["endColumn"] >= region["startColumn"]  # Clamped to >= 25
```

---

## 5. Verification Method

Once Worker M2-r4 applies the blueprint, verification must be executed using the following commands:

### 5.1 Verification Commands
```bash
# 1. Direct one-liner to verify float('inf') handling across HTML, SARIF, and PDF
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.html_exporter import export_html; from app.exporters.sarif_exporter import generate_sarif_dict; from app.exporters.pdf_exporter import export_pdf; r={'job_id':'x','status':'done','summary':{'total_findings':float('inf'),'by_severity':{'CRITICAL':float('inf')}},'findings':[{'id':'1','rule_id':'r','location':{'file_path':'a.py','start_line':float('inf')}}]}; export_html(r); generate_sarif_dict(r); export_pdf(r); print('ALL EXPORTERS HANDLED FLOAT INF SUCCESSFULLY!')"

# 2. Verify SARIF column ordering invariant
python -c "import sys; sys.path.insert(0, 'backend'); from app.exporters.sarif_exporter import generate_sarif_dict; r={'job_id':'1','status':'done','findings':[{'id':'f1','rule_id':'r1','location':{'file_path':'a.py','start_line':1,'end_line':1,'start_column':10,'end_column':5}}]}; doc=generate_sarif_dict(r); reg=doc['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']; assert reg['endColumn'] >= reg['startColumn'], f'Invalid column ordering: {reg}'; print('SARIF COLUMN INVARIANT VERIFIED!')"

# 3. Run adversarial exporter test suite
pytest backend/tests/test_adversarial_exporters.py -v

# 4. Run entire project test suite
python -m pytest
```

### 5.2 Invalidation Conditions
- If any exporter raises `OverflowError` when provided `float('inf')` or `-float('inf')`.
- If `generate_sarif_dict` emits `endColumn < startColumn` when `startLine == endLine`.
- If any existing tests fail in `python -m pytest`.
