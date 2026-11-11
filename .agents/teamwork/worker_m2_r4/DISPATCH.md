# Dispatch: Worker M2-r4 (Backend Remediation & Exporter Hardening)

## 2026-11-07T09:05:00Z

**Assigned Agent**: Worker M2-r4 (`teamwork_worker`)
**Working Directory**: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\worker_m2_r4`
**Parent Conversation ID**: `bd6ab654-c7e3-4745-8e5f-2ab6c9ba48f5`

### Mandatory Reading
1. `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md` (MANDATORY — Read first!)
2. `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md`
3. Forensic Auditor Evidence: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\auditor_m2_1_r3\handoff.md`
4. Reviewer 1 Report: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\reviewer_m2_1_r3\handoff.md`
5. Explorer 1 Blueprint: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_1_r4\handoff.md`
6. Explorer 2 Blueprint: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_2_r4\handoff.md`
7. Explorer 3 Blueprint: `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m2_3_r4\handoff.md`

### MANDATORY INTEGRITY WARNING
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.
DO NOT fabricate test outputs. You MUST execute every verification command and paste authentic terminal logs in your handoff report.

### File Write Ownership
You exclusively own:
- `backend/app/exporters/json_exporter.py`
- `backend/app/exporters/html_exporter.py`
- `backend/app/exporters/sarif_exporter.py`
- `backend/app/exporters/pdf_exporter.py`
- `backend/tests/test_adversarial_exporters.py`

### Implementation Tasks
1. **In `backend/app/exporters/json_exporter.py`**:
   Implement the robust `normalize_report_dict` and `_safe_int` from Explorer 1's blueprint. Ensure all snippet line types (model, dict, str, int, None) are normalized with snake_case and camelCase aliases without calling `dict(ln)` on raw strings.
2. **In `backend/app/exporters/html_exporter.py`, `sarif_exporter.py`, `pdf_exporter.py`**:
   Update `_safe_int` to catch `(ValueError, TypeError, OverflowError)`.
3. **In `backend/app/exporters/sarif_exporter.py`**:
   Enforce OASIS SARIF 2.1.0 §3.30.2 column ordering:
   `if start_line == end_line and end_col and end_col > 0: end_col = max(start_col, end_col)`
4. **In `backend/tests/test_adversarial_exporters.py`**:
   Add comprehensive adversarial tests for:
   - `float('inf')`, `-float('inf')`, `float('nan')` across HTML, SARIF, PDF, and JSON exporters.
   - OASIS SARIF column ordering when `start_line == end_line` and `start_column > end_column`.
   - Snippet line normalization with raw strings, non-dict objects, and mixed line structures.
5. **Run Verification Commands**:
   - `pytest backend/tests/test_adversarial_exporters.py -v`
   - `pytest backend/tests/ -v`
   - `pytest tests/adversarial/ -v`
   - `pytest tests/e2e/ -v`
   - `python -m pytest`
   - `npm --prefix frontend run build`

Document actual, authentic terminal outputs in `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\worker_m2_r4\handoff.md`.
Send completion message to parent: `bd6ab654-c7e3-4745-8e5f-2ab6c9ba48f5`.
