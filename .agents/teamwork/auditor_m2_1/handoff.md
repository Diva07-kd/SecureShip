# Forensic Audit Report: Milestone 2 — Backend API, Exporters, and Test Integrity

**Work Product**: Milestone 2 FastAPI REST API, Job Queue, Exporters, and Test Suite  
**Profile**: General Project  
**Integrity Mode**: Development (per `ORIGINAL_REQUEST.md` line 8)  
**Auditor**: Forensic Integrity Auditor (`auditor_m2_1`)  
**Verdict**: **CLEAN**  

---

## Forensic Audit Summary

| Check Name | Status | Summary Details |
|---|---|---|
| Hardcoded Output Detection | **PASS** | No hardcoded responses, synthetic flags, or test-specific bypasses detected in `backend/app/`. |
| Facade & Stub Detection | **PASS** | No stub functions, empty dict/list returns, or `NotImplementedError` placeholders. |
| Pre-populated Artifact Detection | **PASS** | Zero pre-existing `.log`, `*result*`, or `*output*` files in `backend/`. |
| Build & Runtime Test Execution | **PASS** | 223 total passing tests (123 backend, 72 adversarial, 28 e2e). Zero test failures. |
| Rate Limiter Enforcement | **PASS** | SlowAPI limiter state active on `app.state.limiter`; 10 reqs succeed, 11th triggers HTTP 429. |
| Queue Runner CWD Propagation | **PASS** | `queue.py:151-157` resolves `/secureship` and passes `cwd=cli_cwd` to `run_secureship_cli`. |
| Exporter Dynamic Transformation | **PASS** | JSON, SARIF 2.1.0, HTML, and ReportLab PDF dynamically bind from `ScanReport` instances. |
| Test Assertion Substance | **PASS** | Zero trivial (`True == True`, `1 == 1`) assertions across all unit, adversarial, and e2e test files. |

---

## 1. Observation

### 1.1 Static Analysis Observations
1. **No Test Name Bypasses or Hardcoded Return Values**:
   - Automated regex scan for bypass keywords, hardcoded job checks (`if job_id == ...`), and empty returns in `backend/app` yielded only `backend/app/models/report.py:356`, which is an input validation guard `if not raw: return []` in `extract_cwe_ids`.
   - Router endpoints in `backend/app/routers/upload.py`, `backend/app/routers/jobs.py`, `backend/app/routers/reports.py`, and `backend/app/routers/health.py` all retrieve or compute state dynamically via `uuid.uuid4()`, `get_job_queue()`, and `normalize_report_dict(job.report)`.

2. **Genuine Multi-Format Exporters**:
   - `backend/app/exporters/json_exporter.py:16-103`: `normalize_report_dict` inspects `ScanReport` model dumps, maps severity distributions (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), OWASP counts, and line snippets dynamically.
   - `backend/app/exporters/sarif_exporter.py:34-146`: Builds OASIS SARIF v2.1.0 schema conforming dictionaries with deduplicated rule tags (CWE, OWASP, category), physical location URI forward-slash normalization, and severity-to-SARIF level translation (`CRITICAL`/`HIGH` -> `error`, `MEDIUM` -> `warning`, `LOW`/`INFO` -> `note`).
   - `backend/app/exporters/html_exporter.py:20-434`: Interpolates dynamic finding data into an air-gapped, self-contained single HTML file with embedded CSS (`#090d16` dark theme), line markers (`>>`), and zero external stylesheet or script references.
   - `backend/app/exporters/pdf_exporter.py:29-246`: Dynamically instantiates ReportLab `SimpleDocTemplate`, `Table`, `ParagraphStyle`, and `HRFlowable` flowables, generating compliant binary `%PDF-` streams from `ScanReport` payloads.

3. **Rate Limiting Validation**:
   - `backend/app/routers/upload.py:22-29`: `limiter = Limiter(key_func=get_remote_address)` with `@limiter.limit("10/hour")` applied to `POST /api/scan`.
   - `backend/app/main.py:55-57`: Attaches `app.state.limiter = limiter`, registers `_rate_limit_exceeded_handler`, and adds `SlowAPIMiddleware`.
   - Empirical test execution sending 12 sequential upload requests yielded:
     ```
     200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429, 429
     [WARNING] slowapi: ratelimit 10 per 1 hour (testclient) exceeded at endpoint: /api/scan
     ```
     Confirming that rate limiting state is fully functional and not a no-op decorator.

4. **Queue CWD Parameter Propagation**:
   - In `backend/app/core/queue.py:136-157`:
     ```python
     sig = inspect.signature(runner_fn)
     has_cwd = "cwd" in sig.parameters
     ...
     if has_cwd:
         cli_cwd = getattr(settings, "SECURESHIP_CWD", None) or os.environ.get("SECURESHIP_CWD", "/secureship")
         runner_kwargs["cwd"] = cli_cwd

     raw_report = await run_secureship_cli(
         scratch_dir,
         **runner_kwargs,
     )
     ```
   - In `backend/app/core/runner.py:98, 121, 128`:
     `cwd: Optional[Path | str] = None` is resolved as `work_dir = Path(cwd).resolve() if cwd else target` and passed as `cwd=str(work_dir)` to `asyncio.create_subprocess_exec`.

5. **Test Assertion Substance**:
   - Automated regex search for trivial assertions (`assert True`, `assert 1 == 1`, `assert True == True`) across `backend/tests/`, `tests/adversarial/`, and `tests/e2e/` returned 0 occurrences.
   - `backend/tests/test_api.py` and `backend/tests/test_exporters.py` assert on status codes, content-type headers, Content-Disposition filenames, JSON schemas, SARIF drivers, HTML DOM nodes, and PDF binary headers.

---

## 2. Logic Chain

1. **Integrity Mode Conformance**:
   - `ORIGINAL_REQUEST.md` specifies `Integrity mode: development`. Under development mode, the auditor must strictly verify that implementations are non-facade, free of hardcoded test inputs/outputs, and perform genuine computation.
   - Every endpoint in `backend/app/routers/` actively processes incoming requests, enforces validation schemas, delegates to the background queue, and formats real data structures.

2. **Absence of Fabricated Artifacts**:
   - Inspection of the repository confirmed that no pre-populated log or result files were stored in `backend/` to bypass verification.
   - All test runs executed fresh tests in memory and against test databases/queues.

3. **Authentic Multi-Format Exporter Execution**:
   - Direct execution of `export_report` against clean and vulnerable `ScanReport` models confirmed that JSON (620 bytes), SARIF (346 bytes), HTML (8,111 bytes), and PDF (2,449 bytes) were dynamically generated by the exporters with correct Content-Type and MIME headers.

4. **Substantive Test Suites**:
   - The test suites do not self-certify on tautologies. They execute actual FastAPI client requests, stream files to temporary directories, validate PK zip signatures, verify size ceilings (50MB), and verify HTTP 400, 404, 409, 413, 422, and 429 status codes.

---

## 3. Caveats

1. **Strict M1 Adversarial xfails**:
   - Two tests in `backend/tests/test_adversarial_m1.py` are marked as `@pytest.mark.xfail(strict=True)` (`test_finding_map_cwe_to_owasp_missing_none_cwe_ids` and `test_finding_runner_kills_child_on_cancellation`). These are pre-existing, gate-approved findings from Milestone 1 and are not regressions or integrity violations introduced by Milestone 2.
2. **WeasyPrint vs. ReportLab**:
   - While `ORIGINAL_REQUEST.md` noted `weasyprint`, ReportLab 5.1.0 was selected in `PROJECT.md` and implemented to avoid non-portable Windows C-library dependencies (cairo/pango). The binary PDF output satisfies the acceptance criterion ("GET /api/reports/{id}/export?format=pdf returns a valid binary PDF document").

---

## 4. Conclusion

**Verdict: CLEAN**

Milestone 2 implementation exhibits high integrity:
- Zero facades, zero stubs, zero hardcoded return values.
- Genuine multi-format exporters (JSON, SARIF 2.1.0, standalone HTML, binary PDF).
- Genuine SlowAPI rate limiting (10 uploads/hour/IP) enforcing HTTP 429.
- Verified CWD propagation (`/secureship`) in `queue.py`.
- 100% test pass rate across 223 tests with substantive assertions.

The work product is approved for Milestone 2 gate clearance.

---

## 5. Verification Method

To independently reproduce the forensic audit results:

### 5.1 Run Full Test Battery
```powershell
pytest backend/tests/ -v
pytest tests/adversarial/ -v
pytest tests/e2e/ -v
```
*Expected Result*: 223 passing tests (123 backend, 72 adversarial, 28 e2e), 2 M1 xfails, 0 failures.

### 5.2 Empirically Verify Rate Limiter Quota
```powershell
python -c "
import sys; sys.path.insert(0, 'backend')
import io, zipfile
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('test.txt', 'clean')
content = buf.getvalue()

responses = [client.post('/api/scan', files={'file': (f'test_{i}.zip', content, 'application/zip')}).status_code for i in range(12)]
print('Responses:', responses)
assert responses == [200]*10 + [429]*2
print('RATE LIMITER VERIFIED!')
"
```

### 5.3 Empirically Verify Exporter Transformations
```powershell
python -c "
import sys; sys.path.insert(0, 'backend')
from app.models.report import ScanReport
from app.services.exporter import export_report

rep = ScanReport(id='audit-test', status='done')
for fmt in ['json', 'sarif', 'html', 'pdf']:
    b, ct, ext = export_report(rep, fmt)
    assert len(b) > 0
    print(f'{fmt.upper()}: {len(b)} bytes, {ct}')
print('ALL EXPORTERS EMPIRICALLY GENERATED!')
"
```
