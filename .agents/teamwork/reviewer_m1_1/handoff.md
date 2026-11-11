# Milestone 1 Code Review & Adversarial Challenge Report

- **Date:** 2026-11-07T06:46:00Z
- **Reviewer:** `teamwork_reviewer` (reviewer_m1_1)
- **Roles:** Reviewer & Adversarial Critic
- **Subject:** Milestone 1 — Backend Core: Extraction, Runner & Queue
- **Verdict:** **APPROVE**

---

## Review Summary

**Verdict**: **APPROVE**

All code components for Milestone 1 (`safe_extract.py`, `runner.py`, `queue.py`, `context_extractor.py`, `models/report.py`, `models/job.py`, `config.py`) have been independently inspected, reviewed against architectural requirements, stress-tested against adversarial inputs, and verified via test execution. Zero integrity violations (hardcoded test answers, dummy facades, or shortcuts) were detected. All 71 unit tests in `backend/tests` and all 28 E2E tests in `tests/e2e` pass with 100% success.

---

## Findings

### [Minor] Finding 1: Root `pytest.ini` Missing Explicit `pytest_asyncio.plugin` under Plugin Autoload Suppression
- **What**: When `PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"` environment variable is set in the shell, running `pytest tests/e2e -v` without `-p pytest_asyncio.plugin` fails on 2 async tests (`test_300_second_timeout_semantics` and `test_queue_concurrency_is_strictly_one`) because root `pytest.ini` does not declare `-p pytest_asyncio.plugin` in `addopts`.
- **Where**: `pytest.ini:3` vs `backend/pytest.ini:4`.
- **Why**: `backend/pytest.ini` specifies `addopts = -p no:hypothesis -p pytest_asyncio.plugin`, making it robust against plugin autoload disabling. Root `pytest.ini` specifies `addopts = -p no:hypothesispytest -p no:hypothesis` without `-p pytest_asyncio.plugin`.
- **Suggestion**: In root `pytest.ini`, update `addopts` to include `-p pytest_asyncio.plugin` so that running `pytest tests/e2e -v` with `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"` succeeds without needing manual `-p` command-line flags. (Note: As a reviewer under review-only constraints, this was observed during independent verification and verified to pass completely when `-p pytest_asyncio.plugin` is passed).

---

## Verified Claims

1. **Safe Extraction Defenses (`backend/app/core/safe_extract.py`)**:
   - Zip-slip path traversal defense (blocking `..`, leading slashes, Windows drive letters `C:`, and reserved device names `CON`, `NUL`, `AUX`, `COM1-9`, `LPT1-9`) -> **VERIFIED (Pass)**
   - Symlink defense (detecting and rejecting `0xA1ED`, `stat.S_IFLNK` upper/lower bits, FIFOs, special device files) -> **VERIFIED (Pass)**
   - Zip-bomb defense (pre-extraction compression ratio > 100x check and dynamic streaming chunk ratio verification) -> **VERIFIED (Pass)**
   - Size quotas (single uncompressed file > 10 MB and total uncompressed archive > 50 MB rejected) -> **VERIFIED (Pass)**
   - Inode / entry count limit (max 10,000 files) -> **VERIFIED (Pass)**
   - Atomic rollback and cleanup (`_cleanup_partial_extraction` and `_handle_remove_readonly` Windows chmod error recovery) -> **VERIFIED (Pass)**

2. **Subprocess Runner (`backend/app/core/runner.py`)**:
   - Subprocess invocation uses argument-list form `[node_bin, cli_dist, "scan", target, "--json"]` via `asyncio.create_subprocess_exec` with strictly zero `shell=True` -> **VERIFIED (Pass)**
   - 300-second hard timeout terminates child process and reaps zombies via `process.kill()` and `process.wait()` -> **VERIFIED (Pass)**
   - Exit code 0 (clean scan) and exit code 1 (findings detected) are both parsed as successful scans with valid JSON report -> **VERIFIED (Pass)**
   - Exit codes > 1 or malformed JSON raise `ScannerExecutionError` -> **VERIFIED (Pass)**

3. **Asynchronous Job Queue (`backend/app/core/queue.py`)**:
   - `asyncio.Queue` concurrency is strictly 1 via single background worker task -> **VERIFIED (Pass)**
   - Job lifecycle state machine transitions (`QUEUED` -> `RUNNING` -> `DONE` / `FAILED`) correctly tracked -> **VERIFIED (Pass)**
   - Temporary scan directories and uploaded zip archives are reliably cleaned up in `finally:` blocks -> **VERIFIED (Pass)**

4. **Code Context Extractor (`backend/app/core/context_extractor.py`)**:
   - Extracts exact ±5 context lines around vulnerable span with safe boundary clamping -> **VERIFIED (Pass)**
   - Rejects binary files containing null bytes in initial 4 KB -> **VERIFIED (Pass)**
   - Safely decodes UTF-8 with fallback to Latin-1 -> **VERIFIED (Pass)**
   - Blocks path traversal in finding `filePath` -> **VERIFIED (Pass)**

5. **Unified Data Models & Taxonomies (`backend/app/models/report.py`, `job.py`)**:
   - Pydantic v2 schemas support bidirectional camelCase and snake_case serialization via `to_camel` alias generator -> **VERIFIED (Pass)**
   - Complete CWE canonical normalization (`extract_cwe_ids`) sorting numerically -> **VERIFIED (Pass)**
   - 3-tier OWASP Top 10 (2021) mapping engine (CWE dictionary -> rule/description keywords -> category fallback) -> **VERIFIED (Pass)**
   - Reachability verdict normalizer maps to `REACHABLE`, `UNREACHABLE`, or `UNKNOWN` -> **VERIFIED (Pass)**

---

## Adversarial Challenge & Stress-Testing

### Challenge Summary
- **Overall Risk Assessment**: **LOW**
- The core implementation demonstrates defense-in-depth at multiple abstraction boundaries.

### Stress Test Results

| Attack Scenario | Invariant Challenged | Expected Behavior | Observed Result | Status |
|---|---|---|---|---|
| Deep nested path traversal `foo/bar/../../evil` | Zip-slip defense | Raise `ValueError` | Rejected with `traversal sequence '..' detected` | **PASS** |
| Windows reserved device `con.txt`, `aux.json` | Windows filesystem exploit | Raise `ValueError` | Rejected with `Windows reserved device name forbidden` | **PASS** |
| Symlink with POSIX mode `0o120755` (`0xA1ED`) | Symlink bypass | Raise `ValueError` | Rejected with `Symlink detected in archive entry` | **PASS** |
| High compression ratio bomb (1023.5x) | Zip bomb exhaustion | Raise `ValueError` | Rejected upfront before extraction | **PASS** |
| Single file exceeding 10 MB quota | Resource quota exhaustion | Raise `ValueError` | Rejected with `exceeds single file limit` | **PASS** |
| Total archive exceeding 50 MB quota | Resource quota exhaustion | Raise `ValueError` | Rejected with `Total uncompressed archive size exceeds limit` | **PASS** |
| Subprocess shell injection strings | Subprocess isolation | Executed literally as arguments | Arg-list form prevents shell interpolation | **PASS** |
| Scanner process timeout simulation | DoS / hang defense | Child killed after timeout | Process killed, raises `ScannerTimeoutError` | **PASS** |
| Queue concurrency flood (multiple concurrent jobs) | Concurrency limit = 1 | Strict sequential execution | Processed strictly one-at-a-time | **PASS** |
| Context extraction out-of-bounds (negative line, line 9999) | Boundary clamping | Clamped to [1, total_lines] | Safely clamped without indexing crashes | **PASS** |

---

## 5-Component Handoff Protocol

### 1. Observation
- Verified backend files: `backend/app/core/safe_extract.py`, `backend/app/core/runner.py`, `backend/app/core/queue.py`, `backend/app/core/context_extractor.py`, `backend/app/models/job.py`, `backend/app/models/report.py`, `backend/app/config.py`, `backend/app/__init__.py`.
- Unit tests execution command and verbatim result:
  ```powershell
  $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'; pytest -c backend/pytest.ini backend/tests -v
  ```
  Result: `71 passed in 1.33s`.
- E2E tests execution command and verbatim result:
  ```powershell
  $env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'; pytest tests/e2e -v -p pytest_asyncio.plugin
  ```
  Result: `28 passed in 0.74s`.
- Adversarial test script confirmed proper boundary clamping, Windows device blocking, and traversal rejection.

### 2. Logic Chain
1. `worker_m1` delivered 18 files implementing the Milestone 1 backend core and unit test suite.
2. Direct inspection of all source code proved that real business and security logic is implemented without stubs, dummy facades, or hardcoded values.
3. Unit test execution in `backend/tests` verified all 71 tests pass without regression.
4. E2E test execution in `tests/e2e` verified all 28 multi-tier tests pass cleanly against the implemented core and contracts.
5. Adversarial stress tests targeting zip-slip, symlinks, bombs, size quotas, process timeouts, and concurrency verified robustness against malicious inputs.
6. Therefore, Milestone 1 satisfies all criteria in `ORIGINAL_REQUEST.md` and `PROJECT.md`.

### 3. Caveats
- Node.js runtime and pre-baked CLI binary execution inside Docker container will be tested in Milestone 4 container integration. In local testing, standard fallback discovery and mocks/argument verification were verified.
- Root `pytest.ini` requires adding `-p pytest_asyncio.plugin` if developers run `pytest tests/e2e` with `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"` without explicit `-p` flag.

### 4. Conclusion
- Milestone 1 is **APPROVED**.
- Ready for unblocking Milestone 2 (Backend API & Exporters).

### 5. Verification Method
To independently reproduce verification:
```powershell
# 1. Run full unit test suite:
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'; pytest -c backend/pytest.ini backend/tests -v

# 2. Run full E2E test suite:
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'; pytest tests/e2e -v -p pytest_asyncio.plugin
```
Both commands must yield 100% pass (71/71 unit tests, 28/28 E2E tests).
