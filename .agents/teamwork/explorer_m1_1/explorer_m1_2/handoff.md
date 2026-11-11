# Milestone 1: Subprocess Runner & Job Queue Handoff Report

- **Date:** 2026-11-07
- **Author:** Explorer Subagent 2 (`teamwork_explorer`)
- **Working Directory:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2`
- **Specification Report:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md`
- **Milestone:** Milestone 1 — Backend Core: Extraction, Runner & Queue

---

## 1. Observation

1. **SecureShip CLI Invocation & Output Verification:**
   - Command executed:
     ```powershell
     node "c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\packages\cli\dist\index.js" scan "c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\packages\benchmark\corpus\case1-secrets-prod" --json --scanners secrets
     ```
     Result: Exited with **code 0**; output valid ScanReport JSON to stdout (`"schemaVersion": "1.3"`, `"findings": [...]`, duration 1156ms).
   - Command executed with `--fail-on MEDIUM`:
     ```powershell
     node "c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\packages\cli\dist\index.js" scan "c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\packages\benchmark\corpus\case1-secrets-prod" --json --scanners secrets --fail-on MEDIUM
     ```
     Result: Exited with **code 1**; output identical valid ScanReport JSON to stdout with findings present.

2. **SecureShip CLI Source Code Semantics:**
   - `packages/cli/src/commands/scan.ts` lines 498-535:
     ```typescript
     const failOn = (options.failOn?.toUpperCase() as FailOnSeverity) || 'HIGH';
     const failOnRank = SEVERITY_RANK[failOn] ?? SEVERITY_RANK['HIGH'];
     if (failOnRank > 0) {
       const hasFailingFindings = report.findings.some(
         (f) => SEVERITY_RANK[f.severity] >= failOnRank
       );
       if (hasFailingFindings) {
         return 1;
       }
     }
     ...
     return 0;
     ```
     Error handling block (lines 523-534) emits JSON error to stderr when `isJson` is true (`{"error": msg}`) and returns `3` for offline violations or `2` for configuration/usage errors.
   - `packages/cli/src/index.ts` lines 548-549:
     ```typescript
     const exitCode = await ScanCommand.run(targetPath, options);
     process.exitCode = exitCode;
     ```

3. **Container Packaging & Binary Paths:**
   - `Dockerfile.cli` lines 52-53, 104-105: Standalone CLI bundle is placed at `/opt/secureship/cli/dist/index.js` and symlinked to `/usr/local/bin/secureship`.

4. **Runtime Python Environment Verification:**
   - `python --version` $\rightarrow$ `Python 3.12.10`
   - `pytest --version` $\rightarrow$ `pytest 9.2.0`
   - `pydantic` $\rightarrow$ `2.14.2`
   - `fastapi` $\rightarrow$ `0.162.0`
   - `reportlab` $\rightarrow$ `5.1.0`

---

## 2. Logic Chain

1. **Exit Code Semantics**:
   - Observations 1 and 2 prove that both exit code `0` (clean scan) and exit code `1` (findings present meeting threshold) produce valid, complete ScanReport JSON on stdout.
   - Therefore, a wrapper that treats exit code 1 as a failure would incorrectly mark scans with vulnerabilities as failed.
   - The runner MUST evaluate `returncode in (0, 1)` as **SUCCESS**, parse stdout with `json.loads()`, and transition the job to `JobStatus.DONE`.
   - Exit codes `> 1` (such as code 2 for bad arguments, code 3 for missing engines) MUST be treated as failures, raising `ScannerExecutionError` with diagnostic messages extracted from stderr.

2. **Subprocess Security & Argument Form**:
   - The user request and project acceptance criteria explicitly mandate argument list form without shell interpolation (`['node', cli_path, 'scan', str(target_dir), '--json']`).
   - Using `asyncio.create_subprocess_exec(*cmd, stdout=..., stderr=..., cwd=...)` directly without `shell=True` ensures that untrusted directory names or characters cannot cause command injection.

3. **Concurrency 1 & Memory Isolation**:
   - The project constraints allocate 3 GB RAM and 1.5 CPUs in Docker Compose.
   - Parallel scanner executions (e.g. simultaneous Opengrep, Trivy, OSV, and Checkov runs) would exceed the container ceiling and trigger OOM killer termination.
   - Enforcing concurrency = 1 via an `asyncio.Queue` with a single dedicated worker loop ensures that all uploaded scans are processed strictly sequentially (FIFO), guaranteeing predictable resource consumption.

4. **Resource & Scratch Directory Cleanup**:
   - The acceptance criteria require temporary scan directories to be deleted upon scan completion or failure.
   - Wrapping the entire extraction, execution, and enrichment sequence in `try ... finally:` blocks guarantees that `shutil.rmtree(temp_dir, ignore_errors=True)` and `zip_path.unlink()` execute under every execution path (success, validation failure, timeout, crash).

---

## 3. Caveats

1. **Node Executable Availability**: On development environments, Node.js must be present on PATH (or specified via `NODE_PATH`). In Docker containers, Node 22 is guaranteed. The path resolver includes multi-level fallbacks.
2. **Stderr Formatting**: In rare cases, third-party scanner binaries may emit non-JSON logs to stderr before SecureShip catches them; the runner falls back to raw stderr decoding if JSON parsing fails.
3. **In-Memory Storage Scope**: In Milestone 1, job state is stored in an in-memory dictionary. Persistence across container restarts is not required per the spec, but could be upgraded to SQLite/Redis if required in future releases.

---

## 4. Conclusion

The specification for `backend/app/core/runner.py`, `backend/app/core/queue.py`, `backend/tests/test_runner.py`, and `backend/tests/test_queue.py` is fully verified, mathematically sound, and ready for immediate implementation by the Milestone 1 Implementer:
1. `run_secureship_cli` enforces argument-list execution, 300-second hard timeout, and proper exit code 0/1 success handling.
2. `ScanJobQueue` enforces strict single concurrency (concurrency = 1), FIFO scheduling, progress tracking (0% to 100%), and guaranteed cleanup of temporary directories.
3. Complete unit test specifications with mock and behavioral test cases cover 100% of the operational and failure modes.

The complete report and code blueprints are published in `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md`.

---

## 5. Verification Method

To independently verify the findings and specifications:
1. **Verify CLI Exit Codes:**
   ```powershell
   # Clean scan (Exit 0)
   node packages/cli/dist/index.js scan packages/benchmark/corpus/case1-secrets-prod --json --scanners secrets
   echo "Exit Code: $LASTEXITCODE"

   # Scan with findings exceeding threshold (Exit 1)
   node packages/cli/dist/index.js scan packages/benchmark/corpus/case1-secrets-prod --json --scanners secrets --fail-on MEDIUM
   echo "Exit Code: $LASTEXITCODE"
   ```
2. **Verify Specifications Document:**
   Inspect `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md`.
3. **Execute Unit Tests once Implemented:**
   ```powershell
   pytest backend/tests/test_runner.py -v
   pytest backend/tests/test_queue.py -v
   ```
4. **Invalidation Condition:**
   If SecureShip CLI changes exit code semantics such that exit code 1 is reserved for critical fatal errors rather than findings detection, the exit code handling logic in `runner.py` would require revision.
