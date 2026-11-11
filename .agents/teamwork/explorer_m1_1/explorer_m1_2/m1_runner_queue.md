# Milestone 1: Subprocess Runner & Job Queue Specification & Test Plan

**Document Path:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md`  
**Author:** Explorer Subagent 2 (`teamwork_explorer`)  
**Workspace:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE`  
**Milestone:** M1 — Backend Core: Extraction, Runner & Queue  
**Date:** 2026-11-07  

---

## 1. Executive Summary & Architectural Role

In the SecureScan architecture, the **Subprocess Runner** (`backend/app/core/runner.py`) and the **Job Queue** (`backend/app/core/queue.py`) constitute the core execution engine of the security scanning pipeline. They bridge untrusted external inputs (uploaded repository zip archives) with the underlying multi-engine security CLI (`@secureship/cli`), enforcing strict operational safety, memory isolation, concurrency constraints, and process lifecycle cleanup.

```
                                  FastAPI Web Layer
                                          │
                        POST /api/scan    │    GET /api/jobs/{id}
                        (Upload .zip)     │    GET /api/health
                                          ▼
                ┌──────────────────────────────────────────────────┐
                │          Job Queue (backend/app/core/queue.py)   │
                │  • asyncio.Queue (concurrency = 1)               │
                │  • In-memory job state store (JobRecord)         │
                │  • FIFO single-worker background coroutine       │
                │  • Progress: 0% -> 10% -> 30% -> 90% -> 100%     │
                │  • Lifecycle cleanup (temp_dir & zip unlink)     │
                └─────────────────────────┬────────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
         [Stage 1: Extraction]                          [Stage 2: Scan Runner]
         safe_extract()                                 backend/app/core/runner.py
         • Defends against Zip-Slip,                    • Argument list: ['node', cli_path,
           Symlinks (0xA1ED), Bombs,                      'scan', target_dir, '--json']
           Size limits (10MB/50MB)                      • Strictly NO shell=True
                                                        • 300-second hard timeout
                                                        • Exit code 0 & 1 = SUCCESS
                                                        • Exit code > 1 = ScannerExecutionError
                                                                  │
                                                                  ▼
                                                        [Stage 3: Enrichment]
                                                        context_extractor.py & models
                                                        • Slice ±5 lines snippet
                                                        • OWASP Top 10 & CWE mapping
                                                        • Reachability verdict
```

### Critical Operational Invariants
1. **Single Concurrency Ceiling (Concurrency = 1)**: The container environment is bounded to 3 GB RAM and 1.5 CPUs. Running multiple scanner processes simultaneously risks OOM kill by the Linux kernel. A single-worker `asyncio.Queue` guarantees strictly sequential execution.
2. **Subprocess Argument-List Invocation (Zero Shell Interpolation)**: All CLI invocations must execute via `asyncio.create_subprocess_exec(*args)` passing arguments as an explicit vector. String concatenation and `shell=True` are categorically prohibited to eliminate command injection vulnerabilities.
3. **Exit Code Semantics Handling (Exit Codes 0 & 1 as Success)**: The SecureShip CLI exits with code `0` when no findings reach the threshold, and exit code `1` when findings or policy violations are detected. **Both exit codes 0 and 1 indicate a successful scan with valid ScanReport JSON emitted to stdout.** Exit codes `> 1` indicate configuration or infrastructure errors (`ScannerExecutionError`).
4. **Hard Timeout Protection (300 Seconds)**: Any CLI scan taking longer than 300 seconds is terminated via `process.kill()` to prevent hanging processes or resource starvation, raising `ScannerTimeoutError`.
5. **Temporary Directory Lifecycle Guarantee**: Every extracted scratch directory (`temp_dir`) and uploaded temporary zip file must be completely deleted upon job completion or failure inside guaranteed `finally:` blocks.

---

## 2. Subprocess Runner Specification (`backend/app/core/runner.py`)

### 2.1 Interface Contract
```python
async def run_secureship_cli(
    scan_target_dir: Path,
    timeout_seconds: int = 300,
    extra_args: Optional[list[str]] = None,
    node_path: Optional[str] = None,
    cli_path: Optional[str] = None,
    cwd: Optional[Path] = None,
) -> dict[str, Any]:
    """
    Executes the SecureShip CLI scan command against scan_target_dir using
    an argument list (NO shell=True) and returns the parsed JSON report.

    Args:
        scan_target_dir: Directory containing extracted source code to scan.
        timeout_seconds: Hard execution timeout in seconds (default: 300).
        extra_args: Additional command-line flags (e.g. ['--gate2', 'annotate']).
        node_path: Explicit path to node binary (auto-discovered if None).
        cli_path: Explicit path to SecureShip CLI index.js (auto-discovered if None).
        cwd: Working directory for child process (defaults to scan_target_dir).

    Returns:
        dict[str, Any]: Parsed ScanReport JSON object.

    Raises:
        ScannerNotFoundError: If node or secureship CLI cannot be located.
        ScannerTimeoutError: If execution exceeds timeout_seconds.
        ScannerExecutionError: If CLI exits with code > 1 or produces corrupt JSON.
    """
```

### 2.2 Command Line Assembly & Argument List Invariant
The command must be constructed as a list of strings and passed directly to `asyncio.create_subprocess_exec`:

```python
args: list[str] = [
    str(node_bin),
    str(cli_script),
    "scan",
    str(scan_target_dir.resolve()),
    "--json",
]
if extra_args:
    args.extend(extra_args)
```

**Prohibition Rule**: Passing strings to `asyncio.create_subprocess_shell` or setting `shell=True` is prohibited. Under no circumstances should string formatting (such as `f"node {cli} scan {dir}"`) be used.

### 2.3 CLI & Node Path Resolution Strategy
To ensure seamless execution across local development (Windows/macOS/Linux) and production Docker containers:

```python
def resolve_cli_paths(
    custom_node: Optional[str] = None,
    custom_cli: Optional[str] = None
) -> tuple[str, str]:
    """
    Resolves the paths to the Node.js executable and SecureShip CLI bundle.
    """
    # 1. Resolve Node.js binary
    node_bin = custom_node or os.environ.get("NODE_PATH") or shutil.which("node")
    if not node_bin:
        raise ScannerNotFoundError("Node.js binary not found in PATH or NODE_PATH.")

    # 2. Resolve SecureShip CLI distribution
    # Priority order:
    # a. Explicit argument / environment variable SECURESHIP_CLI_PATH
    # b. Container installation path: /opt/secureship/cli/dist/index.js
    # c. Standalone binary in PATH: shutil.which("secureship")
    # d. Local repo relative path: packages/cli/dist/index.js
    candidates = []
    if custom_cli:
        candidates.append(Path(custom_cli))
    if os.environ.get("SECURESHIP_CLI_PATH"):
        candidates.append(Path(os.environ["SECURESHIP_CLI_PATH"]))
    
    candidates.extend([
        Path("/opt/secureship/cli/dist/index.js"),
        Path(__file__).resolve().parents[3] / "packages" / "cli" / "dist" / "index.js",
        Path("packages/cli/dist/index.js").resolve(),
    ])

    for candidate in candidates:
        if candidate.is_file():
            return node_bin, str(candidate)

    # Check if 'secureship' executable is in system PATH
    secureship_bin = shutil.which("secureship")
    if secureship_bin and Path(secureship_bin).is_file():
        return node_bin, secureship_bin

    raise ScannerNotFoundError(
        f"SecureShip CLI not found. Checked: {[str(c) for c in candidates]}"
    )
```

### 2.4 Timeout Enforcement & Process Reaping
Execution uses `asyncio.wait_for(process.communicate(), timeout=timeout_seconds)`:

```python
process = await asyncio.create_subprocess_exec(
    *args,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    cwd=str(cwd or scan_target_dir),
    env={**os.environ, "NODE_ENV": "production", "NO_COLOR": "1"},
)

try:
    stdout_bytes, stderr_bytes = await asyncio.wait_for(
        process.communicate(),
        timeout=float(timeout_seconds),
    )
except asyncio.TimeoutError:
    # 1. Kill child process immediately
    try:
        process.kill()
    except ProcessLookupError:
        pass
    # 2. Reap child process to prevent zombies
    try:
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except Exception:
        pass
    raise ScannerTimeoutError(
        f"SecureShip CLI scan timed out after {timeout_seconds} seconds on target '{scan_target_dir}'",
        timeout_seconds=timeout_seconds,
    )
```

### 2.5 Exit Code Semantics Handling Matrix

| Exit Code | SecureShip CLI Meaning | Runner Status | Action Taken |
|:---:|:---|:---:|:---|
| **`0`** | Clean scan: zero findings met `--fail-on` threshold | **SUCCESS** | Decode stdout, parse JSON with `json.loads`, return report dictionary |
| **`1`** | Policy violation: findings met/exceeded `--fail-on` threshold | **SUCCESS** | Decode stdout, parse JSON with `json.loads`, return report dictionary |
| **`2`** | Usage / configuration error (invalid flag, bad arguments) | **FAILED** | Decode stderr (check for JSON error payload), raise `ScannerExecutionError` |
| **`3`** | Infrastructure failure (missing scanner engine, offline violation) | **FAILED** | Decode stderr, raise `ScannerExecutionError` with `exit_code=3` |
| **`>3` / `<0`** | Unhandled process crash, OOM kill, or SIGKILL/SIGTERM signal | **FAILED** | Raise `ScannerExecutionError` with exit code details |

#### Handling Corrupt or Missing JSON on Exit Code 0/1
If the CLI exits with code 0 or 1 but stdout is empty or contains non-JSON text (e.g. Node warning messages or unhandled output):
```python
stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

if process.returncode in (0, 1):
    try:
        report_data = json.loads(stdout_str)
        return report_data
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError(
            f"SecureShip CLI exited with code {process.returncode} but produced invalid JSON: {exc}\n"
            f"Stdout: {stdout_str[:500]}\nStderr: {stderr_str[:500]}",
            exit_code=process.returncode,
            stdout=stdout_str,
            stderr=stderr_str,
        ) from exc
```

#### Extracting Error Diagnostics on Exit Code > 1
When `--json` is supplied to SecureShip CLI, errors emitted to stderr are formatted as `{"error": "<message>"}`. The runner parses this JSON to extract a concise message:
```python
error_msg = stderr_str
try:
    err_json = json.loads(stderr_str)
    if isinstance(err_json, dict) and "error" in err_json:
        error_msg = str(err_json["error"])
except Exception:
    pass

raise ScannerExecutionError(
    f"SecureShip CLI failed with exit code {process.returncode}: {error_msg or 'Unknown error'}",
    exit_code=process.returncode,
    stdout=stdout_str,
    stderr=stderr_str,
)
```

### 2.6 Custom Exception Hierarchy
```python
class ScannerError(Exception):
    """Base exception for scanner execution errors."""
    pass

class ScannerNotFoundError(ScannerError):
    """Raised when Node.js binary or CLI distribution script cannot be found."""
    pass

class ScannerTimeoutError(ScannerError, TimeoutError):
    """Raised when scanner execution exceeds the timeout limit."""
    def __init__(self, message: str, timeout_seconds: int):
        super().__init__(message)
        self.timeout_seconds = timeout_seconds

class ScannerExecutionError(ScannerError):
    """Raised when scanner CLI exits with error code (>1) or fails to emit valid JSON."""
    def __init__(self, message: str, exit_code: int, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
```

---

## 3. Asynchronous Job Queue Specification (`backend/app/core/queue.py`)

### 3.1 Concurrency Model & Resource Safeguards
The assessment environment restricts resources to **3 GB RAM and 1.5 CPUs**. Security engines (such as Opengrep and Trivy) consume substantial memory during AST parsing and vulnerability database queries. Running concurrent scans would easily trigger OOM killer termination.

The Job Queue enforces a **strict concurrency limit of 1**:
- An `asyncio.Queue[str]` holds pending `job_id` strings.
- A **single background worker coroutine** (`_worker_loop()`) continuously dequeues one job at a time.
- The worker executes the entire scan pipeline (extraction $\rightarrow$ CLI execution $\rightarrow$ enrichment $\rightarrow$ cleanup) before fetching the next job from the queue.
- Incoming upload requests receive HTTP 200 with status `queued` immediately and await their turn in FIFO order.

### 3.2 Job State Machine & Progress Metrics

```
                     Worker Dequeues Job
  [QUEUED] ───────────────────────────────────────────► [RUNNING]
   Prog: 0%                                              Prog: 10% (Stage: EXTRACTING)
                                                               │
                                                               ▼
                                                         Prog: 30% -> 80% (Stage: SCANNING)
                                                               │
                                                               ▼
                                                         Prog: 90% (Stage: ENRICHING)
                                                               │
                           ┌───────────────────────────────────┴───────────────────────────────────┐
                           │ (CLI exit 0 or 1, JSON valid)                                         │ (ValueError / Timeout / Exit >1)
                           ▼                                                                       ▼
                        [DONE]                                                                  [FAILED]
                      Prog: 100%                                                              Prog: 100%
                      Stage: COMPLETED                                                        Stage: FAILED
                      Report saved                                                            Error message recorded
```

### 3.3 Job Data Model (`JobRecord`)
Defined in `backend/app/models/job.py` (or imported directly):

```python
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

class JobStage(str, Enum):
    QUEUED = "queued"
    EXTRACTING = "extracting"
    SCANNING = "scanning"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"

class JobRecord(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    stage: JobStage = JobStage.QUEUED
    progress: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    zip_path: Optional[str] = None
    temp_dir: Optional[str] = None
    report: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    poll_url: str = ""
    report_url: Optional[str] = None
```

### 3.4 Guaranteed Temporary Directory & Resource Cleanup
**Acceptance Criterion:** *"Temporary scan directories are deleted upon scan completion or failure."*

The Job Queue worker encapsulates the entire execution in a `try ... finally` block. Regardless of whether the scan completes cleanly, raises a `ValueError` during safe extraction, times out after 300 seconds, or experiences an unhandled crash, the temporary directory and uploaded zip file are unconditionally unlinked:

```python
scratch_dir = Path(tempfile.mkdtemp(prefix=f"securescan_job_{job_id}_"))
job.temp_dir = str(scratch_dir)

try:
    # 1. Safe extraction into scratch_dir
    # 2. Execute CLI runner against scratch_dir
    # 3. Context snippet extraction against scratch_dir
    # 4. Populate job.report
    job.status = JobStatus.DONE
    job.stage = JobStage.COMPLETED
    job.progress = 100
except Exception as exc:
    job.status = JobStatus.FAILED
    job.stage = JobStage.FAILED
    job.error = str(exc)
    job.progress = 100
finally:
    # Guaranteed cleanup: delete scratch directory
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir, ignore_errors=True)
    job.temp_dir = None

    # Guaranteed cleanup: delete uploaded archive file
    if job.zip_path and Path(job.zip_path).exists():
        try:
            Path(job.zip_path).unlink(missing_ok=True)
        except Exception:
            pass
```

### 3.5 Worker Lifecycle & FastAPI Integration
The queue provides `start()` and `stop()` lifecycle methods designed for FastAPI's `@asynccontextmanager` lifespan:

```python
class ScanJobQueue:
    def __init__(self, maxsize: int = 100):
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._jobs: dict[str, JobRecord] = {}
        self._worker_task: Optional[asyncio.Task] = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._current_job_id: Optional[str] = None
        self._lock: asyncio.Lock = asyncio.Lock()

    async def start(self) -> None:
        """Starts the single background worker task."""
        if self._worker_task is None or self._worker_task.done():
            self._shutdown_event.clear()
            self._worker_task = asyncio.create_task(
                self._worker_loop(), name="securescan-single-worker"
            )

    async def stop(self) -> None:
        """Gracefully stops the worker task."""
        self._shutdown_event.set()
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    def get_stats(self) -> dict[str, Any]:
        """Returns operational metrics for GET /api/health."""
        return {
            "queued_jobs": self._queue.qsize(),
            "is_processing": self._current_job_id is not None,
            "active_job_id": self._current_job_id,
        }
```

---

## 4. Unit Test Suite Specifications

### 4.1 Subprocess Runner Test Suite (`backend/tests/test_runner.py`)

The runner test suite verifies process invocation, exit code interpretation, timeout enforcement, and security properties.

#### Required Test Cases:
1. `test_runner_success_exit_code_0`:
   - Mock subprocess returning `returncode = 0` and standard valid `ScanReport` JSON on stdout.
   - Assert returns parsed dictionary with `schemaVersion`, `findings`, and `summary`.
2. `test_runner_success_exit_code_1_with_findings`:
   - Mock subprocess returning `returncode = 1` and `ScanReport` JSON containing findings.
   - Assert returns parsed dictionary and does NOT raise `ScannerExecutionError`.
3. `test_runner_failure_exit_code_2_usage_error`:
   - Mock subprocess returning `returncode = 2` and stderr `{"error": "Invalid --gate2 mode"}`.
   - Assert raises `ScannerExecutionError` with `exit_code == 2` and message containing error detail.
4. `test_runner_failure_exit_code_3_infrastructure_error`:
   - Mock subprocess returning `returncode = 3` and stderr `Scanner opengrep failed or missing`.
   - Assert raises `ScannerExecutionError` with `exit_code == 3`.
5. `test_runner_timeout_300s_kills_process`:
   - Mock `asyncio.wait_for` raising `asyncio.TimeoutError`.
   - Assert raises `ScannerTimeoutError`.
   - Assert `mock_proc.kill()` was invoked.
6. `test_runner_argument_list_no_shell`:
   - Spy on `asyncio.create_subprocess_exec`.
   - Verify first argument is node, second is cli script, followed by `'scan'`, target path, and `'--json'`.
   - Verify `shell` keyword argument is NOT in kwargs or is `False`.
7. `test_runner_corrupt_json_stdout`:
   - Mock subprocess returning exit code 0 or 1, but stdout is unparseable text (`"SyntaxError: invalid"`).
   - Assert raises `ScannerExecutionError` detailing the JSON decode failure.
8. `test_runner_live_cli_integration`:
   - Live integration test executing actual CLI against `packages/benchmark/corpus/case1-secrets-prod`.
   - Skip if node or CLI dist not present.
   - Assert scan runs and parses valid `NormalizedFinding` for AWS access token.

#### Reference Implementation for `backend/tests/test_runner.py`:
```python
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.core.runner import (
    run_secureship_cli,
    ScannerError,
    ScannerNotFoundError,
    ScannerTimeoutError,
    ScannerExecutionError,
    resolve_cli_paths,
)

SAMPLE_REPORT_JSON = json.dumps({
    "schemaVersion": "1.3",
    "tool": {"name": "secureship", "version": "1.0.0"},
    "target": "/workspace/target",
    "mode": "FULL",
    "findings": [
        {
            "id": "finding-test-1",
            "ruleId": "secureship-py-sql-format",
            "severity": "HIGH",
            "category": "SAST",
            "location": {"filePath": "app.py", "startLine": 10, "endLine": 10}
        }
    ],
    "summary": {"totalReported": 1, "bySeverity": {"HIGH": 1}}
})

CLEAN_REPORT_JSON = json.dumps({
    "schemaVersion": "1.3",
    "tool": {"name": "secureship", "version": "1.0.0"},
    "target": "/workspace/target",
    "mode": "FULL",
    "findings": [],
    "summary": {"totalReported": 0, "bySeverity": {"CRITICAL": 0, "HIGH": 0}}
})

@pytest.fixture
def mock_proc():
    proc = MagicMock()
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=0)
    proc.communicate = AsyncMock()
    return proc

@pytest.mark.asyncio
async def test_runner_success_exit_code_0(tmp_path, mock_proc):
    """Exit code 0 (clean scan) must parse stdout JSON and return report."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (CLEAN_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            report = await run_secureship_cli(tmp_path)
            assert report["schemaVersion"] == "1.3"
            assert len(report["findings"]) == 0
            assert report["summary"]["totalReported"] == 0

@pytest.mark.asyncio
async def test_runner_success_exit_code_1_with_findings(tmp_path, mock_proc):
    """Exit code 1 (findings present) must be handled as SUCCESS and parse stdout JSON."""
    mock_proc.returncode = 1
    mock_proc.communicate.return_value = (SAMPLE_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            report = await run_secureship_cli(tmp_path)
            assert report["schemaVersion"] == "1.3"
            assert len(report["findings"]) == 1
            assert report["findings"][0]["ruleId"] == "secureship-py-sql-format"

@pytest.mark.asyncio
async def test_runner_failure_exit_code_2_usage_error(tmp_path, mock_proc):
    """Exit code 2 (usage/config error) must raise ScannerExecutionError with stderr message."""
    mock_proc.returncode = 2
    mock_proc.communicate.return_value = (
        b"",
        json.dumps({"error": "Invalid --gate2 mode 'invalid'"}).encode("utf-8")
    )

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert exc_info.value.exit_code == 2
            assert "Invalid --gate2 mode 'invalid'" in exc_info.value.message

@pytest.mark.asyncio
async def test_runner_failure_exit_code_3_infrastructure_error(tmp_path, mock_proc):
    """Exit code 3 (engine failure) must raise ScannerExecutionError."""
    mock_proc.returncode = 3
    mock_proc.communicate.return_value = (b"", b"Critical scanner failure: strict mode violation")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert exc_info.value.exit_code == 3

@pytest.mark.asyncio
async def test_runner_timeout_kills_process(tmp_path, mock_proc):
    """Subprocess exceeding timeout must be killed and raise ScannerTimeoutError."""
    mock_proc.communicate.side_effect = asyncio.TimeoutError()

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerTimeoutError) as exc_info:
                await run_secureship_cli(tmp_path, timeout_seconds=1)
            assert exc_info.value.timeout_seconds == 1
            mock_proc.kill.assert_called_once()

@pytest.mark.asyncio
async def test_runner_argument_list_no_shell(tmp_path, mock_proc):
    """Subprocess runner must invoke create_subprocess_exec with argument list, no shell."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (CLEAN_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            await run_secureship_cli(tmp_path, extra_args=["--gate2", "annotate"])
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            # Verify argument list structure
            assert call_args[0] == "node"
            assert call_args[1] == "/cli/dist/index.js"
            assert call_args[2] == "scan"
            assert call_args[3] == str(tmp_path.resolve())
            assert call_args[4] == "--json"
            assert call_args[5] == "--gate2"
            assert call_args[6] == "annotate"
            # Verify shell is not enabled
            assert "shell" not in mock_exec.call_args[1] or mock_exec.call_args[1]["shell"] is False

@pytest.mark.asyncio
async def test_runner_corrupt_json_stdout(tmp_path, mock_proc):
    """Corrupted JSON on exit code 0 or 1 must raise ScannerExecutionError."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (b"Fatal: Node heap out of memory", b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert "invalid JSON" in exc_info.value.message.lower()
```

---

### 4.2 Job Queue Test Suite (`backend/tests/test_queue.py`)

The job queue test suite verifies FIFO scheduling, the strict single-concurrency invariant, lifecycle state transitions, error handling, and temporary resource deletion.

#### Required Test Cases:
1. `test_queue_fifo_order`:
   - Enqueue jobs 1, 2, 3 in rapid succession.
   - Verify jobs are executed and completed in exact FIFO order.
2. `test_queue_concurrency_one_invariant`:
   - Enqueue multiple jobs with a simulated processing duration.
   - Sample active running count continuously.
   - Assert running count never exceeds 1 at any point in time.
3. `test_queue_successful_job_lifecycle`:
   - Enqueue valid job.
   - Track state progression: `queued` $\rightarrow$ `running` (extracting $\rightarrow$ scanning $\rightarrow$ enriching) $\rightarrow$ `done` (completed).
   - Assert progress reaches 100% and `job.report` is populated.
4. `test_queue_extraction_failure_sets_failed`:
   - Trigger `ValueError("Zip-slip detected")` during extraction stage.
   - Assert job status becomes `failed`, stage is `failed`, progress is 100%, and `job.error` contains the message.
5. `test_queue_scanner_failure_sets_failed`:
   - Trigger `ScannerExecutionError("CLI exited with code 3", exit_code=3)` during scanning stage.
   - Assert job status transitions to `failed` and error is captured.
6. `test_queue_scanner_timeout_sets_failed`:
   - Trigger `ScannerTimeoutError("Scan timed out", timeout_seconds=300)`.
   - Assert job status transitions to `failed` with timeout detail.
7. `test_queue_temp_dir_deleted_on_success`:
   - Complete a successful job.
   - Record `temp_dir` path during execution.
   - Assert recorded `temp_dir` does NOT exist after completion.
8. `test_queue_temp_dir_deleted_on_failure`:
   - Fail a job during scanning.
   - Record `temp_dir` path.
   - Assert recorded `temp_dir` does NOT exist after failure.
9. `test_queue_zip_file_deleted_after_scan`:
   - Create a dummy uploaded zip file on disk and pass to queue.
   - Assert dummy zip file is deleted after scan finishes.
10. `test_queue_stats_and_health`:
    - Enqueue jobs and query `get_stats()`.
    - Assert `queued_jobs` and `is_processing` accurately reflect active state.

#### Reference Implementation for `backend/tests/test_queue.py`:
```python
import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

from app.core.queue import ScanJobQueue
from app.models.job import JobStatus, JobStage
from app.core.runner import ScannerExecutionError, ScannerTimeoutError

@pytest.fixture
def temp_zip(tmp_path):
    zip_file = tmp_path / "test.zip"
    zip_file.write_bytes(b"PK\x03\x04test_content")
    return zip_file

@pytest.mark.asyncio
async def test_queue_concurrency_one_invariant(tmp_path):
    """Validates that at most 1 job is executing concurrently."""
    queue = ScanJobQueue()
    await queue.start()

    concurrent_running = []
    current_running = 0

    async def mock_scan_runner(target_dir, **kwargs):
        nonlocal current_running
        current_running += 1
        concurrent_running.append(current_running)
        await asyncio.sleep(0.1)  # Simulate scan work
        current_running -= 1
        return {"summary": {"totalReported": 0}, "findings": []}

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", side_effect=mock_scan_runner):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                # Enqueue 3 jobs simultaneously
                j1 = await queue.enqueue("job-1", str(tmp_path / "1.zip"))
                j2 = await queue.enqueue("job-2", str(tmp_path / "2.zip"))
                j3 = await queue.enqueue("job-3", str(tmp_path / "3.zip"))

                # Wait for all jobs to complete
                for _ in range(50):
                    if (queue.get_job("job-1").status in (JobStatus.DONE, JobStatus.FAILED) and
                        queue.get_job("job-2").status in (JobStatus.DONE, JobStatus.FAILED) and
                        queue.get_job("job-3").status in (JobStatus.DONE, JobStatus.FAILED)):
                        break
                    await asyncio.sleep(0.05)

    await queue.stop()

    assert len(concurrent_running) >= 3
    # Concurrency peak must never exceed 1
    assert max(concurrent_running) == 1
    assert queue.get_job("job-1").status == JobStatus.DONE
    assert queue.get_job("job-2").status == JobStatus.DONE
    assert queue.get_job("job-3").status == JobStatus.DONE

@pytest.mark.asyncio
async def test_queue_lifecycle_success(temp_zip):
    """Validates complete state machine transitions for a successful scan."""
    queue = ScanJobQueue()
    await queue.start()

    mock_report = {"summary": {"totalReported": 0}, "findings": []}

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value=mock_report)):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                job = await queue.enqueue("job-success", str(temp_zip))
                assert job.status == JobStatus.QUEUED
                assert job.progress == 0

                for _ in range(50):
                    updated = queue.get_job("job-success")
                    if updated.status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.05)

                final_job = queue.get_job("job-success")
                assert final_job.status == JobStatus.DONE
                assert final_job.stage == JobStage.COMPLETED
                assert final_job.progress == 100
                assert final_job.report is not None
                assert final_job.error is None
                assert final_job.started_at is not None
                assert final_job.completed_at is not None

    await queue.stop()

@pytest.mark.asyncio
async def test_queue_extraction_failure_sets_failed(temp_zip):
    """Extraction security violation (ValueError) transitions job to FAILED."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract", side_effect=ValueError("Zip-slip path traversal rejected")):
        await queue.enqueue("job-fail-extract", str(temp_zip))

        for _ in range(50):
            job = queue.get_job("job-fail-extract")
            if job.status == JobStatus.FAILED:
                break
            await asyncio.sleep(0.05)

        job = queue.get_job("job-fail-extract")
        assert job.status == JobStatus.FAILED
        assert job.stage == JobStage.FAILED
        assert "Zip-slip path traversal rejected" in job.error
        assert job.report is None

    await queue.stop()

@pytest.mark.asyncio
async def test_queue_scanner_failure_sets_failed(temp_zip):
    """ScannerExecutionError transitions job to FAILED."""
    queue = ScanJobQueue()
    await queue.start()

    with patch("app.core.queue.safe_extract"):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=ScannerExecutionError("Exit 3", exit_code=3))):
            await queue.enqueue("job-fail-scanner", str(temp_zip))

            for _ in range(50):
                job = queue.get_job("job-fail-scanner")
                if job.status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.05)

            job = queue.get_job("job-fail-scanner")
            assert job.status == JobStatus.FAILED
            assert job.stage == JobStage.FAILED
            assert "Exit 3" in job.error

    await queue.stop()

@pytest.mark.asyncio
async def test_queue_temp_dir_deleted_on_success_and_failure(temp_zip):
    """Scratch directories and zip files must be deleted in both success and failure states."""
    queue = ScanJobQueue()
    await queue.start()

    created_dirs = []

    def mock_safe_extract(src, dst):
        created_dirs.append(Path(dst))

    # 1. Test success cleanup
    with patch("app.core.queue.safe_extract", side_effect=mock_safe_extract):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(return_value={"findings": []})):
            with patch("app.core.queue.enrich_report_with_snippets", side_effect=lambda r, d: r):
                zip1 = temp_zip.parent / "test1.zip"
                zip1.write_bytes(b"content")
                await queue.enqueue("clean-1", str(zip1))

                for _ in range(50):
                    if queue.get_job("clean-1").status == JobStatus.DONE:
                        break
                    await asyncio.sleep(0.05)

                assert len(created_dirs) == 1
                assert not created_dirs[0].exists(), "Temporary directory must be deleted after success"
                assert not zip1.exists(), "Uploaded zip file must be deleted after success"

    # 2. Test failure cleanup
    with patch("app.core.queue.safe_extract", side_effect=mock_safe_extract):
        with patch("app.core.queue.run_secureship_cli", AsyncMock(side_effect=RuntimeError("Unexpected crash"))):
            zip2 = temp_zip.parent / "test2.zip"
            zip2.write_bytes(b"content")
            await queue.enqueue("clean-2", str(zip2))

            for _ in range(50):
                if queue.get_job("clean-2").status == JobStatus.FAILED:
                    break
                await asyncio.sleep(0.05)

            assert len(created_dirs) == 2
            assert not created_dirs[1].exists(), "Temporary directory must be deleted after failure"
            assert not zip2.exists(), "Uploaded zip file must be deleted after failure"

    await queue.stop()
```

---

## 5. Implementation Code Blueprints

### 5.1 Subprocess Runner Blueprint (`backend/app/core/runner.py`)
```python
"""
Subprocess Runner for SecureShip CLI.
Executes CLI scans using an argument list with a 300-second hard timeout.
Treats exit codes 0 and 1 as successful scans with valid ScanReport JSON.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("securescan.runner")

DEFAULT_TIMEOUT_SECONDS = 300

class ScannerError(Exception):
    """Base exception for scanner execution errors."""
    pass

class ScannerNotFoundError(ScannerError):
    """Raised when Node.js binary or CLI script cannot be located."""
    pass

class ScannerTimeoutError(ScannerError, TimeoutError):
    """Raised when scanner CLI execution exceeds the timeout limit."""
    def __init__(self, message: str, timeout_seconds: int):
        super().__init__(message)
        self.timeout_seconds = timeout_seconds

class ScannerExecutionError(ScannerError):
    """Raised when scanner CLI exits with error code (>1) or produces corrupt output."""
    def __init__(self, message: str, exit_code: int, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def resolve_cli_paths(
    custom_node: Optional[str] = None,
    custom_cli: Optional[str] = None
) -> tuple[str, str]:
    """
    Locates Node.js binary and SecureShip CLI index.js.
    """
    node_bin = custom_node or os.environ.get("NODE_PATH") or shutil.which("node")
    if not node_bin:
        raise ScannerNotFoundError("Node.js executable not found in PATH or NODE_PATH.")

    candidates: list[Path] = []
    if custom_cli:
        candidates.append(Path(custom_cli))
    if os.environ.get("SECURESHIP_CLI_PATH"):
        candidates.append(Path(os.environ["SECURESHIP_CLI_PATH"]))

    # Add standard container and repository locations
    candidates.extend([
        Path("/opt/secureship/cli/dist/index.js"),
        Path(__file__).resolve().parents[3] / "packages" / "cli" / "dist" / "index.js",
        Path("packages/cli/dist/index.js").resolve(),
    ])

    for candidate in candidates:
        if candidate.is_file():
            return str(node_bin), str(candidate)

    # Check if 'secureship' executable is in system PATH
    secureship_bin = shutil.which("secureship")
    if secureship_bin and Path(secureship_bin).is_file():
        return str(node_bin), str(secureship_bin)

    raise ScannerNotFoundError(
        f"SecureShip CLI not found. Checked candidate paths: {[str(c) for c in candidates]}"
    )


async def run_secureship_cli(
    scan_target_dir: Path | str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    extra_args: Optional[list[str]] = None,
    node_path: Optional[str] = None,
    cli_path: Optional[str] = None,
    cwd: Optional[Path | str] = None,
) -> dict[str, Any]:
    """
    Executes SecureShip CLI in argument-list form (NO shell=True) and returns parsed JSON.
    Exit codes 0 and 1 are parsed as successful scans.
    """
    target = Path(scan_target_dir).resolve()
    if not target.is_dir():
        raise ValueError(f"Scan target directory does not exist or is not a directory: {target}")

    node_bin, cli_script = resolve_cli_paths(node_path, cli_path)

    cmd_args: list[str] = [
        node_bin,
        cli_script,
        "scan",
        str(target),
        "--json",
    ]
    if extra_args:
        cmd_args.extend(extra_args)

    work_dir = Path(cwd).resolve() if cwd else target

    logger.info("Starting SecureShip scan: target=%s, timeout=%ds", target, timeout_seconds)

    process = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(work_dir),
        env={**os.environ, "NODE_ENV": "production", "NO_COLOR": "1"},
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout_seconds),
        )
    except asyncio.TimeoutError:
        logger.error("Scan exceeded timeout of %ds on %s; terminating child process", timeout_seconds, target)
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except Exception:
            pass
        raise ScannerTimeoutError(
            f"SecureShip CLI scan timed out after {timeout_seconds} seconds on target '{target}'",
            timeout_seconds=timeout_seconds,
        )

    stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
    stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()
    returncode = process.returncode if process.returncode is not None else -1

    logger.info("SecureShip CLI finished with exit code %d (stdout=%d bytes, stderr=%d bytes)",
                returncode, len(stdout_bytes), len(stderr_bytes))

    # Exit code 0 (clean) and 1 (findings detected) are BOTH SUCCESSFUL scans
    if returncode in (0, 1):
        if not stdout_str:
            raise ScannerExecutionError(
                f"SecureShip CLI exited with code {returncode} but produced empty stdout.",
                exit_code=returncode,
                stdout=stdout_str,
                stderr=stderr_str,
            )
        try:
            report_data = json.loads(stdout_str)
            return report_data
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError(
                f"SecureShip CLI exited with code {returncode} but output invalid JSON: {exc}\n"
                f"Stdout snippet: {stdout_str[:300]}",
                exit_code=returncode,
                stdout=stdout_str,
                stderr=stderr_str,
            ) from exc

    # Exit code > 1 represents configuration or infrastructure errors
    error_msg = stderr_str
    try:
        parsed_err = json.loads(stderr_str)
        if isinstance(parsed_err, dict) and "error" in parsed_err:
            error_msg = str(parsed_err["error"])
    except Exception:
        pass

    raise ScannerExecutionError(
        f"SecureShip CLI scan failed with exit code {returncode}: {error_msg or 'Execution error'}",
        exit_code=returncode,
        stdout=stdout_str,
        stderr=stderr_str,
    )
```

---

### 5.2 Job Queue Blueprint (`backend/app/core/queue.py`)
```python
"""
Asynchronous Job Queue for SecureScan.
Enforces max concurrency = 1 using a single-worker asyncio.Queue.
Guarantees cleanup of temporary scan directories and uploaded zip archives.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.core.runner import (
    run_secureship_cli,
    ScannerError,
    ScannerTimeoutError,
    ScannerExecutionError,
)
from app.core.safe_extract import safe_extract
from app.core.context_extractor import enrich_report_with_snippets
from app.models.job import JobRecord, JobStatus, JobStage

logger = logging.getLogger("securescan.queue")

class ScanJobQueue:
    def __init__(self, maxsize: int = 100):
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._jobs: dict[str, JobRecord] = {}
        self._worker_task: Optional[asyncio.Task] = None
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._current_job_id: Optional[str] = None
        self._lock: asyncio.Lock = asyncio.Lock()

    async def start(self) -> None:
        """Starts the background worker task."""
        async with self._lock:
            if self._worker_task is None or self._worker_task.done():
                self._shutdown_event.clear()
                self._worker_task = asyncio.create_task(
                    self._worker_loop(), name="securescan-single-worker"
                )
                logger.info("ScanJobQueue worker started (concurrency=1)")

    async def stop(self) -> None:
        """Gracefully halts the background worker task."""
        self._shutdown_event.set()
        async with self._lock:
            if self._worker_task and not self._worker_task.done():
                self._worker_task.cancel()
                try:
                    await self._worker_task
                except asyncio.CancelledError:
                    pass
                self._worker_task = None
                logger.info("ScanJobQueue worker stopped")

    async def enqueue(self, job_id: str, zip_path: str) -> JobRecord:
        """Enqueues a new scan job for processing."""
        async with self._lock:
            record = JobRecord(
                job_id=job_id,
                zip_path=zip_path,
                status=JobStatus.QUEUED,
                stage=JobStage.QUEUED,
                progress=0,
                poll_url=f"/api/jobs/{job_id}",
                report_url=f"/api/reports/{job_id}",
            )
            self._jobs[job_id] = record
            await self._queue.put(job_id)
            logger.info("Enqueued job %s (queue depth=%d)", job_id, self._queue.qsize())
            return record

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[JobRecord]:
        return list(self._jobs.values())

    def get_stats(self) -> dict[str, Any]:
        return {
            "queued_jobs": self._queue.qsize(),
            "is_processing": self._current_job_id is not None,
            "active_job_id": self._current_job_id,
        }

    async def _worker_loop(self) -> None:
        """Single worker loop guaranteeing concurrency = 1."""
        while not self._shutdown_event.is_set():
            try:
                job_id = await self._queue.get()
            except asyncio.CancelledError:
                break

            self._current_job_id = job_id
            try:
                await self._process_job(job_id)
            except Exception as exc:
                logger.exception("Unexpected error processing job %s: %s", job_id, exc)
            finally:
                self._current_job_id = None
                self._queue.task_done()

    async def _process_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if not job:
            return

        scratch_dir: Optional[Path] = None
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc).isoformat()

        try:
            # 1. Extraction Stage
            job.stage = JobStage.EXTRACTING
            job.progress = 10
            scratch_dir = Path(tempfile.mkdtemp(prefix=f"securescan_job_{job_id}_"))
            job.temp_dir = str(scratch_dir)

            if not job.zip_path or not Path(job.zip_path).is_file():
                raise ValueError("Uploaded archive file not found.")

            safe_extract(job.zip_path, scratch_dir)

            # 2. Scanning Stage
            job.stage = JobStage.SCANNING
            job.progress = 30
            raw_report = await run_secureship_cli(
                scan_target_dir=scratch_dir,
                timeout_seconds=300,
            )
            job.progress = 80

            # 3. Enrichment Stage (Snippets ±5 lines, CWE/OWASP taxonomies)
            job.stage = JobStage.ENRICHING
            job.progress = 90
            enriched_report = enrich_report_with_snippets(raw_report, scratch_dir)

            # 4. Completion
            job.report = enriched_report
            job.status = JobStatus.DONE
            job.stage = JobStage.COMPLETED
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()
            logger.info("Job %s completed successfully", job_id)

        except ValueError as exc:
            # Safe extraction or parameter validation error
            logger.warning("Job %s extraction validation failed: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = f"Archive extraction rejected: {exc}"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except ScannerTimeoutError as exc:
            logger.error("Job %s scanner timed out: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = "Scan execution timed out (exceeded 300 seconds limit)."
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except ScannerExecutionError as exc:
            logger.error("Job %s scanner execution failed (exit code %d): %s", job_id, exc.exit_code, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = exc.message
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        except Exception as exc:
            logger.exception("Job %s unhandled failure: %s", job_id, exc)
            job.status = JobStatus.FAILED
            job.stage = JobStage.FAILED
            job.error = f"Internal scanner failure: {exc}"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

        finally:
            # Lifecycle cleanup: delete temporary scratch directory
            if scratch_dir and scratch_dir.exists():
                shutil.rmtree(scratch_dir, ignore_errors=True)
            job.temp_dir = None

            # Lifecycle cleanup: delete uploaded temporary zip archive
            if job.zip_path and Path(job.zip_path).exists():
                try:
                    Path(job.zip_path).unlink(missing_ok=True)
                except Exception:
                    pass
```

---

## 6. Integration Contract with FastAPI & Exporters

### 6.1 Application Startup & Shutdown Lifespan
In `backend/app/main.py`:
```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.queue import ScanJobQueue

job_queue = ScanJobQueue()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start single-worker task
    await job_queue.start()
    yield
    # Shutdown: Stop worker gracefully
    await job_queue.stop()

app = FastAPI(title="SecureScan API", version="1.0.0", lifespan=lifespan)
```

### 6.2 Endpoint Integration Details

#### `POST /api/scan`
1. Verifies `.zip` extension and checks magic bytes `PK\x03\x04`.
2. Enforces 50 MB upload size limit during streaming chunks.
3. Saves file to `/tmp/securescan_uploads/{uuid4}.zip`.
4. Calls `await job_queue.enqueue(job_id, zip_path)`.
5. Returns HTTP 200: `{"job_id": job_id, "status": "queued", "poll_url": f"/api/jobs/{job_id}"}`.

#### `GET /api/jobs/{id}`
1. Calls `job = job_queue.get_job(id)`.
2. If `None`, returns HTTP 404 (`{"detail": "Job not found"}`).
3. Returns HTTP 200 with `status`, `stage`, `progress`, `error`, `report_url`.

#### `GET /api/reports/{id}`
1. Calls `job = job_queue.get_job(id)`.
2. If `None`, returns HTTP 404.
3. If `job.status in (JobStatus.QUEUED, JobStatus.RUNNING)`, returns HTTP 409 Conflict (`{"detail": "Scan is still in progress"}`).
4. If `job.status == JobStatus.FAILED`, returns HTTP 422 Unprocessable Entity (`{"detail": job.error}`).
5. If `job.status == JobStatus.DONE`, returns HTTP 200 with full `job.report` JSON.

#### `GET /api/health`
1. Queries `job_queue.get_stats()`.
2. Returns readiness/liveness payload including `queued_jobs`, `is_processing`, and scanner statuses.

---

## 7. Edge Cases, Security Invariants & Risk Mitigation Matrix

| # | Scenario / Attack Vector | Risk | System Behavior & Mitigation | Verified By |
|---|--------------------------|------|------------------------------|-------------|
| 1 | Finding severity matches `--fail-on HIGH` | CLI exits with code 1; naive wrappers treat code 1 as failure | Runner explicitly checks `returncode in (0, 1)`, parses stdout JSON, marks job `DONE` | `test_runner_success_exit_code_1_with_findings` |
| 2 | Target repo is completely clean | CLI exits with code 0, emits `findings: []` | Runner parses clean report, marks job `DONE` with 0 findings | `test_runner_success_exit_code_0` |
| 3 | Malicious archive attempts Zip-Slip (`../../evil.sh`) | Directory traversal, arbitrary file overwrite | `safe_extract()` raises `ValueError`, job transitions to `FAILED`, scratch dir deleted | `test_queue_extraction_failure_sets_failed` |
| 4 | Malicious input causes CLI infinite loop or hang | Thread exhaustion, queue blockage | Hard 300s timeout triggers `process.kill()`, raises `ScannerTimeoutError`, job marked `FAILED` | `test_runner_timeout_kills_process`, `test_queue_scanner_timeout_sets_failed` |
| 5 | Concurrent uploads arrive simultaneously | CPU/memory exhaustion exceeding 3G/1.5 CPU ceiling | Single-worker `asyncio.Queue` processes jobs strictly one at a time (FIFO) | `test_queue_concurrency_one_invariant` |
| 6 | Missing scanner engine or strict mode failure | CLI exits with code 3 | Runner captures exit code 3, raises `ScannerExecutionError`, job marked `FAILED` | `test_runner_failure_exit_code_3_infrastructure_error` |
| 7 | Subprocess stdout is truncated or invalid JSON | Unhandled JSON decode exception crashes worker | Runner catches `json.JSONDecodeError`, attaches stdout snippet, raises `ScannerExecutionError` | `test_runner_corrupt_json_stdout` |
| 8 | Server crashes or job terminates abruptly | Lingering temporary files consume disk volume | Scratch directories and uploaded archives are deleted in `finally:` blocks | `test_queue_temp_dir_deleted_on_success_and_failure` |
| 9 | Command injection in directory name (`"test; rm -rf /"`) | Shell command injection | Subprocess runner uses argument list form with `create_subprocess_exec` (NO shell=True) | `test_runner_argument_list_no_shell` |
| 10 | Application receives SIGTERM during active scan | Unhandled cancellation leaves zombie process | Lifespan `stop()` signals event, kills running process, and awaits worker task | `test_queue_lifecycle_success` |

---

## 8. Dependencies & Environment Configuration

### Configuration (`backend/app/core/config.py`)
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureScan"
    API_V1_PREFIX: str = "/api"
    SCAN_TIMEOUT_SECONDS: int = 300
    MAX_CONCURRENCY: int = 1
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024     # 50 MB
    MAX_EXTRACTED_BYTES: int = 50 * 1024 * 1024       # 50 MB
    MAX_SINGLE_FILE_BYTES: int = 10 * 1024 * 1024     # 10 MB
    MAX_COMPRESSION_RATIO: float = 100.0
    NODE_PATH: Optional[str] = None
    SECURESHIP_CLI_PATH: Optional[str] = None

    class Config:
        env_file = ".env"

settings = Settings()
```

### Python Package Dependencies (`requirements.txt`)
- `fastapi>=0.115.0`
- `uvicorn[standard]>=0.30.0`
- `pydantic>=2.8.0`
- `pydantic-settings>=2.4.0`
- `python-multipart>=0.0.9`
- `reportlab>=4.2.0`
- `pytest>=8.3.0`
- `pytest-asyncio>=0.24.0`
- `httpx>=0.27.0`
