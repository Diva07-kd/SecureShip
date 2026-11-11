# Task Assignment: M1 Runner & Job Queue Specification & Test Plan

- Working Directory: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2
- Original Request: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
- Project Scope: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md

As an Explorer for Milestone 1, your focus is the Subprocess Runner and Job Queue:
1. Specify `backend/app/core/runner.py`:
   - Subprocess execution using argument list `['node', cli_path, 'scan', str(target_dir), '--json']` (NO `shell=True`)
   - 300-second hard timeout using `asyncio.wait_for` or `asyncio.create_subprocess_exec`
   - Exit code handling:
     - Exit code 0: clean run (no failing findings), parse stdout JSON
     - Exit code 1: findings present, parse stdout JSON as successful scan
     - Exit code > 1: scan execution error, raise `ScannerExecutionError`
2. Specify `backend/app/core/queue.py`:
   - `asyncio.Queue` with single worker task ensuring max concurrency = 1
   - Job lifecycle states: `queued`, `running`, `done`, `failed`
   - Progress tracking and error capturing
3. Specify unit tests in `backend/tests/test_runner.py` and `backend/tests/test_queue.py`.
4. Write your report to `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md` and handoff.md.


## 2026-11-07T06:20:46Z
From: 1b39d829-223c-4805-b373-ad3f9409f65e
Content:
You are a teamwork_explorer subagent for Milestone 1: Subprocess Runner & Job Queue.
Your working directory is: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2
You MUST read:
1. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
2. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md
3. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\DISPATCH.md

Investigate and specify the subprocess runner (`backend/app/core/runner.py`), the job queue (`backend/app/core/queue.py`), and their unit tests (`backend/tests/test_runner.py`, `backend/tests/test_queue.py`).
Deliver your report to `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_2\m1_runner_queue.md` and handoff.md.
When done, message the orchestrator (caller) with your completion status and handoff.md path.
