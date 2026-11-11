# Task Assignment: M1 Safe Extract Specification & Test Plan

- Working Directory: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_1
- Original Request: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
- Project Scope: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md

As an Explorer for Milestone 1, your focus is the Safe Archive Extraction component:
1. Specify `backend/app/core/safe_extract.py`:
   - Defense 1: Path traversal / Zip-Slip (`../`, leading slashes, path resolution validation `is_relative_to`)
   - Defense 2: Symlinks (check `external_attr >> 16 == 0xA1ED` or POSIX `S_IFLNK` bit `0o120000`)
   - Defense 3: Compression bomb ratio (uncompressed size / compressed size > 100) checked upfront and during streaming decompression
   - Defense 4: Size quotas (single uncompressed file > 10MB, total extracted size > 50MB)
   - Defense 5: Atomic extraction & lifecycle cleanup context manager (`tempfile.TemporaryDirectory` with robust error cleanup)
   - Must raise `ValueError` on any violation with clear message.
2. Specify the comprehensive unit test suite in `backend/tests/test_extraction.py` covering all 5 defenses.
3. Write your report to `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_1\m1_safe_extract.md` and handoff.md.


## 2026-11-07T06:20:41Z
From: 1b39d829-223c-4805-b373-ad3f9409f65e
Content:
You are a teamwork_explorer subagent for Milestone 1: Safe Archive Extraction.
Your working directory is: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_1
You MUST read:
1. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
2. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md
3. c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_1\DISPATCH.md

Investigate and specify the safe archive extraction module (`backend/app/core/safe_extract.py`) and its unit tests (`backend/tests/test_extraction.py`).
Deliver your report to `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_m1_1\m1_safe_extract.md` and handoff.md.
When done, message the orchestrator (caller) with your completion status and handoff.md path.
