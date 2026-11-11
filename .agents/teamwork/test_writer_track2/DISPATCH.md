# Task Assignment: E2E Testing Track Orchestration & Test Suite Generation

- Working Directory: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\test_writer_track2
- Original Request: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
- Project Scope: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\orchestrator\PROJECT.md

## Objective
As the E2E Testing agent, you are responsible for the entire opaque-box E2E testing track:
1. Create `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\TEST_INFRA.md` following the template in the project requirements.
2. Generate all synthetic test archives in `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\fixtures\`:
   - `valid_clean.zip` (valid code, no findings)
   - `valid_vulnerable.zip` (valid code with vulnerable patterns, e.g. secrets or insecure deserialization)
   - `zip_slip.zip` (archive containing `../` path traversal entry)
   - `symlink_0xa1ed.zip` (archive containing symlink entry with external_attr `0xA1ED` or `S_IFLNK`)
   - `zip_bomb.zip` (archive with compression ratio > 100x)
   - `oversized_file.zip` (archive containing single uncompressed file > 10 MB)
   - `oversized_archive.zip` (archive with total uncompressed size > 50 MB)
   - `corrupt.zip` (malformed/truncated zip file)
3. Implement the comprehensive E2E test suite in `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\e2e\`:
   - Tier 1: Feature coverage (safe extraction, scan upload, polling, reports, export formats, health endpoint, CLI runner)
   - Tier 2: Boundary & corner cases (zip-slip, symlink, zip bomb, 10MB file, 50MB total, CLI exit 0 vs 1, timeout 300s)
   - Tier 3: Cross-feature combinations (concurrency 1 queue, exports while scan is running vs done, etc.)
   - Tier 4: Real-world application scenarios (end-to-end scan of synthetic project, verification of CWE/OWASP mapping)
4. Verify the test suite and fixtures using `pytest tests/e2e -v` or python scripts.
5. Create `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\TEST_READY.md` at project root summarizing the test suite, execution command, and tier breakdown.
6. Write a complete handoff report to `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\test_writer_track2\handoff.md`.


## 2026-11-07T06:20:13Z
You are a teamwork_test_writer subagent for the E2E Testing Track of SecureScan.
Your working directory is: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\test_writer_track2
Your mission:
1. Create c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\TEST_INFRA.md following the specification in PROJECT.md and ORIGINAL_REQUEST.md.
2. Generate all synthetic test archives in c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\fixtures\ (valid, zip-slip, symlink 0xA1ED, zip-bomb >100x ratio, >10MB file, >50MB archive, corrupt).
3. Implement the full E2E test suite across Tiers 1-4 in c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\tests\e2e\ with comprehensive assertions.
4. Run your test harness/fixtures to verify that all fixtures load and validate cleanly.
5. Create c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\TEST_READY.md summarizing test counts, runner command, and feature coverage matrix.
6. Deliver your complete handoff report to c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\test_writer_track2\handoff.md.
