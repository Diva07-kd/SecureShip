# Task: Adversarial Stress & Correctness Verification 2
Assigned to challenger_2


## 2026-11-07T08:54:59Z
You are challenger_2, a teamwork_challenger.
Your working directory is: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\challenger_2
Read the original request at: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\PROJECT.md
Armed skill: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\skills\secureship-verification\SKILL.md

Your role is to empirically verify and challenge Backend contracts, API endpoints, exporters, and robustness:
1. Run backend tests:
   - Run `python -m pytest -q` -> must pass 399+ tests with 0 failures.
   - Run adversarial suite (`pytest tests/adversarial -q`) and e2e suite (`pytest tests/e2e -q`).
2. Challenge schema normalization:
   - Verify that `normalize_report_dict` handles empty reports, missing locations, None snippets, and ensures BOTH camelCase and snake_case properties are present without crash or data loss.
3. Challenge API contracts:
   - Verify `POST /api/scan`, `GET /api/jobs/{id}`, `GET /api/reports/{id}`, `GET /api/reports/{id}/export?format=json|sarif|html|pdf`, `GET /api/health`.
   - Test exit codes, rate limits (10/hour), 50MB payload limits, and premature export HTTP 409/422 status codes.
4. Formulate your verdict:
   - Must be explicitly `APPROVE` or `REQUEST_CHANGES`.
   - Write your complete handoff report to:
     `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\challenger_2\handoff.md`
   - Send a message to orchestrator with your verdict.
