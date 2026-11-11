# SecureShip Architectural Invariants & Production Standards (Phases 1–3)

## 1. Non-Negotiable Code Freeze on Phases 1, 2, and 3

- The code, contracts, WASM binaries, test suites, fixtures, and benchmark corpora implemented in Phases 1, 2, and 3 are production standard ready.
- Do NOT rewrite, refactor, weaken, or modify existing Phase 1–3 code or verification tests unless explicitly directed with a formal backward-compatible amendment.
- All new features (e.g. Phase 4 AI Triage, Phase 5) MUST build strictly on top of existing contracts and preserve backward compatibility (e.g., ScanReport reader compatibility across schema versions 1.0, 1.1, and future versions).

---

## 2. Core Architectural & Accounting Invariants

### Invariant P1: Ledger Accounting Guarantee

$$\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$$

- Every normalized finding emitted by any scanner belongs to **exactly one** mutually exclusive category.
- **Diff Scoping evaluated FIRST**: When `--diff`, `--staged`, or `--diff-lines` is active, non-matching findings increment `totalOutOfScope` and **NEVER enter the suppression ledger** or undergo Gate 1, ignore, or baseline evaluation.
- `totalSuppressed` strictly tallies findings suppressed by Gate 1, user ignore rules, baseline, or Gate 2:
  $$\text{totalSuppressed} = \text{gate1} + \text{ignoreRules} + \text{baseline} + \text{gate2Unreachable}$$
- Consecutive scans on identical inputs MUST produce byte-for-byte identical suppression ledgers (`suppressedAt` timestamps are excluded from ledger records).

### Precedence Order

$$\text{Diff Scoping} \longrightarrow \text{Gate 1 Scope Tagging} \longrightarrow \text{Ignore Rules} \longrightarrow \text{Baseline Matching} \longrightarrow \text{Gate 2 Reachability}$$

---

## 3. Process Isolation & Sandbox Security

- **Strictly `shell: false`**: Never execute commands with `shell: true`, `exec`, `execSync`, `eval`, or `new Function`.
- **Injection Defense**: All subprocess arguments must be passed as literal array elements. Git refs must be validated against leading `-` and shell metacharacters (`;&|<>$\`\`\`), and disambiguated with `--end-of-options` and `--`.
- **Target Boundary Guard**: `BinaryResolver` must verify that any external executable is strictly **outside the scanned target directory** (preventing planted binary / PATH hijack).
- **Environment Sanitization**: Strip ambient cloud secrets and sensitive tokens (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `SUPER_SECRET_TOKEN`) from child process environments; whitelist only essential OS variables (`PATH`, `SYSTEMROOT`, `TEMP`, etc.).
- **Process Tree Termination**: On timeout or SIGINT, terminate entire process trees (`taskkill /PID <pid> /T /F` on Windows, process group kill on POSIX) with zero orphan processes.
- **Secret Redaction**: All raw snippets, stdout, stderr, and logs must be scrubbed through `SecretRedactor` (idempotent, minimal diagnostic prefix, ReDoS-resistant).

---

## 4. Gate 1 Scope & Secret Policy

- Scopes: `PRODUCTION`, `TEST_OR_MOCK`, `EXAMPLE`, `DOCUMENTATION`.
- **Provider Secret Preservation**: High-entropy provider credentials (AWS, GitHub, Slack, Stripe, PEM keys) located in test code are **NOT suppressed** unless matching known placeholder tokens (`dummy`, `EXAMPLE`, `changeme`, etc.), and remain reported with `confidence: MEDIUM`.
- All other categories (SAST, SCA, IaC) in test/mock directories are suppressed under Gate 1 reasons.

---

## 5. Gate 2 Reachability & Analytical Safety

- **Supply Chain Attestation**: All bundled Tree-sitter WASM grammars must match hardcoded SHA-256 digests. Tampering or corruption fails closed to `UNKNOWN (PARSE_FAILURE)`.
- **External HMAC Cache**: AST extraction cache must be stored strictly outside the target repository (`~/.secureship/cache`), HMAC-SHA256 authenticated with machine-local key (`0600` permissions). Never trust repository-committed caches.
- **Whole-Repo Graph in Diff Mode**: When running `--diff` or `--staged`, the reachability graph is constructed for the **entire repository**; diff scoping is applied exclusively to findings.
- **Leaf Direct Preconditions (a–k)**: An SCA finding evaluates to `UNREACHABLE` (`NOT_IMPORTED-HIGH`) ONLY when all 11 positive preconditions hold (zero parse errors, zero dynamic markers, resolved entrypoints, zero script/config/string references, leaf direct in lockfile tree).
- **Rule C1 (Python SCA Ceiling)**: Python SCA findings are NEVER assigned `UNREACHABLE` with `HIGH` confidence (capped at `MEDIUM`). Therefore, Python SCA findings are NEVER auto-suppressed under default policy.
- **Principle G8 (Non-Gated Categories)**: `SECRET` and `IAC` findings always evaluate to `verdict: UNKNOWN, evidence.kind: NOT_APPLICABLE`.
- **Fail-Closed on Flat Lockfiles**: Unsupported lockfiles (`uv.lock`, `bun.lock`, `yarn.lock` v1, flat `requirements.txt`) fail closed to `UNKNOWN (NO_LOCKFILE_TREE)`.
- **Reference Scanner Guardrails**: Enforce 1 MB per-file size cap, 50 MB total byte budget, and 10-second wall-clock timeout. Budget exhaustion flags `incompleteScan: true` and degrades verdicts to `UNKNOWN (CONFIG_REFERENCE)` with `LOW` confidence.
- **Terminology**: The word "safe" is forbidden when describing `NOT_IMPORTED`. Mandatory disclaimer: _"Import-level analysis only; not proof of exploitability or safety."_

---

## 6. Exit Codes Specification

- `0`: Clean scan (zero findings meeting or exceeding `--fail-on`).
- `1`: Threshold exceeded (one or more reported findings meet or exceed `--fail-on`).
- `2`: Usage / configuration error (invalid flags, baseline-diff conflict, invalid git ref).
- `3`: Infrastructure error (`--strict` mode with missing scanner, or all scanners errored).
- `130`: Cancelled by user signal (SIGINT).

---

## 7. Testing, Verification & Code Coverage Bar

- Global thresholds: $\ge 85\%$ lines, $\ge 75\%$ branches.
- Per-file floor: $\ge 70\%$ lines AND $\ge 70\%$ branches enforced on every single source file in `vitest.config.ts`.
- Zero test failures permitted across all 385+ tests.
- 100% mutation detection across all 17 mutations (`N1`–`N17`).
- Zero false-unreachables across benchmark corpora and ground-truth fuzz suites.
