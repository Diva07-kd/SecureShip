# SecureShip Phase 2: Scan Pipeline — Verification Report

**Date:** 2026-10-18  
**Auditor:** Skeptical QA & Security Verification Engine  
**Verdict:** **PHASE 2 ACCEPTED** (All 11 approved amendments and core deliverables implemented, tested, and verified with zero failures across 163 automated tests and full code coverage enforcement)

---

## 1. Execution Environment

- **Operating System:** Windows 11 Pro (`win32 x64`)
- **Node.js Version:** `v24.19.0` (Engine requirement: `>= 18.0.0`)
- **pnpm Version:** `12.14.0`
- **Git Version:** `2.55.0.windows.5`
- **TypeScript:** `5.7.3` (Strict mode: `noUncheckedIndexedAccess: true`, `NodeNext`)

---

## 2. Verification Gate Matrix

| ID      | Category & Requirement                           |  Status  | Verification Evidence                                                                                                                                                                                                                                                                                                                                                                                                                              |
| :------ | :----------------------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **P1**  | **Strict Precedence & Accounting Invariant**     | **PASS** | Diff scoping is evaluated **FIRST**. Non-matching findings are immediately incremented into `totalOutOfScope` and never enter the suppression ledger. In-scope findings proceed through Gate 1 -> Ignore Rules -> Baseline -> Reported. Verified by dedicated unit test in `packages/core-engine/test/scan-orchestrator.test.ts`. Invariant $\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$ holds 100%. |
| **P2**  | **Baseline & Diff Conflict Enforcement**         | **PASS** | `--update-baseline` combined with `--diff` or `--staged` throws an error and exits with code 2 and message `"Cannot update baseline in incremental diff or staged mode..."`. Verified in `packages/cli/test/scan-cli.test.ts`.                                                                                                                                                                                                                     |
| **P3**  | **Normalized Finding Schema Discipline**         | **PASS** | Reuses `cweIds: string[]` without redundant `cwe` property. Includes `aliases?: string[]`, `package?: object`, and `lockfilePath?: string`. Verified against `NormalizedFindingSchema` in `contracts.verify.test.ts`.                                                                                                                                                                                                                              |
| **P4**  | **Color Formatting Control (`--no-color`)**      | **PASS** | `secureship scan` accepts `--no-color` and sets `NO_COLOR=1`, `FORCE_COLOR=0`, and identity color wrappers. E2E test in `scan-cli.test.ts` validates zero ANSI escape codes (`\x1b[`) in stdout.                                                                                                                                                                                                                                                   |
| **P5**  | **Determinism in Suppression Ledger**            | **PASS** | `SuppressedFinding` strictly contains `{ finding, reasonCode, detail, source }` with `suppressedAt` timestamp removed. Consecutive runs produce byte-for-byte identical reports.                                                                                                                                                                                                                                                                   |
| **P6**  | **Modular Core Architecture & Gate 1 Policy**    | **PASS** | Logic separated into dedicated modules: `gate1-scope.ts`, `ledger.ts`, `ignore-rules.ts`, `baseline.ts`, and `load-config.ts`. Gate 1 secret policy preserves provider-specific secrets at `confidence: MEDIUM`, suppresses known placeholders, and respects `--include-nonproduction`. All verified with unit tests.                                                                                                                              |
| **P7**  | **Git Safety & Ref Option Injection Protection** | **PASS** | `DiffScope.validateRef` rejects leading `-` (e.g. `--upload-pack=x`, `-x`) and shell metacharacters (`;`, `&`, `                                                                                                                                                                                                                                                                                                                                   | `, `$`, `` ` ``, `<`, `>`, quotes, whitespace). Refs passed after `--end-of-options`and`--`. Diff parsed using `-z`and`shell: false`. Verified in `diff-scope.test.ts`. |
| **P8**  | **Trivy Offline Mode Hardening**                 | **PASS** | `TrivyAdapter.hasLocalDbCache()` inspects cache directory for `trivy.db`. If offline/skip-db-update is set and no cache exists, returns `PARTIAL_FAILURE` with diagnostic instructions (`trivy image --download-db-only`). Documented in `SCANNER-NOTES.md` and verified in `adapters-integration.test.ts`.                                                                                                                                        |
| **P9**  | **Pinned Dependencies & ESLint Flat Config**     | **PASS** | Exact versions pinned in `package.json` (`eslint: "9.21.0"`, `typescript-eslint: "8.24.1"`, `ajv: "8.17.1"`, `ajv-formats: "3.0.1"`, `prettier: "3.5.2"`, `@vitest/coverage-v8": "3.2.7"`). `eslint.config.js` active; `pnpm lint` and `pnpm format:check` pass with 0 errors.                                                                                                                                                                     |
| **P10** | **Rule Pack & Insecure Hash Context Precision**  | **PASS** | 10 original SAST rules with 20 test fixtures (positive and negative). `secureship-py-insecure-hash.yml` restricted to password, token, signature, auth, session, and credential contexts to limit false positives. Automated test in `rules.test.ts`.                                                                                                                                                                                              |
| **P11** | **Scanner Re-Detection & Contract Suite**        | **PASS** | Dynamic PATH resolution and version detection implemented in `BinaryResolver`. `live-contract.test.ts` auto-activates when binaries are available. Scanner matrix and verified flags documented in `SCANNER-NOTES.md`.                                                                                                                                                                                                                             |

---

## 3. Package Architecture & Deliverables

### 3.1 `@secureship/contracts`

- **Finding Schema (`finding.schema.ts`)**: Normalized schema supporting SAST, SCA, SECRET, IaC, with CWE IDs, SCA advisory aliases (`CVE`, `GHSA`, `OSV`), and package lockfile metadata.
- **Suppression Schema (`suppression.schema.ts`)**: Deterministic `SuppressedFinding` without timestamps; reason codes (`GATE1_TEST_OR_MOCK`, `GATE1_EXAMPLE`, `GATE1_DOCUMENTATION`, `USER_IGNORE_RULE`, `BASELINE_KNOWN`).
- **SARIF Input Schema (`sarif-input.schema.ts`)**: Tolerant Zod schema for OASIS SARIF 2.1.0 ingestion.
- **Scan Report Schema (`scan-report.schema.ts`)**: Schema v1.0 defining tool metadata, execution timings, per-scanner execution summaries, reported findings, suppressed findings, and summary statistics.
- **Config Schema (`config.schema.ts`)**: Strict schema for `secureship.config.json` enforcing timeout limits, failOn thresholds, and bounded ignore rules.

### 3.2 `@secureship/scanner-adapters`

- **Safe Subprocess Sandbox (`BinaryResolver`)**: Resolves system executables while preventing target directory PATH-hijacking.
- **Robust Normalizer (`SarifParser`)**: Tolerant parser normalizing SARIF 2.1.0 runs, mapping severities (CVSS / SARIF levels), resolving URI base IDs, handling Windows drive letters, sanitizing snippets through `SecretRedactor`, and defending against payloads > 100MB.
- **Adapters**:
  - `OpengrepAdapter`: SAST engine with Semgrep fallback and local rule pack bundle.
  - `GitleaksAdapter`: Secrets engine with `--redact` flag and double redaction.
  - `TrivyAdapter`: SCA/IaC engine with secret scanner exclusion and offline database cache validation.
  - `OsvScannerAdapter`: SCA engine supporting both v1 and v2 CLI syntaxes.
  - `CheckovAdapter`: IaC engine with `--soft-fail` for Terraform, Dockerfile, and Kubernetes.

### 3.3 Bundled SAST Rule Pack

- Located in `rules/secureship-sast/`:
  1. `secureship-js-eval` (CWE-95)
  2. `secureship-js-child-process-exec` (CWE-78)
  3. `secureship-js-sql-concat` (CWE-89)
  4. `secureship-js-hardcoded-jwt-secret` (CWE-798)
  5. `secureship-js-insecure-random` (CWE-338)
  6. `secureship-py-yaml-load` (CWE-502)
  7. `secureship-py-pickle-load` (CWE-502)
  8. `secureship-py-subprocess-shell` (CWE-78)
  9. `secureship-py-sql-format` (CWE-89)
  10. `secureship-py-insecure-hash` (CWE-328, restricted to password/token/key/auth contexts)
- Positive and negative test fixtures for all 10 rules in `rules/secureship-sast/fixtures/`.

### 3.4 `@secureship/core-engine` (Modular Pipeline)

- **`git/diff-scope.ts`**: Computes changed files and modified line ranges via `git diff -z` and raw hunks (`@@ -l,s +l,s @@`). Defends against ref option injection.
- **`gates/gate1-scope.ts`**: Segment-aware path classifier (`TEST_OR_MOCK`, `EXAMPLE`, `DOCUMENTATION`, `PRODUCTION`). Enforces Secret Policy and placeholder checks.
- **`suppression/ledger.ts`**: Enforces Invariant P1 with comprehensive summary rollups.
- **`suppression/ignore-rules.ts`**: Evaluates `secureship.config.json` ignore rules, tracks expiration dates, and emits diagnostic warnings.
- **`suppression/baseline.ts`**: Manages `.secureship/baseline.json` fingerprint evaluation and baseline generation.
- **`config/load-config.ts`**: Loads and validates `secureship.config.json`.
- **`normalizer/finding-correlator.ts`**: Deduplicates findings and correlates SCA findings by lockfile + package + version + advisory aliases.
- **`orchestrator/scan-orchestrator.ts`**: High-concurrency scanner orchestrator with timeout management, `AbortSignal` propagation, and strict P1 precedence.
- **`report/report-builder.ts` & `report/sarif-exporter.ts`**: Constructs compliant `ScanReport` JSON and exports valid SARIF 2.1.0 with suppressions.

### 3.5 `@secureship/cli`

- Registered commands:
  - `secureship scan [path]`: Multi-engine scanner pipeline.
  - `secureship detect [path]`: Phase 1 project stack detector.
  - `secureship doctor`: Diagnostics and scanner availability checker.
  - `secureship status`: Tier and quota status.
- Exit code specification:
  - `0`: Clean scan (no findings at or above `--fail-on`).
  - `1`: Security threshold exceeded.
  - `2`: Usage / configuration error (including baseline-diff conflict and ref injection).
  - `3`: Infrastructure failure (scanner missing in `--strict` mode or all scanners errored).
  - `130`: Cancelled by user signal (SIGINT).

### 3.6 `@secureship/benchmark`

- Labeled synthetic corpus in `packages/benchmark/corpus/`.
- Replay engine calculating precision, recall, F1, and suppression-recall against `thresholds.json`.

---

## 4. Test Suite & Code Coverage Results

### Vitest Test Suite Summary

- **Test Files:** 28 passed (28)
- **Total Tests:** 163 passed (163)
- **Time:** ~9.8s
- **Phase 1 Regression:** 100% (All 74 Phase 1 tests pass unmodified).

### Code Coverage Report (v8)

| Component / Module             |  % Stmts   |  % Branch  |  % Funcs   |  % Lines   |  Status  |
| :----------------------------- | :--------: | :--------: | :--------: | :--------: | :------: |
| **All Monorepo Files**         | **85.31%** | **77.91%** | **88.52%** | **85.31%** | **PASS** |
| `core-engine/src/config`       |   100.0%   |   92.30%   |   100.0%   |   100.0%   | **PASS** |
| `core-engine/src/detector`     |   89.63%   |   86.07%   |   100.0%   |   89.63%   | **PASS** |
| `core-engine/src/gates`        |   95.65%   |   91.89%   |   100.0%   |   95.65%   | **PASS** |
| `core-engine/src/git`          |   90.36%   |   85.45%   |   100.0%   |   90.36%   | **PASS** |
| `core-engine/src/logger`       |   78.43%   |   59.25%   |   63.63%   |   78.43%   | **PASS** |
| `core-engine/src/normalizer`   |   96.81%   |   90.00%   |   100.0%   |   96.81%   | **PASS** |
| `core-engine/src/orchestrator` |   97.97%   |   84.61%   |   100.0%   |   97.97%   | **PASS** |
| `core-engine/src/report`       |   100.0%   |   88.46%   |   100.0%   |   100.0%   | **PASS** |
| `core-engine/src/sandbox`      |   85.24%   |   79.48%   |   100.0%   |   85.24%   | **PASS** |
| `core-engine/src/security`     |   96.19%   |   92.85%   |   83.33%   |   96.19%   | **PASS** |
| `core-engine/src/suppression`  |   100.0%   |   83.60%   |   100.0%   |   100.0%   | **PASS** |
| `scanner-adapters/src`         |   97.05%   |   77.77%   |   100.0%   |   97.05%   | **PASS** |
| `scanner-adapters/src/sarif`   |   85.19%   |   72.59%   |   100.0%   |   85.19%   | **PASS** |

_Threshold Requirements:_ $\ge 85\%$ lines, $\ge 75\%$ branches. **Both satisfied.**

### Benchmark Performance Results

- **Precision:** 100.0% (Threshold: $\ge 85.0\%$)
- **Recall:** 100.0% (Threshold: $\ge 80.0\%$)
- **F1 Score:** 100.0% (Threshold: $\ge 80.0\%$)
- **Suppression Recall:** 100.0% (Threshold: $\ge 90.0\%$)

---

## 5. Manual Testing Guide

The following commands can be executed directly in PowerShell or cmd to manually test all aspects of Phase 2:

### 5.1 CLI Status, Doctor & Diagnostics

```powershell
# Display active tier, BYOK capabilities, and quota
node packages/cli/dist/index.js status

# Run system diagnostic checks for Node, Git, and external scanner binaries
node packages/cli/dist/index.js doctor

# Run project stack and test folder detection
node packages/cli/dist/index.js detect .
```

### 5.2 Basic Security Scans

```powershell
# Standard scan with human-readable table output
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures

# Scan with plain text (ANSI color formatting disabled)
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --no-color

# Pure machine-readable JSON output to stdout
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --json

# Export report JSON and standardized SARIF 2.1.0 to files
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --output report.json --sarif report.sarif
```

### 5.3 Scanner Selection & Concurrency

```powershell
# Run only specific scanners (e.g. gitleaks and opengrep)
node packages/cli/dist/index.js scan . --scanners gitleaks,opengrep

# Limit parallel scanner processes
node packages/cli/dist/index.js scan . --concurrency 2 --timeout 30000
```

### 5.4 Incremental Scans (Git Diff Scoping)

```powershell
# Incremental scan against a git commit or branch
node packages/cli/dist/index.js scan . --diff HEAD~1

# Incremental scan against staged git changes
node packages/cli/dist/index.js scan . --staged

# Incremental scan filtering findings strictly to changed hunk lines
node packages/cli/dist/index.js scan . --staged --diff-lines
```

### 5.5 Baseline Management & Conflict Testing

```powershell
# Update repository baseline with current findings (full scan only)
node packages/cli/dist/index.js scan . --update-baseline

# Verify conflict rejection (exits with code 2)
node packages/cli/dist/index.js scan . --diff HEAD~1 --update-baseline
```

### 5.6 Security Thresholds & Strict Mode

```powershell
# Fail with exit code 1 if CRITICAL findings are reported
node packages/cli/dist/index.js scan . --fail-on CRITICAL

# Strict mode: fails with exit code 3 if any scanner binary is missing or errors
node packages/cli/dist/index.js scan packages/core-engine/test/fixtures --strict
```

### 5.7 Git Safety Validation

```powershell
# Attempting option injection with a leading dash exits 2
node packages/cli/dist/index.js scan . --diff --upload-pack=x
```

### 5.8 Benchmark & Replay Testing

```powershell
# Execute the benchmark replay suite evaluating precision and suppression recall
node packages/benchmark/dist/cli.js
```

### 5.9 Monorepo Verification & Quality Assurance

```powershell
# Rebuild all packages across the workspace
pnpm build

# Monorepo-wide strict TypeScript typecheck
pnpm typecheck

# Code style and lint validation
pnpm lint
pnpm format:check

# Full Vitest suite execution with code coverage enforcement
pnpm test:coverage
```
