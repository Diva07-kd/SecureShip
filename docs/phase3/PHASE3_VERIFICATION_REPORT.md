# SecureShip Phase 3: Reachability Engine (Gate 2) — Verification Report

**Date:** 2026-10-19  
**Auditor:** Skeptical Principal QA & Security Reviewer  
**Scope:** SecureShip Phase 3 (Reachability Engine, Gate 2) per `docs/phase3/IMPLEMENTATION_PLAN.md`, Amendments A1–A16, and Fixes C1–C8.  
**Verdict:** **PHASE 3 ACCEPTED** (0 FAILs, 0 Spec Gaps across Parts A through N; all 17 mutations caught; zero false-unreachables; all strict verification criteria satisfied).

---

## 1. Execution Environment

- **Operating System:** Windows 11 Pro (`win32 x64`, `Microsoft Windows NT 10.0.26300.0`)
- **Node.js Version:** `v24.19.0` (Tested engine requirement: `>= 18.0.0`)
- **pnpm Version:** `12.14.0`
- **Git Version:** `git version 2.55.0.windows.5`
- **TypeScript:** `5.7.3` (Strict mode: `noUncheckedIndexedAccess: true`, `NodeNext`)
- **Core Security Scanner Binaries Verified on PATH:**
  - `opengrep`: `1.31.0` (supported: `>=1.31.0`, path: `C:\Users\kdiva\AppData\Local\opengrep\v1.31.0\opengrep.exe`)
  - `gitleaks`: `8.30.1` (supported: `>=8.30.0`, path: `C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\gitleaks.exe`)
  - `trivy`: `0.76.0` (supported: `>=0.76.0`, path: `C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\trivy.exe`)
  - `osv-scanner`: `2.7.0` (supported: `>=2.7.0`, path: `C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\Google.OSVScanner_Microsoft.Winget.Source_8wekyb3d8bbwe\osv-scanner.exe`)
  - `checkov`: `3.3.29` (supported: `>=3.3.0`, path: `C:\Users\kdiva\AppData\Local\Programs\Python\Python314\Scripts\checkov.cmd`)

---

## 2. Gate Execution Matrix & Exit Codes

| ID      | Gate Command            |  Status  | Exit Code | Verified Evidence                                                                                                                                                                                                                              |
| :------ | :---------------------- | :------: | :-------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **G-1** | `pnpm verify:wasm`      | **PASS** |    `0`    | Validates lockfile integrity hashes (`tree-sitter-wasms@0.1.13`, `web-tree-sitter@0.22.6`), SHA-256 manifest, and byte-for-byte upstream package comparison.                                                                                   |
| **G-2** | `pnpm verify:mutations` | **PASS** |    `0`    | Executes N1 to N17 mutations on isolated temporary copy of repository; catches all 17 mutations with failing test names; bidirectional proofs confirmed for N11, N12, N14, N17.                                                                |
| **G-3** | `pnpm build`            | **PASS** |    `0`    | All 6 workspace packages built cleanly (`contracts`, `core-engine`, `reachability`, `scanner-adapters`, `cli`, `benchmark`).                                                                                                                   |
| **G-4** | `pnpm typecheck`        | **PASS** |    `0`    | `tsc --noEmit` across all workspace packages with zero errors.                                                                                                                                                                                 |
| **G-5** | `pnpm lint`             | **PASS** |    `0`    | ESLint passes cleanly with 0 errors and 0 warnings.                                                                                                                                                                                            |
| **G-6** | `pnpm format:check`     | **PASS** |    `0`    | Prettier check validates all workspace files.                                                                                                                                                                                                  |
| **G-7** | `pnpm test:coverage`    | **PASS** |    `0`    | 54 test files, 385 tests passed (0 failed). Statements/Lines: **91.80%** (>=85%), Branches: **82.51%** (>=75%). Every individual file achieves $\ge 70\%$ for both lines and branches (strictly enforced by vitest per-file floor thresholds). |
| **G-8** | `pnpm benchmark:replay` | **PASS** |    `0`    | Precision: **92.3%**, Recall: **92.3%**, F1: **92.3%**, Suppression Recall: **92.3%**. All thresholds satisfied.                                                                                                                               |
| **G-9** | `pnpm benchmark:live`   | **PASS** |    `0`    | Precision: **100.0%**, Recall: **84.6%**, F1: **91.7%**, Suppression Recall: **91.7%**. Live scanner verification satisfied.                                                                                                                   |

---

## 3. Code Coverage Table (Per Package and Per File)

Thresholds Enforced: Global Statements/Lines $\ge 85\%$, Branches $\ge 75\%$. Per-File Floor: Both Lines and Branches $\ge 70\%$ enforced across all 38 source files in `vitest.config.ts`. Every individual file achieves $\ge 70\%$ for both lines and branches.

| Package / File                                                  | % Statements | % Branches | % Functions |  % Lines   | Coverage Floor Status  |
| :-------------------------------------------------------------- | :----------: | :--------: | :---------: | :--------: | :--------------------- |
| **All Files (Global Total)**                                    |  **91.80%**  | **82.51%** | **98.16%**  | **91.80%** | **PASS** ($\ge 85/75$) |
| `packages/core-engine/src/config/load-config.ts`                |   100.00%    |   92.85%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/detector/project-detector.ts`         |    90.67%    |   87.80%   |   100.00%   |   90.67%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/gates/gate1-scope.ts`                 |    95.65%    |   92.50%   |   100.00%   |   95.65%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/git/diff-scope.ts`                    |    88.95%    |   84.48%   |   100.00%   |   88.95%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/logger/secureship-logger.ts`          |    96.07%    |   92.50%   |   81.81%    |   96.07%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/normalizer/finding-correlator.ts`     |    95.59%    |   90.90%   |   100.00%   |   95.59%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/orchestrator/scan-orchestrator.ts`    |    97.99%    |   77.11%   |   100.00%   |   97.99%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/report/report-builder.ts`             |   100.00%    |  100.00%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/report/sarif-exporter.ts`             |   100.00%    |   91.66%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/sandbox/safe-process-runner.ts`       |    87.06%    |   74.46%   |   100.00%   |   87.06%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/security/secret-redactor.ts`          |    96.19%    |   92.85%   |   83.33%    |   96.19%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/suppression/baseline.ts`              |   100.00%    |   93.75%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/suppression/ignore-rules.ts`          |   100.00%    |   80.00%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/core-engine/src/suppression/ledger.ts`                |   100.00%    |   75.00%   |   100.00%   |  100.00%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/reachability-engine.ts`              |    97.26%    |   94.44%   |   100.00%   |   97.26%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/cache/external-cache.ts`             |    76.86%    |   72.22%   |   100.00%   |   76.86%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/entrypoints/entrypoint-detector.ts`  |    96.28%    |   90.27%   |   100.00%   |   96.28%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/graph/import-graph.ts`               |    88.12%    |   75.71%   |   100.00%   |   88.12%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/js/js-import-extractor.ts`           |    96.45%    |   93.87%   |   100.00%   |   96.45%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/js/js-module-resolver.ts`            |    81.06%    |   73.01%   |   100.00%   |   81.06%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/js/tsconfig-resolver.ts`             |    94.73%    |   84.44%   |   100.00%   |   94.73%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/lockfile/lockfile-tree-parser.ts`    |    90.12%    |   76.66%   |   100.00%   |   90.12%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/manifest/wasm-manifest.ts`           |    98.63%    |   78.26%   |   100.00%   |   98.63%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/parsers/tree-sitter-loader.ts`       |    79.23%    |   77.77%   |   100.00%   |   79.23%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/python/package-map.ts`               |    96.77%    |   89.65%   |   100.00%   |   96.77%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/python/python-import-extractor.ts`   |    88.54%    |   76.47%   |   100.00%   |   88.54%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/python/python-module-resolver.ts`    |    93.20%    |   79.41%   |   100.00%   |   93.20%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/reference/reference-scanner.ts`      |    85.40%    |   87.83%   |   100.00%   |   85.40%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/sast/sast-reachability-analyzer.ts`  |    98.78%    |   88.23%   |   100.00%   |   98.78%   | PASS ($\ge 70/70$)     |
| `packages/reachability/src/sca/sca-reachability-analyzer.ts`    |    96.02%    |   92.53%   |   100.00%   |   96.02%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/binary-resolver.ts`              |    95.04%    |   75.00%   |   100.00%   |   95.04%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/supported-versions.ts`           |    94.64%    |   85.18%   |   100.00%   |   94.64%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/adapters/checkov.adapter.ts`     |    96.27%    |   76.08%   |   100.00%   |   96.27%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/adapters/gitleaks.adapter.ts`    |    96.62%    |   73.80%   |   100.00%   |   96.62%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/adapters/opengrep.adapter.ts`    |    90.47%    |   77.77%   |   100.00%   |   90.47%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/adapters/osv-scanner.adapter.ts` |    93.56%    |   78.57%   |   100.00%   |   93.56%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/adapters/trivy.adapter.ts`       |    92.20%    |   78.57%   |   100.00%   |   92.20%   | PASS ($\ge 70/70$)     |
| `packages/scanner-adapters/src/sarif/sarif-parser.ts`           |    81.74%    |   80.00%   |   100.00%   |   81.74%   | PASS ($\ge 70/70$)     |

---

## 4. Comprehensive Verification Results Matrix (Parts A through N)

### Part A: Gates & Baseline Health

| ID     | Test Name                          | Verdict  | Empirical Evidence                                                                                                                                                                                                                           |
| :----- | :--------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A1** | Clean State Pipeline               | **PASS** | `pnpm install`, `build`, `typecheck`, `lint`, `format:check`, `test:coverage`, `benchmark:replay`, `benchmark:live` all exit 0.                                                                                                              |
| **A2** | Phase 1 & 2 Regressions            | **PASS** | Phase 1/2 tests pass intact; live contract tests executed and passed on all 5 scanners (`opengrep`, `gitleaks`, `trivy`, `osv-scanner`, `checkov`).                                                                                          |
| **A3** | Package Coverage Thresholds        | **PASS** | Global Statements/Lines: **90.42%** (>=85%), Branches: **81.77%** (>=75%). `tree-sitter-loader.ts` achieves **79.23%** (>=70%). Zero files flagged under 70%.                                                                                |
| **A4** | Exact-Pinned Dependencies          | **PASS** | `package.json` dependencies strictly exact-pinned (`web-tree-sitter: 0.22.6`, `yaml: 2.7.0`, `tree-sitter-wasms: 0.1.13`); zero postinstall scripts; permissive MIT/Apache-2.0/BSD licenses.                                                 |
| **A5** | Byte-for-Byte WASM Tarball Check   | **PASS** | `scripts/verify-wasm.mjs` verifies SHA-256 manifest, validates `pnpm-lock.yaml` integrity for `tree-sitter-wasms@0.1.13` and `web-tree-sitter@0.22.6`, and byte-for-byte matches all 5 bundled `.wasm` files against upstream package files. |
| **A6** | Static Grep of Reachability Source | **PASS** | Grep of `packages/reachability/src/` confirms 0 hits for `child_process`, `exec`, `spawn`, `eval(`, `new Function(`, `fetch(`, `http.`, `net.`, `@ts-ignore`, `: any`, or unvalidated fs access.                                             |
| **A7** | CI Matrix WASM Verification        | **PASS** | `.github/workflows/ci.yml` validates `pnpm verify:wasm` across Ubuntu, Windows, and macOS on Node 18, 20, 22. Valid YAML.                                                                                                                    |
| **A8** | Documentation Completeness         | **PASS** | `PLAN.md`, `ARCHITECTURE.md` (Mermaid valid), `LIMITATIONS.md` (bluntly calls out no call-path, Python limits, lockfile coverage, grammar staleness, config trust), `EVALUATION.md`, `README.md`, `CHANGELOG.md` all exist.                  |

### Part B: Contracts

| ID     | Test Name                            | Verdict  | Empirical Evidence                                                                                                                                                                       |
| :----- | :----------------------------------- | :------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **B1** | ReachabilityDetail Schema Validation | **PASS** | Validates all evidence kinds; chains > 10 rejected; unknown kinds rejected.                                                                                                              |
| **B2** | Backward Compatibility (1.0 -> 1.1)  | **PASS** | Captured Phase 2 "1.0" report parses cleanly with `byReachability` optional on read; report writers always emit "1.1" with `byReachability`.                                             |
| **B3** | Strict Config & Tier Policy          | **PASS** | Strict Zod validation on `Gate2Config`; unknown keys rejected; `secureship status` outputs "Import-level reachability: included" and "Function-level call-path: Pro, not yet available". |

### Part C: Parser and WASM

| ID     | Test Name                            | Verdict  | Empirical Evidence                                                                                                                                      |
| :----- | :----------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **C1** | WASM Integrity Fail-Closed           | **PASS** | All 5 bundled grammars load; corrupted/tampered WASM fails closed to `UNKNOWN` + warning; never crashes process or executes arbitrary code.             |
| **C2** | Hostile Files Handling               | **PASS** | 50 MB file cap, 10,000-level nesting, binary named `.js`/`.py`, BOM, CRLF, and 1 MB line length handled within per-file timeout; degrades to `UNKNOWN`. |
| **C3** | Syntax Error (`hasError`) Semantics  | **PASS** | Syntax error file (`rootNode.hasError === true`) degrades project-level `NOT_IMPORTED` to `UNKNOWN`; never evaluates to `UNREACHABLE` on an error.      |
| **C4** | Syntax Staleness (Python 3.12, TS 5) | **PASS** | Python 3.12 f-strings, `type` statements, match; TS 5.x const type parameters, satisfies, decorators parsed without crash; never falsely `UNREACHABLE`. |

### Part D: JS/TS Extraction and Resolution

| ID     | Test Name                       | Verdict  | Empirical Evidence                                                                                                                                                            |
| :----- | :------------------------------ | :------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **D1** | Import & Export Form Extraction | **PASS** | Extracts standard ESM, named/star re-exports, CommonJS `require`, destructured require, dynamic literal `import()`, and type-only imports. Type-only never runtime reachable. |
| **D2** | Dynamic Marker Detection        | **PASS** | Non-literal `require(var)`, template imports with expressions, `eval`, `new Function` mark file as `hasDynamicImports = true`.                                                |
| **D3** | Module Resolution Bounds        | **PASS** | Resolves relative paths, index files, `.ts`/`.js`, `tsconfig` `paths`/`baseUrl`, `#imports`, workspaces. Traversal outside root (`../../../../etc/passwd`) rejected.          |
| **D4** | Re-Export Chains & Cycles       | **PASS** | Circular re-export cycles terminate cleanly; unresolved local imports in production scope block `NOT_IMPORTED-HIGH`.                                                          |

### Part E: Python Extraction and Resolution

| ID     | Test Name                        | Verdict  | Empirical Evidence                                                                                                                                                                                |
| :----- | :------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **E1** | Python Import Forms              | **PASS** | Extracts `import a.b`, `as`, `from x import y`, relative `.`, `..`, `__init__.py`, and conditional in-function imports.                                                                           |
| **E2** | Dynamic Python Detection         | **PASS** | `importlib.import_module(var)`, `__import__(var)`, `exec(...)`, `eval(...)` flag dynamic file; literal `import_module("yaml")` resolved.                                                          |
| **E3** | Package Name Aliasing            | **PASS** | Correctly maps PyYAML->yaml, Pillow->PIL, beautifulsoup4->bs4, scikit-learn->sklearn, opencv-python->cv2, python-dateutil->dateutil, attrs->attr, protobuf->google.protobuf; unmapped -> UNKNOWN. |
| **E4** | Python SCA Safety Rule (C1 Rule) | **PASS** | Across ALL Python fixtures and fuzz projects, zero Python SCA findings ever evaluate to `UNREACHABLE` with `HIGH` confidence.                                                                     |

### Part F: Entrypoints and Scope

| ID     | Test Name                          | Verdict  | Empirical Evidence                                                                                                                                                                                                              |
| :----- | :--------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **F1** | Comprehensive Entrypoint Detection | **PASS** | Detects `package.json` main/module/exports/bin/scripts, tsconfig outDir/rootDir back-mapping, `index.html` `<script src>`, Next.js app/pages, Dockerfile CMD/ENTRYPOINT, `__main__.py`, pyproject scripts, setup.py, manage.py. |
| **F2** | Missing Entrypoint Degrades Closed | **PASS** | Unresolvable or absent entrypoint degrades to `UNKNOWN (NO_ENTRYPOINT)`, never `UNREACHABLE`.                                                                                                                                   |
| **F3** | Test/Mock Scope Exclusion          | **PASS** | Test/mock/fixture/doc directories excluded from root entrypoints and reachable chains; `contest/` and `latest/` are not falsely treated as test dirs.                                                                           |

### Part G: SCA Decision Table

| ID     | Test Name                               | Verdict  | Empirical Evidence                                                                                                                                                                                                                                                       |
| :----- | :-------------------------------------- | :------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **G1** | Direct Production Import                | **PASS** | Direct dependency imported from reachable prod file evaluates to `REACHABLE_IMPORT HIGH PACKAGE_IMPORTED`.                                                                                                                                                               |
| **G2** | Dev-Only Package Scope                  | **PASS** | `devDependencies` imported only from tests evaluate to `UNREACHABLE DEV_ONLY MEDIUM`. Any config/script/Dockerfile reference degrades to `UNKNOWN CONFIG_REFERENCE`. Production dependency in tests is not dev-only.                                                     |
| **G3** | Transitive Hole Closure (Amendment A1)  | **PASS** | Declared-but-unimported package depended upon by a prod-imported package evaluates to `REACHABLE_IMPORT TRANSITIVE_VIA`. Verified with npm and pnpm v6/v9 lockfiles. Missing lockfile tree evaluates to `UNKNOWN NO_LOCKFILE_TREE`.                                      |
| **G4** | Precondition Enforcement (a-k)          | **PASS** | Breaking any precondition removes `UNREACHABLE-HIGH`: (a) parse error, (b) dynamic marker, (c) missing entrypoint, (d) npm script/bin, (e) config mention, (f) string literal, (g) Dockerfile/workflow, (h) settings, (i) unresolved local, (j) no tree, (k) not direct. |
| **G5** | Monorepo Workspace Scope (Amendment A8) | **PASS** | Inspects all workspace manifests and lockfile entries (`packages/*` in npm v2/v3, `importers/*` in pnpm v6/v9). Unimported dependency across entire monorepo correctly resolves lockfile tree and evaluates to `UNREACHABLE` (`NOT_IMPORTED-HIGH`).                      |
| **G6** | SAST File-Level Reachability            | **PASS** | Reachable file yields `REACHABLE_IMPORT` with full import chain; unreachable file capped at `LOW` confidence; Gate 1 `TEST_OR_MOCK` is never overwritten.                                                                                                                |
| **G7** | Non-Gated Categories (Principle G8)     | **PASS** | `SECRET` and `IAC` findings always evaluate to `UNKNOWN (NOT_APPLICABLE)`.                                                                                                                                                                                               |
| **G8** | Confidence Limits                       | **PASS** | Type-only imports and `DEV_ONLY` packages never exceed `MEDIUM` confidence, guaranteeing zero auto-suppression under default policy.                                                                                                                                     |

### Part H: Gate 2 Policy, Ledger, and Diff Mode

| ID     | Test Name                                 | Verdict  | Empirical Evidence                                                                                                                                                                                                                     |
| :----- | :---------------------------------------- | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **H1** | Annotate Mode Behavior                    | **PASS** | In `annotate` mode, 0 findings removed; deterministic sort by severity then reachability; `--fail-on` evaluates all findings.                                                                                                          |
| **H2** | Suppress Mode Behavior                    | **PASS** | Only SCA + `UNREACHABLE` + `HIGH` confidence moves to ledger as `GATE2_UNREACHABLE`. CRITICAL findings retained by default (`neverSuppressSeverities: ['CRITICAL']`). SAST dead-files never suppressed. `off` mode omits reachability. |
| **H3** | Invariant P1 Property Test (1,000 Runs)   | **PASS** | Verified over 1,000 randomized permutations: $\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$. Every finding partitioned into exactly one bucket by fingerprint.                             |
| **H4** | Whole-Repo Graph in Diff Mode (Amend. A2) | **PASS** | `--diff`/`--staged` builds import graph from whole repository. Package in changed lockfile imported by unchanged source file is `REACHABLE_IMPORT`. Graph node count in diff mode equals full mode.                                    |
| **H5** | Diff Scope Isolation                      | **PASS** | Findings outside diff scope are counted in `totalOutOfScope` and never evaluated by Gate 2.                                                                                                                                            |
| **H6** | Noise Reduction Calculation               | **PASS** | Noise reduction percentage calculated as $\frac{\text{gate2Suppressed}}{\text{totalReportedBeforeGate2}} \times 100$; displays `null` (N/A) when denominator is 0.                                                                     |

### Part I: Reference Scanner Limits (Fix C6)

| ID     | Test Name                   | Verdict  | Empirical Evidence                                                                                                                                                                                                                                                                |
| :----- | :-------------------------- | :------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **I1** | Bounded Resource Guardrails | **PASS** | `ReferenceScanner` enforces deterministic lexicographical sorting, 1 MB per-file size cap, 50 MB total byte budget, and 10s wall-clock timeout. On unreadable file or budget exhaustion, sets `incompleteScan: true` and degrades candidate `NOT_IMPORTED` verdicts to `UNKNOWN`. |

### Part J: External HMAC Cache (Amendments A3 & Fix C8)

| ID     | Test Name                       | Verdict  | Empirical Evidence                                                                                                                                                                      |
| :----- | :------------------------------ | :------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **J1** | External Isolation              | **PASS** | Cache stored outside project directory (`~/.secureship/cache`) partitioned by SHA-256 of target realpath. In-repo `.secureship/cache` is strictly ignored.                              |
| **J2** | Cryptographic Authentication    | **PASS** | Entries HMAC-signed with SHA-256 (`0600` key file). Tampered, truncated, wrong-key, or corrupted entries are ignored and safely rebuilt.                                                |
| **J3** | Raw Extraction Only             | **PASS** | Cache stores AST extraction only (no source code, resolved paths, verdicts, or secrets). Verified with canary secrets.                                                                  |
| **J4** | Determinism & Cache Cleanliness | **PASS** | Second run yields identical results from cache; modifying one file invalidates only its cache entry; analyzer/grammar changes invalidate all entries; `--no-cache` bypasses read/write. |
| **J5** | Unwritable Cache Handling       | **PASS** | If cache directory is unwritable, scan runs uncached with a warning; never writes or consumes unsigned cache data.                                                                      |

### Part K: CLI End-to-End

| ID     | Test Name                          | Verdict  | Empirical Evidence                                                                                                                                                                                                                                                                   |
| :----- | :--------------------------------- | :------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **K1** | CLI Flags & Pure JSON              | **PASS** | `secureship scan --gate2 invalidMode` validates mode immediately before running pipeline, prints `Invalid --gate2 mode "invalidMode". Allowed modes: off, annotate, suppress` to stderr, and exits with code 2 without running scanners. Pure JSON validates against ScanReport 1.1. |
| **K2** | Output Terminology & Safety Banner | **PASS** | Prints required tags: `[IMPORTED]`, `[NOT IMPORTED]`, `[DEV/TEST ONLY]`, `[UNKNOWN]`. Disclaimer `"Import-level analysis only; not proof of exploitability or safety."` always printed. Word "safe" is never used to describe `NOT_IMPORTED`. Banner printed in suppress mode.       |
| **K3** | Graph Inspection Command           | **PASS** | `secureship graph [path]` prints entrypoints, file counts, unresolved imports, dynamic markers, and parse failures; `--json` pure JSON; `--format dot` outputs valid Graphviz DOT notation.                                                                                          |
| **K4** | Exit Code Guarantees               | **PASS** | Exit codes preserved: 0 (clean), 1 (vulnerabilities found), 2 (configuration error), 3 (infrastructure/scanner failure), 130 (SIGINT). Phase 2 NOT SCANNED behavior intact.                                                                                                          |
| **K5** | Real E2E Scanner Fixture           | **PASS** | Verified end-to-end against real Trivy and OSV-Scanner binaries across vulnerable imported, dev-only, unimported, and transitive dependencies in JS and Python.                                                                                                                      |
| **K6** | Doctor & Status Diagnostics        | **PASS** | `secureship doctor` verifies all 5 WASM grammars and external scanner binaries; `secureship status` displays Phase 3 capability lines.                                                                                                                                               |

### Part L: Safety and Hostile Inputs

| ID     | Test Name                       | Verdict  | Empirical Evidence                                                                                                                                           |
| :----- | :------------------------------ | :------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **L1** | Symlink Safety                  | **PASS** | Symlink loops and symlinks targeting files outside root are never followed; zero hangs or infinite recursion.                                                |
| **L2** | Path Traversal Escape Defense   | **PASS** | `../` imports, absolute paths, `file://` URLs, and `tsconfig` extends/paths targeting outside root are unresolved; canary files outside root are never read. |
| **L3** | Zero Process & Network Overhead | **PASS** | Zero child processes spawned and zero outbound network requests made from `@secureship/reachability`.                                                        |
| **L4** | Prototype Pollution Defense     | **PASS** | `__proto__` and `constructor` properties in `package.json` and `tsconfig.json` do not pollute `Object.prototype`.                                            |
| **L5** | Performance and Scalability     | **PASS** | 20,000 files, 5 MB generated files, and 200-level nesting benchmarked with peak RSS well under 1.5 GB and duration under 60 s.                               |
| **L6** | Ignored Directories Handling    | **PASS** | `node_modules`, `vendor`, `dist`, and minified assets are skipped for AST parsing, while module package resolution functions accurately.                     |

### Part M: Benchmark, Fuzz, and Real-Repository Review

| ID     | Test Name                          | Verdict  | Empirical Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| :----- | :--------------------------------- | :------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M1** | Corpus Fixture Suite (37 Cases)    | **PASS** | All 37 fixtures pass with 0 false-unreachables. Case 32 reports `TEST_ONLY_IMPORT` (`UNKNOWN`); cases 33-36 cover monorepo workspace behaviors (b-e); case 37 covers unsupported flat lockfiles (`bun.lock`, `uv.lock`) failing closed to `NO_LOCKFILE_TREE`.                                                                                                                                                                                                                                                                                                     |
| **M2** | Metrics Math Verification          | **PASS** | Metric calculations verified. In `packages/benchmark/src/metrics.ts`, empty classes return `null` (`N/A`), never falsely defaulting to `1.0` (100%).                                                                                                                                                                                                                                                                                                                                                                                                              |
| **M3** | Benchmark Oracle Invariant         | **PASS** | Injecting an artificial false-UNREACHABLE into test fixtures causes the benchmark suite to fail with non-zero exit code.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **M4** | 300-Project Ground-Truth Fuzz Test | **PASS** | Automated generator evaluated 300 projects (150 JS/TS, 150 Python) across reachable and unreachable chains: **0 false-unreachables**; confusion matrix verified.                                                                                                                                                                                                                                                                                                                                                                                                  |
| **M5** | Metamorphic Mutation Testing       | **PASS** | 8 metamorphic mutations starting from `UNREACHABLE-HIGH` (adding prod import, dynamic require, string literal, config reference, npm script, Dockerfile reference, parse error, or removing entrypoint) reliably move finding out of `UNREACHABLE-HIGH`. In suppress mode, findings reappear in reported.                                                                                                                                                                                                                                                         |
| **M6** | Real-Repository Audit (3 Repos)    | **PASS** | Evaluated 3 real-world repos: `twbs/bootstrap` (v5.2.0, 120 findings), `python-poetry/poetry` (1.1.13, 51 findings), and `tiangolo/full-stack-fastapi-template` (pinned SHA `b1125d8`, 20 findings). Reconciled 211 raw findings vs 191 reported (20 Gate 1 non-production). Exactly **191 out of 191 reported findings (100%)** independently audited in `docs/phase3/evaluation/audit-<repo>.csv`, covering every single UNREACHABLE/NOT_IMPORTED/DEV_ONLY finding (**92/92, 100%**) + 99 IMPORTED/UNKNOWN findings. **False-unreachable rate: 0.0% (0 / 92)**. |

### Part N: Mutation Sanity Suite (N1 – N17)

| Mutation ID | Injected Fault Description                                        | Verified Detection |
| :---------- | :---------------------------------------------------------------- | :----------------: |
| **N1**      | Uncertainty (parse error) forced to evaluate as UNREACHABLE       |     **CAUGHT**     |
| **N2**      | Dynamic import markers ignored                                    |     **CAUGHT**     |
| **N3**      | Type-only imports treated as runtime imports                      |     **CAUGHT**     |
| **N4**      | CRITICAL findings suppressed by default                           |     **CAUGHT**     |
| **N5**      | SAST dead-file findings suppressed in Gate 2                      |     **CAUGHT**     |
| **N6**      | Gate 2 suppressed findings dropped without ledger record          |     **CAUGHT**     |
| **N7**      | String literal reference scan bypassed                            |     **CAUGHT**     |
| **N8**      | Imports traversing outside project root followed                  |     **CAUGHT**     |
| **N9**      | WASM integrity check skipped                                      |     **CAUGHT**     |
| **N10**     | Gate 1 TEST_OR_MOCK scope overwritten by Gate 2                   |     **CAUGHT**     |
| **N11**     | Transitive-dependent check bypassed (Amendment A1)                |     **CAUGHT**     |
| **N12**     | Diff mode graph built only from changed files (Amendment A2)      |     **CAUGHT**     |
| **N13**     | Extraction cache read from inside target directory (Amendment A3) |     **CAUGHT**     |
| **N14**     | Reference scanner budget cap hits ignored                         |     **CAUGHT**     |
| **N15**     | Python SCA finding assigned UNREACHABLE with HIGH confidence      |     **CAUGHT**     |
| **N16**     | DEV_ONLY finding labeled as [NOT IMPORTED]                        |     **CAUGHT**     |
| **N17**     | `verify:wasm` comparing against manifest without byte check       |     **CAUGHT**     |

---

## 5. Remediated Defects and Verification Evidence

All 4 previously identified verification defects have been remediated in full:

### Defect K1-01: CLI `--gate2` Argument Validation (Severity: High) — **RESOLVED & VERIFIED**

- **Files Remediated:** `packages/cli/src/commands/scan.ts` and `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Resolution:** CLI validates `options.gate2` immediately before starting the scan pipeline. If `options.gate2` is not one of `'off' | 'annotate' | 'suppress'`, an error message (`Invalid --gate2 mode "<value>". Allowed modes: off, annotate, suppress`) is output to `stderr` and execution terminates immediately with exit code `2` without launching scanners.
- **Verification:** Tested in `packages/cli/test/scan-cli.test.ts` ("Defect K1-01: scan --gate2 with invalid mode exits 2 with error and does not run scan"). Command exits with code 2 in 333 ms without invoking scanner adapters.

---

### Defect G5-01: Monorepo Workspace Lockfile Resolution (Severity: Medium) — **RESOLVED & VERIFIED**

- **Files Remediated:** `packages/reachability/src/lockfile/lockfile-tree-parser.ts`
- **Resolution:** `parseNpmLock` and `parsePnpmLock` now inspect all workspace package manifests and lockfile entries (`packages/*` in `package-lock.json` and all workspace entries in `pnpm-lock.yaml#importers`), alongside workspace `package.json` manifests via `scanWorkspaceManifests`.
- **Verification:** Tested in `packages/reachability/test/verification/reachability.verify.test.ts` (Part G-5b) and `test-g5.mjs`. In a multi-workspace monorepo where `shared-dep` is declared in workspace manifests and imported by NO workspace, `isLeafDirectPackage()` succeeds with a valid lockfile tree and evaluates to `UNREACHABLE` (`NOT_IMPORTED-HIGH`).

---

### Defect I1-01: `ReferenceScanner` Resource Guardrails & Error Handling (Severity: Medium) — **RESOLVED & VERIFIED**

- **Files Remediated:** `packages/reachability/src/reference/reference-scanner.ts` and `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Resolution:**
  1. Enforced deterministic lexicographical sorting of directory entries.
  2. Enforced 1 MB per-file size cap (`maxFileBytes`), 50 MB repository total byte budget (`maxTotalBytes`), and 10-second wall-clock timeout (`scanTimeoutMs`).
  3. Errors from `fs.statSync`/`fs.readFileSync` or budget exhaustion are never silently swallowed; `incompleteScan: true` is recorded on the scan result and candidate `NOT_IMPORTED` verdicts degrade fail-closed to `UNKNOWN (LOW, CONFIG_REFERENCE)`.
- **Verification:** Unit tests added in `packages/reachability/test/reference-scanner.test.ts` and verification suite Part I in `packages/reachability/test/verification/reachability.verify.test.ts`.

---

### Defect A5-01: `verify:wasm` Direct Tarball Integrity Comparison (Severity: Low) — **RESOLVED & VERIFIED**

- **Files Remediated:** `scripts/verify-wasm.mjs`, `packages/reachability/package.json`, `pnpm-lock.yaml`
- **Resolution:** `scripts/verify-wasm.mjs` verifies the integrity hashes recorded in `pnpm-lock.yaml` for `tree-sitter-wasms@0.1.13` and `web-tree-sitter@0.22.6`, and compares all 5 bundled `.wasm` binaries byte-for-byte against the upstream package files in `node_modules` (and extracted tarball).
- **Verification:** `pnpm verify:wasm` executes and validates lockfile integrity and byte-for-byte matching for all 5 grammars (`tree-sitter.wasm`, `tree-sitter-javascript.wasm`, `tree-sitter-typescript.wasm`, `tree-sitter-tsx.wasm`, `tree-sitter-python.wasm`), exiting with code 0.

---

## 6. Remediated Specification Gaps

All 3 previously identified specification gaps have been remediated in full:

1. **Spec Gap M1 (Corpus Case 3 Splitting) — RESOLVED & VERIFIED:**
   Created fixture `packages/benchmark/corpus/gate2/32-test-only-prod-declared/` where a test-only imported package is declared under production `dependencies`. Verified that `03-test-only-import` evaluates to `UNREACHABLE DEV_ONLY MEDIUM` while `32-test-only-prod-declared` evaluates to `UNKNOWN CONFIG_REFERENCE LOW`. All 32 corpus cases evaluate with 0 false-unreachables.

2. **Spec Gap M2 (Metric Math on Empty Classes) — RESOLVED & VERIFIED:**
   In `packages/benchmark/src/metrics.ts`, when a reachability class has 0 ground truth cases, accuracy returns `null` (`N/A`) rather than `1.0` (100%). Tested in `packages/benchmark/test/metrics.test.ts`.

3. **Spec Gap A3 (Per-File Coverage Threshold) — RESOLVED & VERIFIED:**
   Added parser fallback and timeout tests in `packages/reachability/test/parsers.test.ts`. Line and statement coverage for `packages/reachability/src/parsers/tree-sitter-loader.ts` increased to **79.23%**, exceeding the 70% threshold.

---

## 7. Re-Run Commands for Independent Reproduction

```bash
# 1. WASM Grammar & Upstream Package Integrity Verification
pnpm verify:wasm

# 2. Mutation Integrity Verification (N1 to N17 in isolated temp environment)
pnpm verify:mutations

# 3. Complete Build, Typecheck, Lint, and Format Verification
pnpm build
pnpm typecheck
pnpm lint
pnpm format:check

# 3. Full Test Suite & Coverage Table
pnpm test:coverage

# 4. Benchmarks (Replay Canned & Live Scanner Binaries)
pnpm benchmark:replay
pnpm benchmark:live

# 5. CLI Verification & Diagnostics
node packages/cli/dist/index.js doctor
node packages/cli/dist/index.js status
node packages/cli/dist/index.js graph packages/reachability --format dot
node packages/cli/dist/index.js graph packages/reachability --json
```

---

## 8. Final Verdict

# **PHASE 3 ACCEPTED**

### Acceptance Criteria Fulfillment Checklist:

- [x] **A1, A2, A5, A6**: All pass cleanly; pipeline clean, Phase 1/2 intact, WASM verified against lockfile integrity and byte-for-byte upstream match, zero unsafe primitives.
- [x] **C1, C3**: WASM fail-closed verified; parse errors degrade safely to `UNKNOWN`.
- [x] **D2, E3, E4**: Dynamic markers flag uncertainty; Python package aliasing verified; zero Python SCA findings evaluate to `UNREACHABLE-HIGH`.
- [x] **F2**: Missing entrypoints degrade to `UNKNOWN (NO_ENTRYPOINT)`.
- [x] **G3, G4 (a-k), G5, G7**: Transitive hole closure verified; all 11 preconditions enforced; monorepo workspace lockfiles parsed comprehensively; SECRET/IAC remain `UNKNOWN`.
- [x] **H2, H3, H4**: Gate 2 default annotate retains all findings; suppress mode moves only SCA `UNREACHABLE-HIGH` to ledger; Invariant P1 verified across 1,000 property runs; whole-repo graph built in diff mode.
- [x] **J1, J2, J5**: External HMAC-SHA256 cache verified; unwritable cache degrades gracefully.
- [x] **K2, K5**: CLI safety banner and required tags enforced; live scanner E2E pipeline verified against real Trivy and OSV-Scanner binaries.
- [x] **L2, L3**: Path traversal outside root prevented; zero network and child processes.
- [x] **M3, M4, M5, M6**: Benchmark oracle invariant verified; 300 fuzz projects verified (0 false-unreachables); 8 metamorphic mutations verified; real-world audit (Bootstrap, Poetry, FastAPI) verified with 0.0% false-unreachable rate.
- [x] **N1–N17**: All 17 mutation sanity faults caught and verified.
- [x] **Zero FAILs in Parts B through M**: All parts evaluate to **PASS**.
- [x] **Zero Spec Gaps**: All 3 spec gaps remediated and verified.
