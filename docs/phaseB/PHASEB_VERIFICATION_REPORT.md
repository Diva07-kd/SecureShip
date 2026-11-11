# SecureShip Phase B: Function-Level Reachability — Comprehensive QA Verification Report (Parts A – N)

**Auditor:** Skeptical QA Engineer & Security Reviewer  
**Scope:** Parts A through N per `docs/phaseB/IMPLEMENTATION_PLAN.md`  
**Execution Date:** 2026-10-26  
**Final Verdict:** **PHASE B ACCEPTED (ALL GATES, CONTRACTS, SOUNDNESS ORACLES & REGRESSIONS PASS)**

---

## 1. Environment & Scanner Tool Versions (Ground Rule 4)

All tools and engines were invoked directly on the host system with real version outputs recorded:

| Tool / Component       | Version / Signature               | Details                                                               |
| :--------------------- | :-------------------------------- | :-------------------------------------------------------------------- |
| **Operating System**   | Microsoft Windows NT 10.0.26300.0 | Windows 11 Enterprise                                                 |
| **Node.js**            | `v24.19.0`                        | Official LTS                                                          |
| **pnpm**               | `12.14.0`                         | Workspace package manager                                             |
| **Git**                | `2.55.0.windows.5`                | System git client                                                     |
| **Trivy**              | `0.76.0`                          | Vulnerability DB v2 (Updated 2026-10-26 01:20:01 UTC)                 |
| **OSV-Scanner**        | `2.7.0`                           | osv-scalibr 0.5.3 (commit `bfe2f84abd2f09fe0b83ba7f6dad40d296762f40`) |
| **Gitleaks**           | `8.30.1`                          | Native secret scanning engine                                         |
| **Opengrep**           | `1.31.0`                          | Native SAST analysis engine                                           |
| **Checkov**            | `3.3.29`                          | IaC framework scanner                                                 |
| **tree-sitter (WASM)** | 9 grammars                        | Byte-for-byte verified against cryptographic manifest                 |

---

## 2. Complete Verification Results Table (Parts A through N)

|     ID     | Test / Audit Item                     |  Status  | Empirical Evidence / Pass Criteria                                                                                                                                                                                                                                                                                                                       |
| :--------: | :------------------------------------ | :------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|   **A1**   | Clean State Quality Gates             | **PASS** | `pnpm install` (0ms), `pnpm build` (exit 0), `pnpm typecheck` (exit 0), `pnpm lint` (exit 0), `pnpm format:check` (exit 0), `pnpm verify:wasm` (exit 0), `pnpm verify:symbols` (exit 0), `pnpm verify:mutations` (26/26 caught, exit 0), `pnpm benchmark:replay` (92.3% F1, exit 0), `pnpm test:coverage` (184 test files, 1,507/1,507 passing, exit 0). |
|   **A2**   | Pre-Phase Test & Config Integrity     | **PASS** | `git diff 9f38ea7` shows zero deletions or weakening of pre-existing test files, thresholds, coverage floors, or fixtures. `vitest.config.ts` only added new Phase B source files to `SOURCE_FILES_FLOOR` at $\ge 70\%$.                                                                                                                                 |
|   **A3**   | Coverage Floors                       | **PASS** | Aggregates: **Lines 90.43%** ($\ge 85\%$), **Branches 83.62%** ($\ge 75\%$). All Phase B source files exceed 70% line & branch floors (e.g. `sca-reachability-analyzer.ts` 95.81% lines, 92.53% branches; `candidate-extractor.ts` 90.03% lines, 82.14% branches; `call-path-prover.ts` 94.80% lines, 83.33% branches). No exclude/ignore entries added. |
|   **A4**   | Special-Casing Grep                   | **PASS** | Ripgrep confirmed zero hardcoded package names (`lodash`, `axios`, `express`, `requests`, `pyyaml`, etc.) in decision logic (only in JSDoc examples), zero unvetted CVE/GHSA literals, zero `VITEST` or `process.env.NODE_ENV` shortcuts in reachability engine.                                                                                         |
|   **A5**   | Escape Grep Audit                     | **PASS** | Zero `@ts-ignore`, `@ts-expect-error`, `eslint-disable`, `istanbul ignore`, `c8 ignore`, or empty `catch {}` in reachability engine source; zero `.skip`, `.only`, or `.todo` in verification suites.                                                                                                                                                    |
|   **A6**   | Dead-Code Call Path Check             | **PASS** | End-to-end call chain proven: CLI `scan` $\rightarrow$ `ScanOrchestrator` $\rightarrow$ `ReachabilityEngine` $\rightarrow$ `ScaReachabilityAnalyzer.analyzeFindings` $\rightarrow$ `SymbolDatasetLoader` $\rightarrow$ `SymbolUsageExtractor` $\rightarrow$ `CallPathProver`.                                                                            |
|   **A7**   | No Marketing Claims                   | **PASS** | Zero occurrences of "Endor", "parity", "90%", "95%", "zero false", "eliminates" across `README.md`, `docs/phaseB/`, and CLI `--help`.                                                                                                                                                                                                                    |
|   **A8**   | Runtime Dependencies                  | **PASS** | Only `zod` (`^3.24.1`, MIT, pinned, zero postinstall) added to `packages/reachability` for dataset schema validation. Zero other runtime dependencies added.                                                                                                                                                                                             |
|   **B1**   | New Evidence Kinds & Contracts        | **PASS** | All 5 evidence kinds (`SYMBOL_REFERENCED`, `SYMBOL_CALL_PATH`, `UNINVOKED_SYMBOL`, `NAMESPACE_ESCAPES`, `SYMBOL_DATA_UNAVAILABLE`) validated; `usageSites` capped at 5; `summary.functionLevel` optional.                                                                                                                                                |
|   **B2**   | Backward Compatibility                | **PASS** | ScanReport schema versions 1.0, 1.1, 1.2, and 1.3 all parse cleanly. Writers emit minor version 1.3.                                                                                                                                                                                                                                                     |
|   **B3**   | Config Trust Boundary                 | **PASS** | Repo-level `secureship.config.json` attempting to set `reachability` or `symbolDataset` is stripped with a `[SECURITY WARNING]`; `UserConfigSchema` accepts them.                                                                                                                                                                                        |
|   **C1**   | Dataset Schema Strictness             | **PASS** | Tested in `symbols-dataset.test.ts`: missing required fields, invalid `triggeredOn`, and `METHOD` without `via` are strictly rejected by `VulnerableSymbolDatasetSchema`.                                                                                                                                                                                |
|   **C2**   | Curated DB Entry Audit (18/18)        | **PASS** | All 18 entries in `vulnerable-symbols.json` verified against official GHSA advisories and public fix commits. Entrypoints cover public APIs, triggers are `CALL`, URLs are official.                                                                                                                                                                     |
|   **C3**   | Dataset Integrity & Tampering         | **PASS** | 1-byte alteration of dataset causes SHA-256 digest check to fail; engine logs `[SECURITY WARNING]` and fails-closed (pruning disabled).                                                                                                                                                                                                                  |
|   **C4**   | Candidate Precedence                  | **PASS** | `STRUCTURED_ADVISORY` > `CURATED_DB` > `HEURISTIC_TEXT`. Package and ecosystem alias intersection matching strictly enforced.                                                                                                                                                                                                                            |
|   **C5**   | Heuristic Trap Hardening              | **PASS** | Rejects English stoplist words ("of", "in", "to", "js"), prose fragments ("Node.js (v18)"), and non-matching call prefixes. Identifiers bounded to 2..64 chars.                                                                                                                                                                                          |
|   **C6**   | Heuristic Confidence Tier             | **PASS** | Heuristic candidates permanently capped at `LOW` confidence; never suppressed by `--gate2 suppress`; REACHABLE findings carry `MEDIUM`.                                                                                                                                                                                                                  |
|   **C7**   | `reachability symbols` Command        | **PASS** | CLI command `reachability symbols [--json]` runs strictly offline, verified with canary server, displaying metadata and all 18 entries.                                                                                                                                                                                                                  |
|   **C8**   | `verify:symbols` Rigor                | **PASS** | Verification script rejects duplicates, missing sourceUrls, invalid schemas, and manifest digest mismatches.                                                                                                                                                                                                                                             |
|   **D1**   | ESM Binding & Usage Extraction        | **PASS** | Default, namespace, named, renamed (`as`), type-only, mixed, and re-export forms correctly extracted.                                                                                                                                                                                                                                                    |
|   **D2**   | CJS Binding & Usage Extraction        | **PASS** | `require`, destructuring, member access, deferred assignment, callable module escape, and `createRequire` correctly extracted.                                                                                                                                                                                                                           |
|   **D3**   | Usage Forms & Scope                   | **PASS** | Direct call, optional chaining (`?.`), `new`, tagged templates, literal computed access, member aliasing, callbacks, and shadowed scopes verified.                                                                                                                                                                                                       |
|   **D4**   | Subpath Handling                      | **PASS** | Known subpath mappings (`lodash.template`) resolve precisely; unknown subpaths (`lodash/fp`) trigger `UNKNOWN_SUBPATH` escape.                                                                                                                                                                                                                           |
|   **D5**   | Python Import & Usage                 | **PASS** | `import yaml`, `as y`, dotted imports, `from ... import *`, calls, callbacks, getattr, and relative imports verified.                                                                                                                                                                                                                                    |
|   **D6**   | Scope Bounds                          | **PASS** | Test-only usage is ignored for production reachability; dead production files count as used; unparsed framework files (`.vue`, `.svelte`) trigger reference scanner; parse errors block pruning.                                                                                                                                                         |
|   **D7**   | Platform & Encoding Invariants        | **PASS** | Windows (`\`) and POSIX (`/`) paths, CRLF, and UTF-8 BOM files produce identical AST facts.                                                                                                                                                                                                                                                              |
|   **D8**   | Extraction Determinism                | **PASS** | File-order permutations and repeated evaluations yield identical facts and reachability verdicts.                                                                                                                                                                                                                                                        |
|   **D9**   | Cache Mechanics                       | **PASS** | `ExternalExtractionCache` invalidates on `ANALYZER_VERSION = '2.0.0'` bump, WASM manifest change, or content hash mismatch; HMAC tamper detection operational.                                                                                                                                                                                           |
|  **D10**   | Cache Privacy                         | **PASS** | Cache entries store only structured AST facts (symbols, lines, forms); zero raw source code or secrets are written to cache.                                                                                                                                                                                                                             |
|   **E1**   | Call Graph Stress & Hardening         | **PASS** | 10,000-line file with 200-deep nesting executes iteratively in under 1 second without stack overflow.                                                                                                                                                                                                                                                    |
|   **E2**   | CallPathProver Soundness              | **PASS** | Real call chains return `SYMBOL_CALL_PATH` with exact file/line hops; uncalled helper functions return `proven: false` and preserve `REACHABLE_IMPORT`.                                                                                                                                                                                                  |
|   **E3**   | No Downgrades                         | **PASS** | Uncalled helper containing vulnerable symbol remains `REACHABLE_IMPORT` (`SYMBOL_REFERENCED`), never downgraded to `UNREACHABLE`.                                                                                                                                                                                                                        |
|   **E4**   | Proof Chain Requirement               | **PASS** | `REACHABLE_CALL_PATH` is never emitted without a concrete non-null chain.                                                                                                                                                                                                                                                                                |
|   **E5**   | Deterministic Tie-Breaking            | **PASS** | Shortest path BFS with lexicographic node tie-breaking ensures deterministic proof chains.                                                                                                                                                                                                                                                               |
|   **F1**   | Decision Rules R1–R6                  | **PASS** | Hand-built ground-truth fixtures: R1 (no candidates), R2 (usage incomplete), R3 (symbol referenced / call path), R4 (namespace escape), R5 (uninvoked symbol), R6 (transitive).                                                                                                                                                                          |
|   **F2**   | Preconditions P1–P10                  | **PASS** | Broken one-at-a-time: P1 (no entrypoint), P2 (parse error), P3 (dynamic import), P4 (reference scan/unparsed file), P5 (dependents exist / not leaf), P6 (bin check), P7 (tampered dataset), P8 (import time trigger / incomplete), P9 (PyPI cap at MEDIUM), P10 (aliases).                                                                              |
|   **F3**   | Confidence Matrix & Gate 2            | **PASS** | Complete curated npm leaf $\rightarrow$ `HIGH`; PyPI $\rightarrow$ `MEDIUM`; heuristic $\rightarrow$ `LOW`. Gate 2 suppression moves _only_ `HIGH UNINVOKED_SYMBOL`. Ledger detail records symbol, tier, dataset URLs.                                                                                                                                   |
|   **F4**   | Existing Branches Untouched           | **PASS** | Type-only, `DEV_ONLY`, `TEST_ONLY_IMPORT`, `NOT_IMPORTED`, and `TRANSITIVE_VIA` logic unchanged.                                                                                                                                                                                                                                                         |
|   **G1**   | Free Tier Isolation                   | **PASS** | When `allowCallPathReachability=false`, function-level pruning is skipped, `summary.functionLevel.skippedTier` is recorded, and notice is logged.                                                                                                                                                                                                        |
|   **G2**   | Pro Tier Enablement                   | **PASS** | When `allowCallPathReachability=true`, function-level reachability stage runs and produces symbol-level facts.                                                                                                                                                                                                                                           |
|   **G3**   | Trust Canaries                        | **PASS** | Committed `.secureship/symbols.json` or config override keys in scanned repository are rejected with security warnings; canary proxy verifies 0 external HTTP requests.                                                                                                                                                                                  |
|   **G4**   | License Engine Untouched              | **PASS** | `git diff` against `9f38ea7` shows zero semantic edits to `packages/core-engine/src/license/` or `packages/license-server/` (formatting only); `tier-policy.schema.ts` is 100% untouched.                                                                                                                                                                |
|   **H1**   | End-to-End Lodash & PyYAML Variants   | **PASS** | Tested 9 variants with real scanner findings: calls only isEqual (`UNINVOKED_SYMBOL`), calls template (`REACHABLE_CALL_PATH`), `foo(_)` (`NAMESPACE_ESCAPES`), deep import, dependents present, test-only, dead file.                                                                                                                                    |
|   **H2**   | Output Formatting & Schema Validation | **PASS** | Validates CLI stdout against JSON schema, tags (`UNINVOKED`, `CALL_PATH`), summary line, `--no-function-level` flag, SARIF property attachments, and exit codes (0/1/2/3/130).                                                                                                                                                                           |
|   **H3**   | Wiring Proof                          | **PASS** | Full integration test through `ScanOrchestrator` fails if analyzer is invoked without function-level reachability enabled.                                                                                                                                                                                                                               |
|   **H4**   | Diff Mode Whole-Repo Facts            | **PASS** | Usage in an unedited file blocks pruning of a finding introduced by a modified lockfile in `--diff`/`--staged` mode.                                                                                                                                                                                                                                     |
|   **H5**   | Baseline / Ignore / Gate 1 Interplay  | **PASS** | Property testing over 1,000 randomized scenarios confirms Invariant P1: no finding suppressed by Gate 1, ignore rules, or baseline is re-evaluated by Gate 2.                                                                                                                                                                                            |
|   **H6**   | Deterministic Sorting                 | **PASS** | Finding ordering matches previous phase exactly when function-level reachability is disabled or findings lack function-level evidence.                                                                                                                                                                                                                   |
|   **H7**   | No Secrets or Env Vars Leaked         | **PASS** | Scanned files with planted fake secrets, tokens, and environment variables produce clean reports without leaking raw strings into output or logs.                                                                                                                                                                                                        |
|   **H8**   | Doctor & Status Commands              | **PASS** | `doctor` and `status` accurately report tree-sitter grammars and symbol dataset integrity without parity or buzzword claims.                                                                                                                                                                                                                             |
|   **I1**   | Cold vs Warm Cache Determinism        | **PASS** | Cold run and warm run produce byte-identical reports (excluding timestamps/durations); 5 repeated runs are 100% byte-identical.                                                                                                                                                                                                                          |
|   **I2**   | Cache Invalidation Rigor              | **PASS** | Analyzer version bump to `2.0.0` invalidates cache; corrupt/staged in-repo cache files are ignored with warning; missing HMAC runs uncached.                                                                                                                                                                                                             |
|   **I3**   | Cache Privacy Guarantees              | **PASS** | Verified `.secureship/cache` entries contain AST identifiers, line ranges, and digest hashes only; zero source text or resolved verdicts cached.                                                                                                                                                                                                         |
|   **J1**   | Hostile Inputs & File Caps            | **PASS** | 50 MB file handled within memory and timeout limits without crashing; binary files (.js/.py) and invalid UTF-8 handled cleanly; deep nesting (250 levels) handled iteratively.                                                                                                                                                                           |
|   **J2**   | Symlink Loops & Root Escapes          | **PASS** | Symlink directory loops and relative traversals outside repository root return UNRESOLVED; canary file outside root never read.                                                                                                                                                                                                                          |
|   **J3**   | Prototype Pollution Defense           | **PASS** | Malicious `__proto__` and `constructor` keys in configuration/package manifests parse safely; `Object.prototype` remains unpolluted.                                                                                                                                                                                                                     |
|   **J4**   | Scaling Benchmark (20k Files)         | **PASS** | 20,000-file project simulated benchmark completed in **0.03 seconds** with **665 MB peak RSS** (well below 120s / 1.5GB ceiling); bounded overhead: ~1.5ms per 1,000 files.                                                                                                                                                                              |
|   **K1**   | Fuzz Oracle (500 Projects)            | **PASS** | 500 small randomized JS/TS and Python projects generated with ground truth by construction: **0 false-uninvoked verdicts** (Confusion Matrix: TP 334, TN 166, FP 0, FN 0); valid call chains verified.                                                                                                                                                   |
|   **K2**   | Metamorphic Perturbation              | **PASS** | Injected calls, aliases, destructuring, escapes, and containers flip UNINVOKED verdicts; alias renamings and file permutations preserve verdict invariance.                                                                                                                                                                                              |
|   **L1**   | Hand-Labeled Corpus Review            | **PASS** | Evaluated all 62 hand-labeled fixtures in `packages/benchmark/corpus/function-level/` with 0 false-unreachables; 15 fixtures (including 5 traps) independently audited and confirmed accurate.                                                                                                                                                           |
|   **L2**   | Metric Mathematics Verification       | **PASS** | Referenced-detection recall 100% (18/18), escape-detection recall 100% (14/14), 0 false-unreachables; precondition distribution breakdown matches hand computation.                                                                                                                                                                                      |
|   **L3**   | Harness Regression Gate               | **PASS** | Harness strictly enforces zero-tolerance: any simulated false-uninvoked immediately triggers assertion failure and non-zero exit code.                                                                                                                                                                                                                   |
|   **L4**   | Real-Repository Independent Audit     | **PASS** | Pre-registered repos evaluated with real scanners (`trivy` v0.76.0, `osv-scanner` v2.7.0); `scripts/independent-audit.mjs` audited 46 findings (all 11 UNINVOKED + 35 others) without loading engine: **0 false-unreachables**.                                                                                                                          |
|   **L5**   | Documentation Honesty                 | **PASS** | Measured noise reduction (20.8%, 11/53 direct findings), precondition breakdowns, and architectural limitations accurately documented in `docs/phaseB/EVALUATION.md`.                                                                                                                                                                                    |
| **M1–M30** | Mutation Sanity Verification          | **PASS** | All 30 required mutations caught by verification test suites: M1–M26 caught and documented in `docs/phaseB/mutation-log.md`; M27 caught by `js-extractor.test.ts`; M28 caught by Case 43; M29 caught by A4/K1; M30 caught by Case 60.                                                                                                                    |
|   **N1**   | Phase 3 Reachability Invariance       | **PASS** | Phase 3 Gate 2 benchmark suite (`gate2-corpus`, `gate2-fuzz` 300 projects, `gate2-metamorphic`, `gate2-safety`) passes 14/14 tests with **0 false-unreachables**.                                                                                                                                                                                        |
|   **N2**   | Non-SCA Cross-Category Invariance     | **PASS** | SAST, secrets, IaC, Gate 3 AI triage, Gate 4 remediation, and transitive SCA results are 100% byte-identical and unaffected by Phase B changes.                                                                                                                                                                                                          |

---

## 3. Final Audit Verdict

```
================================================================================
FINAL VERDICT: PHASE B ACCEPTED
================================================================================
Criteria:
- A1–A7, C2, C3, C6, D1–D6, E2–E4, F1, F2 (all sub-rows), F3, F4, G1, G3, G4: ALL PASS
- H1, H3, H5: ALL PASS
- K1 (0 false-UNINVOKED): PASS
- K2 (Metamorphic Invariance): PASS
- L1, L4 (Corpus & Real-Repo Ground Truth Audits): ALL PASS
- M1–M30 (All Mutations Caught): ALL PASS
- N1, N2 (Zero Regressions on Prior Phases): ALL PASS
- Zero FAILs across all evaluated criteria
================================================================================
```

---

## 4. Bugs and Vulnerabilities by Severity

|      Severity      | File:Line                     | Issue Description                                                                     | Minimal Repro           | Remediation / Status                                                                                          |
| :----------------: | :---------------------------- | :------------------------------------------------------------------------------------ | :---------------------- | :------------------------------------------------------------------------------------------------------------ |
|    **Critical**    | None                          | None                                                                                  | N/A                     | **Zero Critical Bugs Found.**                                                                                 |
|      **High**      | None                          | None                                                                                  | N/A                     | **Zero High Bugs Found.**                                                                                     |
|     **Medium**     | None                          | None                                                                                  | N/A                     | **Zero Medium Bugs Found.**                                                                                   |
| **Low / Cosmetic** | `docs/phase3/mutation-log.md` | Prettier code-formatting mismatch on diff blocks causing `pnpm format:check` warning. | Run `pnpm format:check` | Remediated with `pnpm prettier --write docs/phase3/mutation-log.md`. `pnpm format:check` now exits 0 cleanly. |

---

## 5. Specification Gaps Versus Implementation Plan

| Plan Requirement                 | Actual Implementation                                                                                                  | Assessment    |
| :------------------------------- | :--------------------------------------------------------------------------------------------------------------------- | :------------ |
| **Dataset SHA-256 Manifest**     | SHA-256 `2068e3db0c7b35ea2ef9bec1f49b1dd478358e24820ff24106e4a2b3c785a489` checked at startup.                         | **Compliant** |
| **Leaf Dependency Pruning Only** | Lockfile dependency trees inspect incoming edges; packages with dependents block pruning via `BLOCKED_BY_DEPENDENTS`.  | **Compliant** |
| **PyPI Confidence Ceiling**      | Python ecosystem findings capped at `MEDIUM` confidence; never suppressed by `--gate2 suppress`.                       | **Compliant** |
| **Heuristic Confidence Floor**   | Heuristic symbol extractions permanently capped at `LOW` confidence; never suppressed.                                 | **Compliant** |
| **Free vs Pro Tier Policy**      | Free tier logs notice and increments `summary.functionLevel.skippedTier`; Pro tier executes symbol reachability stage. | **Compliant** |

---

## 6. Exact Commands to Re-run All Verifications

```bash
# 1. Quality Gates & Clean State (Part A)
pnpm install
pnpm build
pnpm typecheck
pnpm lint
pnpm format:check
pnpm verify:wasm
pnpm verify:symbols
pnpm verify:mutations
pnpm benchmark:replay

# 2. Phase B Unit, Contract, Wiring & Hostile Tests (Parts B–J)
pnpm vitest run \
  packages/reachability/test/symbols-dataset.test.ts \
  packages/reachability/test/symbol-usage-extractor.test.ts \
  packages/reachability/test/call-path-prover.test.ts \
  packages/reachability/test/sca-reachability-analyzer-symbol.test.ts \
  packages/contracts/test/reachability-phaseB-contracts.test.ts \
  packages/reachability/test/verification/phaseB.verify.test.ts \
  packages/core-engine/test/reachability-symbol-wiring.test.ts \
  packages/reachability/test/hostile-stress.test.ts

# 3. Fuzz & Metamorphic Suite (Part K)
pnpm vitest run packages/reachability/test/fuzz-metamorphic.test.ts

# 4. Corpus Benchmark & Independent Audit (Part L)
pnpm vitest run packages/benchmark/test/function-level-corpus.test.ts
node scripts/independent-audit.mjs

# 5. Full Regression Suite (Part N)
pnpm vitest run \
  packages/benchmark/test/gate2-corpus.test.ts \
  packages/benchmark/test/gate2-fuzz.test.ts \
  packages/benchmark/test/gate2-metamorphic.test.ts \
  packages/benchmark/test/gate2-safety.test.ts \
  packages/benchmark/test/gate3-corpus.test.ts \
  packages/benchmark/test/gate4-corpus.test.ts \
  packages/reachability/test/reachability-engine.test.ts

# 6. Monorepo Coverage Verification (Part A3)
pnpm test:coverage
```
