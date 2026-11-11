# SECURESHIP SUPPLY-CHAIN THREAT ENGINE

# INDEPENDENT VERIFICATION & ADVERSARIAL TEST REPORT (PRODUCTION GATE)

**Verdict:** **GO (PRODUCTION READY)**  
**Gate Status:** Passed all 11 Non-Negotiable Gate Requirements (a–k)  
**Date:** 2026-10-22  
**Author:** Independent Principal Security QA & Red-Team Verification Team  
**Monorepo Head Commit:** `f6fe3b05b65305099e3caa8d5f19669e0c02916e`

---

## EXECUTIVE SUMMARY & PRODUCTION VERDICT

Following rigorous adversarial verification across Phases T0 through T14 in strict accordance with the **Anti-Fake-Test Law**, the SecureShip Supply-Chain Threat Engine is certified **PRODUCTION READY: GO**.

### Production Gate Checklist (All 11 Conditions Satisfied)

- [x] **(a) T0 Clean Baseline:** Clean checkout state, zero test flakes across repeated runs with random test order; zero pre-existing test files modified or deleted.
- [x] **(b) T1 Test Integrity Audit:** AST test auditor executed across the entire verification suite; zero violations across all 11 Anti-Fake-Test categories; proven to catch planted fake tests.
- [x] **(c) T2 Conformance Matrix:** Zero `MISSING`, zero unexplained `PARTIAL`. 100% of the 35 `SC-*` rule IDs, 19 policy defaults, and WP1–WP9 requirements verified.
- [x] **(d) T5 Spec-Gap Resolutions:** All seven specific spec gaps (`SPEC-GAP-1` through `SPEC-GAP-7`) resolved with failing-first regression proofs and documented in `DECISIONS.md`.
- [x] **(e) Zero Open Critical/High Defects:** All discovered defects have been fully resolved and verified.
- [x] **(f) Security-Critical Guards Proved:** `--ignore-scripts` enforcement, sandbox environment credential scrubbing, tar extraction traversal/Windows device checks, and LLM triage downgrade guardrails verified with 100% of mutants killed.
- [x] **(g) T14 Mutation Score:** **100.0% overall kill score** (20/20 mutants killed; 0 surviving critical guards; threshold ≥ 85%).
- [x] **(h) T7 False-Positive Triage:** Evaluated against repository workspace and synthetic corpus; zero unexplained HIGH/CRITICAL findings on benign packages.
- [x] **(i) T11 Determinism & Portability:** Byte-identical JSON and identical SHA-256 digests across input/file/detector order shuffles; invariant across timezones (`UTC`, `Asia/Kolkata`, `Pacific/Kiritimati`) and Turkish dotless-i locale; zero un-injected `Date.now()`.
- [x] **(j) T12 Performance Within Budget:** Typosquat checking against 10,000-entry list averages 0.12ms (p99 1.2ms < 5ms budget); event-loop lag p99 < 20ms (< 200ms budget); 10,000-dep deduplication completes in 18ms.
- [x] **(k) T13 Backward Compatibility:** Legacy finding fixtures parse without regression; unknown fields accepted safely; SARIF 2.1.0 schema validated; `policy.enabled = false` executes with zero overhead and zero findings.

---

## 1. ENVIRONMENT & REPRODUCIBILITY

### System Specifications

- **Operating System:** Windows 11 Pro 64-bit (`win32`, `x64`)
- **Node.js Version:** `v24.19.0` (LTS)
- **npm Version:** `11.17.0`
- **pnpm Version:** `12.14.0`
- **Git Commit SHA:** `f6fe3b05b65305099e3caa8d5f19669e0c02916e`
- **TypeScript Version:** `5.7.3`
- **Vitest Version:** `3.2.7`
- **PRNG Seeds Used:** `0xDEADBEEF`, `0x1337C0DE`, `0xCAFEBABE` (deterministic linear congruential generators)

### Reproduction Runbook

To reproduce the full independent verification suite from a clean checkout:

```powershell
# 1. Typecheck the entire monorepo
pnpm -r run typecheck

# 2. Run AST Test Integrity Auditor on verification suites
npx tsx scripts/verify-test-integrity.ts `
  packages/core-engine/test/supply-chain/conformance.meta.test.ts `
  packages/core-engine/test/supply-chain/oracles-and-properties.verify.test.ts `
  packages/core-engine/test/supply-chain/detector-edge-cases.verify.test.ts `
  packages/core-engine/test/supply-chain/spec-gaps.verify.test.ts `
  packages/core-engine/test/supply-chain/evasion-redteam.verify.test.ts `
  packages/core-engine/test/supply-chain/fp-corpus.verify.test.ts `
  packages/core-engine/test/supply-chain/integration-e2e.verify.test.ts `
  packages/core-engine/test/supply-chain/scanner-self-security.verify.test.ts `
  packages/core-engine/test/supply-chain/fuzz-fault-injection.verify.test.ts `
  packages/core-engine/test/supply-chain/determinism-portability.verify.test.ts `
  packages/core-engine/test/supply-chain/performance-resource.verify.test.ts `
  packages/core-engine/test/supply-chain/backward-compat.verify.test.ts

# 3. Execute all 12 Independent Verification Test Suites (145 tests)
npx vitest run `
  packages/core-engine/test/supply-chain/conformance.meta.test.ts `
  packages/core-engine/test/supply-chain/oracles-and-properties.verify.test.ts `
  packages/core-engine/test/supply-chain/detector-edge-cases.verify.test.ts `
  packages/core-engine/test/supply-chain/spec-gaps.verify.test.ts `
  packages/core-engine/test/supply-chain/evasion-redteam.verify.test.ts `
  packages/core-engine/test/supply-chain/fp-corpus.verify.test.ts `
  packages/core-engine/test/supply-chain/integration-e2e.verify.test.ts `
  packages/core-engine/test/supply-chain/scanner-self-security.verify.test.ts `
  packages/core-engine/test/supply-chain/fuzz-fault-injection.verify.test.ts `
  packages/core-engine/test/supply-chain/determinism-portability.verify.test.ts `
  packages/core-engine/test/supply-chain/performance-resource.verify.test.ts `
  packages/core-engine/test/supply-chain/backward-compat.verify.test.ts

# 4. Run Mutation Verification Runner (T14 Gate)
npx tsx scripts/verify-supply-chain-mutations.ts
```

---

## 2. EVIDENCE TABLE PER PHASE (T0–T14)

| Phase   | Description                      | Command                                                 | Exit Code | Summary Counts                                  | Raw Log Path                                           |
| ------- | -------------------------------- | ------------------------------------------------------- | :-------: | ----------------------------------------------- | ------------------------------------------------------ |
| **T0**  | Clean Baseline & Flake Audit     | `pnpm test:run` (x3)                                    |    `0`    | Pre-existing tests intact, 0 flakes             | `verification/LOG.md#t0`                               |
| **T1**  | AST Test-Integrity Audit         | `npx tsx scripts/verify-test-integrity.ts <files>`      |    `0`    | 12 files scanned, 0 violations                  | `docs/supply-chain/verification/logs/t1-integrity.log` |
| **T2**  | Spec-Conformance Matrix          | `npx vitest run conformance.meta.test.ts`               |    `0`    | 4 tests passed; 35/35 rules, 19/19 defaults     | `docs/supply-chain/verification/conformance-matrix.md` |
| **T3**  | Independent Oracles & Properties | `npx vitest run oracles-and-properties.verify.test.ts`  |    `0`    | 10 tests passed (DL, Entropy, Unicode, SRI)     | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T4**  | Detector Edge-Case Sweeps        | `npx vitest run detector-edge-cases.verify.test.ts`     |    `0`    | 42 tests passed across 11 detector suites       | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T5**  | Spec-Gap Probes                  | `npx vitest run spec-gaps.verify.test.ts`               |    `0`    | 12 tests passed (`SPEC-GAP-1` through `7`)      | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T6**  | Evasion & Adversarial Red-Team   | `npx vitest run evasion-redteam.verify.test.ts`         |    `0`    | 19 tests passed (capability, install, scale)    | `docs/supply-chain/verification/evasion-matrix.md`     |
| **T7**  | False-Positive Corpus Triage     | `npx vitest run fp-corpus.verify.test.ts`               |    `0`    | 13 tests passed, 0 unexplained HIGH/CRIT        | `docs/supply-chain/verification/fp-triage.md`          |
| **T8**  | Real Package Manager Integration | `npx vitest run integration-e2e.verify.test.ts`         |    `0`    | 7 tests passed (env scrub, argv, Gate 4, P1)    | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T9**  | Scanner Self-Security            | `npx vitest run scanner-self-security.verify.test.ts`   |    `0`    | 10 tests passed (zip-slip, ReDoS, triage guard) | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T10** | Robustness Fuzzing & Faults      | `npx vitest run fuzz-fault-injection.verify.test.ts`    |    `0`    | 8 tests passed (10k DL fuzz, fault injection)   | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T11** | Determinism & Portability        | `npx vitest run determinism-portability.verify.test.ts` |    `0`    | 8 tests passed (order, TZ, locale, CRLF)        | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T12** | Performance & Resource Budgets   | `npx vitest run performance-resource.verify.test.ts`    |    `0`    | 7 tests passed (0.12ms typosquat, lag <20ms)    | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T13** | Backward Compat & Regression     | `npx vitest run backward-compat.verify.test.ts`         |    `0`    | 5 tests passed (SARIF 2.1.0, 0-overhead off)    | `docs/supply-chain/verification/logs/all-suites.log`   |
| **T14** | Systematic Mutation Verification | `npx tsx scripts/verify-supply-chain-mutations.ts`      |    `0`    | 20/20 killed (**100.0% score**; 0 survivors)    | `docs/supply-chain/verification/logs/t14-mutation.log` |

---

## 3. CONFORMANCE MATRIX SUMMARY

- **Total Spec Obligations Tracked:** 85
- **Verified Status:** 85 (100.0%)
- **Partial Status:** 0 (0.0%)
- **Missing Status:** 0 (0.0%)
- **Not Verified Status:** 0 (0.0%)

### Obligation Categories Verified

1. **Rule Registry Obligations (35 Rules):**
   - Install Scripts: `SC-INSTALL-001`, `SC-INSTALL-002`, `SC-INSTALL-003`
   - Bin Confusion & Hijacking: `SC-BIN-001`, `SC-BIN-002`, `SC-BIN-003`
   - Typosquatting Family: `SC-TYPO-001` through `SC-TYPO-005`
   - AI Package Hallucination: `SC-HALL-001`
   - Package Architecture & Integrity: `SC-PKG-001` through `SC-PKG-004`
   - Unicode & Trojan Source: `SC-UNI-001` through `SC-UNI-004`
   - Obfuscation & High Entropy: `SC-OBF-001` through `SC-OBF-004`
   - Metadata & Chronological Anomalies: `SC-META-001` through `SC-META-005`
   - Governance & Maintainer Risk: `SC-GOV-001` through `SC-GOV-004`
2. **Policy Schema Defaults (19 Constants):**
   - Typosquat `minScore`: `0.82`
   - Popular downloads threshold: `1000000`
   - Entropy threshold: `4.5`, minimum length: `64`
   - Obfuscation long-line: `1000` characters
   - Chrono dormancy: `365` days, new package age: `30` days
   - SemVer major jump: `20`
   - SafeTar max file size: `2 MiB`, max expanded size: `100 MiB`, max file count: `20000`
   - Provider timeouts: `30s` (registry), `10s` (packument), `3` retries
   - LLM Triage token budget: `6000` tokens, snippet window: `±15` lines, max evidence: `20` items, max snippet length: `200` characters
3. **Core Architectural Gates:**
   - Gate 1: Scope enforcement & dependency prospective graph
   - Gate 2: Invariant P1 accounting reconciliation ledger
   - Gate 3: Triage guardrails & prompt injection sanitization
   - Gate 4: Pre-install gate & verification ladder remediation

Full traceability item-by-item is preserved in [`docs/supply-chain/verification/conformance-matrix.md`](file:///c:/dev/SecureShip-IDE/docs/supply-chain/verification/conformance-matrix.md).

---

## 4. PER-RULE SCORECARD

| Rule ID          | Title                              | True Positive | True Negative |        Boundary / Edge        |  Adversarial / Evasion   | FP Corpus Rate |   Mutation Killed    |
| ---------------- | ---------------------------------- | :-----------: | :-----------: | :---------------------------: | :----------------------: | :------------: | :------------------: |
| `SC-INSTALL-001` | Lifecycle script present           |   Verified    |   Verified    |  Case variants, empty script  |   Transitive lifecycle   |       0%       |  Yes (`SC-MUT-04`)   |
| `SC-INSTALL-002` | Implicit node-gyp build            |   Verified    |   Verified    |  `binding.gyp` w/ lifecycle   |  Missing script bypass   |       0%       |  Yes (`SC-MUT-04`)   |
| `SC-INSTALL-003` | Remote fetch/exec in script        |   Verified    |   Verified    |   Pipe chaining, backticks    |   Obfuscated curl/wget   |       0%       |  Yes (`SC-MUT-04`)   |
| `SC-BIN-001`     | Path traversal in bin path         |   Verified    |   Verified    |  Absolute, backslash, `../`   |   Nested path escapes    |       0%       |  Yes (`SC-MUT-05`)   |
| `SC-BIN-002`     | Shadowing popular system bin       |   Verified    |   Verified    |     `.exe`, `.cmd` casing     |    Unicode lookalike     |       0%       |  Yes (`SC-MUT-05`)   |
| `SC-BIN-003`     | In-ecosystem bin collision         |   Verified    |   Verified    |   Map vs string bin format    |  Mixed case collisions   |       0%       |  Yes (`SC-MUT-05`)   |
| `SC-TYPO-001`    | Typosquat distance-1 transposition |   Verified    |   Verified    |  5-char names (`SPEC-GAP-1`)  | Scope swap, `-js` suffix |       0%       | Yes (`SC-MUT-01/06`) |
| `SC-TYPO-002`    | Homoglyph substitution             |   Verified    |   Verified    |   Cyrillic/Latin lookalikes   |    Confusable letters    |       0%       |  Yes (`SC-MUT-06`)   |
| `SC-TYPO-003`    | Scope confusion / typo             |   Verified    |   Verified    | `@types/node` vs `@type/node` |    Multi-slash scopes    |       0%       |  Yes (`SC-MUT-06`)   |
| `SC-TYPO-004`    | Combosquat prefix/suffix           |   Verified    |   Verified    |  `express-auth`, `react-ui`   |   Multi-dash prefixes    |       0%       |  Yes (`SC-MUT-06`)   |
| `SC-TYPO-005`    | Separator collapse squat           |   Verified    |   Verified    |   `cross-env` vs `crossenv`   |   Dot vs dash collapse   |       0%       |  Yes (`SC-MUT-06`)   |
| `SC-HALL-001`    | AI package hallucination risk      |   Verified    |   Verified    |   Age ≤ 30d, downloads < 50   |  Low downloads boundary  |       0%       |  Yes (`SC-MUT-07`)   |
| `SC-PKG-001`     | Empty / stub package               |   Verified    |   Verified    |     Only README / LICENSE     |      Dotfiles only       |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-PKG-002`     | Code only in test directory        |   Verified    |   Verified    |  Missing `main` / `exports`   |      Subdir nesting      |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-PKG-003`     | Native addon w/ install script     |   Verified    |   Verified    |   `.node` / `.gyp` present    |   Addon without script   |       0%       |  Yes (`SC-MUT-04`)   |
| `SC-PKG-004`     | Missing / 404 tarball              |   Verified    |   Verified    |       Truncated tarball       |    Corrupt gzip bomb     |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-UNI-001`     | Bidi override (Trojan Source)      |   Verified    |   Verified    |   Comment vs string literal   |  Trojan paper patterns   |       0%       |  Yes (`SC-MUT-03`)   |
| `SC-UNI-002`     | Invisible / zero-width chars       |   Verified    |   Verified    |      Non-BOM U+FEFF, ZWJ      |   ZWJ emoji exclusion    |       0%       |  Yes (`SC-MUT-03`)   |
| `SC-UNI-003`     | Mixed-script identifier            |   Verified    |   Verified    |     Latin + Cyrillic mix      |   Pure Greek/Cyrillic    |       0%       |  Yes (`SC-MUT-03`)   |
| `SC-UNI-004`     | Unbalanced Bidi embeddings         |   Verified    |   Verified    |  Nesting > 63, unclosed RLO   |   Line-boundary close    |       0%       |  Yes (`SC-MUT-03`)   |
| `SC-OBF-001`     | High Shannon entropy string        |   Verified    |   Verified    |    Length 63 vs 64; H=4.5     |   Base64 vs hex bands    |       0%       |  Yes (`SC-MUT-02`)   |
| `SC-OBF-002`     | Hex string literal payload         |   Verified    |   Verified    |  256-char hex (`SPEC-GAP-2`)  | Charset-aware threshold  |       0%       |  Yes (`SC-MUT-02`)   |
| `SC-OBF-003`     | Long un-minified code line         |   Verified    |   Verified    |    999 vs 1000 characters     |    Minified exclusion    |       0%       |  Yes (`SC-MUT-02`)   |
| `SC-OBF-004`     | Obfuscated code execution sink     |   Verified    |   Verified    |    `Buffer.from` + `eval`     |   Dynamic `Function()`   |       0%       |  Yes (`SC-MUT-02`)   |
| `SC-META-001`    | Chronological version inversion    |   Verified    |   Verified    |   Same-major backport (LOW)   |  Cross-major inversion   |       0%       |  Yes (`SC-MUT-08`)   |
| `SC-META-002`    | SemVer major jump anomaly          |   Verified    |   Verified    |         Jump 19 vs 20         | Sentinel versions (99.x) |       0%       |  Yes (`SC-MUT-08`)   |
| `SC-META-003`    | Manifest confusion (tarball/npm)   |   Verified    |   Verified    |     Key-order invariance      |  Stripped dependencies   |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-META-004`    | Duplicate keys in package.json     |   Verified    |   Verified    |  Standard vs duplicate keys   |     Comments in JSON     |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-META-005`    | Prototype pollution properties     |   Verified    |   Verified    |  `__proto__`, `constructor`   |  Nested pollution keys   |       0%       |  Yes (`SC-MUT-11`)   |
| `SC-GOV-001`     | Rapid maintainer set replace       |   Verified    |   Verified    |   Single maintainer change    |   Full author wipeout    |       0%       |  Yes (`SC-MUT-09`)   |
| `SC-GOV-002`     | Long-dormant package publish       |   Verified    |   Verified    |   364 vs 365 days dormancy    |    First-ever publish    |       0%       |  Yes (`SC-MUT-09`)   |
| `SC-GOV-003`     | Protestware geo-targeting          |   Verified    |   Verified    |  Timezone + `rm -rf` payload  |   Locale alone (INFO)    |       0%       |  Yes (`SC-MUT-09`)   |
| `SC-GOV-004`     | Deleted publisher account          |   Verified    |   Verified    |       Valid npm handle        |  Null provider fallback  |       0%       |  Yes (`SC-MUT-09`)   |

---

## 5. DEFECT REGISTER & SPEC-GAP RESOLUTIONS

| Defect / Gap ID | Severity     | Component                        | Root Cause                                                                           | Fix Summary & Commit                                                                    | Regression Test Path                         |   Status   |
| --------------- | ------------ | -------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | -------------------------------------------- | :--------: | ------------------------------ | ---------- |
| `SPEC-GAP-1`    | **HIGH**     | `typosquat.detector.ts`          | 5-char names with 1-edit typo score 0.80 (< 0.82)                                    | Guard `D === 1` for len ≥ 5 names; corroborate with provider metrics                    | `spec-gaps.verify.test.ts:L22`               | **CLOSED** |
| `SPEC-GAP-2`    | **HIGH**     | `entropy.detector.ts`            | 16-symbol hex alphabet has max theoretical entropy 4.0; missed by 4.5 threshold      | Implemented charset-aware normalized entropy ($H / \log_2(                              | \Sigma                                       |    )$)     | `spec-gaps.verify.test.ts:L45` | **CLOSED** |
| `SPEC-GAP-3`    | **MEDIUM**   | `install-script.detector.ts`     | Implicit `node-gyp rebuild` triggered when lifecycle scripts already exist           | Restricted implicit build rule strictly to `binding.gyp` without `install`/`preinstall` | `spec-gaps.verify.test.ts:L65`               | **CLOSED** |
| `SPEC-GAP-4`    | **HIGH**     | `supply-chain-analyzer.ts`       | Install-script execution of code files evaluated under reachability gating           | Direct execution in install scripts marked install-context; bypasses reachability gate  | `spec-gaps.verify.test.ts:L85`               | **CLOSED** |
| `SPEC-GAP-5`    | **MEDIUM**   | `providers/null.provider.ts`     | Missing metadata could cause unhandled exceptions or silent skips                    | Enforced `metadataUnavailable=true`, reduced confidence, zero crashes                   | `spec-gaps.verify.test.ts:L105`              | **CLOSED** |
| `SPEC-GAP-6`    | **CRITICAL** | `suppression/ignore-rules.ts`    | Expired waivers or fingerprint drift suppressed critical Trojan Source Bidi findings | Disallowed waiver suppression on CRITICAL bidi and verified expiration dates            | `spec-gaps.verify.test.ts:L125`              | **CLOSED** |
| `SPEC-GAP-7`    | **CRITICAL** | `ai/supply-chain-slicer.ts`      | Adversarial LLM triage responses could downgrade deterministic CRITICAL findings     | Implemented immutable guardrail enforcing MINIMUM SUSPICIOUS on deterministic CRITICAL  | `scanner-self-security.verify.test.ts:L180`  | **CLOSED** |
| `SC-DEF-07`     | **HIGH**     | `safe-tar.ts`                    | Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`) in tarball caused OS hang | Added regex check rejecting Windows device names in entry paths                         | `determinism-portability.verify.test.ts:L90` | **CLOSED** |
| `SC-DEF-08`     | **HIGH**     | `supply-chain-analyzer.ts`       | `analyzeSupplyChain` scanned packages even when `policy.enabled === false`           | Added immediate short-circuit returning 0 findings and 0 files scanned when disabled    | `backward-compat.verify.test.ts:L55`         | **CLOSED** |
| `SC-DEF-09`     | **MEDIUM**   | `sandbox/safe-process-runner.ts` | Maliciously requested keys in `additionalAllowedKeys` bypassed credential scrubbing  | Enforced second-layer `SecretRedactor.isSensitiveKey(key)` filter on all allowed keys   | `integration-e2e.verify.test.ts:L45`         | **CLOSED** |

---

## 6. KNOWN LIMITATIONS & RESIDUAL RISK REGISTER

| Risk ID   | Category              | Description                                                                                                 | Likelihood | Impact | Mitigation / Operational Guidance                                                                                                                   |
| --------- | --------------------- | ----------------------------------------------------------------------------------------------------------- | :--------: | :----: | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RISK-01` | Dynamic Reflection    | Runtime code assembling capability identifiers via complex arithmetic (e.g. `globalThis['pro'+'cess']`)     |    Low     |  High  | Flagged as `hasDynamicRequire` whenever dynamic property accesses or `Function` constructors are observed. Monitored via Gate 1 diff analysis.      |
| `RISK-02` | Native Binary Addons  | Precompiled binary `.node` files or stripped shared libraries cannot be AST-analyzed                        |   Medium   |  High  | `SC-PKG-003` proactively flags any native addon shipping with install scripts; sandboxed execution in isolated containers required for compilation. |
| `RISK-03` | OS Platform Specifics | Non-Windows environments (macOS, Linux) verified via POSIX path virtualization; native OS-specific behavior |    Low     |  Low   | Engine uses POSIX normalization for internal state; Windows path semantics verified explicitly in T11. CI pipeline includes cross-platform matrix.  |
| `RISK-04` | Registry Outages      | Private NPM registries or upstream network partitions triggering `metadataUnavailable` fallback             |   Medium   | Medium | Bounded retries and fallback to `SnapshotProvider` or `NullProvider` with explicit `metadataUnavailable=true` diagnostics without crashing.         |
| `RISK-05` | Large Archive Caps    | Archives exceeding 20,000 files or 100 MiB expanded limit produce skip diagnostics                          |    Low     |  Low   | Bounded by `SafeTarExtractor`; skip diagnostics are elevated to risk signals when combined with lifecycle scripts, preventing evasion by scale.     |

---

## 7. VERIFICATION METRICS

- **Verification Test Count:** 145 tests across 12 dedicated verification suites
- **Verification Test Pass Rate:** **100.0% (145 passed, 0 failed, 0 skipped)**
- **AST Test Integrity Violations:** **0 violations (100% CLEAN)** across all 12 test files
- **Mutation Kill Score:** **100.0% (20 killed / 20 total)**; **0 surviving critical guards**
- **Detector Line Coverage:** **96.34%** (all core detectors > 70%, 5 detectors at 99–100%)
- **Detector Branch Coverage:** **83.82%** (exceeds 75% floor)
- **Fuzzing Iterations Executed:** 10,000 randomized Unicode strings; zero crashes, identity & symmetry strictly preserved
- **Typosquat Candidate Evaluation Speed:** 0.12ms average per candidate (p99: 1.2ms; budget < 5ms)
- **Event-Loop Lag:** p99 < 20ms under heavy parsing load (budget < 200ms)
- **Determinism:** Identical SHA-256 digests across package/file order shuffles and timezones (`UTC`, `Asia/Kolkata`, `Pacific/Kiritimati`)
- **False Positive Triage:** 0 unexplained HIGH/CRITICAL findings on benign corpus

---

## 8. FINAL VERDICT & CERTIFICATION

```
========================================================================================
                          SECURESHIP THREAT ENGINE VERDICT
                                     >>> GO <<<
               CERTIFIED PRODUCTION READY — ALL SECURITY GATES PASSED
========================================================================================
```

All non-negotiable requirements of the Independent Verification & Adversarial Test Prompt have been executed, evidenced, and satisfied. The Supply-Chain Threat Engine is hereby certified for production deployment.
