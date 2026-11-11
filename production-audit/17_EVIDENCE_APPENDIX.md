# SecureShip-IDE Production-Readiness Audit

# 17. Evidence Appendix

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Git Tree Hash:** `0c308a8e6639f8eb227e0d3b246a85f2be153e07`  
**Auditor:** Autonomous Verification Engine

---

## 1. Environment & Baseline Execution Logs

### 1.1 Git Commit Identification

```text
$ git rev-parse HEAD
70c3087b863d06538a6b7116eaa4d22e25073e29

$ git rev-parse HEAD^{tree}
0c308a8e6639f8eb227e0d3b246a85f2be153e07

$ git status
On branch main
Your branch is up to date with 'origin/main'.
nothing to commit, working tree clean
```

### 1.2 Runtime Environment Identification

```text
$ node -v
v24.19.0

$ pnpm -v
12.14.0
```

---

## 2. Static Analysis & Build Verification Logs

### 2.1 TypeScript Compilation (`pnpm typecheck`)

```text
$ pnpm typecheck
> secureship-monorepo@0.1.0 typecheck C:\dev\SecureShip-IDE
> tsc --noEmit -p tsconfig.json

[Exit code: 0 - Clean pass across all 13 workspace packages]
```

### 2.2 Linter Verification (`pnpm lint`)

```text
$ pnpm lint
> secureship-monorepo@0.1.0 lint C:\dev\SecureShip-IDE
> eslint .

[Exit code: 0 - Zero lint warnings or errors]
```

### 2.3 Code Formatting (`pnpm format:check`)

```text
$ pnpm format:check
> secureship-monorepo@0.1.0 format:check C:\dev\SecureShip-IDE
> prettier --check .

Checking formatting...
All matched files are formatted correctly!
[Exit code: 0]
```

---

## 3. Dynamic Test Suite Logs

### 3.1 Vitest Full Suite (`pnpm test`)

```text
$ pnpm test
> secureship-monorepo@0.1.0 test C:\dev\SecureShip-IDE
> vitest run

 RUN  v3.2.7 C:/dev/SecureShip-IDE

 ✓ packages/ai/test/http-client.test.ts (24 tests)
 ✓ packages/ai/test/prompt-builder.test.ts (18 tests)
 ✓ packages/ai/test/sanitizer.test.ts (16 tests)
 ✓ packages/ai/test/skeptic.test.ts (22 tests)
 ✓ packages/context-slicer/test/slicer.test.ts (35 tests)
 ✓ packages/contracts/test/finding-schema.test.ts (15 tests)
 ✓ packages/core-engine/test/gate1-scope-classifier.test.ts (28 tests)
 ✓ packages/core-engine/test/gate3-integration.test.ts (19 tests)
 ✓ packages/core-engine/test/remediation/verification-ladder.test.ts (26 tests)
 ✓ packages/core-engine/test/remediation/fix-store.test.ts (18 tests)
 ✓ packages/patch-engine/test/diff-parser.test.ts (32 tests)
 ✓ packages/patch-engine/test/policy-engine.test.ts (41 tests)
 ✓ packages/patch-engine/test/applier.test.ts (21 tests)
 ✓ packages/reachability/test/sca-reachability.test.ts (48 tests)
 ✓ packages/reachability/test/hostile-stress.test.ts (7 tests)
 ✓ packages/reachability/test/wasm-manifest.test.ts (14 tests)
 ✓ packages/sandbox/test/backends.test.ts (25 tests)
 ✓ packages/sandbox/test/baseline-runner.test.ts (19 tests)
 ... [175 other test files passing] ...

 Test Files  193 passed (193)
      Tests  1607 passed (1607)
   Start at  14:02:11
   Duration  501.31s (transform 12.4s, setup 3.2s, collect 45.1s, tests 412.5s)
[Exit code: 0]
```

---

## 4. Supply Chain & Attestation Logs

### 4.1 WebAssembly Grammar Verification (`pnpm verify:wasm`)

```text
$ node scripts/verify-wasm.mjs
[WASM SSoT Verifier] Inspecting 9 bundled WebAssembly grammars in packages/reachability/wasm/...
  ✓ tree-sitter.wasm (188,635 bytes) -> 29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f
  ✓ tree-sitter-javascript.wasm (647,334 bytes) -> 63812b9e275d26851264734868d27a1656bd44a2ef6eb3e85e6b03728c595ab5
  ✓ tree-sitter-typescript.wasm (2,342,690 bytes) -> 8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f
  ✓ tree-sitter-tsx.wasm (2,411,272 bytes) -> 6aa3b2c70e76f5d48eafef1093e9c4de383e13f2fdde2f4e9b98a378f6a8f1b6
  ✓ tree-sitter-python.wasm (476,105 bytes) -> 9056d0fb0c337810d019fae350e8167786119da98f0f282aceae7ab89ee8253b
  ✓ tree-sitter-go.wasm (235,957 bytes) -> 9963ca89b616eaf04b08a43bc1fb0f07b85395bec313330851f1f1ead2f755b6
  ✓ tree-sitter-java.wasm (430,239 bytes) -> 637aac4415fb39a211a4f4292d63c66b5ce9c32fa2cd35464af4f681d91b9a1f
  ✓ tree-sitter-rust.wasm (818,756 bytes) -> 4409921a70d0aa5bec7d1d7ce809a557a8ee1cf6ace901e3ac6a76e62cfea903
  ✓ tree-sitter-c_sharp.wasm (3,978,594 bytes) -> 6266a7e32d68a3459104d994dc848df15d5672b0ea8e86d327274b694f8e6991
[WASM SSoT Verifier] ALL 9 WASM GRAMMARS MATCH DECLARED REPO & UPSTREAM DIGESTS.
[Exit code: 0]
```

### 4.2 Curated Symbols Attestation (`pnpm verify:symbols`)

```text
$ node scripts/verify-symbols.mjs
[Symbols Verifier] Attesting packages/reachability/data/vulnerable-symbols.json...
  - Symbol count: 18
  - Computed SHA-256: 2068e3dbf074d289b4f2c8bb86dd2648714eb6408a287233777d1ca476c596ff
  - Expected SHA-256: 2068e3dbf074d289b4f2c8bb86dd2648714eb6408a287233777d1ca476c596ff
[Symbols Verifier] SYMBOLS DATASET VALID AND CRYPTOGRAPHICALLY ATTESTED.
[Exit code: 0]
```

### 4.3 Anti-Fake-Test Law Auditor Output

```text
$ node --experimental-strip-types scripts/verify-test-integrity.ts
🛡️  SecureShip Supply-Chain Threat Engine — Test Integrity Auditor (T1)
Scanning test suite against Anti-Fake-Test Law requirements...

Scanned Test Files : 106
Total Violations   : 4

--- Breakdown by Violation Category ---
  - zero-assertions          : CLEAN
  - tautology                : CLEAN
  - weak-only                : VIOLATION (2)
  - skip-only-todo           : CLEAN
  - commented-assertion      : CLEAN
  - swallowed-catch          : CLEAN
  - prod-constant-expected   : CLEAN
  - forbidden-mock           : CLEAN
  - snapshot-only            : CLEAN
  - async-missing-await      : CLEAN
  - unfaked-timer            : VIOLATION (2)

❌ AUDIT FAILED: Fake or weakened test patterns detected:

  [UNFAKED-TIMER] C:\dev\SecureShip-IDE\packages\reachability\test\hostile-stress.test.ts:12:3
  Test: Hostile 1: 50 MB file handled within memory and timeout limits without crashing
  Message: Test 'Hostile 1: 50 MB file handled within memory and timeout limits without crashing' asserts on real clock elapsed time without vi.useFakeTimers(), leading to flakiness.

  [WEAK-ONLY] C:\dev\SecureShip-IDE\packages\reachability\test\hostile-stress.test.ts:47:3
  Test: Hostile 2: binary file named .js and .py handled safely without crashing
  Message: Test 'Hostile 2: binary file named .js and .py handled safely without crashing' contains only weak assertions (toBeDefined/toBeTruthy/not.toThrow). Hard semantic assertions required.

  [WEAK-ONLY] C:\dev\SecureShip-IDE\packages\reachability\test\hostile-stress.test.ts:70:3
  Test: Hostile 3: invalid UTF-8 byte sequences handled without throwing or crashing
  Message: Test 'Hostile 3: invalid UTF-8 byte sequences handled without throwing or crashing' contains only weak assertions (toBeDefined/toBeTruthy/not.toThrow). Hard semantic assertions required.

  [UNFAKED-TIMER] C:\dev\SecureShip-IDE\packages\reachability\test\hostile-stress.test.ts:136:3
  Test: Hostile 7: 20,000-file project simulated tree benchmark (reports duration and peak RSS)
  Message: Test 'Hostile 7: 20,000-file project simulated tree benchmark (reports duration and peak RSS)' asserts on real clock elapsed time without vi.useFakeTimers(), leading to flakiness.
[Exit code: 1]
```

### 4.4 Subdirectory Monorepo Incremental Scan Crash Reproduction

```text
$ node packages/cli/dist/index.js scan packages/core-engine --staged
Error: Directory 'C:\dev\SecureShip-IDE\packages\core-engine' is not a git repository
    at Function.resolveDiffFiles (C:\dev\SecureShip-IDE\packages\core-engine\dist\index.js:1482:13)
    at Object.runScan (C:\dev\SecureShip-IDE\packages\core-engine\dist\index.js:2104:42)
    at Command.<anonymous> (C:\dev\SecureShip-IDE\packages\cli\dist\index.js:125:31)
[Exit code: 1]
```
