# SecureShip-IDE Production-Readiness Audit

# 04. Claims vs. Reality Ledger

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Auditor:** Autonomous Verification Engine

---

## 1. Executive Claims Comparison Table

The following ledger systematically evaluates every claim made in project documentation, `package.json` descriptions, CLI `--help` menus, and architectural specifications against empirical codebase evidence.

|    #     | Public / Marketing Claim                                                                         | Documented Location                                                                                                                                                                        | Technical Reality in Codebase                                                                                                                                                                          |           Verdict           |
| :------: | :----------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------: |
| **C-1**  | _"Zero-False-Positive DevSecOps Intelligence Engine"_                                            | [`packages/cli/package.json#L5`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json#L5)                                                                                               | Reachability analysis (Gate 2) and AI triage (Gate 3) significantly prune noise, but cannot guarantee mathematical zero. `FakeSandboxBackend` falsely marks patches as verified.                       | ⚠️ **PARTIAL / MISLEADING** |
| **C-2**  | _"Completely self-contained, air-gapped security analysis with zero run-time network downloads"_ | [`THIRD_PARTY_NOTICES.md#L146`](file:///c:/dev/SecureShip-IDE/THIRD_PARTY_NOTICES.md#L146)                                                                                                 | Tree-sitter WASM grammars and curated symbols are 100% offline. However, standalone bun binaries omit WASM files, breaking air-gap execution unless source tree is present.                            |       ⚠️ **PARTIAL**        |
| **C-3**  | _"Every verified remediation patch is validated against a clean test suite before merge"_        | [`packages/core-engine/src/remediation/verification-ladder.ts#L60-L80`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts#L60-L80)                 | If `userConfig.sandbox.backend === 'none'`, the engine invokes `FakeSandboxBackend`, which fabricates exit code 0 without executing any tests.                                                         |  ❌ **FABRICATED / FAKE**   |
| **C-4**  | _"Enterprise License Server with cryptographic validation and Stripe integration"_               | [`packages/license-server/src/worker.ts#L1-L20`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L1-L20)                                                               | `GET /v1/validate` does not verify JWT signatures and re-signs unverified claims (JWT oracle). The Stripe webhook handler is a stub that ignores secrets and persists nothing.                         |   ❌ **UNSAFE / STUBBED**   |
| **C-5**  | _"Automated Registry Package Supply-Chain Risk Provider"_                                        | [`packages/core-engine/src/supply-chain/providers/registry.provider.ts#L1-L15`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts#L1-L15) | All 4 methods in `RegistryProvider` return `{ ok: false, error: { code: 'UNAVAILABLE' } }` with zero network implementation.                                                                           |       ❌ **STUBBED**        |
| **C-6**  | _"Centralized Enterprise Fleet Management & Telemetry Server"_                                   | [`packages/fleet/src/server/fleet-server.ts#L1-L30`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts#L1-L30)                                                       | Server logs `FLEET_TOKEN` in plaintext to stdout, and exposes `/api/policy` and all management endpoints with zero authentication checks.                                                              |        ❌ **UNSAFE**        |
| **C-7**  | _"Native single-binary standalone distributions for Linux, macOS, and Windows"_                  | [`.github/workflows/release.yml#L30-L50`](file:///.github/workflows/release.yml#L30-L50)                                                                                                   | Binaries are compiled via `bun build --compile`, but `wasm/` files are not copied to `release-dist/`, causing immediate startup failure upon download.                                                 |        ❌ **BROKEN**        |
| **C-8**  | _"Zero native process shell invocations (Principle P6: shell: false)"_                           | [`.agents/skills/secureship-verification/SKILL.md`](file:///c:/dev/SecureShip-IDE/.agents/skills/secureship-verification/SKILL.md)                                                         | `packages/cli/src/commands/license.ts#L169-L178` executes `child_process.exec(cmd)` to launch web browsers, directly violating Principle P6.                                                           |       ❌ **VIOLATED**       |
| **C-9**  | _"Strict Trojan Source (bidi override) and hidden Unicode defense"_                              | [`packages/patch-engine/src/policy-engine.ts#L718-L727`](file:///c:/dev/SecureShip-IDE/packages/patch-engine/src/policy-engine.ts#L718-L727)                                               | Verified in code and test suite. Blocks Unicode bidi override codepoints and hidden zero-width characters in patches and AI responses.                                                                 |    ✅ **VERIFIED REAL**     |
| **C-10** | _"Cryptographic WebAssembly Grammar Attestation & SSoT Verification"_                            | [`scripts/verify-wasm.mjs#L1-L30`](file:///c:/dev/SecureShip-IDE/scripts/verify-wasm.mjs#L1-L30)                                                                                           | Verified in code and test execution. All 9 WASM grammars match hardcoded SHA-256 digests and upstream release tarball hashes.                                                                          |    ✅ **VERIFIED REAL**     |
| **C-11** | _"Curated Vulnerable Symbol Graph Attestation"_                                                  | [`scripts/verify-symbols.mjs#L1-L25`](file:///c:/dev/SecureShip-IDE/scripts/verify-symbols.mjs#L1-L25)                                                                                     | Verified in code and execution. 18 vulnerability symbols match cryptographic digest `2068e3db...`.                                                                                                     |    ✅ **VERIFIED REAL**     |
| **C-12** | _"Fast Incremental Monorepo Staged / Branch Diff Scans"_                                         | [`packages/cli/src/commands/scan.ts#L80-L100`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/scan.ts#L80-L100)                                                                   | Full repo scans work, but running incremental diff scans on a subdirectory (e.g., `secureship scan packages/core-engine --staged`) crashes immediately with `Directory '...' is not a git repository`. |        ❌ **BROKEN**        |

---

## 2. In-Depth Reality Analysis of Core Subsystems

### 2.1 The "Zero-False-Positive" Claim

- **Marketing Assertion:** SecureShip eliminates false positives through formal AST graph reachability.
- **Auditor Verification:** In `packages/core-engine/src/orchestrator/scan-orchestrator.ts`, Gate 1 successfully suppresses non-production files (tests, fixtures, examples), and Gate 2 successfully suppresses uninvoked function imports for JavaScript and TypeScript. However:
  - Python SCA findings cannot achieve HIGH confidence reachability (Rule C1).
  - Any syntax error or dynamic import (`eval`, dynamic `require`) forces findings to fallback to `UNKNOWN`, bypassing suppression.
  - Calling this "Zero False Positives" rather than "Substantially Reduced Noise" is mathematically inaccurate and creates liability under enterprise SLAs.

### 2.2 The "Verified Remediation" Claim

- **Marketing Assertion:** Every remediation patch is tested against a clean test suite before merging.
- **Auditor Verification:** If a user specifies `sandbox.backend: none` in their configuration, `verification-ladder.ts` instantiates `FakeSandboxBackend`:
  ```typescript
  // packages/core-engine/src/remediation/verification-ladder.ts:608-610
  if (backendType === 'none') {
    return new FakeSandboxBackend();
  }
  ```
  `FakeSandboxBackend` unconditionally returns exit code 0 with output `"fake execution passed"`. The engine then assigns `VERIFIED_RUNTIME`, deceiving the developer into believing their unit tests passed in a container.

### 2.3 The "Enterprise Fleet" Claim

- **Marketing Assertion:** Centralized repository policy enforcement and telemetry aggregation.
- **Auditor Verification:** In `packages/fleet/src/server/fleet-server.ts`, the router handles `/api/policy` and `/api/fleet/repos` without validating authorization tokens. Anyone on the network can push arbitrary security policies or query the complete list of corporate repositories and vulnerabilities.
