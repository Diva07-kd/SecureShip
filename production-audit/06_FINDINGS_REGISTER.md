# SecureShip-IDE Production-Readiness Audit

# 06. Findings Register

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Total Verified Findings:** 19 (8 P0, 5 P1, 5 P2, 1 P3)  
**Total Debunked Findings:** 3 (F-FLT-002, F-CICD-001, F-AI-001)  
**Auditor:** Autonomous Verification Engine

---

## 1. Master Findings Index (Active Verified Findings)

| Finding ID                | Severity |       Category       | Title                                                                         | Primary File Location                                                                                                                                                                      | Verification Status |
| :------------------------ | :------: | :------------------: | :---------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------------: |
| [`F-SEC-001`](#f-sec-001) |  **P0**  |       Security       | Unverified & Forged JWT Signing Oracle on License Server                      | [`packages/license-server/src/worker.ts:270-327`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L270-L327)                                                           |    **Verified**     |
| [`F-SEC-002`](#f-sec-002) |  **P0**  |       Security       | Unverified & Stubbed Stripe Webhook Handler                                   | [`packages/license-server/src/worker.ts:338-374`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L338-L374)                                                           |    **Verified**     |
| [`F-DIS-001`](#f-dis-001) |  **P0**  |     Distribution     | NPM Package Dependency Confusion & CLI Installation Implosion                 | [`packages/cli/package.json:33-41`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json#L33-L41)                                                                                       |    **Verified**     |
| [`F-REL-001`](#f-rel-001) |  **P0**  |       Release        | Standalone Binaries Missing Bundled WASM Grammars                             | [`.github/workflows/release.yml:79-83`](file:///.github/workflows/release.yml#L79-L83)                                                                                                     |    **Verified**     |
| [`F-LIC-001`](#f-lic-001) |  **P0**  | Licensing / Protocol | Fatal Client-Server Protocol Incompatibility in Background Renewal            | [`packages/core-engine/src/license/tier-resolver.ts:178-190`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/license/tier-resolver.ts#L178-L190)                                   |    **Verified**     |
| [`F-FLT-003`](#f-flt-003) |  **P0**  |   Security / Fleet   | Wildcard CORS `*` on Fleet Server Exposes Telemetry and Policy Tampering      | [`packages/fleet/src/server/fleet-server.ts:81-85`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts#L81-L85)                                                       |    **Verified**     |
| [`F-LIC-002`](#f-lic-002) |  **P0**  |     Monetization     | Zero Seat Limit Enforcement on License Server / Infinite Activations          | [`packages/license-server/src/worker.ts:180-248`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L180-L248)                                                           |    **Verified**     |
| [`F-PKG-001`](#f-pkg-001) |  **P0**  |     Distribution     | Curated Symbol Dataset & SAST Rules Missing From Shipped Artifacts            | [`packages/reachability/src/symbols/dataset-loader.ts:28-47`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/symbols/dataset-loader.ts#L28-L47)                                   |    **Verified**     |
| [`F-ENG-001`](#f-eng-001) |  **P1**  |        Engine        | Fake Remediation Backend (`FakeSandboxBackend`) in Production Engine          | [`packages/core-engine/src/remediation/verification-ladder.ts:608-610`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts#L608-L610)               |    **Verified**     |
| [`F-GIT-001`](#f-git-001) |  **P1**  |      CLI / Git       | Fatal Crash on Subdirectory Monorepo Incremental Git Diff Scans               | [`packages/core-engine/src/git/diff-scope.ts:68-73`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/git/diff-scope.ts#L68-L73)                                                     |    **Verified**     |
| [`F-FLT-001`](#f-flt-001) |  **P1**  |        Fleet         | Fleet Server Token Leak to stdout & Unauthenticated Control Endpoints         | [`packages/fleet/src/server/fleet-server.ts:138-190`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts#L138-L190)                                                   |    **Verified**     |
| [`F-SAN-001`](#f-san-001) |  **P1**  |  Platform / Sandbox  | Windows Container Mount Path `/c/...` Translation Rejection by Docker Desktop | [`packages/sandbox/src/backends/container-backend.ts:39-50`](file:///c:/dev/SecureShip-IDE/packages/sandbox/src/backends/container-backend.ts#L39-L50)                                     |    **Verified**     |
| [`F-FLT-004`](#f-flt-004) |  **P1**  | Architecture / Fleet | Unsynchronized Non-Atomic `fs.writeFileSync` in FleetStore Data Loss          | [`packages/fleet/src/storage/fleet-store.ts:60-76`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/storage/fleet-store.ts#L60-L76)                                                       |    **Verified**     |
| [`F-SEC-003`](#f-sec-003) |  **P2**  |       Security       | Prohibited Shell Invocations (`child_process.exec`) in License Command        | [`packages/cli/src/commands/license.ts:169-178`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/license.ts#L169-L178)                                                             |    **Verified**     |
| [`F-VSC-001`](#f-vsc-001) |  **P2**  |       Security       | Insecure Temp File Permissions in VSCode Extension Runner                     | [`packages/vscode-extension/src/cli/cli-runner.ts:46-49`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/cli/cli-runner.ts#L46-L49)                                           |    **Verified**     |
| [`F-SUP-001`](#f-sup-001) |  **P2**  |     Supply Chain     | Completely Stubbed Registry Supply-Chain Risk Provider                        | [`packages/core-engine/src/supply-chain/providers/registry.provider.ts:10-75`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts#L10-L75) |    **Verified**     |
| [`F-LEG-001`](#f-leg-001) |  **P2**  |        Legal         | Rebranded Third-Party Scanner Rule IDs Missing Upstream Notices               | [`packages/contracts/src/engine-brand.ts:13-115`](file:///c:/dev/SecureShip-IDE/packages/contracts/src/engine-brand.ts#L13-L115)                                                           |    **Verified**     |
| [`F-TST-001`](#f-tst-001) |  **P2**  |     Test Quality     | Anti-Fake-Test Law Integrity Violations in Reachability Suite                 | [`packages/reachability/test/hostile-stress.test.ts:12,47,70,136`](file:///c:/dev/SecureShip-IDE/packages/reachability/test/hostile-stress.test.ts#L12)                                    |    **Verified**     |
| [`F-WIN-001`](#f-win-001) |  **P3**  |       Platform       | Windows Path Normalization Inconsistencies in VSCode Runner                   | [`packages/vscode-extension/src/extension.ts:80-95`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/extension.ts#L80-L95)                                                     |    **Verified**     |

---

## 2. Debunked / Removed Findings (Skeptical Review)

During the skeptical re-verification phase, the following 3 findings from the initial pass were determined to be invalid, misread, or ungrounded in production reality and were removed from the active register:

| Finding ID   | Original Severity | Claimed Issue                                                 | Reason for Debunking / Actual Codebase Reality                                                                                                                                                                                                                                         |
| :----------- | :---------------: | :------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `F-FLT-002`  |        P3         | Lack of Connection Pooling & WAL Mode in Fleet SQLite Backend | **Debunked (Non-Existent File & Hallucinated DB Engine):** Fleet does not use SQLite; it uses an in-memory `Map<string, FleetRepoSummary>` backed by JSON file persistence (`FleetStore`). The claimed file `packages/fleet/src/server/storage.ts` does not exist in the codebase.     |
| `F-CICD-001` |        P2         | Fragile 15-Second Download Timeout in CI Tool Pin Verifier    | **Debunked (Non-Production Maintenance Script):** Line 44 in `scripts/verify-tool-pins.ts` fetches small (<5KB) SHA256 checksum manifests from GitHub release CDNs in CI, not 50MB binaries. A 15-second timeout on a 5KB manifest in a developer verification script is not a defect. |
| `F-AI-001`   |        P3         | Hardcoded AI Client Max Concurrency Bottleneck                | **Debunked (Configurable API & Safe Default):** Concurrency is not hardcoded; `HttpClient.setMaxConcurrency(max: number)` is explicitly exported. Defaulting to 2 is an intentional defense-in-depth measure against rate-limiting on Ollama and cloud LLMs.                           |

---

## 3. Active Findings Distribution Statistics

```
Total Active Findings: 19
---------------------------------
P0 (Blocker)  : 8  (42.1%)
P1 (Critical) : 5  (26.3%)
P2 (High)     : 5  (26.3%)
P3 (Medium)   : 1  (5.3%)
---------------------------------
By Domain:
  - Security & Crypto : 4 (F-SEC-001, F-SEC-002, F-SEC-003, F-FLT-003)
  - Licensing & Money : 2 (F-LIC-001, F-LIC-002)
  - Distribution & Rel: 3 (F-DIS-001, F-REL-001, F-PKG-001)
  - Engine & Git      : 2 (F-ENG-001, F-GIT-001)
  - Fleet & Telemetry : 2 (F-FLT-001, F-FLT-004)
  - Platform & Sandbox: 2 (F-SAN-001, F-WIN-001)
  - Supply Chain & Leg: 2 (F-SUP-001, F-LEG-001)
  - IDE & Extension   : 1 (F-VSC-001)
  - Test Quality      : 1 (F-TST-001)
```

For complete technical descriptions, exact code snippets, proof-of-concept exploits, and line citations, refer to [07_FINDINGS_DETAIL.md](file:///c:/dev/SecureShip-IDE/production-audit/07_FINDINGS_DETAIL.md).
