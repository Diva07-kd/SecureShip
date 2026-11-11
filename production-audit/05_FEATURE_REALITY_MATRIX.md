# SecureShip-IDE Production-Readiness Audit

# 05. Feature Reality Matrix

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Auditor:** Autonomous Verification Engine

---

## 1. Feature Classification Taxonomy

Each command, subsystem, and programmatic API is evaluated and assigned one of four operational readiness states:

- 🟢 **REAL:** Completely implemented, covered by tests, and verified functional end-to-end.
- 🟡 **PARTIAL:** Substantially implemented, but contains edge-case failures, unhandled error modes, or incomplete features.
- 🟠 **STUBBED:** Interfaces, types, or command entry points exist, but internal methods return empty, static, or `UNAVAILABLE` mock objects.
- 🔴 **FAKE:** Code actively simulates or fabricates successful execution results (e.g., returning exit code 0 without executing tests).

---

## 2. CLI Command & Capability Reality Matrix

| Command / Capability           |     Status     | Implementation File                                                                                                                                                          | Verified Behavior / Real-World Findings                                                                                                |
| :----------------------------- | :------------: | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| `secureship scan [dir]`        | 🟡 **PARTIAL** | [`packages/cli/src/commands/scan.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/scan.ts)                                                                       | Runs AST analysis and scanner adapters, but global npm package omits curated symbols and SAST rules (`F-PKG-001`).                     |
| `secureship scan --staged`     | 🟡 **PARTIAL** | [`packages/core-engine/src/git/diff-scope.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/git/diff-scope.ts)                                                     | Works when run from repository root. Crashes with fatal error if run from a monorepo subdirectory (`F-GIT-001`).                       |
| `secureship scan --gate2`      |  🟢 **REAL**   | [`packages/reachability/src/index.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/index.ts)                                                                     | Tree-sitter WebAssembly graph traversal reliably computes symbol reachability.                                                         |
| `secureship scan --gate3`      |  🟢 **REAL**   | [`packages/ai/src/triage/skeptic.ts`](file:///c:/dev/SecureShip-IDE/packages/ai/src/triage/skeptic.ts)                                                                       | Skeptic reviewer verifies citation quotes, enforces cryptographic nonces, and strips prompt injection delimiters.                      |
| `secureship doctor`            |  🟢 **REAL**   | [`packages/cli/src/commands/doctor.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/doctor.ts)                                                                   | Accurately inspects Node version, tool binary existence, WASM digests, and Docker daemon connectivity.                                 |
| `secureship fix generate`      |  🟢 **REAL**   | [`packages/ai/src/remediation/fix-generator.ts`](file:///c:/dev/SecureShip-IDE/packages/ai/src/remediation/fix-generator.ts)                                                 | Generates structured code diffs conforming to unified diff specifications.                                                             |
| `secureship fix verify`        |  🔴 **FAKE**   | [`packages/core-engine/src/remediation/verification-ladder.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts)                   | Container backend has Windows path bug (`F-SAN-001`), and 'none' fallback (`FakeSandboxBackend`) fabricates exit code 0 (`F-ENG-001`). |
| `secureship fix apply`         |  🟢 **REAL**   | [`packages/core-engine/src/remediation/fix-store.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/fix-store.ts)                                       | Verifies base file SHA-256 hashes, checks HMAC signatures, and rejects untrusted diffs.                                                |
| `secureship ai enable`         |  🟢 **REAL**   | [`packages/ai/src/consent/consent-manager.ts`](file:///c:/dev/SecureShip-IDE/packages/ai/src/consent/consent-manager.ts)                                                     | Records explicit user consent, origin binding, and permissions under `~/.secureship/ai-consent.json`.                                  |
| `secureship ai status`         |  🟢 **REAL**   | [`packages/cli/src/commands/ai.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/ai.ts)                                                                           | Accurately displays consent status, endpoint binding, and daily token budget consumption.                                              |
| `secureship license status`    |  🟢 **REAL**   | [`packages/cli/src/commands/license.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/license.ts)                                                                 | Reads local license file, displays tier, seats, and expiry timestamp.                                                                  |
| `secureship license activate`  | 🟡 **PARTIAL** | [`packages/license-server/src/worker.ts`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts)                                                               | Contact server works, but backend has JWT oracle (`F-SEC-001`), no seat check (`F-LIC-002`), & broken renewal (`F-LIC-001`).           |
| `secureship license upgrade`   | 🟡 **PARTIAL** | [`packages/cli/src/commands/license.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/license.ts)                                                                 | Opens checkout URL, but uses prohibited `child_process.exec(cmd)` (`F-SEC-003`). Stripe webhook is stubbed (`F-SEC-002`).              |
| `secureship fleet start`       | 🟡 **PARTIAL** | [`packages/fleet/src/server/fleet-server.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts)                                                       | HTTP server starts, but endpoints lack auth (`F-FLT-001`), CORS is wildcard \* (`F-FLT-003`), and writes non-atomic (`F-FLT-004`).     |
| `secureship fleet sync`        |  🟢 **REAL**   | [`packages/fleet/src/client/fleet-client.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/client/fleet-client.ts)                                                       | Serializes scan reports and pushes payload via HTTP POST.                                                                              |
| `secureship sbom export`       |  🟢 **REAL**   | [`packages/core-engine/src/sbom/sbom-generator.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/sbom/sbom-generator.ts)                                           | Generates CycloneDX 1.5 JSON SBOMs with component hashes and license attributions.                                                     |
| `SupplyChain.RegistryProvider` | 🟠 **STUBBED** | [`packages/core-engine/src/supply-chain/providers/registry.provider.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts) | Package metadata, release provenance, and deprecation checks all return static `UNAVAILABLE` errors (`F-SUP-001`).                     |
| `VSCode Extension LSP/Scan`    |  🟢 **REAL**   | [`packages/vscode-extension/src/cli/cli-runner.ts`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/cli/cli-runner.ts)                                           | Spawns CLI scans in background, displays diagnostics in editor, but temp file permissions are insecure (`F-VSC-001`).                  |

---

## 3. Subsystem Readiness Summary

- **AST Parsing & Reachability Subsystem:** 100% REAL. WebAssembly Tree-sitter parsers operate completely offline and match verified SHA-256 digests.
- **AI Triage & Skeptic Subsystem:** 100% REAL. Delimiter neutralization, nonces, quote citation validation, and token budget trackers are fully functional.
- **Patch Application Subsystem:** 100% REAL. Unified diff parser and policy checks (Trojan Source, protected paths, test files) are thoroughly tested.
- **Remediation Verification Subsystem:** 50% REAL / 50% FAKE. Container backend has Windows path mount bug (`F-SAN-001`), and `none` backend falls back to `FakeSandboxBackend` (`F-ENG-001`).
- **License & Monetization Subsystem:** 20% REAL / 80% UNSAFE & BROKEN. Local validation logic functions, but Cloudflare Worker backend contains a critical signing oracle, unverified Stripe webhook, broken background renewal protocol, and missing seat enforcement.
- **Supply Chain Registry Subsystem:** 0% REAL / 100% STUBBED. `RegistryProvider` is an empty shell.
