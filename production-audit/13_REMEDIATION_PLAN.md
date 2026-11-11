# SecureShip-IDE Production-Readiness Audit

# 13. Phased Remediation Plan

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Estimated Time to Production:** 14 Working Days  
**Auditor:** Autonomous Verification Engine

---

## 1. Remediation Dependency Roadmap

```
+-------------------------------------------------------------+
| Wave 0: Critical Blockers (Days 1–4)                        |
|  - Fix License JWT verification oracle (F-SEC-001)          |
|  - Implement Stripe HMAC webhook validation (F-SEC-002)     |
|  - Clean CLI package.json dependencies (F-DIS-001)          |
|  - Bundle WASM in GitHub release workflows (F-REL-001)      |
|  - Align background renewal client-server protocol (F-LIC-001) |
|  - Eliminate wildcard CORS * on Fleet server (F-FLT-003)    |
|  - Enforce seat limit checks in license activation (F-LIC-002) |
|  - Bundle curated symbols & SAST rules in CLI pkg (F-PKG-001) |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Wave 1: Safety & Architecture (Days 5–8)                    |
|  - Purge FakeSandboxBackend from engine (F-ENG-001)         |
|  - Fix monorepo root discovery in DiffScope (F-GIT-001)     |
|  - Secure Fleet control plane endpoints & token (F-FLT-001) |
|  - Fix Windows Docker Desktop path translation (F-SAN-001)  |
|  - Implement atomic file persistence in FleetStore (F-FLT-004) |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Wave 2: Integrity & Legal Hardening (Days 9–12)             |
|  - Eliminate shell:true exec() in license cmd (F-SEC-003)   |
|  - Secure temp files in VSCode runner (F-VSC-001)           |
|  - Fix 4 test suite integrity violations (F-TST-001)        |
|  - Update THIRD_PARTY_NOTICES.md engine licenses (F-LEG-001)|
|  - Implement real RegistryProvider HTTP client (F-SUP-001)  |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Wave 3: Polish & Hardening (Days 13–14)                     |
|  - Windows path normalization in extension (F-WIN-001)      |
+-------------------------------------------------------------+
```

---

## 2. Detailed Task Breakdown by Wave

### Wave 0: Immediate Blockers (Release Blockers)

#### Task 0.1: Cryptographic JWT Verification & Revocation Check (`F-SEC-001`)

- **Target File:** [`packages/license-server/src/worker.ts`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts)
- **Changes Required:**
  1. Replace unverified `atob()` with WebCrypto `verifyJwtWebCrypto(token, env.JWT_PUBLIC_KEY)`.
  2. Query Cloudflare D1 database: `SELECT revoked_at FROM licenses WHERE id = ?`. Return 403 if revoked.
  3. Only re-sign refreshed tokens if both the cryptographic signature and active license record are verified.
- **Acceptance Criteria:** Forged JWT payloads are rejected with 401; revoked licenses rejected with 403; test added in `packages/license-server/test/license-server.test.ts`.

#### Task 0.2: Stripe Webhook Signature Verification & DB Persistence (`F-SEC-002`)

- **Target File:** [`packages/license-server/src/worker.ts`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts)
- **Changes Required:**
  1. Validate `stripe-signature` header against `env.STRIPE_WEBHOOK_SECRET` using WebCrypto HMAC-SHA256.
  2. On `checkout.session.completed`, generate license key, sign JWT, and insert record into D1 `licenses` table.
- **Acceptance Criteria:** Requests without valid Stripe signature return 400/401; completed checkouts successfully write to D1.

#### Task 0.3: Fix Dependency Confusion in `@secureship/cli` (`F-DIS-001`)

- **Target File:** [`packages/cli/package.json`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json)
- **Changes Required:**
  1. Remove lines 33–41 (`@secureship/ai`, `@secureship/core-engine`, etc.) from `"dependencies"`.
  2. Verify that `tsup.config.ts` bundles all workspace packages into `dist/index.js`.
- **Acceptance Criteria:** `npm pack --dry-run` in `packages/cli` shows zero private `@secureship/*` dependencies.

#### Task 0.4: Bundle WebAssembly Assets in Binary Releases (`F-REL-001`)

- **Target Files:** [`.github/workflows/release.yml`](file:///.github/workflows/release.yml), [`packages/reachability/src/manifest/wasm-manifest.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/manifest/wasm-manifest.ts)
- **Changes Required:**
  1. Update `release.yml` to package each binary along with `packages/reachability/wasm/` into `.tar.gz` and `.zip` archives.
  2. Add `path.join(path.dirname(process.execPath), 'wasm')` to `wasm-manifest.ts` search candidates.
- **Acceptance Criteria:** Standalone executable extracts and runs `secureship scan` in an empty directory without error.

#### Task 0.5: Synchronize Background License Renewal Protocol (`F-LIC-001`)

- **Target Files:**
  - [`packages/core-engine/src/license/tier-resolver.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/license/tier-resolver.ts)
  - [`packages/license-server/src/worker.ts`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts)
- **Changes Required:**
  1. Update `refreshLicenseInBackground` in `tier-resolver.ts` to execute HTTP `GET ${serverUrl}/v1/validate` with header `Authorization: Bearer ${existingJwt}`.
  2. Update response parsing to extract `data.refreshedJwt` and cryptographically verify the token before writing to `licensePath`.
  3. Ensure server returns proper HTTP 200 with refreshed JWT for valid near-expiry licenses.
- **Acceptance Criteria:** Integration test in `packages/core-engine/test/license/background-refresh.test.ts` asserts `GET /v1/validate` with Bearer token successfully saves `data.refreshedJwt`.

#### Task 0.6: Eliminate Wildcard CORS `*` on Fleet Server (`F-FLT-003`)

- **Target File:** [`packages/fleet/src/server/fleet-server.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts)
- **Changes Required:**
  1. Remove `res.setHeader('Access-Control-Allow-Origin', '*')`.
  2. If CORS is enabled, validate incoming `Origin` against a strict whitelist configured in `FleetServerOptions.allowedOrigins`.
  3. Reject unauthorized cross-origin requests by omitting CORS headers or returning 403.
- **Acceptance Criteria:** Browser cross-origin requests from arbitrary origins are blocked by CORS policy.

#### Task 0.7: Enforce Seat Limits on License Server (`F-LIC-002`)

- **Target File:** [`packages/license-server/src/worker.ts`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts)
- **Changes Required:**
  1. In `POST /v1/activate`, execute `SELECT COUNT(DISTINCT machine_fingerprint) as count FROM activations WHERE license_id = ?`.
  2. If `count >= record.seats` and the current `machineFingerprint` is not already active, reject activation with HTTP 403 (`Seat limit reached`).
  3. Implement `POST /v1/deactivate` to allow seat releases.
- **Acceptance Criteria:** Activation fails with 403 when requesting machine N+1 for an N-seat license.

#### Task 0.8: Bundle Curated Symbols & SAST Rules in Published CLI Package (`F-PKG-001`)

- **Target Files:**
  - [`packages/cli/package.json`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json)
  - [`packages/reachability/src/symbols/dataset-loader.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/symbols/dataset-loader.ts)
  - [`packages/scanner-adapters/src/adapters/opengrep.adapter.ts`](file:///c:/dev/SecureShip-IDE/packages/scanner-adapters/src/adapters/opengrep.adapter.ts)
- **Changes Required:**
  1. Add build script in `packages/cli` to copy `rules/` and `packages/reachability/data/` into `packages/cli/dist/assets/`.
  2. Add `dist/assets/` to `"files"` in `packages/cli/package.json`.
  3. Update `dataset-loader.ts` and `opengrep.adapter.ts` to locate assets relative to `fileURLToPath(import.meta.url)` first, eliminating reliance on `process.cwd()`.
- **Acceptance Criteria:** `npm pack` contains asset files; executing CLI from `/tmp/empty-dir` successfully locates rules and symbols.

---

### Wave 1: Safety & Architecture (Critical)

#### Task 1.1: Purge `FakeSandboxBackend` from Remediation Engine (`F-ENG-001`)

- **Target Files:**
  - [`packages/core-engine/src/remediation/verification-ladder.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts)
  - [`packages/core-engine/src/remediation/sca-verification-ladder.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/sca-verification-ladder.ts)
- **Changes Required:**
  1. Delete `FakeSandboxBackend` class.
  2. When `sandbox.backend === 'none'`, return `outcome: 'SKIPPED'` and cap final ladder verdict at `VERIFIED_STATIC`.
- **Acceptance Criteria:** Running verification without Docker returns `VERIFIED_STATIC` and never claims runtime test passes.

#### Task 1.2: Fix Monorepo Root Discovery in `DiffScope` (`F-GIT-001`)

- **Target File:** [`packages/core-engine/src/git/diff-scope.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/git/diff-scope.ts)
- **Changes Required:**
  1. Replace `path.join(targetDir, '.git')` with recursive directory traversal or `git rev-parse --show-toplevel`.
  2. Scope git diff results to `targetDir` via relative path prefixes.
- **Acceptance Criteria:** `secureship scan packages/core-engine --staged` executes successfully from within the monorepo.

#### Task 1.3: Secure Fleet Server Endpoints & Remove stdout Token Leak (`F-FLT-001`)

- **Target Files:**
  - [`packages/fleet/src/cli.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/cli.ts)
  - [`packages/fleet/src/server/fleet-server.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts)
- **Changes Required:**
  1. Remove `console.log(FLEET_TOKEN)` from `cli.ts`.
  2. Add bearer token check to `/api/fleet/repos`, `/api/fleet/summary`, `/api/fleet/sbom`, `/api/fleet/compliance/cra`, and `/api/policy`.
- **Acceptance Criteria:** Unauthenticated requests to `/api/fleet/repos` return 401 Unauthorized.

#### Task 1.4: Fix Windows Docker Desktop Path Translation in Sandbox (`F-SAN-001`)

- **Target File:** [`packages/sandbox/src/backends/container-backend.ts`](file:///c:/dev/SecureShip-IDE/packages/sandbox/src/backends/container-backend.ts)
- **Changes Required:**
  1. In `translateHostPath`, do not convert `C:\...` to `/c/...` on Windows; convert backslashes to forward slashes preserving drive letter (e.g. `C:/Users/...`).
  2. Ensure volume mounts format correctly for Docker Desktop CLI.
- **Acceptance Criteria:** Container sandbox runs without daemon syntax errors on Windows Docker Desktop.

#### Task 1.5: Atomic Write-and-Rename Persistence in FleetStore (`F-FLT-004`)

- **Target File:** [`packages/fleet/src/storage/fleet-store.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/storage/fleet-store.ts)
- **Changes Required:**
  1. In `persistToDisk()`, write first to a temporary file `${this.storageFile}.tmp.${Date.now()}`.
  2. Perform an atomic rename (`fs.renameSync`) to `this.storageFile`.
  3. Maintain a `.bak` backup file and add error logging when JSON parsing fails.
- **Acceptance Criteria:** Interrupted write simulations do not corrupt the primary database file or cause data wipe on restart.

---

### Wave 2: Integrity & Legal Hardening (High)

#### Task 2.1: Eliminate `child_process.exec` in License Command (`F-SEC-003`)

- **Target File:** [`packages/cli/src/commands/license.ts`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/license.ts)
- **Changes Required:** Replace `exec(cmd)` with `spawn(opener, [url], { shell: false })`.
- **Acceptance Criteria:** Zero calls to `exec` across `packages/cli/src`.

#### Task 2.2: Secure Temporary Files in VSCode Runner (`F-VSC-001`)

- **Target File:** [`packages/vscode-extension/src/cli/cli-runner.ts`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/cli/cli-runner.ts)
- **Changes Required:** Use `fs.mkdtempSync` inside a user-restricted directory with mode `0o700`.
- **Acceptance Criteria:** Temp directories created with permissions `0700`.

#### Task 2.3: Implement Real `RegistryProvider` Client (`F-SUP-001`)

- **Target File:** [`packages/core-engine/src/supply-chain/providers/registry.provider.ts`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts)
- **Changes Required:** Implement HTTP queries against NPM and PyPI with local LRU caching.
- **Acceptance Criteria:** Live metadata checks return package info when network is available.

#### Task 2.4: Update Rebranded Engine Notices (`F-LEG-001`)

- **Target File:** [`THIRD_PARTY_NOTICES.md`](file:///c:/dev/SecureShip-IDE/THIRD_PARTY_NOTICES.md)
- **Changes Required:** Embed complete license texts for Opengrep, Checkov, Trivy, Gitleaks, and OSV-Scanner directly in documentation and shipping distributions.
- **Acceptance Criteria:** No broken local file paths in `THIRD_PARTY_NOTICES.md`.

#### Task 2.5: Fix Test Integrity Violations in Reachability Suite (`F-TST-001`)

- **Target File:** [`packages/reachability/test/hostile-stress.test.ts`](file:///c:/dev/SecureShip-IDE/packages/reachability/test/hostile-stress.test.ts)
- **Changes Required:** Replace weak `toBeDefined()` checks with deep structural assertions; wrap wall-clock timing checks in deterministic fake timers.
- **Acceptance Criteria:** `node --experimental-strip-types scripts/verify-test-integrity.ts` exits with code 0.

---

### Wave 3: Polish & Hardening (Medium)

#### Task 3.1: Windows Path Normalization in Extension (`F-WIN-001`)

- **Target File:** [`packages/vscode-extension/src/extension.ts`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/extension.ts)
- **Changes Required:** Standardize on POSIX-style paths before comparing file URIs with scanner output.
- **Acceptance Criteria:** Diagnostics markers attach reliably on Windows workstations.
