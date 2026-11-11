# SecureShip-IDE Production-Readiness Audit

# 08. Fake and Dummy Code Register

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Total Fake / Dummy / False-Coded Entries:** 8  
**Auditor:** Autonomous Verification Engine

---

## 1. Registry of Fake, Dummy, and Stubbed Code

The following register documents every instance of simulated, stubbed, fabricated, or false-coded logic identified in non-test production pathways across the repository.

| Entry ID  |   Classification    | Subsystem               | Location                                                                                                                                                                                     | Description & Verified Behavior                                                                                                                           |   Risk Level    |
| :-------: | :-----------------: | :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------: |
| **FD-01** |      **FAKE**       | Core Remediation Engine | [`packages/core-engine/src/remediation/verification-ladder.ts#L608-L610`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts#L608-L610)               | `FakeSandboxBackend` returns hardcoded exit code 0 (`"fake execution passed"`), falsely certifying unverified patches as `VERIFIED_RUNTIME`.              | 🔴 **CRITICAL** |
| **FD-02** |      **FAKE**       | Core SCA Remediation    | [`packages/core-engine/src/remediation/sca-verification-ladder.ts#L481`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/sca-verification-ladder.ts#L481)                 | Fallback sandbox instantiation for SCA patches also uses `FakeSandboxBackend` when backend is `'none'`.                                                   | 🔴 **CRITICAL** |
| **FD-03** |     **STUBBED**     | License Server          | [`packages/license-server/src/worker.ts#L338-L374`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L338-L374)                                                           | Stripe webhook endpoint acknowledges requests with `{ received: true, action: 'license_created' }` without checking signatures or writing to D1 database. | 🔴 **CRITICAL** |
| **FD-04** |     **STUBBED**     | Supply Chain Engine     | [`packages/core-engine/src/supply-chain/providers/registry.provider.ts#L10-L75`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts#L10-L75) | `RegistryProvider` contains four stub methods that return static `{ ok: false, error: { code: 'UNAVAILABLE' } }` without initiating network calls.        |   🟡 **HIGH**   |
| **FD-05** | **INSECURE BYPASS** | License Server          | [`packages/license-server/src/worker.ts#L270-L327`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L270-L327)                                                           | `GET /v1/validate` decodes JWT via unverified `atob()` and re-signs expired/near-expiry claims, bypassing cryptographic verification.                     | 🔴 **CRITICAL** |
| **FD-06** |   **DUMMY CHECK**   | License Server          | [`packages/license-server/src/worker.ts#L180-L248`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L180-L248)                                                           | `POST /v1/activate` claims seat enforcement, but performs zero query against active machines in `activations`, minting unlimited valid JWTs.              | 🔴 **CRITICAL** |
| **FD-07** |   **FALSE LOGIC**   | Client License Resolver | [`packages/core-engine/src/license/tier-resolver.ts#L178-L190`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/license/tier-resolver.ts#L178-L190)                                   | `refreshLicenseInBackground` sends incompatible POST with `{ sub }` and swallows 404/network errors, creating a false illusion of auto-renewal.           | 🔴 **CRITICAL** |
| **FD-08** | **FAIL-OPEN STORE** | Fleet Storage           | [`packages/fleet/src/storage/fleet-store.ts#L40-L76`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/storage/fleet-store.ts#L40-L76)                                                       | Synchronous non-atomic overwrite corrupts on abort; `loadFromDisk` silently catches JSON parse failures and resets database to empty, losing all data.    |   🟡 **HIGH**   |

---

## 2. In-Depth Technical Analysis of Entries

### 2.1 FD-01 & FD-02: `FakeSandboxBackend`

- **Location:** `packages/core-engine/src/remediation/verification-ladder.ts:608-610`
- **Source Code Evidence:**
  ```typescript
  if (backendType === 'none') {
    return new FakeSandboxBackend();
  }
  ```
- **Operational Reality:**
  `FakeSandboxBackend` implements the `SandboxBackend` interface. When `runStage` is called:
  ```typescript
  async runStage(stage: VerificationStage): Promise<StageResult> {
    return {
      id: stage.id,
      outcome: 'PASS',
      exitCode: 0,
      outputTail: 'fake execution passed',
      durationMs: 5,
    };
  }
  ```
  This creates an illusion of security: a user who has not configured Docker or Host execution receives a clean report stating their patch passed dynamic regression testing.

### 2.2 FD-03: Stubbed Stripe Webhook

- **Location:** `packages/license-server/src/worker.ts:338-374`
- **Source Code Evidence:**
  ```typescript
  // In production: verify Stripe-Signature header with env.STRIPE_WEBHOOK_SECRET
  // For now, accept and acknowledge event
  ...
  if (type === 'checkout.session.completed') {
    // In production: provision license and record in D1
    return new Response(JSON.stringify({ received: true, action: 'license_created' }), { status: 200, headers });
  }
  ```
- **Operational Reality:**
  This code is a non-functional mock. Real users purchasing licenses through Stripe will never have their license keys created in the database.

### 2.3 FD-04: Stubbed `RegistryProvider`

- **Location:** `packages/core-engine/src/supply-chain/providers/registry.provider.ts:10-75`
- **Source Code Evidence:**
  All four methods (`getPackageMetadata`, `getReleaseProvenance`, `getDeprecationStatus`, `checkAdvisories`) unconditionally return `{ ok: false, error: { code: 'UNAVAILABLE', message: 'Registry provider unavailable' } }`.
- **Operational Reality:**
  Any feature relying on live package registry queries receives zero live data.

### 2.4 FD-05: Insecure JWT Signing Oracle

- **Location:** `packages/license-server/src/worker.ts:270-327`
- **Source Code Evidence:**
  Decodes incoming JWT via unverified `atob()` without validating against `env.JWT_PUBLIC_KEY`, and re-signs claims with `env.JWT_PRIVATE_KEY` if within 7 days of expiration.
- **Operational Reality:**
  Acts as an open signing oracle for forged enterprise tokens.

### 2.5 FD-06: Omitted Seat Limit Check on License Activations

- **Location:** `packages/license-server/src/worker.ts:180-248`
- **Source Code Evidence:**
  Reads `record.seats`, but logs activations via `INSERT INTO activations ...` without ever performing `SELECT COUNT(DISTINCT machine_fingerprint) FROM activations WHERE license_id = ?`.
- **Operational Reality:**
  A single 1-seat license can be activated thousands of times with valid RS256 signatures, completely subverting monetization controls.

### 2.6 FD-07: Broken False-Coded Background Renewal

- **Location:** `packages/core-engine/src/license/tier-resolver.ts:178-190`
- **Source Code Evidence:**
  Sends `POST /v1/validate` with `{ sub }` body expecting `data.jwt`. The server handles `GET /v1/validate` with `Authorization: Bearer <token>` and returns `refreshedJwt`. The client swallows all errors via `catch {}`.
- **Operational Reality:**
  The auto-renewal logic is completely non-functional. Customer licenses silently expire without renewal.

### 2.7 FD-08: Corruptible Non-Atomic Storage with Fail-Open Erasure

- **Location:** `packages/fleet/src/storage/fleet-store.ts:40-76`
- **Source Code Evidence:**
  `persistToDisk` synchronously overwrites `storageFile`. If interrupted, `loadFromDisk` encounters an invalid JSON syntax error, catches it, ignores it, and initializes with an empty database.
- **Operational Reality:**
  Any unexpected crash or process restart mid-write permanently wipes corporate fleet telemetry and policies.

---

## 3. Remediation Directives

1. **Purge Fake Sandbox:** Delete `FakeSandboxBackend` from `verification-ladder.ts`. If `backend === 'none'`, the engine must report `outcome: 'SKIPPED'` and cap the final ladder verdict at `VERIFIED_STATIC`.
2. **Implement Real Stripe Webhook:** Integrate Stripe SDK or WebCrypto HMAC validation and persist license rows into D1 table `licenses`.
3. **Complete Registry Provider:** Implement HTTP clients for `registry.npmjs.org` and `pypi.org/pypi` with local cache support.
4. **Enforce Seat Limits:** Add pre-issuance count query against D1 activations table in `POST /v1/activate`.
5. **Harmonize Renewal Protocol:** Align `tier-resolver.ts` to `GET /v1/validate` with `Authorization: Bearer <token>` and parse `data.refreshedJwt`.
6. **Atomic Persistence:** Write fleet database to a temporary file and atomically rename (`fs.renameSync`).
