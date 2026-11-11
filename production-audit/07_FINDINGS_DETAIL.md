# SecureShip-IDE Production-Readiness Audit

# 07. Findings Detail & Technical Proofs

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Total Active Findings:** 19 (8 P0, 5 P1, 5 P2, 1 P3)  
**Total Debunked Findings:** 3 (F-FLT-002, F-CICD-001, F-AI-001)  
**Auditor:** Autonomous Verification Engine

---

## 1. P0 (Blocker) Findings

### F-SEC-001: Unverified & Forged JWT Signing Oracle on License Server

- **Severity:** P0 (Blocker)
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-640 (Weak Password Recovery Mechanism for Forgotten Password / Oracle)
- **Affected File:** [`packages/license-server/src/worker.ts#L270-L327`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L270-L327)
- **Vulnerable Code Snippet:**

  ```typescript
  // packages/license-server/src/worker.ts:270-327
  // 3. GET /v1/validate (Background Refresh)
  if (url.pathname === '/v1/validate' && method === 'GET') {
    const authHeader = request.headers.get('Authorization') ?? '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    ...
    // Decode payload via unverified atob without checking RSA signature:
    let base64 = parts[1]!.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    const payload = JSON.parse(atob(base64)) as LicenseJwtPayload;
    ...
    // Extend by 30 days if near expiry (< 7 days) and re-sign with server private key:
    if (secondsRemaining < 7 * 86400 && env.JWT_PRIVATE_KEY) {
      const refreshedPayload: LicenseJwtPayload = {
        ...payload,
        iat: now,
        exp: now + 30 * 86400,
      };
      refreshedJwt = await signJwtWebCrypto(refreshedPayload, env.JWT_PRIVATE_KEY);
    }
  ```

- **Technical Vulnerability Analysis:**
  1. `parts[1]` is parsed using standard base64 decoding (`atob`) without calling WebCrypto `verify()` with `env.JWT_PUBLIC_KEY`.
  2. If the user presents any JWT with `exp` set to `now + 3600` (within 7 days), the server triggers the refresh branch: `signJwtWebCrypto(refreshedPayload, env.JWT_PRIVATE_KEY)`.
  3. This turns the endpoint into an arbitrary cryptographic signing oracle. An unauthenticated attacker can create a fake JWT with `tier: "enterprise"`, `seats: 100000`, send it to `/v1/validate`, and the server will return a cryptographically signed RS256 token signed by the company's private key.
  4. In addition, revoked licenses stored in Cloudflare D1 are never checked during validation.
- **Proof of Concept:**
  ```bash
  FAKE_PAYLOAD=$(echo -n '{"sub":"user@pirate.com","tier":"ENTERPRISE","seats":99999,"exp":'$(($(date +%s)+86400))'}' | base64 -w 0 | tr '/+' '_-' | tr -d '=')
  FAKE_TOKEN="eyJhbGciOiJSUzI1NiJ9.${FAKE_PAYLOAD}.invalidsig"
  curl -H "Authorization: Bearer $FAKE_TOKEN" https://license.secureship.dev/v1/validate
  # Returns HTTP 200 with { "valid": true, "refreshedJwt": "eyJhbGci...<VALID_CRYPTO_SIGNATURE>" }
  ```
- **Remediation:**
  1. Call `await verifyJwtWebCrypto(token, env.JWT_PUBLIC_KEY)` before inspecting payload claims.
  2. Query Cloudflare D1 database: `SELECT revoked_at FROM licenses WHERE id = ?`. If `revoked_at IS NOT NULL`, reject with 403.
  3. Only refresh tokens after confirming valid cryptographic signature AND active database record.

---

### F-SEC-002: Unverified & Stubbed Stripe Webhook Handler

- **Severity:** P0 (Blocker)
- **CWE:** CWE-353 (Missing Support for Integrity Check), CWE-287 (Improper Authentication)
- **Affected File:** [`packages/license-server/src/worker.ts#L338-L374`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L338-L374)
- **Vulnerable Code Snippet:**

  ```typescript
  // packages/license-server/src/worker.ts:338-374
  if (url.pathname === '/v1/webhook/stripe' && method === 'POST') {
    // In production: verify Stripe-Signature header with env.STRIPE_WEBHOOK_SECRET
    // For now, accept and acknowledge event
    const sig = request.headers.get('stripe-signature');
    ...
    if (type === 'checkout.session.completed') {
      // In production: provision license and record in D1
      return new Response(JSON.stringify({ received: true, action: 'license_created' }), {
        status: 200,
        headers,
      });
    }
    return new Response(JSON.stringify({ received: true }), { status: 200, headers });
  ```

- **Technical Vulnerability Analysis:**
  1. The code explicitly leaves `sig` unverified, commenting `"For now, accept and acknowledge event"`.
  2. Any external client can send HTTP POST requests with forged JSON payloads.
  3. The handler returns a stubbed JSON response without inserting or updating license records in Cloudflare D1. Payments through Stripe are completely decoupled from license generation, causing financial disruption, manual provisioning overhead, and lost revenue.
- **Remediation:**
  1. Read `env.STRIPE_WEBHOOK_SECRET`.
  2. Verify HMAC-SHA256 signature against raw request body using Stripe Webhooks or WebCrypto.
  3. On `checkout.session.completed`, generate cryptographic license record and insert into D1 table `licenses` in a transactional block.

---

### F-DIS-001: NPM Package Dependency Confusion & CLI Installation Implosion

- **Severity:** P0 (Blocker)
- **CWE:** CWE-427 (Uncontrolled Search Path Element / Dependency Confusion)
- **Affected Files:**
  - [`packages/cli/package.json#L33-L41`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json#L33-L41)
  - [`packages/cli/tsup.config.ts#L16-L26`](file:///c:/dev/SecureShip-IDE/packages/cli/tsup.config.ts#L16-L26)
  - [`.github/workflows/release.yml#L153-L160`](file:///.github/workflows/release.yml#L153-L160)
- **Vulnerable Code Snippet:**
  ```json
  // packages/cli/package.json:30-41
  "dependencies": {
    "@inquirer/prompts": "^8.7.4",
    "web-tree-sitter": "0.22.6",
    "@secureship/ai": "workspace:*",
    "@secureship/context-slicer": "workspace:*",
    "@secureship/contracts": "workspace:*",
    "@secureship/core-engine": "workspace:*",
    "@secureship/fleet": "workspace:*",
    "@secureship/patch-engine": "workspace:*",
    "@secureship/reachability": "workspace:*",
    "@secureship/sandbox": "workspace:*",
    "@secureship/scanner-adapters": "workspace:*",
    ...
  }
  ```
- **Technical Vulnerability Analysis:**
  1. `@secureship/cli` bundles internal packages into `dist/index.js` using `tsup` with `noExternal: ['@secureship/*']`.
  2. However, lines 33-41 list all 9 workspace packages as runtime `"dependencies"`.
  3. When `pnpm publish` runs in CI (`release.yml:153-160`), pnpm converts `workspace:*` to the current package version (e.g. `"^0.1.0"`).
  4. None of the internal packages (`@secureship/core-engine`, `@secureship/reachability`, etc.) are published to npmjs.org (all have `"private": true`).
  5. An end user executing `npm install -g @secureship/cli` will experience an installation crash with `E404 Not Found: @secureship/core-engine`.
  6. More critically: If an external attacker registers `@secureship/core-engine` or un-scoped package names on npmjs.org, NPM clients will pull and execute the attacker's package with full root/user privileges on developer workstations.
- **Remediation:**
  1. Remove all `@secureship/*` packages from `"dependencies"` in `packages/cli/package.json` since they are bundled into `dist/index.js` via `tsup`.
  2. Alternatively, claim the `@secureship` organization scope on npmjs.org and publish all workspace packages with cryptographic provenance.

---

### F-REL-001: Standalone Binaries Missing Bundled WASM Grammars

- **Severity:** P0 (Blocker)
- **CWE:** CWE-440 (Expected Behavior Violation), CWE-426 (Untrusted Search Path)
- **Affected Files:**
  - [`.github/workflows/release.yml#L79-L83`](file:///.github/workflows/release.yml#L79-L83)
  - [`packages/reachability/src/manifest/wasm-manifest.ts#L196-L204`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/manifest/wasm-manifest.ts#L196-L204)
- **Vulnerable Code Snippet:**
  ```yaml
  # .github/workflows/release.yml:78-83
  - name: Compile Standalone Executable
    shell: bash
    run: |
      mkdir -p release-dist
      bun build packages/cli/src/index.ts \
        --compile \
        --target bun-${{ matrix.target }} \
        --outfile release-dist/${{ matrix.binary_name }}
  ```
  ```typescript
  // packages/reachability/src/manifest/wasm-manifest.ts:196-204
  const candidates = candidatesOverride ?? [
    ...(envDir ? [envDir] : []),
    path.resolve(__dirname, 'wasm'),
    path.resolve(__dirname, '..', 'wasm'),
    path.resolve(__dirname, '..', 'dist', 'wasm'),
    path.resolve(__dirname, '..', '..', 'wasm'),
    path.resolve(__dirname, '..', '..', 'packages', 'reachability', 'wasm'),
    path.resolve(process.cwd(), 'packages', 'reachability', 'wasm'),
  ];
  ```
- **Technical Vulnerability Analysis:**
  1. `bun build --compile` compiles JavaScript/TypeScript into a standalone executable.
  2. However, `packages/reachability` reads `.wasm` files directly from the disk filesystem using `fs.existsSync` and `fs.readFileSync`.
  3. `release.yml` does not copy `packages/reachability/wasm/*.wasm` into `release-dist/`, nor does it package them into a `.tar.gz` or `.zip` release archive.
  4. When an end user downloads `secureship-linux-x64` or `secureship-win32-x64.exe` to `/usr/local/bin` or `C:\tools` and executes `secureship scan`, the binary discovers no WASM files in any candidate path and fails immediately with `WASM directory not found`.
- **Remediation:**
  1. Package binary releases as archives (`secureship-<os>-<arch>.tar.gz` / `.zip`) containing the binary and a `wasm/` directory alongside it.
  2. Update `wasm-manifest.ts` to inspect `path.dirname(process.execPath)` for the `wasm/` directory.

---

### F-LIC-001: Fatal Client-Server Protocol Incompatibility in Background Renewal

- **Severity:** P0 (Blocker)
- **CWE:** CWE-436 (Interpretation Conflict), CWE-398 (Indicator of Poor Code Quality)
- **Affected Files:**
  - [`packages/core-engine/src/license/tier-resolver.ts#L178-L190`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/license/tier-resolver.ts#L178-L190)
  - [`packages/license-server/src/worker.ts#L270-L325`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L270-L325)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/core-engine/src/license/tier-resolver.ts:178-190
  const res = await fetch(`${serverUrl}/v1/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sub }),
    signal: controller.signal,
  });
  if (res.ok) {
    const data = (await res.json()) as { jwt?: string };
    if (data.jwt) {
      writeLicenseFile(data.jwt, licensePath);
    }
  }
  ```
  ```typescript
  // packages/license-server/src/worker.ts:270-274, 323
  if (url.pathname === '/v1/validate' && method === 'GET') {
    const authHeader = request.headers.get('Authorization') ?? '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    ...
    return new Response(JSON.stringify({ valid: true, tier: payload.tier, refreshedJwt }), ...);
  ```
- **Technical Vulnerability Analysis:**
  1. `tier-resolver.ts` attempts to refresh expiring licenses by sending an HTTP `POST` request with JSON body `{ sub }` to `/v1/validate`. It expects response field `data.jwt`.
  2. `license-server` only listens for HTTP `GET /v1/validate` (line 271) and extracts the license token strictly from the `Authorization: Bearer <token>` header (line 272-273).
  3. When `refreshLicenseInBackground` executes in production, the server returns 404 (or 401).
  4. Even if the method matched, the server returns `{ refreshedJwt: "..." }`, while the client checks `data.jwt`.
  5. The client wraps the call in an empty `catch {}` block ("Fire-and-forget: errors are non-fatal"). As a result, the failure is completely silent.
  6. Every paying customer's license will expire when its original TTL ends, locking enterprise users out of CI gates and IDE scans without auto-renewal.
- **Remediation:**
  1. Synchronize protocol: change client call in `tier-resolver.ts` to `GET ${serverUrl}/v1/validate` with `headers: { Authorization: `Bearer ${existingJwt}` }`.
  2. In `tier-resolver.ts`, parse `data.refreshedJwt` instead of `data.jwt`.
  3. Verify cryptographic signature of refreshed JWT before saving to disk.

---

### F-FLT-003: Wildcard CORS `*` on Fleet Server Exposes Telemetry and Policy Tampering

- **Severity:** P0 (Blocker)
- **CWE:** CWE-346 (Origin Validation Error / Permissive CORS), CWE-284 (Improper Access Control)
- **Affected File:** [`packages/fleet/src/server/fleet-server.ts#L81-L85,L174-L190`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts#L81-L85)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/fleet/src/server/fleet-server.ts:81-85
  // CORS headers for corporate API integration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  ```
- **Technical Vulnerability Analysis:**
  1. `FleetServer` sets `Access-Control-Allow-Origin: *` unconditionally on every incoming HTTP response.
  2. As established in `F-FLT-001`, endpoints `/api/fleet/repos`, `/api/fleet/summary`, `/api/fleet/sbom`, and `POST /api/policy` lack any session or bearer authentication.
  3. Any developer, security engineer, or CISO running `secureship fleet start` locally on `http://127.0.0.1:4000` who visits a third-party webpage can have their browser silently execute cross-origin `fetch('http://127.0.0.1:4000/api/fleet/repos')`.
  4. The attacker's webpage can read all proprietary codebase vulnerabilities, SBOM component inventories, and CRA compliance data.
  5. Worse, the attacker's script can issue `fetch('http://127.0.0.1:4000/api/policy', { method: 'POST', body: JSON.stringify({ failOnSeverity: 'NONE', blockUnreachableSca: false }) })`, silently neutralizing central security enforcement across the enterprise fleet.
- **Remediation:**
  1. Remove wildcard `Access-Control-Allow-Origin: *`. Restrict CORS to explicit allowed origins configured in fleet settings, or reject cross-origin requests by default.
  2. Implement strict Bearer token authentication on all administrative and telemetry routes.

---

### F-LIC-002: Zero Seat Limit Enforcement on License Server / Infinite Activations

- **Severity:** P0 (Blocker)
- **CWE:** CWE-799 (Improper Control of Generation of Multiple Requests / Lack of Seat Enforcement)
- **Affected File:** [`packages/license-server/src/worker.ts#L180-L248`](file:///c:/dev/SecureShip-IDE/packages/license-server/src/worker.ts#L180-L248)
- **Vulnerable Code Snippet:**

  ```typescript
  // packages/license-server/src/worker.ts:180-248
  // Read license record:
  record = row ?? null;
  ...
  // Signs JWT containing record.seats:
  const payload: LicenseJwtPayload = {
    sub: record.email ?? 'user@company.com',
    tier: record.tier,
    seats: record.seats,
    ...
  };
  const jwt = await signJwtWebCrypto(payload, privateKey);

  // Inserts into activations without any seat limit check:
  if (env.DB) {
    try {
      await env.DB.prepare(
        `INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(crypto.randomUUID(), record.id, machineFingerprint ?? 'unknown', now, now).run();
    } catch {
      // Activation logging is non-blocking
    }
  }
  ```

- **Technical Vulnerability Analysis:**
  1. In `POST /v1/activate`, the license server reads `record.seats`, but never counts the number of existing activations associated with `record.id`.
  2. There is no `SELECT COUNT(DISTINCT machine_fingerprint) FROM activations WHERE license_id = ?` query.
  3. The server immediately mints and returns an RS256 cryptographically signed JWT.
  4. A customer purchasing a single 1-seat license (`seats = 1`) can distribute the activation code to 10,000 corporate machines or post it publicly; every single activation succeeds and returns a valid signed JWT.
  5. Commercial seat limits and enterprise monetization are completely unenforced.
- **Remediation:**
  1. In `packages/license-server/src/worker.ts`, execute a count query against `activations` table before signing.
  2. If unique active machines >= `record.seats`, return HTTP 403 (`Seat limit exceeded for this license`).
  3. Provide a `/v1/deactivate` endpoint allowing users to release seats when decommissioning workstations.

---

### F-PKG-001: Curated Symbol Dataset & SAST Rules Missing From Shipped Artifacts

- **Severity:** P0 (Blocker)
- **CWE:** CWE-427 (Uncontrolled Search Path Element)
- **Affected Files:**
  - [`packages/reachability/src/symbols/dataset-loader.ts#L28-L47`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/symbols/dataset-loader.ts#L28-L47)
  - [`packages/scanner-adapters/src/adapters/opengrep.adapter.ts#L174-L178`](file:///c:/dev/SecureShip-IDE/packages/scanner-adapters/src/adapters/opengrep.adapter.ts#L174-L178)
  - [`packages/cli/package.json#L16-L20`](file:///c:/dev/SecureShip-IDE/packages/cli/package.json#L16-L20)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/reachability/src/symbols/dataset-loader.ts:28-47
  public static getBundledDataDirectory(): string {
    const candidates = [
      path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../data'),
      path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../data'),
      path.resolve(process.cwd(), 'packages/reachability/data'),
      path.resolve(process.cwd(), 'data'),
    ];
  ...
  // packages/scanner-adapters/src/adapters/opengrep.adapter.ts:176
  this.config.defaultRulePath ?? path.resolve(process.cwd(), 'rules/secureship-sast');
  ```
  ```json
  // packages/cli/package.json:16-20
  "files": [
    "dist/",
    "README.md",
    "LICENSE"
  ]
  ```
- **Technical Vulnerability Analysis:**
  1. `SymbolDatasetLoader` and `OpengrepAdapter` both rely on `process.cwd()` or hardcoded monorepo directory structures (`../../data`, `rules/secureship-sast`).
  2. In `packages/cli/package.json`, only `dist/`, `README.md`, and `LICENSE` are declared in `"files"`. The `rules/secureship-sast/` directory and `packages/reachability/data/` are never included in the npm package tarball.
  3. When an end user installs `@secureship/cli` globally via npm (`npm i -g @secureship/cli`) and runs `secureship scan` inside their own project (e.g. `/home/user/backend`), `process.cwd()` resolves to `/home/user/backend`.
  4. Neither `rules/secureship-sast` nor `data/vulnerable-symbols.json` exist in `/home/user/backend`.
  5. The reachability engine fails to load the curated symbol database, and Opengrep fails to find custom SAST rules, rendering the core differentiation of SecureShip completely non-functional for all global users.
- **Remediation:**
  1. Copy `rules/secureship-sast` and `packages/reachability/data` into `packages/cli/dist/assets/` during the build step.
  2. Update `packages/cli/package.json` to include these asset directories in `"files"`.
  3. Resolve asset paths strictly relative to `fileURLToPath(import.meta.url)` rather than `process.cwd()`.

---

## 2. P1 (Critical) Findings

### F-ENG-001: Fake Remediation Backend (`FakeSandboxBackend`) in Production Engine

- **Severity:** P1 (Critical)
- **CWE:** CWE-393 (Return of Wrong Status Code), CWE-1025 (Comparison Using Wrong Factors)
- **Affected Files:**
  - [`packages/core-engine/src/remediation/verification-ladder.ts#L608-L610`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/verification-ladder.ts#L608-L610)
  - [`packages/core-engine/src/remediation/sca-verification-ladder.ts#L481`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/remediation/sca-verification-ladder.ts#L481)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/core-engine/src/remediation/verification-ladder.ts:608-610
  if (backendType === 'none') {
    return new FakeSandboxBackend();
  }
  ```
- **Technical Vulnerability Analysis:**
  1. `FakeSandboxBackend` unconditionally returns exit code 0 and logs `"fake execution passed"`.
  2. If a developer runs `secureship fix verify` in an environment where Docker is unavailable and `sandbox.backend` is set to `'none'`, the verification ladder treats all test stages as passed.
  3. The engine assigns verdict `VERIFIED_RUNTIME`.
  4. Broken patches that introduce compilation errors or test failures will be certified as safe, causing production outages.
- **Remediation:**
  1. When `sandbox.backend === 'none'`, dynamic stages must return `SKIPPED` or `INCONCLUSIVE`, and the highest achievable verdict must be capped at `VERIFIED_STATIC`.
  2. Remove `FakeSandboxBackend` from production bundles and restrict it strictly to test mock suites.

---

### F-GIT-001: Fatal Crash on Subdirectory Monorepo Incremental Git Diff Scans

- **Severity:** P1 (Critical)
- **CWE:** CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Affected File:** [`packages/core-engine/src/git/diff-scope.ts#L68-L73`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/git/diff-scope.ts#L68-L73)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/core-engine/src/git/diff-scope.ts:68-73
  const gitDir = path.join(targetDir, '.git');
  if (!fs.existsSync(gitDir)) {
    throw new Error(`Directory '${targetDir}' is not a git repository`);
  }
  ```
- **Live Reproduction Command:**
  ```powershell
  node packages/cli/dist/index.js scan packages/core-engine --staged
  ```
- **Execution Output:**
  ```
  Error: Directory 'c:\dev\SecureShip-IDE\packages\core-engine' is not a git repository
      at Function.resolveDiffFiles (c:\dev\SecureShip-IDE\packages\core-engine\dist\index.js:...)
  ```
- **Technical Vulnerability Analysis:**
  1. Monorepo developers frequently scan a single package or subdirectory (e.g. `secureship scan packages/core-engine --staged`).
  2. `DiffScope` checks for `.git` strictly inside `targetDir`. In monorepos, `.git` resides at the workspace root, not inside sub-packages.
  3. The scan immediately crashes with an unhandled exception, breaking IDE integrations and pre-commit hooks.
- **Remediation:**
  Use `git rev-parse --show-toplevel` or recursively walk parent directories to locate the repository root. Filter diff paths using `path.relative(gitRoot, targetDir)`.

---

### F-FLT-001: Fleet Server Token Leak to stdout & Unauthenticated Control Endpoints

- **Severity:** P1 (Critical)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File), CWE-306 (Missing Authentication for Critical Function)
- **Affected Files:**
  - [`packages/fleet/src/cli.ts#L22-L24`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/cli.ts#L22-L24)
  - [`packages/fleet/src/server/fleet-server.ts#L138-L190`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/server/fleet-server.ts#L138-L190)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/fleet/src/cli.ts:22-24
  console.log(`Fleet server started on http://${options.host}:${options.port}`);
  console.log(`FLEET_TOKEN: ${server.token}`);
  ```
- **Technical Vulnerability Analysis:**
  1. The server prints its shared secret `FLEET_TOKEN` directly to stdout upon startup, exposing it to log aggregators, shared terminal sessions, and CI logs.
  2. None of the Fleet HTTP API endpoints validate `Authorization: Bearer <token>`.
  3. Any network actor able to connect to the fleet port can dump company-wide security findings (`/api/fleet/repos`) and inject modified policies (`POST /api/policy`) to silence critical alerts across all development teams.
- **Remediation:**
  1. Remove `console.log(FLEET_TOKEN)` from `cli.ts`.
  2. Implement an authentication middleware verifying `Authorization: Bearer <FLEET_TOKEN>` on all `/api/*` endpoints.

---

### F-SAN-001: Windows Container Mount Path `/c/...` Translation Rejection by Docker Desktop

- **Severity:** P1 (Critical)
- **CWE:** CWE-436 (Interpretation Conflict), CWE-706 (Use of Incorrectly-Resolved Name or Reference)
- **Affected File:** [`packages/sandbox/src/backends/container-backend.ts#L39-L50,L153`](file:///c:/dev/SecureShip-IDE/packages/sandbox/src/backends/container-backend.ts#L39-L50)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/sandbox/src/backends/container-backend.ts:39-50, 153
  public static translateHostPath(hostPath: string): string {
    const normalized = hostPath.replace(/\\/g, '/');
    if (/^[a-zA-Z]:\//.test(normalized)) {
      const drive = normalized[0]?.toLowerCase();
      const rest = normalized.substring(2);
      return `/${drive}${rest}`;
    }
    return normalized;
  }
  ...
  `-v=${translatedShadow}:/work:rw`,
  ```
- **Technical Vulnerability Analysis:**
  1. On Windows, `translateHostPath` converts `C:\Users\username\temp\secureship-shadow` into `/c/Users/username/temp/secureship-shadow`.
  2. This path is passed directly to the Docker CLI as `-v=/c/Users/...:/work:rw`.
  3. Docker Desktop on Windows expects standard Windows path format (`C:\Users\...` or `C:/Users/...`) when running against standard Windows command runners.
  4. Docker daemon interprets `/c/Users/...` as a relative path or an illegal volume name containing slashes, terminating with: `docker: Error response from daemon: create \c\Users\...: "\\c\\Users\\..." includes invalid characters for a local volume name`.
  5. The container sandbox fails immediately on Windows, causing `ContainerBackend` to abort verification.
- **Remediation:**
  On Windows (`process.platform === 'win32'`), preserve drive letter format with forward slashes (e.g. `C:/Users/...`), which Docker Desktop for Windows natively understands without syntax rejection.

---

### F-FLT-004: Unsynchronized Non-Atomic `fs.writeFileSync` in FleetStore Data Loss

- **Severity:** P1 (Critical)
- **CWE:** CWE-362 (Race Condition / TOCTOU), CWE-390 (Detection of Error Condition Without Action)
- **Affected File:** [`packages/fleet/src/storage/fleet-store.ts#L60-L76`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/storage/fleet-store.ts#L60-L76)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/fleet/src/storage/fleet-store.ts:60-76
  private persistToDisk(): void {
    if (!this.storageFile) return;
    try {
      const dir = path.dirname(this.storageFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = {
        repos: Array.from(this.repos.values()),
        policy: this.policy,
        updatedAt: new Date().toISOString(),
      };
      fs.writeFileSync(this.storageFile, JSON.stringify(data, null, 2), 'utf8');
    } catch {
      // Ignore disk persistence failure
    }
  }
  ```
- **Technical Vulnerability Analysis:**
  1. `persistToDisk()` directly overwrites `this.storageFile` in place using synchronous `fs.writeFileSync`.
  2. If the Node process is terminated, crashes, or loses power while `fs.writeFileSync` is mid-write, the storage file is left half-written and truncated.
  3. On subsequent server startup, `loadFromDisk()` attempts `JSON.parse(raw)`. Because the file is truncated, `JSON.parse` throws an exception, which is caught and silently ignored (`catch { // Ignore initial file parse failure }`).
  4. The server initializes with an empty `Map`, permanently wiping all historical fleet repository data, scan statistics, and custom policies.
  5. Furthermore, concurrent ingest requests in an asynchronous HTTP server trigger un-mutexed overlapping synchronous disk writes, blocking the event loop and risking filesystem contention.
- **Remediation:**
  1. Write to a temporary file in the same directory (`${this.storageFile}.tmp.${Date.now()}`) and perform an atomic rename (`fs.renameSync`).
  2. Implement an in-memory persistence queue or async mutex to serialize write operations.
  3. Maintain a `.bak` backup file before overwriting to ensure resilience against unexpected crashes.

---

## 3. P2 (High) Findings

### F-SEC-003: Prohibited Shell Invocations (`child_process.exec`) in License Command

- **Severity:** P2 (High)
- **CWE:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- **Affected File:** [`packages/cli/src/commands/license.ts#L169-L178`](file:///c:/dev/SecureShip-IDE/packages/cli/src/commands/license.ts#L169-L178)
- **Vulnerable Code Snippet:**

  ```typescript
  // packages/cli/src/commands/license.ts:169-178
  import { exec } from 'node:child_process';
  ...
  const cmd =
    process.platform === 'win32'
      ? `start "" "${checkoutUrl}"`
      : process.platform === 'darwin'
        ? `open "${checkoutUrl}"`
        : `xdg-open "${checkoutUrl}"`;

  exec(cmd, (err) => {
    if (err) {
      console.log(`Please visit: ${checkoutUrl}`);
    }
  });
  ```

- **Technical Analysis:**
  Directly violates the architectural rule requiring `shell: false`. On Windows, `start "" "${checkoutUrl}"` invoked via `cmd.exe` is vulnerable to command injection if `checkoutUrl` contains unescaped ampersands (`&`) or quotes.
- **Remediation:**
  Replace `exec` with `spawnSafe` or `spawn(binary, [url], { shell: false })`.

---

### F-VSC-001: Insecure Temp File Permissions in VSCode Extension Runner

- **Severity:** P2 (High)
- **CWE:** CWE-377 (Insecure Temporary File), CWE-732 (Incorrect Permission Assignment)
- **Affected File:** [`packages/vscode-extension/src/cli/cli-runner.ts#L46-L49`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/cli/cli-runner.ts#L46-L49)
- **Vulnerable Code Snippet:**
  ```typescript
  // packages/vscode-extension/src/cli/cli-runner.ts:46-49
  const tmpFile = path.join(
    os.tmpdir(),
    `secureship-scan-${Date.now()}-${Math.random().toString(36).slice(2, 9)}.json`
  );
  ```
- **Technical Analysis:**
  Uses `Math.random()` and writes to the shared system temp directory with default world-readable permissions. On shared multi-user developer workstations (e.g., Linux jump boxes, dev servers), other local users can monitor `/tmp` and read vulnerability findings or exploit symlink races.
- **Remediation:**
  Use `fs.mkdtempSync` under a secure subdirectory with permissions mode `0o700`.

---

### F-SUP-001: Completely Stubbed Registry Supply-Chain Risk Provider

- **Severity:** P2 (High)
- **CWE:** CWE-547 (Use of Hard-coded, Security-relevant Constants)
- **Affected File:** [`packages/core-engine/src/supply-chain/providers/registry.provider.ts#L10-L75`](file:///c:/dev/SecureShip-IDE/packages/core-engine/src/supply-chain/providers/registry.provider.ts#L10-L75)
- **Technical Analysis:**
  All four methods (`getPackageMetadata`, `getReleaseProvenance`, `getDeprecationStatus`, `checkAdvisories`) unconditionally return `{ ok: false, error: { code: 'UNAVAILABLE' } }`. No network requests are made to NPM or PyPI registries.
- **Remediation:**
  Implement real registry HTTP queries with caching and offline fallback modes.

---

### F-LEG-001: Rebranded Third-Party Scanner Rule IDs Missing Upstream Notices

- **Severity:** P2 (High)
- **CWE:** CWE-1025 (Legal & Licensing Non-Compliance)
- **Affected Files:**
  - [`packages/contracts/src/engine-brand.ts#L13-L115`](file:///c:/dev/SecureShip-IDE/packages/contracts/src/engine-brand.ts#L13-L115)
  - [`THIRD_PARTY_NOTICES.md#L145-L165`](file:///c:/dev/SecureShip-IDE/THIRD_PARTY_NOTICES.md#L145-L165)
- **Technical Analysis:**
  SecureShip white-labels upstream third-party scanners (Opengrep [LGPL-2.1], Checkov [Apache-2.0], Trivy [Apache-2.0], Gitleaks [MIT], OSV-Scanner [Apache-2.0]) as proprietary engines (`SS-SAST-`, `SS-SCA-`, `SS-IAC-`). While `THIRD_PARTY_NOTICES.md` lists them in Section 5, it cites container paths (`/licenses/opengrep/LICENSE`) that do not exist in the NPM or standalone binary distributions.
- **Remediation:**
  Embed full copyright notices and upstream license texts in CLI distributions and ensure LGPL-2.1 dynamic execution boundaries are strictly documented.

---

### F-TST-001: Anti-Fake-Test Law Integrity Violations in Reachability Suite

- **Severity:** P2 (High)
- **CWE:** CWE-1076 (Insufficient Adherence to Coding Standards)
- **Affected File:** [`packages/reachability/test/hostile-stress.test.ts#L12,L47,L70,L136`](file:///c:/dev/SecureShip-IDE/packages/reachability/test/hostile-stress.test.ts#L12)
- **Command Output Proof:**
  ```
  [UNFAKED-TIMER] packages\reachability\test\hostile-stress.test.ts:12:3 (Hostile 1 asserts on real clock elapsed time)
  [WEAK-ONLY]     packages\reachability\test\hostile-stress.test.ts:47:3 (Hostile 2 contains only toBeDefined())
  [WEAK-ONLY]     packages\reachability\test\hostile-stress.test.ts:70:3 (Hostile 3 contains only toBeDefined())
  [UNFAKED-TIMER] packages\reachability\test\hostile-stress.test.ts:136:3 (Hostile 7 asserts on real clock elapsed time)
  ```
- **Remediation:**
  Replace weak `toBeDefined()` checks with hard semantic assertions on AST structure, and wrap elapsed time tests in deterministic performance counters or fake timers.

---

## 4. P3 (Medium) Findings

### F-WIN-001: Windows Path Normalization Inconsistencies in VSCode Runner

- **Severity:** P3 (Medium)
- **CWE:** CWE-178 (Improper Handling of Case Sensitivity and Path Separators)
- **Affected File:** [`packages/vscode-extension/src/extension.ts#L80-L95`](file:///c:/dev/SecureShip-IDE/packages/vscode-extension/src/extension.ts#L80-L95)
- **Technical Analysis:**
  Inconsistent mixing of backslashes and forward slashes between VSCode Document URIs (`file:///c:/...`) and CLI output paths causes diagnostic markers to intermittently fail to attach to open editor tabs on Windows workstations.
- **Remediation:**
  Normalize all internal paths using `path.normalize()` or POSIX forward slashes before comparing strings across extension listeners.

---

## 5. Debunked / Removed Findings (Skeptical Review Proofs)

The following 3 items were claimed as findings in initial automated or ungrounded reviews, but were systematically debunked upon empirical code inspection and testing:

### Debunked 1: `F-FLT-002` (Lack of Connection Pooling in Fleet SQLite Backend)

- **Claimed Severity:** P3
- **Claimed Location:** `packages/fleet/src/server/storage.ts#L20-L45`
- **Why Debunked:**
  1. The file `packages/fleet/src/server/storage.ts` does not exist anywhere in the repository.
  2. Fleet does not use SQLite. Fleet is implemented using an in-memory `Map<string, FleetRepoSummary>` backed by JSON file serialization in [`packages/fleet/src/storage/fleet-store.ts`](file:///c:/dev/SecureShip-IDE/packages/fleet/src/storage/fleet-store.ts).
  3. The SQLite connection pooling and WAL mode finding was an ungrounded hallucination. It has been removed and superseded by the real finding `F-FLT-004` (non-atomic JSON file persistence).

### Debunked 2: `F-CICD-001` (Fragile 15-Second Download Timeout in CI Tool Pin Verifier)

- **Claimed Severity:** P2
- **Claimed Location:** `scripts/verify-tool-pins.ts#L44`
- **Why Debunked:**
  1. `scripts/verify-tool-pins.ts` is an internal maintenance script executed during developer verification or scheduled upstream audits. It is not part of the runtime CLI, engine, or release artifacts.
  2. Line 44 (`fetch(manifestUrl, { signal: AbortSignal.timeout(15000) })`) fetches small text manifest files (SHA256 checksum files < 5KB), not full tool binaries. A 15-second timeout on a 5KB manifest is standard and sufficient.
  3. Inflating a 15-second timeout on a 5KB text fetch in a dev script to a P2 security finding violated Anti-Fabrication Rule 7 ("No padding, no inflation"). It has been removed.

### Debunked 3: `F-AI-001` (Hardcoded AI Client Max Concurrency Bottleneck)

- **Claimed Severity:** P3
- **Claimed Location:** `packages/ai/src/providers/http-client.ts#L20-L21`
- **Why Debunked:**
  1. `HttpClient.maxConcurrency` is initialized to 2 as a defensive baseline to protect local Ollama servers and avoid rate-limiting on commercial LLM APIs.
  2. Lines 28-32 explicitly export `HttpClient.setMaxConcurrency(max: number)`:
     ```typescript
     public static setMaxConcurrency(max: number): void {
       if (max > 0) HttpClient.maxConcurrency = max;
     }
     ```
  3. The claim that concurrency is "hardcoded and unmodifiable" is factually false. It has been removed.
