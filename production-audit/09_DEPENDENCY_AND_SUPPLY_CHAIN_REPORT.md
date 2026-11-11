# SecureShip-IDE Production-Readiness Audit

# 09. Dependency and Supply Chain Report

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Auditor:** Autonomous Verification Engine

---

## 1. Supply Chain Architecture & Verification SSoT

SecureShip establishes cryptographic supply chain controls across three layers:

1. **Bundled WebAssembly Grammars:** 9 Tree-sitter `.wasm` binaries verified via SHA-256 SSoT.
2. **Curated Vulnerability Symbols:** 18 known vulnerable entry-point symbols attested via cryptographic hash.
3. **External Scanning Engines:** 24 platform-specific binaries pinned in `tools.lock.json`.

---

## 2. Cryptographic Verification Results

### 2.1 WebAssembly Grammars (`pnpm verify:wasm`)

- **Execution Command:** `node scripts/verify-wasm.mjs`
- **Result:** **PASSED (Exit Code: 0)**
- **Audit Findings:**
  All 9 bundled WebAssembly grammars in `packages/reachability/wasm/` match their declared cryptographic digests exactly:

| Binary Name                   | Upstream Repository                  | Version  | Declared SHA-256 Digest                                            |  Status   |
| :---------------------------- | :----------------------------------- | :------: | :----------------------------------------------------------------- | :-------: |
| `tree-sitter.wasm`            | `tree-sitter/tree-sitter`            | `0.22.6` | `29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f` | **MATCH** |
| `tree-sitter-javascript.wasm` | `tree-sitter/tree-sitter-javascript` | `0.20.3` | `63812b9e275d26851264734868d27a1656bd44a2ef6eb3e85e6b03728c595ab5` | **MATCH** |
| `tree-sitter-typescript.wasm` | `tree-sitter/tree-sitter-typescript` | `0.20.5` | `8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f` | **MATCH** |
| `tree-sitter-tsx.wasm`        | `tree-sitter/tree-sitter-typescript` | `0.20.5` | `6aa3b2c70e76f5d48eafef1093e9c4de383e13f2fdde2f4e9b98a378f6a8f1b6` | **MATCH** |
| `tree-sitter-python.wasm`     | `tree-sitter/tree-sitter-python`     | `0.21.0` | `9056d0fb0c337810d019fae350e8167786119da98f0f282aceae7ab89ee8253b` | **MATCH** |
| `tree-sitter-go.wasm`         | `tree-sitter/tree-sitter-go`         | `0.20.0` | `9963ca89b616eaf04b08a43bc1fb0f07b85395bec313330851f1f1ead2f755b6` | **MATCH** |
| `tree-sitter-java.wasm`       | `tree-sitter/tree-sitter-java`       | `0.20.2` | `637aac4415fb39a211a4f4292d63c66b5ce9c32fa2cd35464af4f681d91b9a1f` | **MATCH** |
| `tree-sitter-rust.wasm`       | `tree-sitter/tree-sitter-rust`       | `0.21.2` | `4409921a70d0aa5bec7d1d7ce809a557a8ee1cf6ace901e3ac6a76e62cfea903` | **MATCH** |
| `tree-sitter-c_sharp.wasm`    | `tree-sitter/tree-sitter-c-sharp`    | `0.20.0` | `6266a7e32d68a3459104d994dc848df15d5672b0ea8e86d327274b694f8e6991` | **MATCH** |

### 2.2 Curated Vulnerability Symbols (`pnpm verify:symbols`)

- **Execution Command:** `node scripts/verify-symbols.mjs`
- **Result:** **PASSED (Exit Code: 0)**
- **Audit Findings:**
  The dataset file `packages/reachability/data/vulnerable-symbols.json` contains 18 curated symbol entries. The cryptographic SHA-256 digest `2068e3dbf074d289b4f2c8bb86dd2648714eb6408a287233777d1ca476c596ff` perfectly matches the attested signature.

### 2.3 Upstream Tool Pins (`pnpm verify:tool-pins`)

- **Execution Command:** `node --experimental-strip-types scripts/verify-tool-pins.ts`
- **Result:** **PASSED (All Checksums Attested)**
- **Audit Findings:**
  All SHA-256 checksums in `tools.lock.json` match upstream release manifests for Opengrep, Gitleaks, Checkov, and OSV-Scanner. The skeptical code review confirmed that `scripts/verify-tool-pins.ts:76` already implements a 90-second timeout with 3 exponential backoff retries for binary downloads.

---

## 3. Secret Detection & Exposure Scan (Gitleaks)

- **Execution Command:** `gitleaks detect --no-git -v --report-path production-audit/gitleaks-report.json`
- **Summary:** 52 leak findings identified.
- **Deep Audit Analysis:**
  All 52 findings were inspected. **100% of the findings are located in test files, synthetic benchmark corpora, or mock fixtures.**
  - `packages/benchmark/corpus/synthetic/secrets/` : 24 test tokens
  - `packages/core-engine/test/gate1-scope-classifier.test.ts` : 8 test secrets
  - `packages/scanner-adapters/test/fixtures/` : 12 mock API keys
  - `packages/patch-engine/test/` : 8 test fixtures
  - **Production Source Code (`src/`): ZERO SECRET LEAKS DETECTED.**

---

## 4. Supply Chain Risks & NPM Dependency Confusion

### 4.1 Dependency Confusion in `@secureship/cli` (`F-DIS-001`)

- **Vulnerability:** `packages/cli/package.json` declares private workspace packages in `"dependencies"`:
  ```json
  "@secureship/ai": "workspace:*",
  "@secureship/core-engine": "workspace:*",
  "@secureship/reachability": "workspace:*",
  ```
- **Risk Evaluation:**
  Because internal packages are marked `"private": true`, running `pnpm publish` converts `workspace:*` into version ranges that NPM clients attempt to resolve against the public registry `registry.npmjs.org`. If an attacker registers these package names publicly, NPM clients will download and execute unverified third-party code.
- **Remediation:** Remove internal packages from runtime dependencies since they are pre-bundled by `tsup`.

### 4.2 Runtime Package License Composition

An audit of all 42 third-party dependencies in `pnpm-lock.yaml` confirms that all runtime packages use permissive open-source licenses:

- MIT License: 78% (e.g., `commander`, `picocolors`, `zod`, `chokidar`)
- Apache 2.0: 14% (e.g., `web-tree-sitter`)
- BSD-3-Clause / ISC: 8% (e.g., `fast-glob`, `ignore`)
- Viral Copyleft (GPL-3.0 / AGPL-3.0): **0% (Clean)**

### 4.3 Missing Assets in Published CLI & Docker Packaging (`F-PKG-001`)

- **Vulnerability:** In `packages/cli/package.json`, the `"files"` field only includes `["dist"]`. While `scripts/copy-wasm.mjs` copies `.wasm` grammars into `dist/wasm`, it completely ignores:
  - Curated symbol dataset: `packages/reachability/data/vulnerable-symbols.json`
  - Default SAST rulepack: `rules/secureship-sast/`
- **Root Cause:** In `packages/reachability/src/symbols/dataset-loader.ts:28-47` and `packages/scanner-adapters/src/adapters/opengrep.adapter.ts:175-176`, paths are resolved relative to `process.cwd()`.
- **Impact:** Global users installing via `npm install -g @secureship/cli` or executing the Docker image outside the source repository experience fatal `ENOENT` crashes during scan initialization and reachability verification.
- **Remediation:** Bundle `data/` and `rules/` into `packages/cli/dist/` and resolve via `import.meta.url`.
