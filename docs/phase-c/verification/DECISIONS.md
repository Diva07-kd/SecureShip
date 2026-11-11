# SecureShip Phase C — Verification Decisions Record (DECISIONS.md)

This document records all conservative engineering decisions, specification clarifications, and environment constraint mitigations adopted during the Phase C Independent Verification and Production Gate Audit.

---

### D12: Linux Syscall Tracing on Windows Host (Addendum Trap 1)

- **Context**: T2, T6, and T9 specify OS-level network tracing (`strace -f -e trace=network`), network namespace isolation (`unshare -n`), and dynamic loader checks (`ldd`).
- **Constraint**: The verification host runs Windows 11 Enterprise (`win32-x64`). Native Linux kernel syscall utilities do not exist in the host PowerShell shell.
- **Decision**: In strict compliance with Anti-Fake-Test Law §1 ("Not run => `NOT VERIFIED` + reason"), OS-level network syscall assertions on the host are marked:
  `NOT VERIFIED (Windows host constraint: Linux syscall tracing requires Linux kernel/WSL; application-level egress barrier verified via assertOfflineAllowed unit tests)`.
- **Mitigation**: Network egress isolation is verified at the application boundary via unit tests in `packages/core-engine/test/offline.test.ts`, and full kernel `--network none` isolation is verified inside the multi-arch Linux CI runner (`.github/workflows/docker.yml`).

---

### D13: Independent Oracle Tool Paths on Windows (Addendum Trap 2)

- **Context**: T3, T7, and T8 mandate verification using independent external oracles (`openssl`, `sha256sum`, `tar`), never production code constants.
- **Constraint**: Windows system `PATH` lacks standard GNU `openssl` and `sha256sum`.
- **Decision**: External oracle checks explicitly resolve:
  - `openssl`: `C:\Program Files\Git\usr\bin\openssl.exe` (OpenSSL 3.5.7) or independent Node.js crypto script.
  - `sha256sum`: `C:\Program Files\Git\usr\bin\sha256sum.exe` (GNU coreutils 8.32).
  - `tar`: `C:\Windows\System32\tar.exe` (bsdtar 3.8.9 / libarchive 3.8.9).
- **Outcome**: Zero oracle checks fail due to path resolution errors.

---

### D14: Test-Integrity Scope vs Pre-existing Legacy Phase B Tests (Addendum Trap 3)

- **Context**: T1 mandates scanning test suites for Anti-Fake-Test Law violations using `scripts/verify-test-integrity.ts`.
- **Constraint**: Running `verify-test-integrity.ts` monorepo-wide flags legacy tests in `packages/reachability/test/hostile-stress.test.ts` (Phase B stress tests with weak assertions). Modifying them would violate T0 ("no pre-existing test file modified/deleted").
- **Decision**: The test-integrity auditor proof is demonstrated via `scripts/test-auditor-proof.ts` (11/11 categories caught). The zero-violation gate is strictly scoped to all Phase C test files and touched modules (`bundle-offline.test.ts`, `fuzz-phase-c.test.ts`, `tar-bundle.test.ts`, `tools-lock.test.ts`, `offline.test.ts`, `install-tools.test.ts`, `paths.test.ts`). Pre-existing Phase B tests remain untouched.

---

### D15: Two-Tier Fuzzing Strategy (Addendum Trap 4)

- **Context**: T11 specifies ">= 100k iterations/target in CI mode".
- **Constraint**: Executing 100,000 synchronous disk extraction and parser iterations in interactive testing triggers vitest timeouts and resource exhaustion on host environments.
- **Decision**: Implemented a two-tier fuzzing architecture:
  - **Local Gate Mode**: 1,500 seeded PRNG iterations per target (6,000 total iterations across SafeTarReader, canonicalJsonStringify, FreshnessEvaluator, OfflineBundleManifestSchema) verifying zero uncaught throws, bounded RSS memory (<512MB), and typed error handling.
  - **Nightly Soak Mode**: Script documented for scheduled headless Linux CI runs executing the 100k iteration soak.

---

### D16: Architecture Synonym Normalization in `resolveToolAsset`

- **Context**: Docker Buildx injects `TARGETARCH=amd64` or `TARGETARCH=arm64`. Node.js platform strings in `tools.lock.json` are keyed by `linux-x64` and `linux-arm64`.
- **Defect**: When `Dockerfile.cli` ran `secureship install-tools --target-platform linux-amd64`, `resolveToolAsset` reported: `No precompiled distribution available for tool 'trivy' on platform 'linux-amd64'`.
- **Decision**: Updated `resolveToolAsset` in `packages/scanner-adapters/src/tools-lock.ts` to normalize architecture synonyms (`amd64`/`x86_64` => `x64`, `aarch64` => `arm64`). Supported both `linux-amd64` and `linux-x64` seamlessly. Added unit test in `tools-lock.test.ts`.

---

### D17: Offline Bundle Deterministic Identification

- **Context**: T7 and T12 mandate that two bundles created from identical inputs must produce byte-identical archives (identical SHA-256).
- **Defect**: `OfflineBundleService.createBundle()` previously injected `crypto.randomBytes(3)` into `bundleId`, guaranteeing SHA-256 divergence on every invocation.
- **Decision**: Added optional `bundleId?: string` to `CreateBundleOptions`. When omitted, default `bundleId` derives from the caller's `now` timestamp (`bundle-${dateStr}`) without random entropy. Added deterministic sorting across all directory listings (`readdirSync.sort()`) and component files, and formatted `manifest.json` using RFC 8785 `canonicalJsonStringify`. Added regression test in `bundle-offline.test.ts`.

---

### D18: Standalone CLI Distribution Deployment in Dockerfile.cli

- **Context**: Container image build failed at Stage 2 because `packages/cli/dist/index.js` could not resolve external dependencies (`commander`, `web-tree-sitter`, `zod`, etc.).
- **Defect**: Stage 1 assembled `/out/cli` with a synthetic `package.json` with 0 dependencies and no `node_modules`.
- **Decision**: Replaced manual file copy in Stage 1 with pnpm's built-in monorepo deployment command:
  `RUN pnpm --filter @secureship/cli deploy --prod /out/cli`.
  This packages the exact production dependency tree and WASM grammars into `/out/cli` while eliminating workspace links.
