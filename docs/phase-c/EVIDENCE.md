# SecureShip Phase C — Verification & Quality Gate Evidence Log

This log records real commands executed, their exit codes, and verbatim output excerpts for each Work Package in Phase C.

## WP-C0: Baseline Environment & Prerequisites Verification

### 1. Phase A Prerequisite: Standalone Packaging & WASM Verification

- **Command**: `node packages/cli/dist/index.js doctor` (executed from temp directory outside repository)
- **Exit Code**: `0`
- **Output Excerpt**:

```text
🔍 SecureShip Environment & Security Doctor

Node.js: ✔ v24.19.0 (Supported >= 18)
OS Platform: win32 (x64)
Git: ✔ git version 2.55.0.windows.5

Core Security Sub-Engines:
  ✔ Active     SecureShip Deep AST Engine           [SAST (Source Code)       ]
  ✔ Active     SecureShip Credential Sentinel       [Secrets & Credentials    ]
  ✔ Active     SecureShip Component Auditor         [Dependencies & Containers]
  ✔ Active     SecureShip Threat Intelligence       [SCA / Lockfile CVEs      ]
  ✔ Active     SecureShip Infrastructure Guard      [Infrastructure as Code   ]

Reachability Engine WASM Grammars:
  ✔ tree-sitter.wasm               Verified (188635 bytes)
  ✔ tree-sitter-javascript.wasm    Verified (647334 bytes)
  ✔ tree-sitter-typescript.wasm    Verified (2342690 bytes)
  ✔ tree-sitter-tsx.wasm           Verified (2411272 bytes)
  ✔ tree-sitter-python.wasm        Verified (476105 bytes)
  ✔ tree-sitter-go.wasm            Verified (235957 bytes)
  ✔ tree-sitter-java.wasm          Verified (430239 bytes)
  ✔ tree-sitter-rust.wasm          Verified (818756 bytes)
  ✔ tree-sitter-c_sharp.wasm       Verified (3978594 bytes)
```

### 2. Monorepo Quality Gate 1 (QG-1) Baseline

- **Build**: `pnpm build` -> Exit Code `0`
- **Typecheck**: `pnpm typecheck` -> Exit Code `0`
- **Lint & Format**: `pnpm lint; pnpm format:check` -> Exit Code `0`
- **WASM Verification**: `pnpm verify:wasm` -> Exit Code `0`
- **Mutation Verification**: `pnpm verify:mutations` -> Exit Code `0` (26/26 mutations caught)
- **Test Coverage**: `pnpm test:coverage` -> Exit Code `0`
  - Total Test Files: 184 passed (184)
  - Total Tests: 1,507 passed (1,507)
  - Statements: 90.43% (Threshold >= 85%)
  - Branches: 83.60% (Threshold >= 75%)
  - Lines: 90.43% (Threshold >= 85%)

---

## WP-C1: Tool Manifest SSoT + install-tools Hardening

- **Tool Pin Verification**: `pnpm verify:tool-pins`
  - **Exit Code**: `0`
  - **Output Excerpt**:
    ```text
    🔒 Verifying SecureShip Tool Lockfile Pins vs Upstream Byte Checksums...
    Checking opengrep:
      ✔ opengrep_manylinux_x86: 8740c83a73c0957fae78bfdeaafe8df3c9a6ef2f7823f647970da6796da72688 (matches SHA256SUMS)
      ✔ opengrep_musllinux_x86: e7a1e0b5714cb2a78377759aa59fecaa7699d4df279b33e2183e85e2fc092f62 (matches SHA256SUMS)
      ✔ opengrep_manylinux_aarch64: cc08eb865fd45aa70597aa23ff6fb07a01d672ef75e3a89104b2b00aa640b33b (matches SHA256SUMS)
      ✔ opengrep_musllinux_aarch64: f53b6fa0f622f9801648aee7a747c32bf5287f39420ddb6399ba7c5c00e62057 (matches SHA256SUMS)
      ✔ opengrep_osx_x86: e61e06fa70f2b33945c5c0a3739a8c14d9b4b025345719782559efea5a17a7fb (matches SHA256SUMS)
      ✔ opengrep_osx_arm64: 3d506940a0c2020227181c4e78a635832a514d4e3cb41180d56561cf2a4cb9fb (matches SHA256SUMS)
      ✔ opengrep_windows_x86.exe: fdd2e22549e7b2339d33261a8f9024f0c4bbd73c73795b6c86ea11d332d4fc19 (matches SHA256SUMS)
    Checking gitleaks:
      ✔ gitleaks_8.24.0_linux_x64.tar.gz: 57423e2003b1e9c565251649a5b3991c28c89c37255473cfcb479a0ce622830f (matches gitleaks_8.24.0_checksums.txt)
      ✔ gitleaks_8.24.0_linux_arm64.tar.gz: cb1481cf5d22b2713f8c85ee918076df3d8ca198d00236a282f6fbf71aee0938 (matches gitleaks_8.24.0_checksums.txt)
      ✔ gitleaks_8.24.0_darwin_x64.tar.gz: dab91070b01ff2a0be4f3ca4e0735702d73fffa4e3d360fba10f0ea58a8a649d (matches gitleaks_8.24.0_checksums.txt)
      ✔ gitleaks_8.24.0_darwin_arm64.tar.gz: 00b080b06cfc72ba1d0c15907c132808c1f038f428c946e6a4574924d5500ce4 (matches gitleaks_8.24.0_checksums.txt)
      ✔ gitleaks_8.24.0_windows_x64.zip: b5e41e6c3be313c4155df98b2df31c8901eb2a29efbfd9333ae4c8cebbca076a (matches gitleaks_8.24.0_checksums.txt)
    Checking osv-scanner:
      ✔ osv-scanner_linux_amd64: 3b057fc0445d3fa7bf589d81d2df8ba9c97b8764b8a4f6be44d9fec9009eb8b3
      ✔ osv-scanner_linux_arm64: 93bc141d08c58284562c2f42775a02ffea387fa7598c47f7d1f5df6d0f62ea6a
      ✔ osv-scanner_darwin_amd64: 479ee364f3febe432eec00cffc1e8471c99ddcae554d3eb9e51c89599557fcff
      ✔ osv-scanner_darwin_arm64: a6d7fb1bca253fa4faea9069d511993214ce2289f8d5fe5518b417c800fcb690
      ✔ osv-scanner_windows_amd64.exe: 0e863372c0c7a5f6e80b43ea35ea83c27da255d6778f240b616428784ef3c676
    Checking trivy:
      ✔ trivy_0.76.0_Linux-64bit.tar.gz: af7492c73295c290130f140682136e9d6d376ca6cfc2db21e05086ee50f005d5 (matches trivy_0.76.0_checksums.txt)
      ✔ trivy_0.76.0_Linux-ARM64.tar.gz: b5c0a373b52d9212c019bf9e34e56598c2ce67aa6f97ef05ec0bc92f9e4dd258 (matches trivy_0.76.0_checksums.txt)
      ✔ trivy_0.76.0_macOS-64bit.tar.gz: 9fa5fb2e9aeec71c3c9fb64177b96043fb94017c603a1d953a9482f3ef4d4c82 (matches trivy_0.76.0_checksums.txt)
      ✔ trivy_0.76.0_macOS-ARM64.tar.gz: a0f0742f8c5b9679fce97455850937c569f6bb121408ccb4169c9b68db96515b (matches trivy_0.76.0_checksums.txt)
      ✔ trivy_0.76.0_windows-64bit.zip: 7b4762a5a53239a9c24090538a7981da4f722a48eaebf7004f1fb97067d58a59 (matches trivy_0.76.0_checksums.txt)
    ✨ All 24 platform distribution pins strictly match verified upstream checksums.
    ```
- **Commit**: `ac8c6e2` (`feat(tool-pins): implement tools.lock.json SSoT, hardened install-tools, in-process extraction, and pin verification (WP-C1)`)

---

## WP-C2: Paths, BinaryResolver, Container Doctor

- **CLI Doctor Execution**: `node packages/cli/dist/index.js doctor`

  - **Exit Code**: `0`
  - **Output Excerpt**:

    ```text
    🔍 SecureShip Environment & Security Doctor

    Node.js: ✔ v24.19.0 (Supported >= 18)
    OS Platform: win32 (x64)
    Container:   ○ Host Environment
    Process ID:  Windows Identity

    SecureShip Storage Directories:
      • SECURESHIP_HOME     : C:\Users\kdiva\.secureship [Writable ✔]
      • Tool Candidate Dirs :
        ↳ C:\Users\kdiva\.secureship\bin [Writable ✔]
      • Vulnerability DB Dir: C:\Users\kdiva\.secureship\db [Writable ✔]
    Git: ✔ git version 2.55.0.windows.5

    Core Security Sub-Engines:
      ✔ Active     SecureShip Deep AST Engine           [SAST (Source Code)       ]
        ↳ Engine Core : SecureShip SAST
        ↳ Runtime Path: C:\Users\kdiva\AppData\Local\opengrep\v1.31.0\opengrep.exe
        ↳ Version     : 1.31.0 (supported: >=1.31.0, tested: 1.31.0)
        ↳ Pin Status  : ⚠ Pin mismatch (actual: 2fd95de62afd..., lock: fdd2e22549e7...)
      ✔ Active     SecureShip Credential Sentinel       [Secrets & Credentials    ]
        ↳ Engine Core : SecureShip Secret
        ↳ Runtime Path: C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\Gitleaks.Gitleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\gitleaks.exe
        ↳ Version     : 8.30.1 (supported: >=8.30.0, tested: 8.30.1)
        ↳ Pin Status  : ⚠ Pin mismatch (actual: 17157e2ee8b7..., lock: dab91070b01f...)
      ✔ Active     SecureShip Component Auditor         [Dependencies & Containers]
        ↳ Engine Core : SecureShip SCA
        ↳ Runtime Path: C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe\trivy.exe
        ↳ Version     : Version: 0.76.0 (supported: >=0.76.0, tested: 0.76.0)
        ↳ Pin Status  : ⚠ Pin mismatch (actual: 51e50a34f873..., lock: 7b4762a5a532...)
      ✔ Active     SecureShip Threat Intelligence       [SCA / Lockfile CVEs      ]
        ↳ Engine Core : SecureShip Intel
        ↳ Runtime Path: C:\Users\kdiva\AppData\Local\Microsoft\WinGet\Packages\Google.OSVScanner_Microsoft.Winget.Source_8wekyb3d8bbwe\osv-scanner.exe
        ↳ Version     : osv-scanner version: 2.7.0 (supported: >=2.7.0, tested: 2.7.0)
        ↳ Pin Status  : ⚠ Pin mismatch (actual: 9964ed64ec9a..., lock: c041e84d6b58...)
      ✔ Active     SecureShip Infrastructure Guard      [Infrastructure as Code   ]
        ↳ Engine Core : SecureShip IaC
        ↳ Runtime Path: C:\Users\kdiva\AppData\Local\Programs\Python\Python314\Scripts\checkov.cmd
        ↳ Version     : (Embedded / Active)
        ↳ Pin Status  : ○ Unpinned / System distribution (sha256:8e4c92342930...)

    Offline Vulnerability Database:
      • Status              : ○ No offline bundle installed (online mode or run `secureship import-offline`)
      • Database Directory  : C:\Users\kdiva\.secureship\db
    ```

- **CLI External Execution**: `node C:\dev\SecureShip-IDE\packages\cli\dist\index.js status` (from `C:\Users\kdiva\AppData\Local\Temp`)
  - **Exit Code**: `0`
- **Part H & Part J Verification**:
  - `pnpm test packages/cli/test/verification/cli.verify.test.ts` -> 6/6 passed (Exit Code `0`)
  - `pnpm test packages/cli/test/verification/part-j.verify.test.ts` -> 6/6 passed (Exit Code `0`)
  - `pnpm test packages/cli/test/doctor-phase-c.test.ts` -> 3/3 passed (Exit Code `0`)
  - `pnpm test packages/core-engine/test/diff-scope.test.ts` -> 6/6 passed (Exit Code `0`)
  - `pnpm test packages/scanner-adapters/test/binary-resolver.test.ts` -> 11/11 passed (Exit Code `0`)

## WP-C3: Hardened Dockerfile.cli, .dockerignore, CI

- **Multi-Stage `Dockerfile.cli`**:
  - Implemented 4-stage build architecture:
    1. `builder`: Node 22 slim, corepack `pnpm@12.14.0`, frozen lockfile, tsup bundling, deployable CLI package with zero `workspace:*` dependencies.
    2. `tools`: Provisions `opengrep`, `gitleaks`, `trivy`, `osv-scanner` using `secureship install-tools --target-platform linux-${TARGETARCH}` and authoritative lockfile SHA-256 pins. Zero curl/shell scripts in runner.
    3. `checkov`: Pinned Python 3.11 virtualenv with Checkov v3.3.29 and wrapper script.
    4. `runner`: Node 22 slim, fixed UID/GID 10001 (`secureship`), root-owned 0555 immutable `/opt/secureship/bin`, `tini` PID 1 signal supervisor, OCI annotations, licenses/notices included.
  - HEALTHCHECK decision: explicitly omitted for one-shot CLI (rationale documented in Dockerfile comments and `docs/docker.md`).
- **Context Exclusion `.dockerignore`**: Created to exclude `.git`, `node_modules`, `dist`, `coverage`, `.secureship`, `.env*`, `license.jwt`, test fixtures, and IDE caches.
- **Redistribution Compliance**: Created `licenses/` directory with official upstream license texts for Opengrep (LGPL-2.1), Gitleaks (MIT), Trivy (Apache-2.0), OSV-Scanner (Apache-2.0), and Checkov (Apache-2.0). Updated `THIRD_PARTY_NOTICES.md` with Section 5 describing external engines, source code URLs, and LGPL-2.1 copyleft compliance.
- **Operations & Runbook**: Created `docs/docker.md` documenting exact run commands (default, non-root arbitrary user, read-only rootfs, separate output mount, `--network none`, git `--diff`, Apple Silicon arm64, Podman rootless), storage permissions layout, and size budget.
- **CI Workflow**: Updated `.github/workflows/docker.yml` with multi-arch Buildx, pre-push smoke tests (doctor, `--version`, air-gap `--network none`, read-only rootfs, read-only volume scan, Tini PID 1 `docker stop` < 3s, Trivy self-scan failing on CRITICAL), and scheduled/PR `verify-tool-pins`.
- **Local Host Docker Build Execution**: `NOT VERIFIED`
  - **Reason**: The Docker CLI client is installed (v29.8.2), but the Docker Desktop Linux Engine daemon service is stopped on this host machine (`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified`). Full multi-arch container verification is automated in `.github/workflows/docker.yml`.
