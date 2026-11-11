# SecureShip-IDE Production-Readiness Audit

# 12. Global User and Enterprise Readiness Report

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Auditor:** Autonomous Verification Engine

---

## 1. Operating System Compatibility Matrix

| Platform / Environment       | Architecture  |   Support Status    | Key Identified Quirks & Limitations                                                                                                        |
| :--------------------------- | :-----------: | :-----------------: | :----------------------------------------------------------------------------------------------------------------------------------------- |
| **Windows 10 / 11**          |      x64      |    🟡 Supported     | Monorepo subdirectory diff crash (`F-GIT-001`); Windows Docker mount path rejection (`F-SAN-001`); Shell command in license (`F-SEC-003`). |
| **Windows Server**           |      x64      |    🟡 Supported     | Requires Git CLI on PATH; Docker Desktop / WSL2 required; Docker container mounts fail due to `/c/...` path translation (`F-SAN-001`).     |
| **Ubuntu / Debian Linux**    |  x64, ARM64   | 🟢 Tier 1 Supported | Primary CI platform. Container sandbox functions natively via Linux Docker socket.                                                         |
| **Alpine Linux (Docker)**    |  x64, ARM64   | 🟢 Tier 1 Supported | `Dockerfile.cli` verified. Hardened with `tini` PID 1 and non-root UID 10001; needs bundled rules & symbols (`F-PKG-001`).                 |
| **macOS (Sonoma / Sequoia)** | Apple Silicon | 🟢 Tier 1 Supported | Native WASM execution verified. Standalone Bun release builds currently omit `wasm/` directory (`F-REL-001`).                              |

---

## 2. Windows Path & Filesystem Handling Review

1. **Drive Letters & UNC Paths:**
   - In `packages/patch-engine/src/diff-parser.ts:623`, the parser properly rejects paths containing drive letters (`/^[a-zA-Z]:/`) or null bytes, preventing path traversal attacks.
   - However, in `packages/core-engine/src/git/diff-scope.ts:68`, `path.join(targetDir, '.git')` assumes `.git` is directly under `targetDir`, failing on Windows monorepos with forward-slash or backslash variations (`F-GIT-001`).
2. **Path Separator Normalization:**
   - In `packages/vscode-extension/src/extension.ts:178-189` and `packages/vscode-extension/src/providers/diagnostic-provider.ts:50-92`, paths received from VSCode document URIs (`file:///c:/dev/...`) are compared against CLI JSON outputs without consistent lowercasing or slash normalization (`F-WIN-001`).
3. **Container Mount Path Translation:**
   - In `packages/sandbox/src/backends/container-backend.ts:39-50`, `translateHostPath` converts Windows drives to `/c/...`, which native Windows Docker CLI rejects as an illegal volume name (`F-SAN-001`).
4. **Missing Production Asset Packaging:**
   - In `packages/reachability/src/symbols/dataset-loader.ts:28-47`, assets resolve relative to `process.cwd()`. Global users running `npm install -g @secureship/cli` outside the repository crash on symbol loading and SAST scanning (`F-PKG-001`).

---

## 3. Enterprise & Corporate Network Readiness

### 3.1 Corporate Proxy & TLS Interception

- **Implementation in `packages/ai/src/providers/http-client.ts`:**
  - AI requests are performed via Node.js native `fetch`.
  - While native `fetch` honors system environment variables in modern Node versions, the client does not explicitly configure proxy agents (e.g. `undici.ProxyAgent` or `https-proxy-agent`).
  - Enterprises running TLS-decrypting corporate proxies (Zscaler, Netskope, BlueCoat) require custom CA certificates (`NODE_EXTRA_CA_CERTS`), which must be documented in enterprise deployment guides.

### 3.2 Air-Gapped Operation

- **Static Analysis & Reachability:** 100% Air-Gapped. Tree-sitter WebAssembly grammars and vulnerability symbol datasets are fully local.
- **Docker Container Execution:** `Dockerfile.cli` passes Gate 3 in `docker.yml` with `--network none`, proving complete zero-network capability.
- **Limitation:** The NPM CLI package currently requires internet during `npm install` due to unbundled workspace dependencies (`F-DIS-001`).

### 3.3 Multi-User Shared Workstations

- **Security Vulnerability (`F-VSC-001`):** `packages/vscode-extension/src/cli/cli-runner.ts` writes scan results to shared `os.tmpdir()` with default world-readable permissions. On shared Linux dev servers, other developers can inspect vulnerability findings.
- **Remediation:** Enforce `0o700` per-user directory creation under `~/.secureship/tmp`.
