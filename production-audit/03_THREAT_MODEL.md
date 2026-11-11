# SecureShip-IDE Production-Readiness Audit

# 03. Threat Model

**Audit Date:** October 27, 2026  
**Subject Commit:** `70c3087b863d06538a6b7116eaa4d22e25073e29`  
**Framework:** STRIDE / OWASP Top 10 / NIST SP 800-218 (SSDF)  
**Auditor:** Autonomous Verification Engine

---

## 1. Assets and Protection Goals

| Asset ID | Asset Description                | Security Goal            | Threat Scenario                                                                                               |
| :------- | :------------------------------- | :----------------------- | :------------------------------------------------------------------------------------------------------------ |
| **A-1**  | **Host Developer Machine**       | Integrity & Availability | Malicious repo exploits scanner, WASM runtime, or patch engine to execute arbitrary code on developer host.   |
| **A-2**  | **Proprietary Source Code**      | Confidentiality          | Source code or proprietary AST context exfiltrated during AI triage or telemetry.                             |
| **A-3**  | **Hardcoded Secrets & API Keys** | Confidentiality          | Secrets embedded in scanned repositories leaked via AI prompts, logs, or unencrypted temp files.              |
| **A-4**  | **Commercial License Keys**      | Integrity & Authenticity | Developers forge enterprise license entitlements, bypass seats, or re-sign expired tokens.                    |
| **A-5**  | **Remediation Code Patches**     | Integrity & Soundness    | AI-generated patches inject subtle backdoors (Trojan Source), bypass security controls, or break clean tests. |
| **A-6**  | **Enterprise Fleet Policies**    | Integrity                | Adversaries alter centralized corporate security rules without authentication.                                |

---

## 2. Threat Actors and Adversary Models

1. **Malicious Repository Author / Contributor:** Prepares a pull request or repository containing hostile code structures (symlink loops, 50MB files, 250-level deep ASTs, prototype pollution payloads, prompt injection strings in code comments).
2. **Untrusted / Compromised AI Provider:** Returns malicious instructions, misleading false-positive rationales, or backdoor code suggestions in LLM responses.
3. **Internal Developer / Rogue User:** Attempts to manipulate local configuration, downgrade security severity rules, forge commercial licenses, or apply unverified patches without running tests.
4. **Supply Chain Adversary:** Exploits dependency confusion on public package registries (NPM) or attempts to tamper with upstream binary tools (Trivy, Opengrep).
5. **Local Network Adversary:** Listens on local network interfaces to capture fleet tokens or tamper with unauthenticated fleet endpoints.

---

## 3. Trust Boundaries

```
[Untrusted Codebase / Pull Request]
             |  (Boundary 1: File Ingestion & Path Traversal)
             v
[Scanner Adapters & AST Parsers (WASM Sandbox)]
             |  (Boundary 2: Context Slicing & Secret Redaction)
             v
[External AI Provider (HTTPS TLS 1.3 / Egress Control)]
             |  (Boundary 3: Model Output & Patch Policy)
             v
[Remediation Sandbox (Docker / Process Isolation)]
             |  (Boundary 4: Local Git Tree Modification)
             v
[Developer Git Working Tree]
```

---

## 4. STRIDE Analysis of Critical Trust Boundaries

### 4.1 Spoofing (Identity & Entitlement Verification)

- **Threat:** Forging License Tier and Seats.
- **Finding (`F-SEC-001`):** In `packages/license-server/src/worker.ts:270-327`, the validation handler decodes JWTs using `atob()` without verifying the incoming cryptographic RSA signature. When `exp - now < 7 * 86400`, the server signs the unverified claims with `env.JWT_PRIVATE_KEY`. Any user can submit an unsigned token claiming `tier: "enterprise"` and `seats: 99999` and obtain a cryptographically valid enterprise token.
- **Threat:** Infinite Seat Activation & License Duplication.
- **Finding (`F-LIC-002`):** `packages/license-server/src/worker.ts:180-248` accepts activations without verifying whether active machines exceed purchased seats in D1, permitting unlimited seat sharing.
- **Threat:** Unauthenticated Fleet Command Injection.
- **Finding (`F-FLT-001`):** `packages/fleet/src/server/fleet-server.ts:138-190` exposes `/api/policy` and `/api/fleet/repos` without validating bearer tokens, allowing unauthenticated network actors to spoof fleet nodes and alter scanning policies.

### 4.2 Tampering (Code & Patch Integrity)

- **Threat:** Trojan Source Bidirectional Overrides & Hidden Unicode.
- **Defense Evaluation:** `packages/patch-engine/src/policy-engine.ts:718-727` and `packages/ai/src/sanitize/output-sanitizer.ts:9-10` enforce strict regex blocking on Unicode bidi override characters (`[\u202A-\u202E\u2066-\u2069]`) and zero-width spaces. This control is sound and tested.
- **Threat:** Tampering with Remediation Verification Verdicts.
- **Finding (`F-ENG-001`):** If `sandbox.backend === 'none'`, the orchestrator invokes `FakeSandboxBackend` (`packages/core-engine/src/remediation/verification-ladder.ts:608-610`), which returns simulated exit code 0 (`"fake execution passed"`), tampering with the verification ladder and falsely granting `VERIFIED_RUNTIME`.
- **Threat:** Cross-Origin Policy Tampering via Wildcard CORS.
- **Finding (`F-FLT-003`):** `packages/fleet/src/server/fleet-server.ts:81-85` sets `Access-Control-Allow-Origin: *` across unauthenticated endpoints, allowing hostile websites visited by an intranet developer to forge policy updates (`POST /api/policy`).

### 4.3 Repudiation (Audit Trail & Ledger Accountability)

- **Threat:** Silently dropping findings without an immutable record.
- **Defense Evaluation:** Principle P1 ("Every suppressed finding has a ledger entry") is enforced across Gates 1-3. Findings suppressed by scope or reachability are recorded in `SuppressionLedger` with rationales, timestamps, and confidence ratings.

### 4.4 Information Disclosure (Secret Leaks & PII)

- **Threat:** Telemetry and Secret Leakage in Logs.
- **Finding (`F-FLT-001`):** `packages/fleet/src/cli.ts:22-24` prints the raw `FLEET_TOKEN` in plaintext to stdout when launching the fleet server.
- **Threat:** Intranet Telemetry Exfiltration via Wildcard CORS.
- **Finding (`F-FLT-003`):** Because the fleet server enables wildcard CORS on `GET /api/fleet/repos` and `GET /api/fleet/summary`, any malicious web page in the developer's browser can extract organization-wide vulnerability reports.
- **Finding (`F-VSC-001`):** `packages/vscode-extension/src/cli/cli-runner.ts:46-49` writes temporary scan reports to `os.tmpdir()` using predictable names generated by `Math.random()` with default operating system permissions (0666 / 0644), vulnerable to local information disclosure on multi-user systems.

### 4.5 Denial of Service (Resource Exhaustion & Data Corruption)

- **Threat:** Parser ReDoS and Hostile AST Nesting.
- **Defense Evaluation:** `packages/reachability/test/hostile-stress.test.ts` proves that 50MB files and 250-level deeply nested ASTs are handled iteratively within bounded heap limits without stack overflow (`RangeError: Maximum call stack size exceeded`).
- **Threat:** Unsynchronized Storage Write Truncation & State Erasure.
- **Finding (`F-FLT-004`):** In `packages/fleet/src/storage/fleet-store.ts:60-76`, non-atomic in-place `fs.writeFileSync` corrupts the repository store if the process restarts or crashes during serialization, resetting the database to empty defaults on subsequent boots.
- **Threat:** Background License Renewal Protocol Implosion.
- **Finding (`F-LIC-001`):** Client sends `POST {sub}` expecting `data.jwt` while server listens on `GET` with Bearer expecting `refreshedJwt`, causing 100% of background renewals to fail with HTTP 404 and triggering license lapse.

### 4.6 Elevation of Privilege (Process & Sandbox Escapes)

- **Threat:** Command Execution via Shell.
- **Finding (`F-SEC-003`):** `packages/cli/src/commands/license.ts:169-178` executes browser launching via `child_process.exec(cmd)`, violating the core requirement for `shell: false`.
- **Threat:** Container Sandbox Jailbreak & Mount Failures.
- **Defense Evaluation:** `packages/sandbox/src/backends/container-backend.ts:916-921` enforces `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--network=none`, and read-only mounts, preventing container breakout under normal Docker daemon configurations.
- **Finding (`F-SAN-001`):** On Windows, `ContainerBackend.translateHostPath` maps drive letters to `/c/...`, which Docker CLI rejects as an illegal volume name, disabling container verification on Windows.
