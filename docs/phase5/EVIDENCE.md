# SecureShip Phase 5: Cryptographic Evidence Bundles & Fix Reports

## 1. Overview

Every candidate patch verified by SecureShip Gate 4 produces a tamper-evident **Evidence Bundle** stored outside the repository in `~/.secureship/fixes/<repoHash>/<fixId>/`.

An evidence bundle consists of:

1. `diff.patch`: The exact unified diff that was tested and applied in the shadow copy.
2. `report.json`: The complete, structured `FixReport` artifact (Schema v1.0).
3. Cryptographic HMAC-SHA256 signature sealing the report against offline modification.

---

## 2. FixReport Schema (v1.0) Specification

```json
{
  "schemaVersion": "1.0",
  "tool": "secureship",
  "findingRef": {
    "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ruleId": "rules.sqli",
    "category": "SAST",
    "severity": "HIGH",
    "file": "src/vuln.ts",
    "line": 2
  },
  "patchSha256": "8f434346648f6b96df89dda901c5176b10f607624f4699565502a5cf3f83ceab",
  "proposalSummary": "Replace string concatenation with parameterized SQL query",
  "baseFiles": [
    {
      "path": "src/vuln.ts",
      "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
    }
  ],
  "status": "VERIFIED_STATIC",
  "requirement": "VERIFIED_STATIC",
  "requirementMet": true,
  "stages": [
    { "id": "APPLY", "outcome": "PASS", "durationMs": 12, "detail": "Clean patch application" },
    { "id": "POLICY", "outcome": "PASS", "durationMs": 4, "detail": "Passed all 23 rules" },
    { "id": "SYNTAX", "outcome": "PASS", "durationMs": 15, "detail": "AST error node check clean" },
    {
      "id": "RESCAN",
      "outcome": "PASS",
      "durationMs": 120,
      "detail": "Finding absent in patched shadow copy"
    },
    {
      "id": "NEW_FINDINGS",
      "outcome": "PASS",
      "durationMs": 150,
      "detail": "Zero new findings >= MEDIUM"
    },
    {
      "id": "IMPORTS",
      "outcome": "PASS",
      "durationMs": 1,
      "detail": "Standard library imports only"
    },
    { "id": "INSTALL", "outcome": "SKIPPED", "durationMs": 0, "detail": "Install stage disabled" },
    {
      "id": "TYPECHECK",
      "outcome": "SKIPPED",
      "durationMs": 0,
      "detail": "Dynamic stages skipped"
    },
    { "id": "BUILD", "outcome": "SKIPPED", "durationMs": 0, "detail": "Dynamic stages skipped" },
    { "id": "TEST", "outcome": "SKIPPED", "durationMs": 0, "detail": "Dynamic stages skipped" }
  ],
  "sandbox": {
    "backend": "container",
    "networkMode": "none",
    "limits": { "memory": "2g", "cpus": 2, "pids": 512 },
    "runtime": "docker",
    "runtimeVersion": "Docker Desktop 4.95.0",
    "imageDigest": "node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6"
  },
  "scanners": [{ "name": "semgrep", "version": "1.100.0" }],
  "attempts": 1,
  "limitations": [
    "Verification checks strictly confirm that listed scanners and tests passed; this does not guarantee general correctness or immunity from unknown vulnerabilities."
  ],
  "disclaimer": "SecureShip automated remediation is provided under developer review.",
  "createdAt": "2026-10-20T11:00:00.000Z",
  "signature": "c8a14b09e25d6b4122d2508129486c8d76d47b59e51c8a127a3c3e7b165bbcb8"
}
```

---

## 3. Cryptographic Signature & Canonicalization

1. **Secret Key**:
   - Stored in `~/.secureship/machine-secret`.
   - Generated with 32 bytes of cryptographically secure random entropy (`crypto.randomBytes(32)`).
   - Mode `0600` (readable only by the local developer account).
2. **Canonical Serialization**:
   - The `signature` field is omitted.
   - Keys are recursively sorted deterministically.
   - Normalized UTF-8 JSON is passed through HMAC-SHA256.
3. **Verification**:
   - `VerificationLadder.verifySignature(report)` recalculates the HMAC-SHA256 signature over the canonical object and compares using timing-safe buffer comparison.

---

## 4. Offline Verification Guide

Auditors, compliance teams, or external CI workflows can verify an evidence bundle offline without running the full scanner engine:

```javascript
import fs from 'node:fs';
import crypto from 'node:crypto';

// 1. Read stored fix report and machine secret
const report = JSON.parse(
  fs.readFileSync('~/.secureship/fixes/<repoHash>/<fixId>/report.json', 'utf8')
);
const secret = fs.readFileSync('~/.secureship/machine-secret', 'utf8').trim();

// 2. Extract signature and compute canonical representation
const expectedSignature = report.signature;
delete report.signature;

function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(canonicalize);
  const sorted = {};
  for (const k of Object.keys(obj).sort()) {
    sorted[k] = canonicalize(obj[k]);
  }
  return sorted;
}

const canonical = canonicalize(report);
const actualSignature = crypto
  .createHmac('sha256', secret)
  .update(JSON.stringify(canonical))
  .digest('hex');

if (crypto.timingSafeEqual(Buffer.from(actualSignature), Buffer.from(expectedSignature))) {
  console.log('✅ Evidence bundle signature is VALID and untampered.');
} else {
  console.error('❌ Evidence bundle TAMPERED: HMAC mismatch!');
}
```

---

## 5. Base File Hash Integrity Pinning

When a developer runs `secureship fix apply <fixId>`:

1. `FixStore` reads `baseFiles` from `report.json`.
2. Each base file is read from the developer's working tree and hashed with SHA-256.
3. If any file hash does not match `baseFiles[].sha256`, the operation **fails closed**:
   ```
   Base file hash mismatch for 'src/vuln.ts'. The file was modified since fix generation. Expected 4b22..., got 8a11...
   ```
4. This strictly prevents stale fixes from being applied on top of concurrent edits or out-of-date working trees.
