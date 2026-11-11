# SecureShip Air-Gap Deployment & Operations Runbook

This runbook documents the complete end-to-end operational procedures, security trust model, and command references for running SecureShip in isolated, classified, or air-gapped production environments with zero outbound network connectivity.

---

## 1. Security Trust Model

SecureShip enforces an uncompromising zero-trust security architecture for offline operations:

| Component                   | Trust Authority                     | Integrity Guarantee                                                     | Failure Mode                                                                                                                          |
| :-------------------------- | :---------------------------------- | :---------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| **Scanner Binaries**        | Bundled `tools.lock.json`           | Every engine binary must match the importing CLI's internal SHA-256 pin | Hard fail with security violation. Bundles cannot introduce untrusted or unpinned executables.                                        |
| **Vulnerability Databases** | User-configured Ed25519 Public Keys | Signed with Ed25519 over RFC 8785 Canonical JSON manifest               | Unsigned bundles are rejected unless `--allow-unsigned` is explicitly supplied. Tampered databases fail signature verification.       |
| **Generation Storage**      | Local Generation Directory          | Atomic pointer swapping (`CURRENT` pointer file + fsync)                | Crash safety: `CURRENT` always points to a verified, complete generation. No corrupted partial state is ever published.               |
| **Freshness & Age**         | Injected Time Clock                 | Warns at >7 days age, fails under `--strict` at >30 days age            | Scans never silently report clean if the database is missing, corrupted, or stale. Reports include explicit `completeness: DEGRADED`. |
| **Rollback Protection**     | Generation Timestamps               | Prevents importing bundles older than the active generation             | Rejects older bundles unless `--allow-downgrade` is provided.                                                                         |

---

## 2. End-to-End Operational Workflow

### Step 1: Keypair Generation (Connected Security Workstation)

Generate an Ed25519 signing keypair for signing offline bundles.

Using OpenSSL (v3.0+):

```bash
# Generate Ed25519 private key
openssl genpkey -algorithm ed25519 -out secureship-offline-private.pem

# Extract corresponding public key
openssl pkey -in secureship-offline-private.pem -pubout -out secureship-offline-public.pem
```

Alternatively, generate keypair using Node.js:

```bash
node -e "
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
require('fs').writeFileSync('secureship-offline-private.pem', privateKey);
require('fs').writeFileSync('secureship-offline-public.pem', publicKey);
"
```

Keep `secureship-offline-private.pem` secure on your connected preparation machine or HSM. Deploy `secureship-offline-public.pem` to air-gapped target machines.

---

### Step 2: Create Offline Bundle (Connected Machine)

On an internet-connected workstation, snapshot the latest vulnerability databases and verified scanner binaries:

```bash
secureship bundle-offline \
  --output secureship-offline-bundle-2026-10-26.tar.gz \
  --sign-key secureship-offline-private.pem \
  --key-id secops-key-2026 \
  --platform linux-x64,linux-arm64 \
  --ecosystems npm,PyPI,Go,Maven \
  --include-java-db
```

Output:

```text
📦 SecureShip Offline Database & Engine Bundler

✔ Successfully created offline bundle:
  File:        /path/to/secureship-offline-bundle-2026-10-26.tar.gz
  Bundle ID:   bundle-2026-10-26T12-00-00-abc123
  Total Size:  48.21 MB
  Components:  3
  Signature:   Ed25519 SIGNED
```

---

### Step 3: Transfer to Air-Gapped Environment

Transfer the generated `.tar.gz` bundle and `secureship-offline-public.pem` to the target air-gapped network via approved data diode, secure optical media, or encrypted USB storage per organizational policy.

---

### Step 4: Import & Verify Offline Bundle (Air-Gapped Machine)

#### 4.1 Verify Bundle Without Importing (Read-Only Check)

```bash
secureship import-offline secureship-offline-bundle-2026-10-26.tar.gz \
  --trust-key secureship-offline-public.pem \
  --verify-only
```

#### 4.2 Dry-Run Import (Simulate Import Without Writing Database)

```bash
secureship import-offline secureship-offline-bundle-2026-10-26.tar.gz \
  --trust-key secureship-offline-public.pem \
  --dry-run
```

#### 4.3 Publish Verified Generation

```bash
secureship import-offline secureship-offline-bundle-2026-10-26.tar.gz \
  --trust-key secureship-offline-public.pem
```

Output:

```text
📥 SecureShip Offline Database & Engine Importer

✔ Successfully imported offline bundle:
  Generation:  gen-20261026-1a2b3c4d
  Bundle ID:   bundle-2026-10-26T12-00-00-abc123
  Trust:       VERIFIED (Ed25519)
  Components:  trivy-db, osv-offline-db, engine-binaries

You can now run offline scans with zero network access:
  secureship scan --offline .
```

---

### Step 5: Execute Offline Scans

Run scans with `--offline`. SecureShip guarantees zero outbound network packets and validates all findings against the local generation database:

```bash
secureship scan --offline /path/to/repo
```

To run in CI/CD with strict enforcement (failing if database is older than 30 days or missing):

```bash
secureship scan --offline --strict /path/to/repo
```

Under Docker with network completely disconnected:

```bash
docker run --rm --network none \
  -v "/path/to/repo:/workspace:ro" \
  -v "$HOME/.secureship/db:/opt/secureship/db:ro" \
  -e SECURESHIP_DB_DIR=/opt/secureship/db \
  secureship/cli:latest scan --offline /workspace
```

---

## 3. Rollback Procedure

If an imported generation contains an issue or needs to be immediately revoked, rollback instantly to the previous installed generation:

```bash
secureship import-offline --rollback
```

Output:

```text
✔ Successfully rolled back active generation to 'gen-20261019-9f8e7d6c'.
```

The rollback atomically updates the `CURRENT` generation pointer without deleting historical records.

---

## 4. Automated Refresh Schedule (Connected Gateway)

To maintain database freshness across connected gateways supplying air-gapped zones, set up a recurring cron job:

```cron
# Every Sunday at 02:00 AM UTC: Snapshot, sign, and export bundle
0 2 * * 0 /usr/local/bin/secureship bundle-offline \
  --output /var/secureship/export/bundle-latest.tar.gz \
  --sign-key /etc/secureship/keys/offline-private.pem \
  --key-id prod-secops \
  --force \
  --json >> /var/log/secureship-bundle.log 2>&1
```

---

## 5. Troubleshooting & Error Catalog

| Error Message                                                                                      | Cause                                                                                                                 | Resolution                                                                                                                        |
| :------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------- |
| `[Security Violation] Bundle is unsigned, but trusted keys were specified`                         | The bundle archive has no Ed25519 signature in its manifest.                                                          | Re-create bundle with `--sign-key` on the connected machine, or import with `--allow-unsigned` if explicitly permitted by policy. |
| `[Security Violation] Signature verification failed`                                               | The bundle signature does not match any provided public key.                                                          | Verify that the bundle was signed with the correct private key and that the public key matches.                                   |
| `[Security Violation] Anti-rollback rejected: Bundle timestamp is older than installed generation` | Attempting to import an older database bundle than the active generation.                                             | Provide `--allow-downgrade` to deliberately override rollback protection.                                                         |
| `[Offline Security Violation] Outbound network operation is strictly blocked`                      | A network-dependent feature (e.g. cloud AI provider, fleet remote reporting) was invoked while `--offline` is active. | Use local loopback models (Ollama on `http://127.0.0.1:11434`) or disable remote reporting.                                       |
| `[Offline Security Violation] No offline vulnerability database installed`                         | Scan ran with `--offline --strict` but no generation is installed in `CURRENT`.                                       | Import an offline bundle using `secureship import-offline` before scanning.                                                       |
