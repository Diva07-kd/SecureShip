# SecureShip Gate 3 Privacy & Data Egress Policy

## 1. Principles of Minimal Disclosure

SecureShip Gate 3 implements a strict zero-leakage, zero-surprise egress architecture. Before any snippet leaves the machine, it must pass multiple containment and redaction stages. When using external LLM providers (e.g. Anthropic, OpenAI) or private self-hosted endpoints (Ollama, LM Studio, vLLM), SecureShip guarantees that only the minimal necessary syntactic context is transmitted.

---

## 2. What Is Sent

Every AI triage request consists of a structured JSON payload containing:

1. **System Prompt**: Rigid analytical instructions and JSON schema constraints. Contains zero user data or workspace context.
2. **User Prompt**:
   - **Candidate Finding Metadata**:
     - `findingId`: Synthetic identifier (e.g., `sast-rule-1`).
     - `ruleId`: SAST rule identifier (e.g., `rules.security.sql_injection`).
     - `severity`: Severity label (`HIGH`, `MEDIUM`, `LOW`, `INFO`).
     - `location`: Root-relative POSIX path (e.g., `src/server/db.ts`) and target line range.
   - **Scanner Evidence**:
     - The untrusted scanner message and finding snippet, enclosed in delimiters.
   - **Contextual Code Slice**:
     - The enclosing AST scope (function, class method, or Terraform block) extracted by `@secureship/context-slicer`.
     - Delimited by a unique, cryptographically random per-request 24-character hexadecimal nonce:
       `<<<SECURESHIP_CODE_SLICE_a1b2c3d4e5f6...>>>`
     - All occurrences of delimiter lookalikes in the source code are neutralized before insertion.

---

## 3. What Is NEVER Sent

Under no circumstances will SecureShip Gate 3 send:

### 3.1 Absolute Paths & User Identities

- Target directories, absolute file paths, Windows drive letters, user directories (`/home/username/`, `C:\Users\username\`), and usernames are never included.
- All file paths are strictly normalized to root-relative POSIX format (`src/app.ts`).

### 3.2 Secret and Credential-Class Findings

- Any finding classified under the `SECRET` category (e.g., by Gitleaks or Trivy) is immediately skipped (`skipReason: 'SECRET'`) and never sliced or transmitted.
- Any finding whose CWE is hardcoded credentials (`CWE-798`, `CWE-259`, `CWE-321`) or whose rule is `secureship-js-hardcoded-jwt-secret` is skipped (`skipReason: 'CREDENTIAL_CLASS'`) and never sliced or transmitted.

### 3.3 Sensitive Files & Configuration (Denylist)

Files matching any of the following patterns are blocked by `SlicerDenylist`:

- Environment files: `.env*` (`.env`, `.env.*`, `*.env`)
- Private keys and certificates: `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `*.crt`, `*.der`
- Credentials and secrets: `credentials*`, `secrets*`, `*.kdbx`
- Tool and package manager configs: `.npmrc`, `.pypirc`, `.netrc`
- Infrastructure state: `terraform.tfstate*`, `*.tfstate`, `*.tfstate.backup`
- Cloud, remote and VCS directories: `.aws/**`, `.ssh/**`, `.git/**`, `.azure/**`, `.gcp/**`, `.kube/**`, `.secureship/**`
- Keystores: `*.jks`, `*.keystore`

### 3.4 Out-of-Workspace Content (Symlink Jailing)

- All target paths and symlinks are resolved using canonical real paths (`fs.realpathSync`). Any symlink pointing outside the workspace root is rejected (`skipReason: 'SYMLINK_JAIL_ESCAPE'`).

### 3.5 Embedded Secrets & High-Entropy Strings (Redactor)

Before transmission, both raw source files and extracted AST slices undergo two-pass automated redaction:

- **Stripe live keys**: `sk_live_[0-9a-zA-Z]{20,99}`, `rk_live_[0-9a-zA-Z]{20,99}`
- **Slack tokens**: `xox[baprs]-[0-9a-zA-Z-]{10,72}`
- **Google API keys**: `AIza[0-9A-Za-z-_]{35}`
- **npm tokens**: `npm_[A-Za-z0-9]{36}`
- **Credentialed URLs**: `postgres://user:pass@host:5432/db` $\to$ `postgres://user:[REDACTED_PASSWORD]@host:5432/db`
- **Variable assignments**: Assignments to `password`, `secret`, `token`, `apikey` $\to$ `[REDACTED_SECRET]`
- **High-entropy strings**: Any quoted string literal $\ge 32$ characters with Shannon entropy $\ge 3.6$ $\to$ `[REDACTED_HIGH_ENTROPY]`
- **Optional Gitleaks scan**: When `gitleaks` is available on `PATH`, the fully assembled payload is scanned as a temporary 0600 file; any detected secret aborts the request.

---

## 4. How to Inspect and Verify Egress

SecureShip provides three distinct modes for verifying what data would leave your machine:

### 4.1 Dry-Run Mode (`--ai-dry-run`)

- Executes the full AST extraction, denylist checks, and two-pass secret redaction.
- Assembles the complete prompt without making any network requests.
- Requires no API key and no endpoint consent.
- Emits advisory dry-run triage verdicts and prints the exact files and tokens that would be processed.

### 4.2 Token Estimation (`--ai-estimate`)

- Quickly calculates the token count, byte footprint, and number of eligible findings.
- Produces zero network calls.

### 4.3 Audit Tracing (`--ai-trace`)

- Opt-in diagnostic audit flag.
- Writes an exact trace of every prompt sent and raw response received to an explicit path or defaults to the per-user data directory (`$LOCALAPPDATA/secureship/traces/` on Windows or `~/.secureship/traces/` on POSIX). It is **NEVER** written inside the scan target repository, guaranteeing prompts and code slices are never committed.
- File is created with restricted permissions (`0600` on POSIX systems).
- All secret redactions remain applied in the trace file.

### 4.4 Automated Egress Accounting

The final execution report's `ai` summary block (`filesSent`, `tokensIn`, `tokensOut`) is continuously verified in automated integration tests against recorded mock server traffic to ensure byte-for-byte accounting honesty.
