# SecureShip Phase 4: Security & Adversarial Threat Model

> [!CAUTION] > **Fundamental Security Limitation**: Large Language Model (LLM) prompt injection defenses are probabilistic mitigations, **NOT mathematical guarantees**. Automated AI suppression of security findings carries the inherent risk of concealing genuine vulnerabilities if an adversary successfully manipulates model judgment.

---

## 1. Threat Overview & Adversarial Goals

In Phase 4 Gate 3, SecureShip accepts code from target repositories that may contain malicious payloads, adversarial comments, crafted test fixtures, or deliberate prompt injections.

### Adversarial Objectives

1. **Suppression Force**: Trick the LLM into classifying a true vulnerability as a false positive (`LIKELY_FALSE_POSITIVE`), hiding it from the security team and CI/CD gates.
2. **Data Exfiltration**: Induce the model or client to transmit sensitive credentials, API keys, environmental variables, or proprietary source code to unauthorized endpoints.
3. **Denial of Service / Resource Exhaustion**: Inject unbounded tokens, trigger infinite loops, or trigger rate limits (HTTP 429) to stall automated pipelines.
4. **Terminal / Client Manipulation**: Exploit terminal emulators or report parsers using ANSI escapes, bidirectional (bidi) text overrides, or zero-width unicode attacks to disguise malicious actions.

---

## 2. Multi-Layer Defense-in-Depth

SecureShip rejects the naive assumption that LLMs can safely evaluate untrusted input on their own. Instead, it enforces six distinct defense layers:

```
[Target Code]
     │
     ▼
Layer 1: Pre-Transmission Isolation (Denylist, Symlink Jail, Secret Redactor)
     │
     ▼
Layer 2: Prompt Hardening (Per-Request Nonce, Delimiter Neutralization)
     │
     ▼
Layer 3: Heuristic Injection Detection (Pre- & Post-Model Heuristics)
     │
     ▼
Layer 4: Deterministic citation verification (Verbatim Citation Verification)
     │
     ▼
Layer 5: Multi-Prompt Self-Consistency (Distinct Query Variants)
     │
     ▼
Layer 6: Policy & Accounting Hard Floor (Severity / Category / Ledger Floors)
```

---

### Layer 1: Pre-Transmission Containment & Redaction

- **Denylist Rejection**: Files matching sensitive patterns (`.env*`, `.git/*`, `*.pem`, `id_rsa`, `*.tfstate`, `.npmrc`, etc.) are blocked at the slicer stage and never read or transmitted.
- **Symlink Jailing**: All target paths are checked with `fs.realpathSync`. Any path escaping the workspace root is rejected with `SYMLINK_JAIL_ESCAPE`.
- **Two-Pass Automated Redaction**: Before transmission, both raw files and AST slices are scanned and redacted for Stripe keys, Slack tokens, Google AIza keys, npm tokens, credentialed URLs (`user:pass@host`), variable assignments to passwords/secrets, and high-entropy string literals ($\ge 32$ chars, entropy $\ge 3.6$).
- **Secret & Credential Findings Excluded**: Findings in category `SECRET` or credential-class SAST (`CWE-798`, `CWE-259`, `CWE-321`) are immediately skipped (`CREDENTIAL_CLASS`) and never sent to Gate 3.

---

### Layer 2: Prompt Nonce & Delimiter Neutralization

- **Cryptographic Nonce**: Every triage request generates a cryptographically random 24-character hexadecimal nonce (`<<<UNTRUSTED_DATA_{nonce}>>>`).
- **Lookalike Neutralization**: All occurrences of delimiter patterns (`<<<UNTRUSTED_`, `<<<END_UNTRUSTED_`) in the source code or scanner evidence are neutralized to `<<<NEUTRALIZED_` prior to insertion.
- **Nonce Regeneration**: If the raw code slice contains the generated candidate nonce, the system discards it and regenerates a new nonce.

---

### Layer 3: Heuristic Injection Detection

The `InjectionDetector` scans the code slice, scanner messages, and model rationale for known prompt injection signatures, including:

- Instruction resets (`ignore previous instructions`, `system prompt`, `override all rules`)
- Role / Persona hijacking (`you are now a helpful assistant`, `developer mode`, `DAN mode`)
- Suppression mandates (`mark this as safe`, `classify as false positive`, `this is not a vulnerability`)
- Delimiter breakout attempts (`<<<END_UNTRUSTED`, `[SYSTEM]`, `<|im_start|>`)

**Enforcement**: Any detected injection trigger locks the verdict to `NEEDS_HUMAN_REVIEW` and prefixes the rationale with a security warning.

---

### Layer 4: Skeptic Citation Verification

A model cannot merely declare a finding to be a false positive; it must cite verbatim proof.

- **Citation Format**: Every citation in `citations` must provide `file`, `line`, and `quote`.
- **Verbatim Match**: `CitationVerifier` validates that the cited line exists in the primary slice and that `quote` matches the actual source text on that line.
- **Enforcement**: If any citation is fabricated, misquoted, or points to a non-existent line, the verdict is immediately downgraded from `LIKELY_FALSE_POSITIVE` to `NEEDS_HUMAN_REVIEW`.

---

### Layer 5: Self-Consistency Sample in Suppress Mode

In `suppress` mode, temperature-0 models can be deceptively confident. Therefore:

- SecureShip executes **two independent requests with distinct prompt variants**:
  - **Variant 0**: Finding attributes $\to$ Delimited Slice $\to$ Standard Question.
  - **Variant 1**: Delimited Slice (reordered sections) $\to$ Finding attributes $\to$ Rephrased Analytical Query.
- **Consensus Requirement**: Automated suppression occurs **only if both samples independently pass schema validation, pass citation verification, and agree unanimously on `LIKELY_FALSE_POSITIVE`**. Any disagreement defaults to `NEEDS_HUMAN_REVIEW`.

---

### Layer 6: Policy & Suppression Floors

Automated suppression is constrained by hard policy rules:

1. **Severity Floor**: `CRITICAL` and `HIGH` findings are **NEVER suppressed by default** (`neverSuppressSeverities: ['CRITICAL', 'HIGH']`).
2. **Category Floor**: Only `SAST` findings are eligible for Gate 3 suppression; Infrastructure-as-Code (`IAC`), SCA, and Secret findings are never suppressed.
3. **Confidence Floor**: Only `HIGH` confidence verdicts can trigger suppression.
4. **Truncation Disqualification**: If a code slice was truncated to fit the token budget, it is automatically disqualified from suppression.
5. **Experimental Banner**: Suppress mode is marked `EXPERIMENTAL` in CLI help and displays a prominent warning banner during execution:
   ```
   [GATE 3 EXPERIMENTAL] AI-assisted suppression is active.
   Suppressed findings: 3. Review all suppressed findings with --include-suppressed.
   ```
6. **Output Sanitization**: Model rationale and exploitability notes are stripped of ANSI escape codes, terminal control characters, Unicode bidirectional overrides, and zero-width spaces before reaching stdout, stderr, JSON, or SARIF reports. Model text is never executed or rendered as clickable HTML/terminal links.
