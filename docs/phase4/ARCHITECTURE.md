# SecureShip Phase 4: Gate 3 AI Triage Architecture

## 1. Executive Overview

Phase 4 introduces **Gate 3 AI Triage**, an advisory and experimental suppression engine designed to triage Static Application Security Testing (SAST) and Infrastructure as Code (IaC) findings using targeted contextual code slices and Large Language Models (LLMs). IaC misconfigurations are annotate-eligible in Gate 3, and ContextSlicer covers JS, TS, Python, and Terraform/YAML/Dockerfile blocks. Gate 3 operates under strict security boundaries, defense-in-depth against prompt injection, zero network transmission without explicit user consent, and fail-safe policy enforcement.

```mermaid
flowchart TD
    RawFindings[Scanner Findings] --> Diff[Diff Scoping]
    Diff --> Gate1[Gate 1 Scope Classifier]
    Gate1 --> Ignore[Ignore Rules Evaluator]
    Ignore --> Baseline[Baseline Ledger]
    Baseline --> Gate2[Gate 2 Reachability Engine]
    Gate2 --> CandidateFilter{Eligible for Gate 3?}
    CandidateFilter -- "SECRET / SCA / CREDENTIAL_CLASS / Out of Budget" --> ReportDirect[Add to Reported Findings]
    CandidateFilter -- "SAST or IAC (Non-Credential)" --> Slicer[ContextSlicer]

    subgraph ContextSlicer Engine
        Slicer --> DenylistCheck{Sensitive Denylist / Symlink Jail?}
        DenylistCheck -- Match --> SlicerSkip[Skip Finding]
        DenylistCheck -- Pass --> AstScope[AstScopeFinder + UsageFinder]
        AstScope --> RedactorPass1[Pass 1 Secret Redactor]
        RedactorPass1 --> RedactorPass2[Pass 2 Payload Redactor]
        RedactorPass2 --> Truncation[Token Budget Truncator]
    end

    Truncation --> PromptBuilder[PromptBuilder with Dynamic Nonce]
    PromptBuilder --> SkepticEngine[SkepticEngine]

    subgraph Skeptic Triage & Verification
        SkepticEngine --> CacheCheck{External HMAC Cache}
        CacheCheck -- Hit --> VerifyCacheCitations[Re-verify Cached Citations]
        CacheCheck -- Miss --> ProviderClient[HttpClient / LLM Provider]
        ProviderClient --> JsonParse[Strict TriageSchema Validator]
        JsonParse --> Citations[CitationVerifier]
        Citations --> Injection[InjectionDetector]
        Injection --> Consistency{Suppress Mode?}
        Consistency -- Yes --> Sample2[Consistency Prompt Variant Request]
        Sample2 --> ConsistencyCheck{Both Samples Agree?}
        Consistency -- No --> Sanitizer[OutputSanitizer]
        ConsistencyCheck -- Yes --> Sanitizer
        ConsistencyCheck -- No --> DowngradeHuman[Downgrade to NEEDS_HUMAN_REVIEW]
        DowngradeHuman --> Sanitizer
    end

    Sanitizer --> SuppressionPolicy{Gate 3 Mode: Suppress?}
    SuppressionPolicy -- "Suppress Mode & LIKELY_FALSE_POSITIVE & Agreed & Citations Valid" --> SuppressLedger[SuppressionLedger: GATE3_LIKELY_FALSE_POSITIVE]
    SuppressionPolicy -- "Annotate Mode or Not Qualifying" --> ReportWithTriage[Add to Reported with aiTriage]

    SuppressLedger --> Sort[Deterministic Sort: Severity desc -> Reachability -> AI Verdict -> Fingerprint]
    ReportWithTriage --> Sort
    ReportDirect --> Sort
    Sort --> Output[ReportBuilder / SARIF Exporter / CLI Output]
```

---

## 2. Component Breakdown

### 2.1 `@secureship/context-slicer`

The context slicer is responsible for extracting the minimal relevant syntactic scope around a finding while preventing data exfiltration:

- **`SlicerDenylist`**: Prevents reading sensitive configuration, secret files, credential stores, keys, certificates, or VCS directories (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `*.p12`, `*.pfx`, `credentials*`, `secrets*`, `*.kdbx`, `.npmrc`, `.pypirc`, `.netrc`, `terraform.tfstate*`, `.aws/**`, `.ssh/**`, `.git/**`).
- **Symlink Jailing**: Resolves paths via `fs.realpathSync` to guarantee symlinks cannot escape the scan target workspace.
- **`AstScopeFinder`**: Parses JavaScript, TypeScript, Python, and IaC (Terraform HCL blocks, YAML, Dockerfile) to extract enclosing functions, classes, resource blocks, or bounded line windows.
- **`UsageFinder`**: Identifies call sites and references to provide context on tainted inputs without extracting whole files.
- **`SecretRedactor`**: Two-pass redactor scanning both raw file content and sliced fragments for:
  - Stripe secret keys (`sk_live_`, `rk_live_`)
  - Slack tokens (`xox[baprs]-*`)
  - Google API keys (`AIza*`)
  - npm tokens (`npm_*`)
  - Credentialed connection URLs (`postgres://user:pass@host`)
  - String-literal password/secret/token assignments
  - High-entropy strings ($\ge 32$ chars, Shannon entropy $\ge 3.6$)
- **Token Budgeting**: Clamps total code slice tokens (default 6,000 tokens) using token estimation. Truncated slices are flagged and disqualified from automated suppression.

### 2.2 `@secureship/ai`

The AI triage orchestration package provides structured reasoning, communication, and skepticism:

- **`PromptBuilder`**:
  - Dynamically generates random 24-character hexadecimal nonces per request.
  - Automatically neutralizes any delimiter lookalikes in untrusted input.
  - Generates distinct prompt variants for consistency checks (reordering sections and rephrasing analytical queries) so temperature-0 evaluations provide an independent signal.
- **`HttpClient`**:
  - Validates endpoints strictly: loopback hosts are restricted to literal `localhost`, `127.0.0.0/8`, and `[::1]` (rejecting lookalikes such as `localhost.evil.com`).
  - Rejects URLs with embedded credentials, fragments, or non-http(s) schemes.
  - Enforces HTTPS for all non-loopback endpoints.
  - Explicitly refuses HTTP redirects (`redirect: 'error'`).
  - Employs exponential backoff on HTTP 429 rate limits.
- **`SkepticEngine`**:
  - Parses LLM responses against the rigid Zod `TriageResultSchema`.
  - Runs `CitationVerifier`: every citation quote must exist verbatim in the supplied code slice. Fabricated or misquoted citations force verdict downgrade to `NEEDS_HUMAN_REVIEW`.
  - Runs `InjectionDetector`: detects heuristic instruction override patterns (`ignore previous instructions`, `system prompt`, `override`, `jailbreak`, etc.).
  - Executes self-consistency validation in `suppress` mode.
- **`ConsentManager`**:
  - Stores user consent cryptographically bound to `scheme + host + port`. Any destination change invalidates prior consent.
- **`AiCache`**:
  - External HMAC-SHA256 cache residing outside the scan repository.
  - Cache key incorporates provider, model, prompt version, schema version, slice hash, and prompt variant.
  - Re-verifies citations against current code slice upon read.
- **`OutputSanitizer`**:
  - Strips ANSI escape codes, terminal control sequences, Unicode bidirectional (bidi) override characters, and zero-width spaces from model responses before terminal, JSON, or SARIF emission.

---

## 3. Trust Boundary & Data Isolation

| Layer                        | Source of Truth                             | Trust Level            | Security Controls                                                                                                                   |
| :--------------------------- | :------------------------------------------ | :--------------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| **User Configuration**       | `~/.secureship/config.json`, CLI flags, env | High (Trusted)         | AI enablement, model, provider, baseUrl, and gate3 mode are sourced strictly from the user environment.                             |
| **Repository Configuration** | `secureship.config.json`                    | Untrusted              | Ignored if containing `ai` or `gate3` keys with a security warning. Cannot enable AI or redirect traffic to canary endpoints.       |
| **Code Base & Slices**       | Scan target workspace                       | Untrusted              | Delimited by random nonces, sanitized, redacted for secrets, checked against denylist, jailed against symlink breakout.             |
| **Scanner Messages**         | AST / SCA / SAST engines                    | Untrusted              | Treated as untrusted text; placed strictly inside delimited slice prompt blocks.                                                    |
| **Model Output**             | LLM Provider response                       | Adversarial / Advisory | Sanitized against ANSI/bidi attacks; validated against Zod schema; checked for injection cues; verified with exact slice citations. |

---

## 4. Pipeline Precedence & Ledger Accounting (Invariant P1)

Findings flow through the pipeline in strict order:
$$\text{Diff Scoping} \longrightarrow \text{Gate 1 (Scope)} \longrightarrow \text{Ignore Rules} \longrightarrow \text{Baseline} \longrightarrow \text{Gate 2 (Reachability)} \longrightarrow \text{Gate 3 (AI Triage)}$$

- **Invariant P1 Integrity**:
  $$\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$$
  Every finding that reaches Gate 3 is either suppressed into `GATE3_LIKELY_FALSE_POSITIVE` in the suppression ledger or recorded in the reported findings list. No finding can be both or dropped without a ledger record.
- **Deterministic Sort**:
  1. Severity descending (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`)
  2. Gate 2 Reachability (`REACHABLE_CALL_PATH` > `REACHABLE_IMPORT` > `UNKNOWN` > `UNREACHABLE`)
  3. Gate 3 AI Verdict (`LIKELY_TRUE_POSITIVE` > `NEEDS_HUMAN_REVIEW` > `LIKELY_FALSE_POSITIVE`)
  4. Fingerprint ascending (lexicographical tie-breaker)
     _AI triage never promotes or reorders findings above severity._
