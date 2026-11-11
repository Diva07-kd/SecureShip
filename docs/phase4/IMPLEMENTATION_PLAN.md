# SecureShip Phase 4: AI Triage (Gate 3) — Implementation Plan (Approved with Amendments A1–A18)

## Goal

Implement **SecureShip Phase 4 ("AI TRIAGE (Gate 3)")** to production standard:

1. Provide an optional, opt-in, Bring-Your-Own-Key (BYOK) Large Language Model (LLM) triage layer that reads bounded, redacted code slices for remaining SAST and IaC findings and returns structured, evidence-cited verdicts (`LIKELY_TRUE_POSITIVE`, `LIKELY_FALSE_POSITIVE`, or `NEEDS_HUMAN_REVIEW`).
2. Default behavior is strictly **ANNOTATE-ONLY**: findings are tagged with evidence citations and rationales without dropping any findings.
3. Suppression is strictly opt-in (`--gate3 suppress`, marked EXPERIMENTAL) and gated behind an exhaustive safety checklist (SAST category only, non-critical/non-high severity, high confidence, verified citations, self-consistency agreement, slice not truncated, zero prompt injection).
4. Untrusted code is treated strictly as passive data inside random nonce-delimited blocks. Delimiter lookalikes are neutralized. Models have zero tool access and zero autonomous execution privileges.
5. Absolute backward compatibility: Phases 1–3 pipelines, contracts, exit codes, and test suites pass 100% unchanged.

---

## Plan Amendments Applied (A1–A18)

Where any prior plan text conflicted with these amendments, the amendment won:

- **A1 (Trust Schema Split)**: Created separate `UserConfigSchema` loaded strictly from per-user directory (`~/.secureship/config.json`), CLI flags, and environment variables. The repo `ConfigSchema` strictly rejects `ai` and `gate3` keys; if present in repo config, they are ignored with a warning. Never load `.env` files from the scan target.
- **A2 (API Keys)**: No `--api-key` CLI flag. API keys originate exclusively from environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `SECURESHIP_AI_API_KEY`) or an optional user-level 0600 file (`~/.secureship/ai-key`). Keys never appear in logs, traces, cache, reports, SARIF, or verbose output.
- **A3 (Endpoint and Consent Rules)**: Loopback is strictly restricted to literal `localhost`, `127.0.0.0/8`, and `[::1]` (rejecting lookalikes such as `localhost.evil.com`). URLs with embedded credentials, fragments, or non-http(s) schemes are rejected. HTTPS is mandatory for non-loopback. Model name is required (no default model). Consent strictly binds `scheme + host + port`; changes require re-consent. Non-interactive `ai enable` requires explicit `--provider`, `--model`, `--base-url`, and `--yes`.
- **A4 (Egress Redaction)**: Extended `SecretRedactor` with tests for Stripe (`sk_live_`, `rk_live_`), Slack (`xox` tokens), Google (`AIza` keys), npm tokens (`npm_`), credentialed connection URLs (`postgres://user:pass@...`), password/token assignments, and high-entropy string literals ($\ge 32$ chars). If `gitleaks` is on PATH, scanned assembled payload in a temp file (0600, deleted in `finally`) and redacted or skipped on match. Only root-relative POSIX paths sent. Scanner messages and snippets treated as untrusted data inside delimiters.
- **A5 (Credential-Class Findings)**: SAST findings with hardcoded credentials CWEs (CWE-798, CWE-259, CWE-321, `secureship-js-hardcoded-jwt-secret`) are skipped by Gate 3 with skip reason `CREDENTIAL_CLASS`, never sliced or egressed, like `SECRET`.
- **A6 (Prompt and Consistency)**: Per-request random nonce generation; regenerated if slice contains it; delimiter lookalikes neutralized. Temperature 0 where supported; if rejected, retried once without it and recorded `deterministic: false`. Consistency samples use distinct prompt variants (reordered slice sections and rephrased query). Consistency requires unanimous agreement across independently schema- and citation-verified samples. Max output tokens capped.
- **A7 (Output Sanitization)**: Strips ANSI escapes, control characters, bidi overrides (`\u202A`–`\u202E`, `\u2066`–`\u2069`), and zero-width characters (`\u200B`–`\u200D`, `\uFEFF`) from model text before rendering or serializing to JSON, SARIF, or terminal. Enforces length caps after sanitization. Model text is never executed or rendered as clickable links.
- **A8 (Cache)**: Keyed by `hash(provider, model, PROMPT_VERSION, schemaVersion, sliceHash, sampleVariant)`. Reuses Phase 3 external HMAC cache outside target. Stores only validated triage objects. Deterministically re-verifies citations against current slice on read. Not used by `--ai-dry-run`; bypassable via `--no-ai-cache`.
- **A9 (Policy Clarifications)**: Failures never alter scan exit codes (exit 0/1 preserved; missing key/consent/model with `--ai` exits 2; missing scanners exits 3). Suppressed findings reduce exit code under `--fail-on` naturally. AI never alters severity or `confidence`. Gate 3 suppress is marked `EXPERIMENTAL` with a banner. Final deterministic sort: Severity desc $\to$ Gate 2 reachability $\to$ AI verdict (`LIKELY_TRUE_POSITIVE`, `NEEDS_HUMAN_REVIEW`, `LIKELY_FALSE_POSITIVE`) $\to$ Fingerprint. AI never reorders above severity.
- **A10 (Concurrency, Abort, Fake Provider)**: Concurrency capped at max 2 with global backoff on 429. `AbortSignal` and `SIGINT` abort active requests, clean temp files, and exit 130. Fake provider isolated in `@secureship/ai/testing` (not selectable via repo config, omitted from CLI provider list).
- **A11 (explain Command)**: Report file treated as untrusted input. Accepts explicit `--root <dir>` (default cwd). Ignores report target and absolute paths; jails all paths within `--root`. Validates fingerprint exists. Applies consent, redaction, denylist, and egress rules. Output labeled advisory.
- **A12 (Contracts and SARIF)**: Explicit `ai` report summary schema (`provider`, `model`, `host` without credentials, `deterministic`, `findingsConsidered`, `findingsSent`, `findingsSkipped`, `tokensIn`, `tokensOut`, `filesSent`, `truncatedSlices`, `cacheHits`, `warnings`). SARIF exports `aiTriage` under `properties.secureship`. Gate 3 suppressions emitted with `justification = GATE3_LIKELY_FALSE_POSITIVE` only with `--include-suppressed`. `ScanReportSchema` tests updated for versions 1.0, 1.1, and 1.2.
- **A13 (Status and Tier Text)**: Status command text updated: local OpenAI-compatible endpoints (Ollama, LM Studio, vLLM) are included; managed private deployment and support = Enterprise. No license enforcement code.
- **A14 (Provider API Verification)**: Official Anthropic Messages API and OpenAI Chat Completions API specifications verified and recorded in `docs/phase4/PROVIDERS.md`. No hardcoded model names (docs examples only). No dependency on provider JSON modes. Zero vendor SDKs; zero new runtime dependencies.
- **A15 (Dry-Run, Estimate, Trace)**: `--ai-dry-run` and `--ai-estimate` require no key/consent and produce zero network requests while enforcing denylist and redaction. `--ai-trace` is opt-in, redacted, 0600 on POSIX. Egress report verified against recording test server.
- **A16 (Evaluation Honesty)**: Replay measures pipeline safety against scripted adversarial outputs; live runs measure accuracy and FP reduction. Without live API key, benchmark reports `PENDING-KEY`. Zero false-suppresses and 100% injection resistance required.
- **A17 (Docs and Standards)**: Full documentation suite delivered: `ARCHITECTURE.md`, `PRIVACY.md`, `SECURITY-MODEL.md`, `PROVIDERS.md`, `EVALUATION.md`, README updates, CHANGELOG. CI runs with fake provider. Global coverage $\ge 85/75$, per-file floor $\ge 70/70$ across all source files including `@secureship/ai` and `@secureship/context-slicer`. Zero `console.log` in libraries. Strict TypeScript (`noUncheckedIndexedAccess: true`), ESLint/Prettier clean.
- **A18 (Mutation Integrity)**: Committed `pnpm verify:mutations` script executes 21 faults against a temporary repository copy, verifying failing test names in `docs/phase4/mutation-log.md`.

---

## Non-Negotiable Principles

| ID     | Principle                    | Enforcement Mechanism                                                                                                                                                                                                                                                                                                                 |
| :----- | :--------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **T1** | **Off by Default**           | AI never activates unless user explicitly ran `secureship ai enable` (consent recorded) AND passed `--ai` on the scan invocation. Zero outbound network traffic leaves the machine without both prerequisites.                                                                                                                        |
| **T2** | **Conservative Suppression** | Suppression (`--gate3 suppress`) requires ALL: category SAST, severity not in `neverSuppressSeverities` (default `[CRITICAL, HIGH]`), verdict `LIKELY_FALSE_POSITIVE`, confidence `HIGH`, verified citations, consistency agreement, not truncated, no injection flag. IAC is annotate-only. SECRET and credential-class are skipped. |
| **T3** | **Strict Trust Model**       | AI enablement, provider, model, base URL, API keys, consent, and suppress mode may come ONLY from CLI flags, environment variables, or per-user config (`~/.secureship/`). Repo-provided `secureship.config.json` cannot enable AI or suppression (ignored with a warning). Canary server verifies zero requests.                     |
| **T4** | **Prompt-Injection Defense** | Code slice wrapped in random nonce delimiters (`<<<UNTRUSTED_CODE_${nonce}>>>`). Nonces regenerated if present in slice; delimiter lookalikes neutralized. Model has NO tools. Output strictly validated by Zod schema. Citations deterministically verified against slice. Injected instructions force `NEEDS_HUMAN_REVIEW`.         |
| **T5** | **Privacy & Minimal Egress** | Minimum code sliced; secrets redacted (`SecretRedactor`) before and after slicing; sensitive denylist files never read; optional gitleaks payload scan; `--ai-dry-run` displays exact payload without sending; egress audit summary included in every AI scan report. Egress report matches recording test server.                    |
| **T6** | **Failure Isolation**        | Any provider, network, or schema validation failure leaves the finding untouched with a warning. AI problems never alter scan exit codes (exit 0/1 preserved; missing key/consent/model exits 2; missing scanners exits 3). Suppressed findings naturally affect `--fail-on`.                                                         |
| **T7** | **Accounting Invariant P1**  | Every raw finding belongs to exactly one bucket: $\text{totalRaw} = \text{totalReported} + \text{totalSuppressed} + \text{totalOutOfScope}$. Gate 3 suppressions are recorded in the ledger as `GATE3_LIKELY_FALSE_POSITIVE`. Suppressed findings never dropped without a ledger entry.                                               |
| **T8** | **Determinism & Cache**      | Temperature 0 with deterministic:false fallback tracking, versioned prompts (`PROMPT_VERSION`), external HMAC-signed cache keyed by content hash. Re-verify citations on read. Bypassable via `--no-ai-cache`.                                                                                                                        |
| **T9** | **Backward Compatibility**   | Phase 1, 2, and 3 contracts, adapters, reachability engine, and benchmark suites continue to pass 100% unchanged. ScanReport moves from `1.1` to `1.2` (readers accept 1.0, 1.1, and 1.2).                                                                                                                                            |

---

## Architecture & Subsystems

```mermaid
flowchart TD
    RawFindings["Raw Scanner Findings (Normalized)"] --> DiffScope{"Diff Scope Check<br/>(Git Changed Files)"}

    DiffScope -- "Out of Scope" --> OutOfScope["totalOutOfScope<br/>(Never Enters Ledger)"]
    DiffScope -- "In Scope" --> Gate1{"Gate 1 Scope Tagging<br/>(Test / Mock / Doc / Example)"}

    Gate1 -- "Non-Production Scope" --> Gate1Supp["Ledger Suppress:<br/>GATE1_* Reason"]
    Gate1 -- "Production Scope" --> IgnoreCheck{"Ignore Rules<br/>(secureship.config.json)"}

    IgnoreCheck -- "Matches Active Rule" --> IgnoreSupp["Ledger Suppress:<br/>USER_IGNORE_RULE"]
    IgnoreCheck -- "No Match" --> BaselineCheck{".secureship/baseline.json"}

    BaselineCheck -- "Known Finding" --> BaseSupp["Ledger Suppress:<br/>BASELINE_KNOWN"]
    BaselineCheck -- "New Finding" --> Gate2["Gate 2: Reachability Engine<br/>(Import Graph & AST Analysis)"]

    Gate2 --> Gate2Mode{"Gate 2 Mode"}
    Gate2Mode -- "mode: suppress" --> Gate2SuppCheck{"Qualifies for SCA Suppress?<br/>SCA + UNREACHABLE + HIGH Conf"}
    Gate2SuppCheck -- "Yes" --> Gate2Supp["Ledger Suppress:<br/>GATE2_UNREACHABLE"]
    Gate2SuppCheck -- "No" --> Gate3Check{"Gate 3: AI Triage<br/>(--ai & Consent Granted?)"}
    Gate2Mode -- "mode: annotate / off" --> Gate3Check

    Gate3Check -- "AI Off / Not Opted In" --> FinalReport["Report Finding"]
    Gate3Check -- "AI Active" --> CategoryFilter{"Category / Rule Check"}

    CategoryFilter -- "SECRET, SCA, or Credential-Class (CWE-798/259/321)" --> SkipAI["Skip AI (Untouched, Recorded in Skipped)"]
    CategoryFilter -- "SAST or IAC" --> Slicer["@secureship/context-slicer<br/>- Denylist & Symlink Jail<br/>- Pre & Post Redaction (SecretRedactor)<br/>- AST Enclosing Scope & Resource<br/>- Usage Sites (Bounded Scan)"]

    Slicer --> Skeptic["@secureship/ai (Skeptic)<br/>- Nonce Delimited Prompt<br/>- Output Sanitization (Strip ANSI/Bidi)<br/>- Hardened Fetch (Loopback vs HTTPS, 1MB cap, no redirects)<br/>- Strict Zod Validation & Repair<br/>- Deterministic Citation Check<br/>- Self-Consistency (Distinct Prompts)"]

    Skeptic --> Gate3Mode{"Gate 3 Mode"}
    Gate3Mode -- "mode: annotate (Default)" --> AnnotateAI["Attach aiTriage<br/>Sort by Severity then AI Verdict<br/>Report Finding"]
    Gate3Mode -- "mode: suppress (Experimental)" --> SuppressCheck{"Qualifies for Suppression?<br/>SAST + NOT [CRITICAL,HIGH]<br/>+ LIKELY_FALSE_POSITIVE + HIGH Conf<br/>+ Verified Citations + Agreed<br/>+ Not Truncated + No Injection"}

    SuppressCheck -- "Yes" --> Gate3Supp["Ledger Suppress:<br/>GATE3_LIKELY_FALSE_POSITIVE"]
    SuppressCheck -- "No" --> AnnotateAI
    SkipAI --> FinalReport
    AnnotateAI --> FinalReport
```

---

## Proposed Changes per Package

### 1. `@secureship/contracts`

- [MODIFY] `packages/contracts/src/finding.schema.ts`:
  - Define `AiVerdictSchema`: `z.enum(['LIKELY_TRUE_POSITIVE', 'LIKELY_FALSE_POSITIVE', 'NEEDS_HUMAN_REVIEW'])`.
  - Define `AiCitationSchema`: `z.object({ file: z.string(), line: z.number().int().positive(), quote: z.string().max(200) })`.
  - Define `AiTriageSchema`:
    ```ts
    export const AiTriageSchema = z.object({
      verdict: AiVerdictSchema,
      confidence: ConfidenceSchema,
      rationale: z.string().max(600),
      citations: z.array(AiCitationSchema).max(5),
      exploitabilityNotes: z.string().max(300).optional(),
      model: z.string(),
      promptVersion: z.string(),
      cached: z.boolean(),
      consistency: z
        .object({ samples: z.number().int().positive(), agreed: z.boolean() })
        .optional(),
      tokens: z
        .object({ in: z.number().int().nonnegative(), out: z.number().int().nonnegative() })
        .optional(),
      injectionFlag: z.boolean().optional(),
    });
    ```
  - Add optional `aiTriage?: AiTriageSchema` to `NormalizedFindingSchema`.
- [MODIFY] `packages/contracts/src/suppression.schema.ts`:
  - Add `'GATE3_LIKELY_FALSE_POSITIVE'` to `SuppressionReasonCodeSchema`.
- [MODIFY] `packages/contracts/src/scan-report.schema.ts`:
  - Update `schemaVersion: z.enum(['1.0', '1.1', '1.2']).default('1.2')`.
  - Define `AiExecutionSummarySchema`:
    ```ts
    export const AiExecutionSummarySchema = z.object({
      provider: z.string(),
      model: z.string(),
      host: z.string(),
      deterministic: z.boolean(),
      findingsConsidered: z.number().int().nonnegative(),
      findingsSent: z.number().int().nonnegative(),
      findingsSkipped: z.array(
        z.object({
          reason: z.string(),
          count: z.number().int().nonnegative(),
        })
      ),
      tokensIn: z.number().int().nonnegative(),
      tokensOut: z.number().int().nonnegative(),
      filesSent: z.array(z.string()),
      truncatedSlices: z.number().int().nonnegative(),
      cacheHits: z.number().int().nonnegative(),
      warnings: z.array(z.string()),
    });
    ```
  - Add `byAiVerdict: z.record(AiVerdictSchema, z.number().int().nonnegative()).optional()` to `ScanSummarySchema`.
  - Add `ai: AiExecutionSummarySchema.optional()` to `ScanReportSchema`.
- [MODIFY] `packages/contracts/src/config.schema.ts`:
  - Repo `ConfigSchema`: Ensure `ai` and `gate3` are NOT accepted in `ConfigSchema`.
  - Define separate `UserConfigSchema`:
    ```ts
    export const UserConfigSchema = z.object({
      enabled: z.boolean().default(false),
      provider: z.enum(['anthropic', 'openai', 'fake']).optional(),
      model: z.string().optional(),
      baseUrl: z.string().url().optional(),
      gate3: z
        .object({
          mode: z.enum(['off', 'annotate', 'suppress']).default('annotate'),
          neverSuppressSeverities: z.array(SeveritySchema).default(['CRITICAL', 'HIGH']),
          minConfidence: ConfidenceSchema.default('HIGH'),
          consistencyChecks: z.number().int().positive().default(2),
          maxFindings: z.number().int().positive().default(25),
          budgetTokens: z.number().int().positive().default(200000),
          sliceTokens: z.number().int().positive().default(6000),
          concurrency: z.number().int().positive().default(2),
        })
        .default({}),
    });
    ```
- [MODIFY] `packages/contracts/src/tier-policy.schema.ts`:
  - Update descriptions to reflect that local loopback OpenAI-compatible endpoints are included for BYOK; enterprise tier designates managed on-prem deployments and commercial support.

---

### 2. `@secureship/context-slicer` (NEW WORKSPACE PACKAGE)

- [NEW] `packages/context-slicer/package.json`: workspace package configuration.
- [NEW] `packages/context-slicer/tsconfig.json`: TypeScript configuration.
- [NEW] `packages/context-slicer/src/index.ts`: Public API exports.
- [NEW] `packages/context-slicer/src/denylist.ts`:
  - Comprehensive sensitive file denylist (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx`, `credentials*`, `secrets*`, `*.kdbx`, `.npmrc`, `.pypirc`, `.netrc`, `terraform.tfstate*`, `.aws/*`, `.ssh/*`).
  - Path traversal and symlink jail verification (ensuring canonical realpath stays strictly inside scan root).
- [NEW] `packages/context-slicer/src/ast-scope.ts`:
  - AST boundary search using TreeSitterLoader for JS, TS, Python to enclose offending function/class/method.
  - Fallback window for other languages (+/- 30 lines).
  - IaC resource block parser for Terraform, CloudFormation, YAML, and JSON.
- [NEW] `packages/context-slicer/src/usage-finder.ts`:
  - Deterministic text scan for up to $K=3$ usage/call sites of flagged symbol within root.
  - Enforces denylist, binary skip, file size limit (1 MB), and reference scanner limits.
- [NEW] `packages/context-slicer/src/slicer.ts`:
  - Enforces two-pass redaction via extended `SecretRedactor` (before AST slicing and after payload assembly).
  - Optional Gitleaks verification scan: writes assembled payload to a 0600 temp file; if Gitleaks is available on PATH and flags any secret, redacts or skips the finding; temp file securely deleted in `finally`.
  - Converts all file paths to root-relative POSIX paths.
  - Rejects `SECRET` findings and credential-class findings (`CWE-798`, `CWE-259`, `CWE-321`, `secureship-js-hardcoded-jwt-secret`).
  - Bounded token estimation (`Math.ceil(chars / 4)`). Sets `truncated = true` when slice exceeds `sliceTokens`.

---

### 3. `@secureship/ai` (NEW WORKSPACE PACKAGE)

- [NEW] `packages/ai/package.json`: workspace package configuration.
- [NEW] `packages/ai/tsconfig.json`: TypeScript configuration.
- [NEW] `packages/ai/src/index.ts`: Public API exports.
- [NEW] `packages/ai/src/sanitize/output-sanitizer.ts`:
  - Strips ANSI escapes, control characters, bidi overrides (`\u202A`–`\u202E`, `\u2066`–`\u2069`), and zero-width characters (`\u200B`–`\u200D`, `\uFEFF`) from model output.
  - Enforces post-sanitization length caps.
- [NEW] `packages/ai/src/providers/provider.interface.ts`: `ILlmProvider`, `AiError`, and error taxonomy.
- [NEW] `packages/ai/src/providers/http-client.ts`:
  - Native fetch wrapper.
  - Loopback validation: strictly `localhost`, `127.0.0.0/8`, and `[::1]`; rejects `localhost.evil.com`.
  - Rejects URLs with embedded credentials, fragments, or non-http(s) schemes.
  - Requires HTTPS for non-loopback hosts.
  - Refuses redirects (`redirect: 'error'`).
  - Response size limit (1 MB).
  - Timeout and retry with exponential backoff on 429 (`Retry-After` honored).
  - Max concurrent requests (default 2) with global backoff on 429.
  - AbortSignal support.
- [NEW] `packages/ai/src/providers/anthropic.provider.ts`: Official Messages API (`/v1/messages`).
- [NEW] `packages/ai/src/providers/openai.provider.ts`: Official Chat Completions API (`/chat/completions`).
- [NEW] `packages/ai/src/testing/fake.provider.ts`: Fake provider in subpath `@secureship/ai/testing`.
- [NEW] `packages/ai/src/prompts/prompt-builder.ts`:
  - Dynamic cryptographically secure nonce generation per request; regenerates nonce if slice contains it.
  - Neutralizes delimiter lookalikes in untrusted slice data.
  - Treats scanner-provided rule messages and snippets as untrusted data within delimited blocks.
  - Prompt variation generator for consistency checks (reordering sections and rephrasing question).
- [NEW] `packages/ai/src/triage/triage-schema.ts`: Strict Zod schema for model response validation.
- [NEW] `packages/ai/src/triage/citation-verifier.ts`: Deterministic citation verification against the exact slice.
- [NEW] `packages/ai/src/triage/injection-detector.ts`: Heuristic injection scanner.
- [NEW] `packages/ai/src/triage/skeptic.ts`: End-to-end skeptical triage orchestrator.
- [NEW] `packages/ai/src/cache/ai-cache.ts`: External HMAC-signed cache keyed by content hash. Re-verifies citations on read.
- [NEW] `packages/ai/src/budget/budget-tracker.ts`: Token and finding budget counter with graceful saturation halt.
- [NEW] `packages/ai/src/consent/consent-manager.ts`: User consent file manager in user config directory (`~/.secureship/ai-consent.json`). Binds `scheme + host + port`.
- [NEW] `packages/ai/src/user-config/user-config-loader.ts`: Loads user configuration from `~/.secureship/config.json`, env vars, and CLI options. Never loads `.env` files from scan target.

---

### 4. `@secureship/core-engine`

- [MODIFY] `packages/core-engine/src/config/load-config.ts`:
  - Rejects `ai` and `gate3` in repo `secureship.config.json` with a warning; strips them from parsed repo config.
- [MODIFY] `packages/core-engine/src/security/secret-redactor.ts`:
  - Adds patterns for Google AIza keys, npm tokens, credentialed connection URLs (`postgres://...`), password string-literal assignments, and high-entropy string literals ($\ge 32$ chars).
- [MODIFY] `packages/core-engine/src/orchestrator/scan-orchestrator.ts`:
  - Gate 3 integration:
    - Filters findings: skips `SECRET`, `SCA`, and credential-class findings (`CWE-798`, `CWE-259`, `CWE-321`, `secureship-js-hardcoded-jwt-secret`).
    - Orders candidates: Severity desc $\to$ Reachability $\to$ Fingerprint.
    - Slices code with `@secureship/context-slicer`.
    - Triages with `@secureship/ai`.
    - Handles annotate mode (attaches `aiTriage`).
    - Handles suppress mode (routes qualifying findings to ledger under `GATE3_LIKELY_FALSE_POSITIVE`).
    - Sorts final reported findings: Severity desc $\to$ Gate 2 reachability $\to$ AI verdict (`LIKELY_TRUE_POSITIVE`, `NEEDS_HUMAN_REVIEW`, `LIKELY_FALSE_POSITIVE`) $\to$ Fingerprint.
    - Assembles `ScanReport` version `1.2` with `ai` summary block and `byAiVerdict` metrics.
- [MODIFY] `packages/core-engine/src/report/sarif-exporter.ts`:
  - Exports `aiTriage` under `properties.secureship`.
  - Emits Gate 3 suppressed findings with `justification = GATE3_LIKELY_FALSE_POSITIVE` only when `--include-suppressed` is true.

---

### 5. `@secureship/cli`

- [MODIFY] `packages/cli/src/commands/scan.ts`:
  - Adds flags: `--ai`, `--gate3 <off|annotate|suppress>`, `--ai-dry-run`, `--ai-estimate`, `--ai-max-findings`, `--ai-budget-tokens`, `--no-ai-cache`, `--ai-trace`.
  - Removes `--api-key` flag.
  - Missing key/consent/model with `--ai` exits 2.
  - All scanners missing with `--ai` preserves exit 3 without AI calls.
  - Banner for `--gate3 suppress` indicating experimental status, suppression counts, and how to inspect suppressed findings.
  - Advisory disclosure: `"AI triage is advisory, not proof."`
- [NEW] `packages/cli/src/commands/ai.ts`:
  - `secureship ai enable` (validates loopback/HTTPS, required model, consent binding; non-interactive mode requires `--provider`, `--model`, `--base-url`, `--yes`).
  - `secureship ai disable`.
  - `secureship ai status`.
  - `secureship ai test` (ping prompt without egressing workspace code).
- [NEW] `packages/cli/src/commands/explain.ts`:
  - `secureship explain <fingerprint|index> --report <file> --root <dir>`.
  - Jails report paths within `--root`; enforces consent, redaction, denylist, and egress rules; labels output advisory.
- [MODIFY] `packages/cli/src/commands/doctor.ts`:
  - Checks AI readiness: provider, model, consent status, and API key presence in environment or user file.
- [MODIFY] `packages/cli/src/commands/status.ts`:
  - Clarifies tier capability text per A13 (local loopback endpoints included for BYOK; enterprise is managed private deployment and support).

---

### 6. `@secureship/benchmark`

- [NEW] `packages/benchmark/corpus/gate3/`:
  - $\ge 40$ test cases across SAST and IaC covering clear TPs, tricky TPs, FP traps, and $\ge 15$ prompt injection variants.
  - Replay fixtures with committed outputs marked `source: real | synthetic`.
- [MODIFY] `packages/benchmark/src/metrics.ts`:
  - Metrics calculation for Gate 3: false-suppress count (threshold: 0), accuracy, FP reduction, injection resistance (threshold: 100%), tokens per finding.
- [MODIFY] `packages/benchmark/src/runner.ts` & `cli.ts`:
  - Support Gate 3 evaluation in replay (pipeline safety) and live modes (`PENDING-KEY` when no API key is set).

---

### 7. Mutation Harness & Documentation

- [MODIFY] `scripts/verify-mutations.mjs`:
  - Phase 4 mutation suite enforcing 21 faults on temporary repository copy:
    1. repo config enabling AI or setting baseUrl
    2. skipped consent check
    3. following redirects
    4. allowing http to non-loopback
    5. removed citation verification
    6. removed injection heuristic AND consistency check together
    7. suppressing HIGH by default
    8. suppressing IAC
    9. sending SECRET or credential-class findings
    10. skipped slicer redaction
    11. removed denylist
    12. following symlinks outside root
    13. fixed (non-random) nonce
    14. dropping Gate 3 suppressed findings without a ledger entry
    15. provider failure changing the exit code
    16. printing the API key in verbose output
    17. running Gate 3 on already-suppressed findings
    18. egress report undercounting files
    19. `localhost.evil.com` treated as loopback
    20. identical prompts used for consistency samples
    21. unsanitized model output (ANSI/bidi) reaching terminal
- [NEW] `docs/phase4/ARCHITECTURE.md`: High-level and component architecture.
- [NEW] `docs/phase4/PRIVACY.md`: Egress transparency, redaction, denylist, and inspection guide.
- [NEW] `docs/phase4/SECURITY-MODEL.md`: Threat model, defenses, and blunt limitations.
- [NEW] `docs/phase4/PROVIDERS.md`: Verified provider API specifications and documentation notes.
- [NEW] `docs/phase4/EVALUATION.md`: Empirical evaluation results.
- [NEW] `docs/phase4/mutation-log.md`: Mutation run log.

---

## Verification Plan

### Automated Tests

1. **Unit & Integration Tests**:
   - `packages/contracts`: Schema validation for `UserConfigSchema`, `ScanReportSchema` (1.0, 1.1, 1.2), `AiTriageSchema`.
   - `packages/core-engine`: `SecretRedactor` extended patterns, canary server test (repo config attempts zero network requests), ledger P1 invariant with Gate 3 suppressions.
   - `packages/context-slicer`: Denylist matching, symlink jail, AST scoping, usage finder, Gitleaks payload scan, credential-class filtering.
   - `packages/ai`: HTTP client (loopback validation, redirect rejection, 1MB limit, 429 backoff, abort signal), prompt builder (nonce generation, variants), output sanitizer (ANSI/bidi stripping), skeptic triage, HMAC cache with citation re-check.
   - `packages/cli`: CLI flags, `scan --ai`, `--ai-dry-run` (verifying zero secrets), `explain` (jail inside `--root`), `ai enable/disable/status/test`.
2. **Coverage Enforcement**:
   - `pnpm test:coverage`: Enforces $\ge 85\%$ lines, $\ge 75\%$ branches per package, and $\ge 70\%$ lines and branches per file across all source files in `vitest.config.ts`.
3. **Pipeline Quality Gates**:
   - `pnpm build`: Clean build of all 8 workspace packages.
   - `pnpm typecheck`: Clean TypeScript compilation with strict flags.
   - `pnpm lint`: Clean ESLint.
   - `pnpm format:check`: Clean Prettier check.
   - `pnpm verify:mutations`: All 21 Phase 4 mutations caught with failing test names.
   - `pnpm benchmark:replay`: 0 false-suppresses, 100% injection resistance.
