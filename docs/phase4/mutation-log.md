# SecureShip Phase 4: Mutation Verification Log (M1–M21)

In accordance with Phase 4 Amendment A18 specification, this log records the real execution of `pnpm verify:mutations`. Each mutation was applied to an isolated temporary copy of the repository in `$env:TEMP`, evaluated against the verification test suite, and confirmed to fail with specific failing test names.

**Verification Attestation:** Exactly 21 out of 21 mutations were successfully caught (0 uncaught mutations). Bidirectional proof confirms that each test fails under mutation and passes cleanly when restored.

---

## 1. Mutation Summary Table

| ID      | Description                                                | Target File                                                  | Verification Test                                     |   Status   | Failing Test(s)                                                                                              |
| :------ | :--------------------------------------------------------- | :----------------------------------------------------------- | :---------------------------------------------------- | :--------: | :----------------------------------------------------------------------------------------------------------- |
| **M1**  | repo config enabling AI or setting baseUrl                 | `packages/core-engine/src/config/load-config.ts`             | `packages/core-engine/test/config-loader.test.ts`     | **CAUGHT** | `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`                              |
| **M2**  | skipped consent check                                      | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `enforces consent check on non-dry-run scans`                                                                |
| **M3**  | following redirects                                        | `packages/ai/src/providers/http-client.ts`                   | `packages/ai/test/http-client.test.ts`                | **CAUGHT** | `refuses redirects (redirect: error)`                                                                        |
| **M4**  | allowing http to non-loopback                              | `packages/ai/src/providers/http-client.ts`                   | `packages/ai/test/http-client.test.ts`                | **CAUGHT** | `strictly requires HTTPS for non-loopback endpoints`                                                         |
| **M5**  | removed citation verification                              | `packages/ai/src/triage/skeptic.ts`                          | `packages/ai/test/skeptic.test.ts`                    | **CAUGHT** | `downgrades to NEEDS_HUMAN_REVIEW when citation quote is fabricated or missing`                              |
| **M6**  | removed injection heuristic AND consistency check together | `packages/ai/src/triage/skeptic.ts`                          | `packages/ai/test/skeptic.test.ts`                    | **CAUGHT** | `locks verdict to NEEDS_HUMAN_REVIEW when prompt injection is detected in slice (T4)`                        |
| **M7**  | suppressing HIGH by default                                | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `in suppress mode: never suppresses HIGH severity findings by default`                                       |
| **M8**  | suppressing IAC                                            | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `in suppress mode: never suppresses IAC findings`                                                            |
| **M9**  | sending SECRET or credential-class findings                | `packages/context-slicer/src/slicer.ts`                      | `packages/context-slicer/test/slicer.test.ts`         | **CAUGHT** | `rejects SECRET category findings immediately (A5, T2)`                                                      |
| **M10** | skipped slicer redaction                                   | `packages/context-slicer/src/redactor.ts`                    | `packages/context-slicer/test/slicer.test.ts`         | **CAUGHT** | `slices JS/TS function and redacts embedded secrets with two passes (A4)`                                    |
| **M11** | removed denylist                                           | `packages/context-slicer/src/slicer.ts`                      | `packages/context-slicer/test/slicer.test.ts`         | **CAUGHT** | `enforces sensitive file denylist (A4)`                                                                      |
| **M12** | following symlinks outside root                            | `packages/context-slicer/src/denylist.ts`                    | `packages/context-slicer/test/slicer.test.ts`         | **CAUGHT** | `prevents symlink jailbreaks and path traversal outside root (A11)`                                          |
| **M13** | fixed (non-random) nonce                                   | `packages/ai/src/prompts/prompt-builder.ts`                  | `packages/ai/test/prompt-builder.test.ts`             | **CAUGHT** | `generates random and non-fixed nonces per request`                                                          |
| **M14** | dropping Gate 3 suppressed findings without a ledger entry | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `records Gate 3 suppressed findings in the suppression ledger`                                               |
| **M15** | provider failure changing the exit code                    | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `provider failure falls back gracefully without failing the scan`                                            |
| **M16** | printing the API key in verbose output                     | `packages/cli/src/commands/scan.ts`                          | `packages/cli/test/ai-cli.test.ts`                    | **CAUGHT** | `never prints API key in verbose or report output (A2, A18)`                                                 |
| **M17** | running Gate 3 on already-suppressed findings              | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `skips already-suppressed findings and never sends them to Gate 3`                                           |
| **M18** | egress report undercounting files                          | `packages/core-engine/src/orchestrator/scan-orchestrator.ts` | `packages/core-engine/test/gate3-integration.test.ts` | **CAUGHT** | `egress-accounting: report filesSent/bytes/tokens equal what recording local server actually received (R13)` |
| **M19** | localhost.evil.com treated as loopback                     | `packages/ai/src/providers/http-client.ts`                   | `packages/ai/test/http-client.test.ts`                | **CAUGHT** | `correctly classifies loopback hosts and rejects lookalikes`                                                 |
| **M20** | identical prompts used for consistency samples             | `packages/ai/src/prompts/prompt-builder.ts`                  | `packages/ai/test/prompt-builder.test.ts`             | **CAUGHT** | `consistency prompt variants produce different user prompts`                                                 |
| **M21** | unsanitized model output (ANSI/bidi) reaching the terminal | `packages/ai/src/sanitize/output-sanitizer.ts`               | `packages/ai/test/sanitizer.test.ts`                  | **CAUGHT** | `strips ANSI color escapes`                                                                                  |

---

## 2. Bidirectional Proofs (Pass on Restoration)

### Mutation M1: repo config enabling AI or setting baseUrl

- **Target File:** `packages/core-engine/src/config/load-config.ts`
- **Verification Suite:** `packages/core-engine/test/config-loader.test.ts`
- **Applied Mutation Patch:**

```diff
-       if ('ai' in obj) {
-         console.warn(
-           `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'ai'. AI configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'ai'.`
-         );
-         delete obj.ai;
-       }
+       if (false && 'ai' in obj) {
+         delete obj.ai;
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M2: skipped consent check

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-           if (!consentCheck.consented) {
-             throw new AiError(
-               consentCheck.reason ||
-                 'AI consent has not been granted. Run "secureship ai enable" to record consent.',
-               'CONFIG_ERROR'
-             );
-           }
+           if (false && !consentCheck.consented) {
+             throw new AiError('AI consent has not been granted.', 'CONFIG_ERROR');
+           }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `enforces consent check on non-dry-run scans`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M3: following redirects

- **Target File:** `packages/ai/src/providers/http-client.ts`
- **Verification Suite:** `packages/ai/test/http-client.test.ts`
- **Applied Mutation Patch:**

```diff
-         redirect: 'error',
+         redirect: 'follow', // MUTATION: follows redirects
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `refuses redirects (redirect: error)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M4: allowing http to non-loopback

- **Target File:** `packages/ai/src/providers/http-client.ts`
- **Verification Suite:** `packages/ai/test/http-client.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (!isLoopback && url.protocol !== 'https:') {
-       throw new AiError(
-         `Insecure endpoint '${urlString}': HTTPS is strictly required for non-loopback hosts.`,
-         'CONFIG_ERROR'
-       );
-     }
+     if (false && !isLoopback && url.protocol !== 'https:') {
+       throw new AiError('Insecure endpoint', 'CONFIG_ERROR');
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `strictly requires HTTPS for non-loopback endpoints`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M5: removed citation verification

- **Target File:** `packages/ai/src/triage/skeptic.ts`
- **Verification Suite:** `packages/ai/test/skeptic.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (!citationCheck.valid) {
-       candidateVerdict = 'NEEDS_HUMAN_REVIEW';
-       sanitizedRationale = OutputSanitizer.sanitizeRationale(
-         `[Citation verification failed: ${citationCheck.failureReason}] ${sanitizedRationale}`
-       );
-     }
+     if (false && !citationCheck.valid) {
+       candidateVerdict = 'NEEDS_HUMAN_REVIEW';
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `downgrades to NEEDS_HUMAN_REVIEW when citation quote is fabricated or missing`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M6: removed injection heuristic AND consistency check together

- **Target File:** `packages/ai/src/triage/skeptic.ts`
- **Verification Suite:** `packages/ai/test/skeptic.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
-       candidateVerdict = 'NEEDS_HUMAN_REVIEW';
-       sanitizedRationale = OutputSanitizer.sanitizeRationale(
-         `[Security Warning: Potential prompt injection detected in code slice] ${sanitizedRationale}`
-       );
-     }
-
-     // 10. Self-Consistency Sample in Suppress Mode (A6)
-     let consistencyResult: { samples: number; agreed: boolean } | undefined;
-     if (isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
+     if (false && injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
+       candidateVerdict = 'NEEDS_HUMAN_REVIEW';
+     }
+
+     // 10. Self-Consistency Sample in Suppress Mode (A6)
+     let consistencyResult: { samples: number; agreed: boolean } | undefined;
+     if (false && isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `locks verdict to NEEDS_HUMAN_REVIEW when prompt injection is detected in slice (T4)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M7: suppressing HIGH by default

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-             const neverSuppress = new Set(
-               userConfig.gate3?.neverSuppressSeverities ?? ['CRITICAL', 'HIGH']
-             );
+             const neverSuppress = new Set(['CRITICAL']); // MUTATION_M7: suppressing HIGH by default
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `in suppress mode: never suppresses HIGH severity findings by default`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M8: suppressing IAC

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-             const isQualifying =
-               finding.category === 'SAST' &&
-               !neverSuppress.has(finding.severity) &&
+             const isQualifying =
+               (finding.category === 'SAST' || finding.category === 'IAC') &&
+               !neverSuppress.has(finding.severity) &&
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `in suppress mode: never suppresses IAC findings`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M9: sending SECRET or credential-class findings

- **Target File:** `packages/context-slicer/src/slicer.ts`
- **Verification Suite:** `packages/context-slicer/test/slicer.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 1. Skip SECRET category findings
-     if (finding.category === 'SECRET') {
-       return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
-     }
-
-     // 2. Skip credential-class findings (A5)
-     if (ContextSlicer.isCredentialClassFinding(finding)) {
-       return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
-     }
+     // 1. Skip SECRET category findings
+     if (false && finding.category === 'SECRET') {
+       return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
+     }
+
+     // 2. Skip credential-class findings (A5)
+     if (false && ContextSlicer.isCredentialClassFinding(finding)) {
+       return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects SECRET category findings immediately (A5, T2)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M10: skipped slicer redaction

- **Target File:** `packages/context-slicer/src/redactor.ts`
- **Verification Suite:** `packages/context-slicer/test/slicer.test.ts`
- **Applied Mutation Patch:**

```diff
-   public static redactText(input: string): string {
-     if (!input || typeof input !== 'string') {
+   public static redactText(input: string): string {
+     return input; // MUTATION: skipped slicer redaction
+     if (!input || typeof input !== 'string') {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `slices JS/TS function and redacts embedded secrets with two passes (A4)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M11: removed denylist

- **Target File:** `packages/context-slicer/src/slicer.ts`
- **Verification Suite:** `packages/context-slicer/test/slicer.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 4. Denylist check on file path
-     const rawFilePath = finding.location.filePath;
-     if (SlicerDenylist.isDenylisted(rawFilePath)) {
-       return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
-     }
+     // 4. Denylist check on file path
+     const rawFilePath = finding.location.filePath;
+     if (false && SlicerDenylist.isDenylisted(rawFilePath)) {
+       return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `enforces sensitive file denylist (A4)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M12: following symlinks outside root

- **Target File:** `packages/context-slicer/src/denylist.ts`
- **Verification Suite:** `packages/context-slicer/test/slicer.test.ts`
- **Applied Mutation Patch:**

```diff
-   public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
-     try {
+   public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
+     return true; // MUTATION: ignore symlink jail escapes
+     try {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `prevents symlink jailbreaks and path traversal outside root (A11)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M13: fixed (non-random) nonce

- **Target File:** `packages/ai/src/prompts/prompt-builder.ts`
- **Verification Suite:** `packages/ai/test/prompt-builder.test.ts`
- **Applied Mutation Patch:**

```diff
-     let nonce = crypto.randomBytes(16).toString('hex');
-     while (contentToInspect.includes(nonce)) {
-       nonce = crypto.randomBytes(16).toString('hex');
-     }
+     let nonce = 'FIXED_NONCE_VALUE_12345'; // MUTATION: fixed non-random nonce
+     while (false && contentToInspect.includes(nonce)) {
+       nonce = crypto.randomBytes(16).toString('hex');
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `generates random and non-fixed nonces per request`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M14: dropping Gate 3 suppressed findings without a ledger entry

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-             if (isQualifying) {
-               ledger.suppress(
-                 finding,
-                 'GATE3_LIKELY_FALSE_POSITIVE',
-                 triageRes.triage.rationale,
-                 'Gate 3 AI Triage'
-               );
+             if (isQualifying) {
+               // MUTATION: dropped without ledger entry
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `records Gate 3 suppressed findings in the suppression ledger`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M15: provider failure changing the exit code

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-           if (triageRes.warning) budgetTracker.addWarning(triageRes.warning);
+           if (triageRes.warning) {
+             throw new Error(`FATAL_PROVIDER_ERROR: ${triageRes.warning}`); // MUTATION: provider failure changing the exit code
+           }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `provider failure falls back gracefully without failing the scan`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M16: printing the API key in verbose output

- **Target File:** `packages/cli/src/commands/scan.ts`
- **Verification Suite:** `packages/cli/test/ai-cli.test.ts`
- **Applied Mutation Patch:**

```diff
-     console.log(`Duration    : ${c.bold(`${report.durationMs}ms`)}\n`);
+     console.log(`Duration    : ${c.bold(`${report.durationMs}ms`)}\n`);
+     if (options.verbose) {
+       console.log(`VERBOSE_KEY: ${process.env.ANTHROPIC_API_KEY || ''}`);
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `never prints API key in verbose or report output (A2, A18)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M17: running Gate 3 on already-suppressed findings

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (gate1Res.shouldSuppress) {
-         ledger.suppress(
-           finding,
-           gate1Res.suppressionReason!,
-           gate1Res.suppressionDetail!,
-           'Gate 1 Scope Classifier'
-         );
-         continue;
-       }
+       if (gate1Res.shouldSuppress) {
+         ledger.suppress(
+           finding,
+           gate1Res.suppressionReason!,
+           gate1Res.suppressionDetail!,
+           'Gate 1 Scope Classifier'
+         );
+         // MUTATION_M17: continue omitted, so Gate 1 suppressed finding is sent to Gate 3
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `skips already-suppressed findings and never sends them to Gate 3`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M18: egress report undercounting files

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/gate3-integration.test.ts`
- **Applied Mutation Patch:**

```diff
-           budgetTracker.recordFindingSent();
-           budgetTracker.recordFiles(sliceResult.filesSent);
+           budgetTracker.recordFindingSent();
+           // MUTATION_M18: omit recording files sent in egress report
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `egress-accounting: report filesSent/bytes/tokens equal what recording local server actually received (R13)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M19: localhost.evil.com treated as loopback

- **Target File:** `packages/ai/src/providers/http-client.ts`
- **Verification Suite:** `packages/ai/test/http-client.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 1. Literal 'localhost'
-     if (clean === 'localhost') {
-       return true;
-     }
+     // 1. Literal 'localhost'
+     if (clean.includes('localhost')) { // MUTATION: lax loopback check
+       return true;
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `correctly classifies loopback hosts and rejects lookalikes`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M20: identical prompts used for consistency samples

- **Target File:** `packages/ai/src/prompts/prompt-builder.ts`
- **Verification Suite:** `packages/ai/test/prompt-builder.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (variant === 1) {
-       // Consistency sample variant 1: reordered sections and rephrased query
+     if (false && variant === 1) { // MUTATION: identical prompt variant 0 used for consistency
+       // Consistency sample variant 1: reordered sections and rephrased query
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `consistency prompt variants produce different user prompts`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation M21: unsanitized model output (ANSI/bidi) reaching the terminal

- **Target File:** `packages/ai/src/sanitize/output-sanitizer.ts`
- **Verification Suite:** `packages/ai/test/sanitizer.test.ts`
- **Applied Mutation Patch:**

```diff
-     let clean = text
-       .replace(OutputSanitizer.ANSI_ESCAPE_REGEX, '')
-       .replace(OutputSanitizer.BIDI_OVERRIDES_REGEX, '')
-       .replace(OutputSanitizer.ZERO_WIDTH_REGEX, '')
-       .replace(OutputSanitizer.CONTROL_CHARS_REGEX, '')
-       .replace(OutputSanitizer.DANGEROUS_LINK_SCHEMES_REGEX, '[$1](advisory-neutralized)');
+     let clean = text; // MUTATION: skipped ANSI, bidi, and control sanitization
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `strips ANSI color escapes`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

## 3. Detailed Patch Log

### M1: repo config enabling AI or setting baseUrl

- **Target:** `packages/core-engine/src/config/load-config.ts`
- **Test Suite:** `packages/core-engine/test/config-loader.test.ts`

```typescript
// Applied Mutation:
if (false && 'ai' in obj) {
  delete obj.ai;
}
```

**Failing Test Names:**

- `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`

### M2: skipped consent check

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
if (false && !consentCheck.consented) {
  throw new AiError('AI consent has not been granted.', 'CONFIG_ERROR');
}
```

**Failing Test Names:**

- `enforces consent check on non-dry-run scans`

### M3: following redirects

- **Target:** `packages/ai/src/providers/http-client.ts`
- **Test Suite:** `packages/ai/test/http-client.test.ts`

```typescript
// Applied Mutation:
redirect: 'follow', // MUTATION: follows redirects
```

**Failing Test Names:**

- `refuses redirects (redirect: error)`

### M4: allowing http to non-loopback

- **Target:** `packages/ai/src/providers/http-client.ts`
- **Test Suite:** `packages/ai/test/http-client.test.ts`

```typescript
// Applied Mutation:
if (false && !isLoopback && url.protocol !== 'https:') {
  throw new AiError('Insecure endpoint', 'CONFIG_ERROR');
}
```

**Failing Test Names:**

- `strictly requires HTTPS for non-loopback endpoints`

### M5: removed citation verification

- **Target:** `packages/ai/src/triage/skeptic.ts`
- **Test Suite:** `packages/ai/test/skeptic.test.ts`

```typescript
// Applied Mutation:
if (false && !citationCheck.valid) {
  candidateVerdict = 'NEEDS_HUMAN_REVIEW';
}
```

**Failing Test Names:**

- `downgrades to NEEDS_HUMAN_REVIEW when citation quote is fabricated or missing`

### M6: removed injection heuristic AND consistency check together

- **Target:** `packages/ai/src/triage/skeptic.ts`
- **Test Suite:** `packages/ai/test/skeptic.test.ts`

```typescript
// Applied Mutation:
if (false && injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
    }

    // 10. Self-Consistency Sample in Suppress Mode (A6)
    let consistencyResult: { samples: number; agreed: boolean } | undefined;
    if (false && isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
```

**Failing Test Names:**

- `locks verdict to NEEDS_HUMAN_REVIEW when prompt injection is detected in slice (T4)`

### M7: suppressing HIGH by default

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
const neverSuppress = new Set(['CRITICAL']); // MUTATION_M7: suppressing HIGH by default
```

**Failing Test Names:**

- `in suppress mode: never suppresses HIGH severity findings by default`

### M8: suppressing IAC

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
const isQualifying =
              (finding.category === 'SAST' || finding.category === 'IAC') &&
              !neverSuppress.has(finding.severity) &&
```

**Failing Test Names:**

- `in suppress mode: never suppresses IAC findings`

### M9: sending SECRET or credential-class findings

- **Target:** `packages/context-slicer/src/slicer.ts`
- **Test Suite:** `packages/context-slicer/test/slicer.test.ts`

```typescript
// Applied Mutation:
// 1. Skip SECRET category findings
if (false && finding.category === 'SECRET') {
  return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
}

// 2. Skip credential-class findings (A5)
if (false && ContextSlicer.isCredentialClassFinding(finding)) {
  return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
}
```

**Failing Test Names:**

- `rejects SECRET category findings immediately (A5, T2)`

### M10: skipped slicer redaction

- **Target:** `packages/context-slicer/src/redactor.ts`
- **Test Suite:** `packages/context-slicer/test/slicer.test.ts`

```typescript
// Applied Mutation:
public static redactText(input: string): string {
    return input; // MUTATION: skipped slicer redaction
    if (!input || typeof input !== 'string') {
```

**Failing Test Names:**

- `slices JS/TS function and redacts embedded secrets with two passes (A4)`

### M11: removed denylist

- **Target:** `packages/context-slicer/src/slicer.ts`
- **Test Suite:** `packages/context-slicer/test/slicer.test.ts`

```typescript
// Applied Mutation:
// 4. Denylist check on file path
const rawFilePath = finding.location.filePath;
if (false && SlicerDenylist.isDenylisted(rawFilePath)) {
  return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
}
```

**Failing Test Names:**

- `enforces sensitive file denylist (A4)`

### M12: following symlinks outside root

- **Target:** `packages/context-slicer/src/denylist.ts`
- **Test Suite:** `packages/context-slicer/test/slicer.test.ts`

```typescript
// Applied Mutation:
public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
    return true; // MUTATION: ignore symlink jail escapes
    try {
```

**Failing Test Names:**

- `prevents symlink jailbreaks and path traversal outside root (A11)`

### M13: fixed (non-random) nonce

- **Target:** `packages/ai/src/prompts/prompt-builder.ts`
- **Test Suite:** `packages/ai/test/prompt-builder.test.ts`

```typescript
// Applied Mutation:
let nonce = 'FIXED_NONCE_VALUE_12345'; // MUTATION: fixed non-random nonce
while (false && contentToInspect.includes(nonce)) {
  nonce = crypto.randomBytes(16).toString('hex');
}
```

**Failing Test Names:**

- `generates random and non-fixed nonces per request`

### M14: dropping Gate 3 suppressed findings without a ledger entry

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
if (isQualifying) {
              // MUTATION: dropped without ledger entry
```

**Failing Test Names:**

- `records Gate 3 suppressed findings in the suppression ledger`

### M15: provider failure changing the exit code

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
if (triageRes.warning) {
  throw new Error(`FATAL_PROVIDER_ERROR: ${triageRes.warning}`); // MUTATION: provider failure changing the exit code
}
```

**Failing Test Names:**

- `provider failure falls back gracefully without failing the scan`

### M16: printing the API key in verbose output

- **Target:** `packages/cli/src/commands/scan.ts`
- **Test Suite:** `packages/cli/test/ai-cli.test.ts`

```typescript
// Applied Mutation:
console.log(`Duration    : ${c.bold(`${report.durationMs}ms`)}\n`);
if (options.verbose) {
  console.log(`VERBOSE_KEY: ${process.env.ANTHROPIC_API_KEY || ''}`);
}
```

**Failing Test Names:**

- `never prints API key in verbose or report output (A2, A18)`

### M17: running Gate 3 on already-suppressed findings

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
if (gate1Res.shouldSuppress) {
  ledger.suppress(
    finding,
    gate1Res.suppressionReason!,
    gate1Res.suppressionDetail!,
    'Gate 1 Scope Classifier'
  );
  // MUTATION_M17: continue omitted, so Gate 1 suppressed finding is sent to Gate 3
}
```

**Failing Test Names:**

- `skips already-suppressed findings and never sends them to Gate 3`

### M18: egress report undercounting files

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/gate3-integration.test.ts`

```typescript
// Applied Mutation:
budgetTracker.recordFindingSent();
// MUTATION_M18: omit recording files sent in egress report
```

**Failing Test Names:**

- `egress-accounting: report filesSent/bytes/tokens equal what recording local server actually received (R13)`

### M19: localhost.evil.com treated as loopback

- **Target:** `packages/ai/src/providers/http-client.ts`
- **Test Suite:** `packages/ai/test/http-client.test.ts`

```typescript
// Applied Mutation:
// 1. Literal 'localhost'
if (clean.includes('localhost')) {
  // MUTATION: lax loopback check
  return true;
}
```

**Failing Test Names:**

- `correctly classifies loopback hosts and rejects lookalikes`

### M20: identical prompts used for consistency samples

- **Target:** `packages/ai/src/prompts/prompt-builder.ts`
- **Test Suite:** `packages/ai/test/prompt-builder.test.ts`

```typescript
// Applied Mutation:
if (false && variant === 1) { // MUTATION: identical prompt variant 0 used for consistency
      // Consistency sample variant 1: reordered sections and rephrased query
```

**Failing Test Names:**

- `consistency prompt variants produce different user prompts`

### M21: unsanitized model output (ANSI/bidi) reaching the terminal

- **Target:** `packages/ai/src/sanitize/output-sanitizer.ts`
- **Test Suite:** `packages/ai/test/sanitizer.test.ts`

```typescript
// Applied Mutation:
let clean = text; // MUTATION: skipped ANSI, bidi, and control sanitization
```

**Failing Test Names:**

- `strips ANSI color escapes`
