# SecureShip Phase 5: Mutation Verification Log (P1–P28)

In accordance with Phase 5 Gate 4 Verified Remediation specification, this log records the real execution of `pnpm verify:mutations`. Each mutation was applied to an isolated temporary copy of the repository in `$env:TEMP`, evaluated against the verification test suite, and confirmed to fail with specific failing test names.

**Verification Attestation:** Exactly 28 out of 28 mutations were successfully caught (0 uncaught mutations). Bidirectional proof confirms that each test fails under mutation and passes cleanly when restored.

---

## 1. Mutation Summary Table

| ID      | Description                                              | Target File                                                   | Verification Test                                                   |   Status   | Failing Test(s)                                                                                      |
| :------ | :------------------------------------------------------- | :------------------------------------------------------------ | :------------------------------------------------------------------ | :--------: | :--------------------------------------------------------------------------------------------------- |
| **P1**  | Allow paths outside root                                 | `packages/patch-engine/src/diff-parser.ts`                    | `packages/patch-engine/test/diff-parser.test.ts`                    | **CAUGHT** | `rejects absolute paths and path traversal with OUTSIDE_ROOT`                                        |
| **P2**  | Allow protected paths                                    | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `rejects protected files (package.json, lockfiles, CI) with PROTECTED_PATH`                          |
| **P3**  | Allow test-file edits                                    | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `rejects test and fixture files with TEST_FILE`                                                      |
| **P4**  | Skip suppression-marker check                            | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `detects all suppression markers with SUPPRESSION_MARKER`                                            |
| **P5**  | Skip hidden-Unicode / Trojan Source check                | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `rejects Trojan Source bidirectional characters and hidden Unicode with HIDDEN_UNICODE`              |
| **P6**  | Skip net-new dangerous API check                         | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `rejects net-new dangerous APIs with NEW_DANGEROUS_API`                                              |
| **P7**  | Skip new-dependency check                                | `packages/patch-engine/src/policy-engine.ts`                  | `packages/patch-engine/test/policy-engine.test.ts`                  | **CAUGHT** | `rejects new unapproved dependencies with NEW_DEPENDENCY`                                            |
| **P8**  | Apply with fuzzy context                                 | `packages/patch-engine/src/applier.ts`                        | `packages/patch-engine/test/applier.test.ts`                        | **CAUGHT** | `fails closed with CONTEXT_MISMATCH when context cannot be found`                                    |
| **P9**  | Treat scanner-missing RESCAN as PASS                     | `packages/core-engine/src/remediation/verification-ladder.ts` | `packages/core-engine/test/remediation/verification-ladder.test.ts` | **CAUGHT** | `returns INCONCLUSIVE when originating scanner is missing (Mutation 9)`                              |
| **P10** | Ignore NEW_FINDINGS                                      | `packages/core-engine/src/remediation/verification-ladder.ts` | `packages/core-engine/test/remediation/verification-ladder.test.ts` | **CAUGHT** | `fails ladder when net-new finding is introduced on patched shadow copy (Mutation 10)`               |
| **P11** | Baseline-fail treated as PASS                            | `packages/sandbox/src/runner/baseline-runner.ts`              | `packages/sandbox/test/baseline-runner.test.ts`                     | **CAUGHT** | `returns INCONCLUSIVE when baseline fails`                                                           |
| **P12** | Patched-fail retried until pass                          | `packages/sandbox/src/runner/baseline-runner.ts`              | `packages/sandbox/test/baseline-runner.test.ts`                     | **CAUGHT** | `returns FAIL when baseline passes and patched fails on rerun`                                       |
| **P13** | Report VERIFIED_RUNTIME when dynamic stages were skipped | `packages/core-engine/src/remediation/verification-ladder.ts` | `packages/core-engine/test/remediation/verification-ladder.test.ts` | **CAUGHT** | `runs static ladder cleanly and reports VERIFIED_STATIC when dynamic stages skipped`                 |
| **P14** | Enable container network in non-install stages           | `packages/sandbox/src/backends/container-backend.ts`          | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `ContainerBackend enforces zero network access in non-install stages (--network=none) (Mutation 14)` |
| **P15** | Add a capability or drop no-new-privileges               | `packages/sandbox/src/backends/container-backend.ts`          | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `ContainerBackend drops all capabilities and enforces no-new-privileges (Mutation 15)`               |
| **P16** | Mount docker.sock or host home                           | `packages/sandbox/src/backends/container-backend.ts`          | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `ContainerBackend never mounts docker.sock or host home directory (Mutation 16)`                     |
| **P17** | Pass ambient host environment into container             | `packages/sandbox/src/backends/container-backend.ts`          | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `ContainerBackend passes minimal env and never forwards ambient host environment (Mutation 17)`      |
| **P18** | Run repo scripts on host without trust                   | `packages/sandbox/src/backends/host-backend.ts`               | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `HostBackend refuses execution on untrusted repository`                                              |
| **P19** | Let repo config set backend, commands, or images         | `packages/core-engine/src/config/load-config.ts`              | `packages/core-engine/test/config-loader.test.ts`                   | **CAUGHT** | `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`                      |
| **P20** | Include .env / sensitive denylist files in shadow copy   | `packages/sandbox/src/shadow/shadow-copy.ts`                  | `packages/sandbox/test/shadow-copy.test.ts`                         | **CAUGHT** | `creates filtered shadow copy excluding .git, node_modules, and sensitive files`                     |
| **P21** | Modify the original working tree                         | `packages/sandbox/src/shadow/shadow-copy.ts`                  | `packages/sandbox/test/shadow-copy.test.ts`                         | **CAUGHT** | `detects tampering in source directory via verifyOriginalUnchanged()`                                |
| **P22** | fix apply skipping HMAC signature verification           | `packages/core-engine/src/remediation/fix-store.ts`           | `packages/core-engine/test/remediation/fix-store.test.ts`           | **CAUGHT** | `detects tampered fix reports with HMAC mismatch (Mutation 22)`                                      |
| **P23** | fix apply skipping base file SHA-256 hash check          | `packages/core-engine/src/remediation/fix-store.ts`           | `packages/core-engine/test/remediation/fix-store.test.ts`           | **CAUGHT** | `rejects apply when base file hash does not match (Mutation 23)`                                     |
| **P24** | fix apply skipping clean git tree check                  | `packages/core-engine/src/remediation/fix-store.ts`           | `packages/core-engine/test/remediation/fix-store.test.ts`           | **CAUGHT** | `rejects apply on non-git directory without --allow-non-git (Mutation 24)`                           |
| **P25** | Auto-commit or auto-branch                               | `packages/core-engine/src/remediation/fix-store.ts`           | `packages/core-engine/test/remediation/fix-store.test.ts`           | **CAUGHT** | `never auto-commits or auto-branches on apply (Mutation 25)`                                         |
| **P26** | Non-atomic file write                                    | `packages/patch-engine/src/applier.ts`                        | `packages/patch-engine/test/applier.test.ts`                        | **CAUGHT** | `atomicWrite writes file atomically preserving mode (Mutation 26)`                                   |
| **P27** | EOL / BOM not preserved                                  | `packages/patch-engine/src/applier.ts`                        | `packages/patch-engine/test/applier.test.ts`                        | **CAUGHT** | `preserves UTF-8 BOM`                                                                                |
| **P28** | Leave orphan containers after abort/SIGINT               | `packages/sandbox/src/backends/container-backend.ts`          | `packages/sandbox/test/backends.test.ts`                            | **CAUGHT** | `ContainerBackend cleanup removes labeled containers (Mutation 28)`                                  |

---

## 2. Bidirectional Proofs (Pass on Restoration)

### Mutation P1: Allow paths outside root

- **Target File:** `packages/patch-engine/src/diff-parser.ts`
- **Verification Suite:** `packages/patch-engine/test/diff-parser.test.ts`
- **Applied Mutation Patch:**

```diff
-     // Reject absolute paths, UNC paths, and drive letters
-     if (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\0')) {
-       throw new PatchPolicyViolationError(
-         'OUTSIDE_ROOT',
-         `Absolute or invalid path rejected: '${rawPath}'`
-       );
-     }
+     // Reject absolute paths, UNC paths, and drive letters
+     if (false && (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\0'))) {
+       throw new PatchPolicyViolationError(
+         'OUTSIDE_ROOT',
+         `Absolute or invalid path rejected: '${rawPath}'`
+       );
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects absolute paths and path traversal with OUTSIDE_ROOT`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P2: Allow protected paths

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-       // Protected path check
-       if (PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
-         violations.push({
-           code: 'PROTECTED_PATH',
-           detail: `Modifying protected project file '${p}' is forbidden`,
-           file: p,
-         });
-       }
+       // Protected path check
+       if (false && PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
+         violations.push({
+           code: 'PROTECTED_PATH',
+           detail: `Modifying protected project file '${p}' is forbidden`,
+           file: p,
+         });
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects protected files (package.json, lockfiles, CI) with PROTECTED_PATH`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P3: Allow test-file edits

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-       // Test file check
-       if (PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
-         violations.push({
-           code: 'TEST_FILE',
-           detail: `Modifying test or fixture file '${p}' is forbidden`,
-           file: p,
-         });
-       }
+       // Test file check
+       if (false && PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
+         violations.push({
+           code: 'TEST_FILE',
+           detail: `Modifying test or fixture file '${p}' is forbidden`,
+           file: p,
+         });
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects test and fixture files with TEST_FILE`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P4: Skip suppression-marker check

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-             // Suppression marker check
-             for (const marker of PatchPolicyEngine.SUPPRESSION_REGEXES) {
-               if (marker.test(line.text)) {
-                 violations.push({
-                   code: 'SUPPRESSION_MARKER',
-                   detail: `Added line contains security suppression marker '${marker.source}': '${trimmed}'`,
-                   file: f.newPath,
-                 });
-                 break;
-               }
-             }
+             // Suppression marker check
+             for (const marker of [] as RegExp[]) {
+               if (marker.test(line.text)) {
+                 violations.push({
+                   code: 'SUPPRESSION_MARKER',
+                   detail: `Added line contains security suppression marker '${marker.source}': '${trimmed}'`,
+                   file: f.newPath,
+                 });
+                 break;
+               }
+             }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `detects all suppression markers with SUPPRESSION_MARKER`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P5: Skip hidden-Unicode / Trojan Source check

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 7. Hidden Unicode / Trojan Source Checks
-     for (const f of files) {
-       for (const hunk of f.hunks) {
-         for (const line of hunk.lines) {
-           if (line.type === 'added') {
-             PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
-           }
-         }
-       }
-     }
+     // 7. Hidden Unicode / Trojan Source Checks
+     for (const f of files) {
+       for (const hunk of f.hunks) {
+         for (const line of hunk.lines) {
+           if (false && line.type === 'added') {
+             PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
+           }
+         }
+       }
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects Trojan Source bidirectional characters and hidden Unicode with HIDDEN_UNICODE`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P6: Skip net-new dangerous API check

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 4. Dangerous API Differential Checks (Per hunk)
-     for (const f of files) {
-       for (const hunk of f.hunks) {
-         PatchPolicyEngine.checkDangerousApiHunk(hunk, f.newPath, violations);
-       }
-     }
+     // 4. Dangerous API Differential Checks (Per hunk)
+     for (const f of files) {
+       for (const hunk of f.hunks) {
+         // MUTATION_P6: skip dangerous API differential check
+       }
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects net-new dangerous APIs with NEW_DANGEROUS_API`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P7: Skip new-dependency check

- **Target File:** `packages/patch-engine/src/policy-engine.ts`
- **Verification Suite:** `packages/patch-engine/test/policy-engine.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 5. New Dependency Checks
-     for (const f of files) {
-       PatchPolicyEngine.checkNewDependencies(f, options, violations);
-     }
+     // 5. New Dependency Checks
+     for (const f of files) {
+       // MUTATION_P7: skip new dependency check
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects new unapproved dependencies with NEW_DEPENDENCY`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P8: Apply with fuzzy context

- **Target File:** `packages/patch-engine/src/applier.ts`
- **Verification Suite:** `packages/patch-engine/test/applier.test.ts`
- **Applied Mutation Patch:**

```diff
-     for (let i = 0; i < expected.length; i++) {
-       if (lines[startIndex + i] !== expected[i]) {
-         return false;
-       }
-     }
+     for (let i = 0; i < expected.length; i++) {
+       if (false && lines[startIndex + i] !== expected[i]) {
+         return false;
+       }
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `fails closed with CONTEXT_MISMATCH when context cannot be found`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P9: Treat scanner-missing RESCAN as PASS

- **Target File:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
-         // Mutation 9: Originating scanner missing MUST NOT be treated as PASS. It must be INCONCLUSIVE.
-         rescanOutcome = 'INCONCLUSIVE';
-         rescanDetail = `Originating scanner '${finding.scannerName}' not available in environment; cannot verify remediation`;
-       }
+       if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
+         rescanOutcome = 'PASS';
+         rescanDetail = `Originating scanner '${finding.scannerName}' not available in environment; cannot verify remediation`;
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `returns INCONCLUSIVE when originating scanner is missing (Mutation 9)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P10: Ignore NEW_FINDINGS

- **Target File:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`
- **Applied Mutation Patch:**

```diff
-             if (qualifyingNew.length > 0) {
-               // Mutation 10: Must not ignore NEW_FINDINGS
-               newFindingsOutcome = 'FAIL';
-               newFindingsDetail = `Net-new finding introduced: ${qualifyingNew[0]!.ruleId} (${qualifyingNew[0]!.severity}) in ${qualifyingNew[0]!.location.filePath}`;
-               break;
-             }
+             if (false && qualifyingNew.length > 0) {
+               newFindingsOutcome = 'FAIL';
+               newFindingsDetail = `Net-new finding introduced: ${qualifyingNew[0]!.ruleId} (${qualifyingNew[0]!.severity}) in ${qualifyingNew[0]!.location.filePath}`;
+               break;
+             }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `fails ladder when net-new finding is introduced on patched shadow copy (Mutation 10)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P11: Baseline-fail treated as PASS

- **Target File:** `packages/sandbox/src/runner/baseline-runner.ts`
- **Verification Suite:** `packages/sandbox/test/baseline-runner.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (baselineResult.timedOut || baselineResult.exitCode !== 0) {
-       return {
-         id: stageId,
-         outcome: 'INCONCLUSIVE',
-         detail: `Baseline ${stageId} failed or timed out (exit code ${baselineResult.exitCode}). Cannot verify regression without clean baseline.`,
-         durationMs: Date.now() - startTime,
-         argv: [command.command, ...command.args],
-         exitCode: null,
-         baselineExitCode: baselineResult.exitCode,
-         outputSha256: baselineResult.outputSha256,
-         outputTail: baselineResult.outputTail,
-       };
-     }
+     if (false && (baselineResult.timedOut || baselineResult.exitCode !== 0)) {
+       return {
+         id: stageId,
+         outcome: 'INCONCLUSIVE',
+         detail: `Baseline ${stageId} failed or timed out`,
+         durationMs: Date.now() - startTime,
+       };
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `returns INCONCLUSIVE when baseline fails`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P12: Patched-fail retried until pass

- **Target File:** `packages/sandbox/src/runner/baseline-runner.ts`
- **Verification Suite:** `packages/sandbox/test/baseline-runner.test.ts`
- **Applied Mutation Patch:**

```diff
-     // Still fails => FAIL (regression detected)
-     return {
-       id: stageId,
-       outcome: 'FAIL',
-       detail: `Patched ${stageId} failed (exit code ${patchedResult.exitCode}), introducing a regression against clean baseline`,
-       durationMs: Date.now() - startTime,
-       argv: [command.command, ...command.args],
-       exitCode: patchedResult.exitCode,
-       baselineExitCode: baselineResult.exitCode,
-       outputSha256: patchedResult.outputSha256,
-       outputTail: patchedResult.outputTail,
-     };
+     // Still fails => FAIL (regression detected)
+     return {
+       id: stageId,
+       outcome: 'PASS',
+       detail: `Patched ${stageId} failed (exit code ${patchedResult.exitCode}), introducing a regression against clean baseline`,
+       durationMs: Date.now() - startTime,
+       argv: [command.command, ...command.args],
+       exitCode: 0,
+       baselineExitCode: baselineResult.exitCode,
+       outputSha256: patchedResult.outputSha256,
+       outputTail: patchedResult.outputTail,
+     };
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `returns FAIL when baseline passes and patched fails on rerun`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P13: Report VERIFIED_RUNTIME when dynamic stages were skipped

- **Target File:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (anyDynamicPassed) {
-       return 'VERIFIED_RUNTIME';
-     }
-
-     return 'VERIFIED_STATIC';
+     if (true || anyDynamicPassed) {
+       return 'VERIFIED_RUNTIME';
+     }
+
+     return 'VERIFIED_STATIC';
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `runs static ladder cleanly and reports VERIFIED_STATIC when dynamic stages skipped`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P14: Enable container network in non-install stages

- **Target File:** `packages/sandbox/src/backends/container-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-     const networkMode = options.network ? 'bridge' : 'none';
+     const networkMode = 'bridge';
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ContainerBackend enforces zero network access in non-install stages (--network=none) (Mutation 14)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P15: Add a capability or drop no-new-privileges

- **Target File:** `packages/sandbox/src/backends/container-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-       '--cap-drop=ALL',
-       '--security-opt=no-new-privileges',
+       '--cap-add=SYS_ADMIN',
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ContainerBackend drops all capabilities and enforces no-new-privileges (Mutation 15)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P16: Mount docker.sock or host home

- **Target File:** `packages/sandbox/src/backends/container-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-       `-v=${translatedShadow}:/work:rw`,
+       `-v=${translatedShadow}:/work:rw`,
+       '-v=/var/run/docker.sock:/var/run/docker.sock',
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ContainerBackend never mounts docker.sock or host home directory (Mutation 16)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P17: Pass ambient host environment into container

- **Target File:** `packages/sandbox/src/backends/container-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-       '-e',
-       'CI=1',
-       '-e',
-       'HOME=/tmp',
-       '-e',
-       'LANG=C.UTF-8',
-     ];
+       '-e',
+       'CI=1',
+       '-e',
+       'HOME=/tmp',
+       '-e',
+       'LANG=C.UTF-8',
+       '-e',
+       `USER=${process.env.USER}`,
+     ];
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ContainerBackend passes minimal env and never forwards ambient host environment (Mutation 17)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P18: Run repo scripts on host without trust

- **Target File:** `packages/sandbox/src/backends/host-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (!this.isRepoTrusted()) {
-       const repoHash = HostBackend.computeRepoHash(this.repoDir);
-       throw new Error(
-         `Host Execution Refused: Repository at '${this.repoDir}' (hash ${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.`
-       );
-     }
+     if (false && !this.isRepoTrusted()) {
+       const repoHash = HostBackend.computeRepoHash(this.repoDir);
+       throw new Error(
+         `Host Execution Refused: Repository at '${this.repoDir}' (hash ${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.`
+       );
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `HostBackend refuses execution on untrusted repository`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P19: Let repo config set backend, commands, or images

- **Target File:** `packages/core-engine/src/config/load-config.ts`
- **Verification Suite:** `packages/core-engine/test/config-loader.test.ts`
- **Applied Mutation Patch:**

```diff
-       if ('sandbox' in obj) {
-         console.warn(
-           `[SECURITY WARNING] Repository config at '${configPath}' contains forbidden key 'sandbox'. Sandbox configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'sandbox'.`
-         );
-         delete obj.sandbox;
-       }
+       if (false && 'sandbox' in obj) {
+         delete obj.sandbox;
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P20: Include .env / sensitive denylist files in shadow copy

- **Target File:** `packages/sandbox/src/shadow/shadow-copy.ts`
- **Verification Suite:** `packages/sandbox/test/shadow-copy.test.ts`
- **Applied Mutation Patch:**

```diff
-         if (ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
-           continue;
-         }
+         if (false && ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
+           continue;
+         }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `creates filtered shadow copy excluding .git, node_modules, and sensitive files`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P21: Modify the original working tree

- **Target File:** `packages/sandbox/src/shadow/shadow-copy.ts`
- **Verification Suite:** `packages/sandbox/test/shadow-copy.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (currentHash !== expectedHash) {
-         throw new Error(
-           `Integrity Violation: Source file '${relPath}' was modified in original repository tree! (expected ${expectedHash}, got ${currentHash})`
-         );
-       }
+       if (false && currentHash !== expectedHash) {
+         throw new Error(
+           `Integrity Violation: Source file '${relPath}' was modified in original repository tree!`
+         );
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `detects tampering in source directory via verifyOriginalUnchanged()`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P22: fix apply skipping HMAC signature verification

- **Target File:** `packages/core-engine/src/remediation/fix-store.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (!stored.validSig) {
-       return {
-         success: false,
-         exitCode: 2,
-         error: `HMAC signature verification failed: fix bundle '${fixId}' has an invalid signature or was tampered with.`,
-       };
-     }
+     if (false && !stored.validSig) {
+       return {
+         success: false,
+         exitCode: 2,
+         error: `HMAC signature verification failed`,
+       };
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `detects tampered fix reports with HMAC mismatch (Mutation 22)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P23: fix apply skipping base file SHA-256 hash check

- **Target File:** `packages/core-engine/src/remediation/fix-store.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (currentHash !== baseFile.sha256) {
-         return {
-           success: false,
-           exitCode: 2,
-           error: `Base file hash mismatch for '${baseFile.path}'. The file was modified since fix generation. Expected ${baseFile.sha256}, got ${currentHash}.`,
-         };
-       }
+       if (false && currentHash !== baseFile.sha256) {
+         return {
+           success: false,
+           exitCode: 2,
+           error: `Base file hash mismatch`,
+         };
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects apply when base file hash does not match (Mutation 23)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P24: fix apply skipping clean git tree check

- **Target File:** `packages/core-engine/src/remediation/fix-store.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (!isGitRepo) {
-       if (!allowNonGit) {
-         return {
-           success: false,
-           exitCode: 2,
-           error:
-             'Repository is not a Git working tree. To apply outside a Git tree, rerun with --allow-non-git.',
-         };
-       }
-     }
+     if (false && !isGitRepo) {
+       if (!allowNonGit) {
+         return {
+           success: false,
+           exitCode: 2,
+           error: 'Repository is not a Git working tree',
+         };
+       }
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects apply on non-git directory without --allow-non-git (Mutation 24)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P25: Auto-commit or auto-branch

- **Target File:** `packages/core-engine/src/remediation/fix-store.ts`
- **Verification Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`
- **Applied Mutation Patch:**

```diff
-     return {
-       success: true,
-       exitCode: 0,
-       appliedFiles,
-     };
+     try { execFileSync('git', ['commit', '-am', 'auto-commit'], { cwd: repoPath }); } catch {}
+     return {
+       success: true,
+       exitCode: 0,
+       appliedFiles,
+     };
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `never auto-commits or auto-branches on apply (Mutation 25)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P26: Non-atomic file write

- **Target File:** `packages/patch-engine/src/applier.ts`
- **Verification Suite:** `packages/patch-engine/test/applier.test.ts`
- **Applied Mutation Patch:**

```diff
-     try {
-       fs.writeFileSync(tempFile, content, {
-         encoding: 'utf8',
-         mode: mode ?? 0o644,
-       });
-       fs.renameSync(tempFile, targetPath);
-     } catch (err) {
+     try {
+       fs.writeFileSync(targetPath, content, {
+         encoding: 'utf8',
+         mode: mode ?? 0o644,
+       });
+     } catch (err) {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `atomicWrite writes file atomically preserving mode (Mutation 26)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P27: EOL / BOM not preserved

- **Target File:** `packages/patch-engine/src/applier.ts`
- **Verification Suite:** `packages/patch-engine/test/applier.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (format.hasBom) {
-       result = '\uFEFF' + result;
-     }
+     if (false && format.hasBom) {
+       result = '\uFEFF' + result;
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `preserves UTF-8 BOM`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation P28: Leave orphan containers after abort/SIGINT

- **Target File:** `packages/sandbox/src/backends/container-backend.ts`
- **Verification Suite:** `packages/sandbox/test/backends.test.ts`
- **Applied Mutation Patch:**

```diff
-   public async cleanup(): Promise<void> {
-     if (this.nativeFallbackBackend) {
-       await this.nativeFallbackBackend.cleanup();
-     }
-
-     const runtime = this.resolvedRuntime;
-     if (!runtime) return;
-
-     try {
-       // Remove any container associated with this run ID
-       await SafeProcessRunner.run(
-         runtime,
-         ['rm', '-f', '--filter', `label=secureship.run=${this.runId}`],
-         { timeoutMs: 5000 }
-       );
-     } catch {
-       // Ignore cleanup error
-     }
-   }
+   public async cleanup(): Promise<void> {
+     return;
+   }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `ContainerBackend cleanup removes labeled containers (Mutation 28)`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

## 3. Detailed Patch Log

### P1: Allow paths outside root

- **Target:** `packages/patch-engine/src/diff-parser.ts`
- **Test Suite:** `packages/patch-engine/test/diff-parser.test.ts`

```typescript
// Applied Mutation:
// Reject absolute paths, UNC paths, and drive letters
if (
  false &&
  (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\0'))
) {
  throw new PatchPolicyViolationError(
    'OUTSIDE_ROOT',
    `Absolute or invalid path rejected: '${rawPath}'`
  );
}
```

**Failing Test Names:**

- `rejects absolute paths and path traversal with OUTSIDE_ROOT`

### P2: Allow protected paths

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// Protected path check
if (false && PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
  violations.push({
    code: 'PROTECTED_PATH',
    detail: `Modifying protected project file '${p}' is forbidden`,
    file: p,
  });
}
```

**Failing Test Names:**

- `rejects protected files (package.json, lockfiles, CI) with PROTECTED_PATH`

### P3: Allow test-file edits

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// Test file check
if (false && PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
  violations.push({
    code: 'TEST_FILE',
    detail: `Modifying test or fixture file '${p}' is forbidden`,
    file: p,
  });
}
```

**Failing Test Names:**

- `rejects test and fixture files with TEST_FILE`

### P4: Skip suppression-marker check

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// Suppression marker check
for (const marker of [] as RegExp[]) {
  if (marker.test(line.text)) {
    violations.push({
      code: 'SUPPRESSION_MARKER',
      detail: `Added line contains security suppression marker '${marker.source}': '${trimmed}'`,
      file: f.newPath,
    });
    break;
  }
}
```

**Failing Test Names:**

- `detects all suppression markers with SUPPRESSION_MARKER`

### P5: Skip hidden-Unicode / Trojan Source check

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// 7. Hidden Unicode / Trojan Source Checks
for (const f of files) {
  for (const hunk of f.hunks) {
    for (const line of hunk.lines) {
      if (false && line.type === 'added') {
        PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
      }
    }
  }
}
```

**Failing Test Names:**

- `rejects Trojan Source bidirectional characters and hidden Unicode with HIDDEN_UNICODE`

### P6: Skip net-new dangerous API check

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// 4. Dangerous API Differential Checks (Per hunk)
for (const f of files) {
  for (const hunk of f.hunks) {
    // MUTATION_P6: skip dangerous API differential check
  }
}
```

**Failing Test Names:**

- `rejects net-new dangerous APIs with NEW_DANGEROUS_API`

### P7: Skip new-dependency check

- **Target:** `packages/patch-engine/src/policy-engine.ts`
- **Test Suite:** `packages/patch-engine/test/policy-engine.test.ts`

```typescript
// Applied Mutation:
// 5. New Dependency Checks
for (const f of files) {
  // MUTATION_P7: skip new dependency check
}
```

**Failing Test Names:**

- `rejects new unapproved dependencies with NEW_DEPENDENCY`

### P8: Apply with fuzzy context

- **Target:** `packages/patch-engine/src/applier.ts`
- **Test Suite:** `packages/patch-engine/test/applier.test.ts`

```typescript
// Applied Mutation:
for (let i = 0; i < expected.length; i++) {
  if (false && lines[startIndex + i] !== expected[i]) {
    return false;
  }
}
```

**Failing Test Names:**

- `fails closed with CONTEXT_MISMATCH when context cannot be found`

### P9: Treat scanner-missing RESCAN as PASS

- **Target:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Test Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`

```typescript
// Applied Mutation:
if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
  rescanOutcome = 'PASS';
  rescanDetail = `Originating scanner '${finding.scannerName}' not available in environment; cannot verify remediation`;
}
```

**Failing Test Names:**

- `returns INCONCLUSIVE when originating scanner is missing (Mutation 9)`

### P10: Ignore NEW_FINDINGS

- **Target:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Test Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`

```typescript
// Applied Mutation:
if (false && qualifyingNew.length > 0) {
  newFindingsOutcome = 'FAIL';
  newFindingsDetail = `Net-new finding introduced: ${qualifyingNew[0]!.ruleId} (${qualifyingNew[0]!.severity}) in ${qualifyingNew[0]!.location.filePath}`;
  break;
}
```

**Failing Test Names:**

- `fails ladder when net-new finding is introduced on patched shadow copy (Mutation 10)`

### P11: Baseline-fail treated as PASS

- **Target:** `packages/sandbox/src/runner/baseline-runner.ts`
- **Test Suite:** `packages/sandbox/test/baseline-runner.test.ts`

```typescript
// Applied Mutation:
if (false && (baselineResult.timedOut || baselineResult.exitCode !== 0)) {
  return {
    id: stageId,
    outcome: 'INCONCLUSIVE',
    detail: `Baseline ${stageId} failed or timed out`,
    durationMs: Date.now() - startTime,
  };
}
```

**Failing Test Names:**

- `returns INCONCLUSIVE when baseline fails`

### P12: Patched-fail retried until pass

- **Target:** `packages/sandbox/src/runner/baseline-runner.ts`
- **Test Suite:** `packages/sandbox/test/baseline-runner.test.ts`

```typescript
// Applied Mutation:
// Still fails => FAIL (regression detected)
return {
  id: stageId,
  outcome: 'PASS',
  detail: `Patched ${stageId} failed (exit code ${patchedResult.exitCode}), introducing a regression against clean baseline`,
  durationMs: Date.now() - startTime,
  argv: [command.command, ...command.args],
  exitCode: 0,
  baselineExitCode: baselineResult.exitCode,
  outputSha256: patchedResult.outputSha256,
  outputTail: patchedResult.outputTail,
};
```

**Failing Test Names:**

- `returns FAIL when baseline passes and patched fails on rerun`

### P13: Report VERIFIED_RUNTIME when dynamic stages were skipped

- **Target:** `packages/core-engine/src/remediation/verification-ladder.ts`
- **Test Suite:** `packages/core-engine/test/remediation/verification-ladder.test.ts`

```typescript
// Applied Mutation:
if (true || anyDynamicPassed) {
  return 'VERIFIED_RUNTIME';
}

return 'VERIFIED_STATIC';
```

**Failing Test Names:**

- `runs static ladder cleanly and reports VERIFIED_STATIC when dynamic stages skipped`

### P14: Enable container network in non-install stages

- **Target:** `packages/sandbox/src/backends/container-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
const networkMode = 'bridge';
```

**Failing Test Names:**

- `ContainerBackend enforces zero network access in non-install stages (--network=none) (Mutation 14)`

### P15: Add a capability or drop no-new-privileges

- **Target:** `packages/sandbox/src/backends/container-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
'--cap-add=SYS_ADMIN',
```

**Failing Test Names:**

- `ContainerBackend drops all capabilities and enforces no-new-privileges (Mutation 15)`

### P16: Mount docker.sock or host home

- **Target:** `packages/sandbox/src/backends/container-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
`-v=${translatedShadow}:/work:rw`,
      '-v=/var/run/docker.sock:/var/run/docker.sock',
```

**Failing Test Names:**

- `ContainerBackend never mounts docker.sock or host home directory (Mutation 16)`

### P17: Pass ambient host environment into container

- **Target:** `packages/sandbox/src/backends/container-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
'-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
      '-e',
      `USER=${process.env.USER}`,
    ];
```

**Failing Test Names:**

- `ContainerBackend passes minimal env and never forwards ambient host environment (Mutation 17)`

### P18: Run repo scripts on host without trust

- **Target:** `packages/sandbox/src/backends/host-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
if (false && !this.isRepoTrusted()) {
  const repoHash = HostBackend.computeRepoHash(this.repoDir);
  throw new Error(
    `Host Execution Refused: Repository at '${this.repoDir}' (hash ${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.`
  );
}
```

**Failing Test Names:**

- `HostBackend refuses execution on untrusted repository`

### P19: Let repo config set backend, commands, or images

- **Target:** `packages/core-engine/src/config/load-config.ts`
- **Test Suite:** `packages/core-engine/test/config-loader.test.ts`

```typescript
// Applied Mutation:
if (false && 'sandbox' in obj) {
  delete obj.sandbox;
}
```

**Failing Test Names:**

- `ignores forbidden ai and gate3 keys in repo config with security warning (A1)`

### P20: Include .env / sensitive denylist files in shadow copy

- **Target:** `packages/sandbox/src/shadow/shadow-copy.ts`
- **Test Suite:** `packages/sandbox/test/shadow-copy.test.ts`

```typescript
// Applied Mutation:
if (false && ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
  continue;
}
```

**Failing Test Names:**

- `creates filtered shadow copy excluding .git, node_modules, and sensitive files`

### P21: Modify the original working tree

- **Target:** `packages/sandbox/src/shadow/shadow-copy.ts`
- **Test Suite:** `packages/sandbox/test/shadow-copy.test.ts`

```typescript
// Applied Mutation:
if (false && currentHash !== expectedHash) {
  throw new Error(
    `Integrity Violation: Source file '${relPath}' was modified in original repository tree!`
  );
}
```

**Failing Test Names:**

- `detects tampering in source directory via verifyOriginalUnchanged()`

### P22: fix apply skipping HMAC signature verification

- **Target:** `packages/core-engine/src/remediation/fix-store.ts`
- **Test Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`

```typescript
// Applied Mutation:
if (false && !stored.validSig) {
  return {
    success: false,
    exitCode: 2,
    error: `HMAC signature verification failed`,
  };
}
```

**Failing Test Names:**

- `detects tampered fix reports with HMAC mismatch (Mutation 22)`

### P23: fix apply skipping base file SHA-256 hash check

- **Target:** `packages/core-engine/src/remediation/fix-store.ts`
- **Test Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`

```typescript
// Applied Mutation:
if (false && currentHash !== baseFile.sha256) {
  return {
    success: false,
    exitCode: 2,
    error: `Base file hash mismatch`,
  };
}
```

**Failing Test Names:**

- `rejects apply when base file hash does not match (Mutation 23)`

### P24: fix apply skipping clean git tree check

- **Target:** `packages/core-engine/src/remediation/fix-store.ts`
- **Test Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`

```typescript
// Applied Mutation:
if (false && !isGitRepo) {
  if (!allowNonGit) {
    return {
      success: false,
      exitCode: 2,
      error: 'Repository is not a Git working tree',
    };
  }
}
```

**Failing Test Names:**

- `rejects apply on non-git directory without --allow-non-git (Mutation 24)`

### P25: Auto-commit or auto-branch

- **Target:** `packages/core-engine/src/remediation/fix-store.ts`
- **Test Suite:** `packages/core-engine/test/remediation/fix-store.test.ts`

```typescript
// Applied Mutation:
try {
  execFileSync('git', ['commit', '-am', 'auto-commit'], { cwd: repoPath });
} catch {}
return {
  success: true,
  exitCode: 0,
  appliedFiles,
};
```

**Failing Test Names:**

- `never auto-commits or auto-branches on apply (Mutation 25)`

### P26: Non-atomic file write

- **Target:** `packages/patch-engine/src/applier.ts`
- **Test Suite:** `packages/patch-engine/test/applier.test.ts`

```typescript
// Applied Mutation:
try {
      fs.writeFileSync(targetPath, content, {
        encoding: 'utf8',
        mode: mode ?? 0o644,
      });
    } catch (err) {
```

**Failing Test Names:**

- `atomicWrite writes file atomically preserving mode (Mutation 26)`

### P27: EOL / BOM not preserved

- **Target:** `packages/patch-engine/src/applier.ts`
- **Test Suite:** `packages/patch-engine/test/applier.test.ts`

```typescript
// Applied Mutation:
if (false && format.hasBom) {
  result = '\uFEFF' + result;
}
```

**Failing Test Names:**

- `preserves UTF-8 BOM`

### P28: Leave orphan containers after abort/SIGINT

- **Target:** `packages/sandbox/src/backends/container-backend.ts`
- **Test Suite:** `packages/sandbox/test/backends.test.ts`

```typescript
// Applied Mutation:
public async cleanup(): Promise<void> {
    return;
  }
```

**Failing Test Names:**

- `ContainerBackend cleanup removes labeled containers (Mutation 28)`
