# SecureShip Phase B: Mutation Verification Log (B1–B26)

In accordance with Phase B Function-Level Reachability specification, this log records the real execution of `pnpm verify:mutations`. Each mutation was applied to an isolated temporary copy of the repository in `$env:TEMP`, evaluated against the verification test suite, and confirmed to fail with specific failing test names.

**Verification Attestation:** Exactly 26 out of 26 mutations were successfully caught (0 uncaught mutations). Bidirectional proof confirms that each test fails under mutation and passes cleanly when restored.

---

## 1. Mutation Summary Table

| ID      | Description                                 | Target File                                                               | Verification Test                                               |   Status   | Failing Test(s)                                                                      |
| :------ | :------------------------------------------ | :------------------------------------------------------------------------ | :-------------------------------------------------------------- | :--------: | :----------------------------------------------------------------------------------- |
| **B1**  | heuristic source treated as HIGH            | `packages/reachability/src/symbols/candidate-extractor.ts`                | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B1: Mutation catches heuristic source treated as HIGH`                              |
| **B2**  | only the first candidate checked            | `packages/reachability/src/symbols/candidate-extractor.ts`                | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B2: Mutation catches only the first candidate checked`                              |
| **B3**  | escapes ignored                             | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B3: Mutation catches escapes ignored`                                               |
| **B4**  | computed access ignored                     | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B4: Mutation catches computed access ignored`                                       |
| **B5**  | import \* ignored                           | `packages/reachability/src/symbol-usage/python-symbol-usage-extractor.ts` | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B5: Mutation catches import * ignored`                                              |
| **B6**  | only calls (not references) counted         | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B6: Mutation catches only calls (not references) counted`                           |
| **B7**  | destructuring rename ignored                | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B7: Mutation catches destructuring rename ignored`                                  |
| **B8**  | unknown subpath treated as no use           | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B8: Mutation catches unknown subpath treated as no use`                             |
| **B9**  | createRequire ignored                       | `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B9: Mutation catches createRequire ignored`                                         |
| **B10** | leaf-dependents check skipped               | `packages/reachability/src/lockfile/lockfile-tree-parser.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B10: Mutation catches leaf-dependents check skipped`                                |
| **B11** | bin check skipped                           | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B11: Mutation catches bin check skipped`                                            |
| **B12** | reference scan of unparsed files skipped    | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B12: Mutation catches reference scan of unparsed files skipped`                     |
| **B13** | dead-file usage ignored                     | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B13: Mutation catches dead-file usage ignored`                                      |
| **B14** | parse-error files ignored                   | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B14: Mutation catches parse-error files ignored`                                    |
| **B15** | IMPORT_TIME treated as CALL                 | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B15: Mutation catches IMPORT_TIME treated as CALL`                                  |
| **B16** | incomplete entry treated as complete        | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B16: Mutation catches incomplete entry treated as complete`                         |
| **B17** | repo dataset honored                        | `packages/reachability/src/symbols/dataset-loader.ts`                     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B17: Mutation catches repo dataset honored`                                         |
| **B18** | integrity check skipped                     | `packages/reachability/src/symbols/dataset-loader.ts`                     | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B18: Mutation catches integrity check skipped`                                      |
| **B19** | tier gating bypassed                        | `packages/core-engine/src/orchestrator/scan-orchestrator.ts`              | `packages/core-engine/test/reachability-symbol-wiring.test.ts`  | **CAUGHT** | `Tier Gating: Free tier skips function-level reachability and records skippedTier`   |
| **B20** | REACHABLE_CALL_PATH emitted without a chain | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B20: Mutation catches REACHABLE_CALL_PATH emitted without a chain`                  |
| **B21** | call graph used to downgrade                | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B21: Mutation catches call graph used to downgrade`                                 |
| **B22** | Python UNINVOKED set to HIGH                | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B22: Mutation catches Python UNINVOKED set to HIGH`                                 |
| **B23** | exception turned into UNREACHABLE           | `packages/reachability/src/sca/sca-reachability-analyzer.ts`              | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B23: Mutation catches exception turned into UNREACHABLE`                            |
| **B24** | ledger loses symbol detail                  | `packages/core-engine/src/orchestrator/scan-orchestrator.ts`              | `packages/core-engine/test/reachability-symbol-wiring.test.ts`  | **CAUGHT** | `Suppression Ledger: suppressed finding includes symbol and source detail in ledger` |
| **B25** | stale cache facts served after version bump | `packages/reachability/src/cache/external-cache.ts`                       | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B25: Mutation catches stale cache facts served after version bump`                  |
| **B26** | nondeterministic ordering                   | `packages/reachability/src/symbols/candidate-extractor.ts`                | `packages/reachability/test/verification/phaseB.verify.test.ts` | **CAUGHT** | `B26: Mutation catches nondeterministic ordering`                                    |

---

## 2. Bidirectional Proofs (Pass on Restoration)

### Mutation B1: heuristic source treated as HIGH

- **Target File:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-   return sorted.map((symbol) => ({
-     symbol,
-     source: 'HEURISTIC_TEXT',
-     confidence: 'LOW' as const,
-   }));
+   return sorted.map((symbol) => ({
+     symbol,
+     source: 'HEURISTIC_TEXT',
+     confidence: 'HIGH' as const, // MUTATION_B1: heuristic source treated as HIGH
+   }));
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B1: Mutation catches heuristic source treated as HIGH`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B2: only the first candidate checked

- **Target File:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (curatedCandidates.length > 0) {
-       return curatedCandidates;
-     }
+     if (curatedCandidates.length > 0) {
+       return curatedCandidates.slice(0, 1); // MUTATION_B2: only first candidate
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B2: Mutation catches only the first candidate checked`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B3: escapes ignored

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-             if (b.importedName === 'default' || b.importedName === 'namespace') {
-               recordEscape(
-                 b.packageRoot,
-                 'ARGUMENT_PASS',
-                 line,
-                 `Passed '${arg.text}' to '${fn.text}'`
-               );
-             }
+             if (false && (b.importedName === 'default' || b.importedName === 'namespace')) { // MUTATION_B3: escapes ignored
+               recordEscape(
+                 b.packageRoot,
+                 'ARGUMENT_PASS',
+                 line,
+                 `Passed '${arg.text}' to '${fn.text}'`
+               );
+             }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B3: Mutation catches escapes ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B4: computed access ignored

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     // 3. Literal computed call: _['template'](...)
-     if (fn.type === 'subscript_expression') {
+     // 3. Literal computed call: _['template'](...)
+     if (false && fn.type === 'subscript_expression') { // MUTATION_B4: computed access ignored
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B4: Mutation catches computed access ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B5: import \* ignored

- **Target File:** `packages/reachability/src/symbol-usage/python-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (child.type === 'wildcard_import') {
-         escapes.push({
-           packageRoot: parsed.packageRoot,
-           reason: 'WILDCARD_IMPORT',
-           file: relativePath,
-           line,
-           detail: `from ${rawSpecifier} import *`,
-         });
-       }
+       if (false && child.type === 'wildcard_import') { // MUTATION_B5: import * ignored
+         escapes.push({
+           packageRoot: parsed.packageRoot,
+           reason: 'WILDCARD_IMPORT',
+           file: relativePath,
+           line,
+           detail: `from ${rawSpecifier} import *`,
+         });
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B5: Mutation catches import * ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B6: only calls (not references) counted

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (root && prop) {
-         recordUsage(
-           root.packageRoot,
-           prop.text,
-           'member_access',
-           line,
-           false,
-           `${root.rootName}.${prop.text}`
-         );
-       }
+       if (false && root && prop) { // MUTATION_B6: member_access non-call omitted
+         recordUsage(
+           root.packageRoot,
+           prop.text,
+           'member_access',
+           line,
+           false,
+           `${root.rootName}.${prop.text}`
+         );
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B6: Mutation catches only calls (not references) counted`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B7: destructuring rename ignored

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-           if (value.type === 'identifier') {
-             const alias = value.text;
+           if (false && value.type === 'identifier') { // MUTATION_B7: destructuring rename ignored
+             const alias = value.text;
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B7: Mutation catches destructuring rename ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B8: unknown subpath treated as no use

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (!isLocal && subpath && !isStatementTypeOnly) {
-         escapes.push({
-           packageRoot,
-           reason: 'UNKNOWN_SUBPATH',
-           file: relativePath,
-           line,
-           detail: `Default import of subpath '${rawSpecifier}'`,
-         });
-       }
+       if (false && !isLocal && subpath && !isStatementTypeOnly) { // MUTATION_B8: unknown subpath treated as no use
+         escapes.push({
+           packageRoot,
+           reason: 'UNKNOWN_SUBPATH',
+           file: relativePath,
+           line,
+           detail: `Default import of subpath '${rawSpecifier}'`,
+         });
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B8: Mutation catches unknown subpath treated as no use`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B9: createRequire ignored

- **Target File:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (
-         node.type === 'identifier' &&
-         (node.text === 'createRequire' || node.text === 'require.context')
-       ) {
-         hasCreateRequire = true;
-       }
+       if (
+         false && node.type === 'identifier' &&
+         (node.text === 'createRequire' || node.text === 'require.context')
+       ) { // MUTATION_B9: createRequire ignored
+         hasCreateRequire = true;
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B9: Mutation catches createRequire ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B10: leaf-dependents check skipped

- **Target File:** `packages/reachability/src/lockfile/lockfile-tree-parser.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     // Dependents must be empty
-     const dependents = graph.dependentsMap.get(norm);
-     return !dependents || dependents.size === 0;
+     // Dependents must be empty
+     return true; // MUTATION_B10: leaf-dependents check skipped
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B10: Mutation catches leaf-dependents check skipped`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B11: bin check skipped

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     return false;
-   }
-
-   /**
-    * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.
+     return true; // MUTATION_B11: bin check skipped
+   }
+
+   /**
+    * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B11: Mutation catches bin check skipped`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B12: reference scan of unparsed files skipped

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     for (const f of files) {
-       if (!f.hasParseError) {
-         excludeFiles.add(f.filePath);
-         excludeFiles.add(f.relativePath);
-       }
-     }
+     for (const f of files) {
+       if (true) { // MUTATION_B12: exclude even unparsed files
+         excludeFiles.add(f.filePath);
+         excludeFiles.add(f.relativePath);
+       }
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B12: Mutation catches reference scan of unparsed files skipped`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B13: dead-file usage ignored

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     const nonTestFiles = Array.from(graph.files.values()).filter(
-       (f) => !EntrypointDetector.isTestOrMockFile(f.relativePath)
-     );
+     const nonTestFiles = Array.from(graph.files.values()).filter(
+       (f) => f.isReachable && !EntrypointDetector.isTestOrMockFile(f.relativePath) // MUTATION_B13: dead-file usage ignored
+     );
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B13: Mutation catches dead-file usage ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B14: parse-error files ignored

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     // P2: Zero parse errors in all non-test source files
-     if (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError)) {
+     // P2: Zero parse errors in all non-test source files
+     if (false && (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError))) {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B14: Mutation catches parse-error files ignored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B15: IMPORT_TIME treated as CALL

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (datasetEntry.triggeredOn !== 'CALL') {
-         return ScaReachabilityAnalyzer.blockedResult(
-           'TRIGGER_NOT_CALL',
-           `Vulnerability triggers on ${datasetEntry.triggeredOn}; not eligible for function call pruning`,
-           chain,
-           packageName
-         );
-       }
+       if (false && datasetEntry.triggeredOn !== 'CALL') { // MUTATION_B15: IMPORT_TIME treated as CALL
+         return ScaReachabilityAnalyzer.blockedResult(
+           'TRIGGER_NOT_CALL',
+           `Vulnerability triggers on ${datasetEntry.triggeredOn}; not eligible for function call pruning`,
+           chain,
+           packageName
+         );
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B15: Mutation catches IMPORT_TIME treated as CALL`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B16: incomplete entry treated as complete

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (!datasetEntry.entryPointsComplete) {
-         return ScaReachabilityAnalyzer.blockedResult(
-           'ENTRYPOINTS_INCOMPLETE',
-           'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
-           chain,
-           packageName
-         );
-       }
+       if (false && !datasetEntry.entryPointsComplete) { // MUTATION_B16: incomplete treated as complete
+         return ScaReachabilityAnalyzer.blockedResult(
+           'ENTRYPOINTS_INCOMPLETE',
+           'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
+           chain,
+           packageName
+         );
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B16: Mutation catches incomplete entry treated as complete`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B17: repo dataset honored

- **Target File:** `packages/reachability/src/symbols/dataset-loader.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (this.isRepoResidentPath(resolvedCustom, projectRoot)) {
+     if (false && this.isRepoResidentPath(resolvedCustom, projectRoot)) { // MUTATION_B17: repo dataset honored
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B17: Mutation catches repo dataset honored`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B18: integrity check skipped

- **Target File:** `packages/reachability/src/symbols/dataset-loader.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-         if (manifest.sha256 !== actualHash) {
+         if (false && manifest.sha256 !== actualHash) { // MUTATION_B18: integrity check skipped
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B18: Mutation catches integrity check skipped`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B19: tier gating bypassed

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/reachability-symbol-wiring.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (functionLevelConfigEnabled) {
-       if (tierCaps.allowCallPathReachability) {
-         functionLevel = true;
-       } else {
+     if (functionLevelConfigEnabled) {
+       if (true || tierCaps.allowCallPathReachability) { // MUTATION_B19: tier gating bypassed
+         functionLevel = true;
+       } else {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `Tier Gating: Free tier skips function-level reachability and records skippedTier`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B20: REACHABLE_CALL_PATH emitted without a chain

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       const isCallPathProven = provenChain !== null;
+       const isCallPathProven = true; // MUTATION_B20: emit without proven chain
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B20: Mutation catches REACHABLE_CALL_PATH emitted without a chain`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B21: call graph used to downgrade

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'REACHABLE_IMPORT';
+       const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'UNREACHABLE'; // MUTATION_B21: call graph downgrades to UNREACHABLE
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B21: Mutation catches call graph used to downgrade`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B22: Python UNINVOKED set to HIGH

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-     } else if (isPythonEco || !isBinSafe) {
-       finalConfidence = 'MEDIUM';
-     } else {
+     } else if (false && (isPythonEco || !isBinSafe)) { // MUTATION_B22: Python set to HIGH
+       finalConfidence = 'MEDIUM';
+     } else {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B22: Mutation catches Python UNINVOKED set to HIGH`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B23: exception turned into UNREACHABLE

- **Target File:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (isEligibleEco && isFunctionLevelEnabled) {
-         return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
-           finding,
-           packageName,
-           normPkg,
-           candidateModuleNames,
-           chain,
-           graph,
-           lockfileGraph,
-           projectRoot,
-           options
-         );
-       }
+       if (isEligibleEco && isFunctionLevelEnabled) {
+         try {
+           return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
+             finding,
+             packageName,
+             normPkg,
+             candidateModuleNames,
+             chain,
+             graph,
+             lockfileGraph,
+             projectRoot,
+             options
+           );
+         } catch {
+           return { verdict: 'UNREACHABLE', analysisConfidence: 'HIGH', evidence: { kind: 'UNINVOKED_SYMBOL' }, limitations: [] }; // MUTATION_B23: fail-open
+         }
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B23: Mutation catches exception turned into UNREACHABLE`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B24: ledger loses symbol detail

- **Target File:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Verification Suite:** `packages/core-engine/test/reachability-symbol-wiring.test.ts`
- **Applied Mutation Patch:**

```diff
-             if (detail.evidence.kind === 'UNINVOKED_SYMBOL') {
-               const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
-               const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
-               const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
-               suppressionDetail = `Symbol '${symStr}' from source ${srcStr} is not invoked (Dataset URLs: ${urlStr})`;
-             }
+             if (false && detail.evidence.kind === 'UNINVOKED_SYMBOL') { // MUTATION_B24: ledger loses symbol detail
+               const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
+               const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
+               const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
+               suppressionDetail = `Symbol '${symStr}' from source ${srcStr} is not invoked (Dataset URLs: ${urlStr})`;
+             }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `Suppression Ledger: suppressed finding includes symbol and source detail in ledger`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B25: stale cache facts served after version bump

- **Target File:** `packages/reachability/src/cache/external-cache.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (
-         entry.version !== ExternalExtractionCache.ANALYZER_VERSION ||
-         entry.manifestHash !== getWasmManifestHash() ||
-         entry.contentHash !== currentContentHash
-       ) {
+       if (
+         (false && entry.version !== ExternalExtractionCache.ANALYZER_VERSION) ||
+         entry.manifestHash !== getWasmManifestHash() ||
+         entry.contentHash !== currentContentHash
+       ) { // MUTATION_B25: stale cache facts served
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B25: Mutation catches stale cache facts served after version bump`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation B26: nondeterministic ordering

- **Target File:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Verification Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`
- **Applied Mutation Patch:**

```diff
-   return candidates.sort((a, b) => a.symbol.localeCompare(b.symbol));
- }
-
- /**
-  * Extracts candidates from title and description
+   return candidates.sort((a, b) => b.symbol.localeCompare(a.symbol)); // MUTATION_B26: reversed ordering
+ }
+
+ /**
+  * Extracts candidates from title and description
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `B26: Mutation catches nondeterministic ordering`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

## 3. Detailed Patch Log

### B1: heuristic source treated as HIGH

- **Target:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
return sorted.map((symbol) => ({
  symbol,
  source: 'HEURISTIC_TEXT',
  confidence: 'HIGH' as const, // MUTATION_B1: heuristic source treated as HIGH
}));
```

**Failing Test Names:**

- `B1: Mutation catches heuristic source treated as HIGH`

### B2: only the first candidate checked

- **Target:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (curatedCandidates.length > 0) {
  return curatedCandidates.slice(0, 1); // MUTATION_B2: only first candidate
}
```

**Failing Test Names:**

- `B2: Mutation catches only the first candidate checked`

### B3: escapes ignored

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && (b.importedName === 'default' || b.importedName === 'namespace')) {
  // MUTATION_B3: escapes ignored
  recordEscape(b.packageRoot, 'ARGUMENT_PASS', line, `Passed '${arg.text}' to '${fn.text}'`);
}
```

**Failing Test Names:**

- `B3: Mutation catches escapes ignored`

### B4: computed access ignored

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
// 3. Literal computed call: _['template'](...)
    if (false && fn.type === 'subscript_expression') { // MUTATION_B4: computed access ignored
```

**Failing Test Names:**

- `B4: Mutation catches computed access ignored`

### B5: import \* ignored

- **Target:** `packages/reachability/src/symbol-usage/python-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && child.type === 'wildcard_import') {
  // MUTATION_B5: import * ignored
  escapes.push({
    packageRoot: parsed.packageRoot,
    reason: 'WILDCARD_IMPORT',
    file: relativePath,
    line,
    detail: `from ${rawSpecifier} import *`,
  });
}
```

**Failing Test Names:**

- `B5: Mutation catches import * ignored`

### B6: only calls (not references) counted

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && root && prop) {
  // MUTATION_B6: member_access non-call omitted
  recordUsage(
    root.packageRoot,
    prop.text,
    'member_access',
    line,
    false,
    `${root.rootName}.${prop.text}`
  );
}
```

**Failing Test Names:**

- `B6: Mutation catches only calls (not references) counted`

### B7: destructuring rename ignored

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && value.type === 'identifier') { // MUTATION_B7: destructuring rename ignored
            const alias = value.text;
```

**Failing Test Names:**

- `B7: Mutation catches destructuring rename ignored`

### B8: unknown subpath treated as no use

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && !isLocal && subpath && !isStatementTypeOnly) {
  // MUTATION_B8: unknown subpath treated as no use
  escapes.push({
    packageRoot,
    reason: 'UNKNOWN_SUBPATH',
    file: relativePath,
    line,
    detail: `Default import of subpath '${rawSpecifier}'`,
  });
}
```

**Failing Test Names:**

- `B8: Mutation catches unknown subpath treated as no use`

### B9: createRequire ignored

- **Target:** `packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (
  false &&
  node.type === 'identifier' &&
  (node.text === 'createRequire' || node.text === 'require.context')
) {
  // MUTATION_B9: createRequire ignored
  hasCreateRequire = true;
}
```

**Failing Test Names:**

- `B9: Mutation catches createRequire ignored`

### B10: leaf-dependents check skipped

- **Target:** `packages/reachability/src/lockfile/lockfile-tree-parser.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
// Dependents must be empty
return true; // MUTATION_B10: leaf-dependents check skipped
```

**Failing Test Names:**

- `B10: Mutation catches leaf-dependents check skipped`

### B11: bin check skipped

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
return true; // MUTATION_B11: bin check skipped
  }

  /**
   * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.
```

**Failing Test Names:**

- `B11: Mutation catches bin check skipped`

### B12: reference scan of unparsed files skipped

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
for (const f of files) {
  if (true) {
    // MUTATION_B12: exclude even unparsed files
    excludeFiles.add(f.filePath);
    excludeFiles.add(f.relativePath);
  }
}
```

**Failing Test Names:**

- `B12: Mutation catches reference scan of unparsed files skipped`

### B13: dead-file usage ignored

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
const nonTestFiles = Array.from(graph.files.values()).filter(
  (f) => f.isReachable && !EntrypointDetector.isTestOrMockFile(f.relativePath) // MUTATION_B13: dead-file usage ignored
);
```

**Failing Test Names:**

- `B13: Mutation catches dead-file usage ignored`

### B14: parse-error files ignored

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
// P2: Zero parse errors in all non-test source files
    if (false && (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError))) {
```

**Failing Test Names:**

- `B14: Mutation catches parse-error files ignored`

### B15: IMPORT_TIME treated as CALL

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && datasetEntry.triggeredOn !== 'CALL') {
  // MUTATION_B15: IMPORT_TIME treated as CALL
  return ScaReachabilityAnalyzer.blockedResult(
    'TRIGGER_NOT_CALL',
    `Vulnerability triggers on ${datasetEntry.triggeredOn}; not eligible for function call pruning`,
    chain,
    packageName
  );
}
```

**Failing Test Names:**

- `B15: Mutation catches IMPORT_TIME treated as CALL`

### B16: incomplete entry treated as complete

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && !datasetEntry.entryPointsComplete) {
  // MUTATION_B16: incomplete treated as complete
  return ScaReachabilityAnalyzer.blockedResult(
    'ENTRYPOINTS_INCOMPLETE',
    'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
    chain,
    packageName
  );
}
```

**Failing Test Names:**

- `B16: Mutation catches incomplete entry treated as complete`

### B17: repo dataset honored

- **Target:** `packages/reachability/src/symbols/dataset-loader.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && this.isRepoResidentPath(resolvedCustom, projectRoot)) { // MUTATION_B17: repo dataset honored
```

**Failing Test Names:**

- `B17: Mutation catches repo dataset honored`

### B18: integrity check skipped

- **Target:** `packages/reachability/src/symbols/dataset-loader.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (false && manifest.sha256 !== actualHash) { // MUTATION_B18: integrity check skipped
```

**Failing Test Names:**

- `B18: Mutation catches integrity check skipped`

### B19: tier gating bypassed

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/reachability-symbol-wiring.test.ts`

```typescript
// Applied Mutation:
if (functionLevelConfigEnabled) {
      if (true || tierCaps.allowCallPathReachability) { // MUTATION_B19: tier gating bypassed
        functionLevel = true;
      } else {
```

**Failing Test Names:**

- `Tier Gating: Free tier skips function-level reachability and records skippedTier`

### B20: REACHABLE_CALL_PATH emitted without a chain

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
const isCallPathProven = true; // MUTATION_B20: emit without proven chain
```

**Failing Test Names:**

- `B20: Mutation catches REACHABLE_CALL_PATH emitted without a chain`

### B21: call graph used to downgrade

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'UNREACHABLE'; // MUTATION_B21: call graph downgrades to UNREACHABLE
```

**Failing Test Names:**

- `B21: Mutation catches call graph used to downgrade`

### B22: Python UNINVOKED set to HIGH

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
} else if (false && (isPythonEco || !isBinSafe)) { // MUTATION_B22: Python set to HIGH
      finalConfidence = 'MEDIUM';
    } else {
```

**Failing Test Names:**

- `B22: Mutation catches Python UNINVOKED set to HIGH`

### B23: exception turned into UNREACHABLE

- **Target:** `packages/reachability/src/sca/sca-reachability-analyzer.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (isEligibleEco && isFunctionLevelEnabled) {
  try {
    return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
      finding,
      packageName,
      normPkg,
      candidateModuleNames,
      chain,
      graph,
      lockfileGraph,
      projectRoot,
      options
    );
  } catch {
    return {
      verdict: 'UNREACHABLE',
      analysisConfidence: 'HIGH',
      evidence: { kind: 'UNINVOKED_SYMBOL' },
      limitations: [],
    }; // MUTATION_B23: fail-open
  }
}
```

**Failing Test Names:**

- `B23: Mutation catches exception turned into UNREACHABLE`

### B24: ledger loses symbol detail

- **Target:** `packages/core-engine/src/orchestrator/scan-orchestrator.ts`
- **Test Suite:** `packages/core-engine/test/reachability-symbol-wiring.test.ts`

```typescript
// Applied Mutation:
if (false && detail.evidence.kind === 'UNINVOKED_SYMBOL') {
  // MUTATION_B24: ledger loses symbol detail
  const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
  const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
  const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
  suppressionDetail = `Symbol '${symStr}' from source ${srcStr} is not invoked (Dataset URLs: ${urlStr})`;
}
```

**Failing Test Names:**

- `Suppression Ledger: suppressed finding includes symbol and source detail in ledger`

### B25: stale cache facts served after version bump

- **Target:** `packages/reachability/src/cache/external-cache.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
if (
        (false && entry.version !== ExternalExtractionCache.ANALYZER_VERSION) ||
        entry.manifestHash !== getWasmManifestHash() ||
        entry.contentHash !== currentContentHash
      ) { // MUTATION_B25: stale cache facts served
```

**Failing Test Names:**

- `B25: Mutation catches stale cache facts served after version bump`

### B26: nondeterministic ordering

- **Target:** `packages/reachability/src/symbols/candidate-extractor.ts`
- **Test Suite:** `packages/reachability/test/verification/phaseB.verify.test.ts`

```typescript
// Applied Mutation:
return candidates.sort((a, b) => b.symbol.localeCompare(a.symbol)); // MUTATION_B26: reversed ordering
}

/**
 * Extracts candidates from title and description
```

**Failing Test Names:**

- `B26: Mutation catches nondeterministic ordering`
