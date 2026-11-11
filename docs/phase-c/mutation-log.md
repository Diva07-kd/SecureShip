# SecureShip Phase C: Mutation Verification Log (C1–C9)

In accordance with Phase C Container & Air-Gap Completeness specification, this log records the real execution of `pnpm verify:mutations`. Each mutation was applied to an isolated temporary copy of the repository in `$env:TEMP`, evaluated against the verification test suite, and confirmed to fail with specific failing test names.

**Verification Attestation:** Exactly 9 out of 9 mutations were successfully caught (0 uncaught mutations). Bidirectional proof confirms that each test fails under mutation and passes cleanly when restored.

---

## 1. Mutation Summary Table

| ID     | Description                                                                            | Target File                                               | Verification Test                                  |   Status   | Failing Test(s)                                                                            |
| :----- | :------------------------------------------------------------------------------------- | :-------------------------------------------------------- | :------------------------------------------------- | :--------: | :----------------------------------------------------------------------------------------- |
| **C1** | Pin authority guard: remote manifest mismatch must fail hard and never override pin    | `packages/cli/src/commands/install-tools.ts`              | `packages/cli/test/install-tools.test.ts`          | **CAUGHT** | `Defect D1 Defense: fails hard when remote manifest hash does not match authoritative pin` |
| **C2** | Hash compare guard: downloaded asset checksum mismatch aborts install                  | `packages/cli/src/commands/install-tools.ts`              | `packages/cli/test/install-tools.test.ts`          | **CAUGHT** | `aborts installation and removes temp file on SHA-256 integrity mismatch`                  |
| **C3** | SafeTarReader traversal/absolute entry guard                                           | `packages/core-engine/src/offline/tar-bundle.ts`          | `packages/core-engine/test/bundle-offline.test.ts` | **CAUGHT** | `rejects path traversal attempts in archive extraction`                                    |
| **C4** | Ed25519 signature verification guard in offline bundle importer                        | `packages/core-engine/src/offline/bundle-service.ts`      | `packages/core-engine/test/bundle-offline.test.ts` | **CAUGHT** | `rejects bundle signed with untrusted key`                                                 |
| **C5** | Anti-rollback guard: rejecting older offline bundles unless --allow-downgrade          | `packages/core-engine/src/offline/bundle-service.ts`      | `packages/core-engine/test/bundle-offline.test.ts` | **CAUGHT** | `enforces anti-rollback protection unless --allow-downgrade is passed`                     |
| **C6** | Atomic swap guard: publishing generation atomically via CURRENT pointer rename         | `packages/core-engine/src/offline/bundle-service.ts`      | `packages/core-engine/test/bundle-offline.test.ts` | **CAUGHT** | `rejects unsigned bundle when trusted keys are required or allowUnsigned is false`         |
| **C7** | Offline egress guard: strictly blocking unauthorized outbound operations               | `packages/core-engine/src/offline/egress-guard.ts`        | `packages/core-engine/test/offline.test.ts`        | **CAUGHT** | `blocks cloud AI egress without loopback in offline mode`                                  |
| **C8** | Stale DB guard: evaluating database expiration when age exceeds maxDbAgeDays           | `packages/core-engine/src/offline/freshness-evaluator.ts` | `packages/core-engine/test/offline.test.ts`        | **CAUGHT** | `evaluates expired generation older than 30 days`                                          |
| **C9** | Planted binary guard: preventing execution of binaries planted inside target directory | `packages/core-engine/src/paths/index.ts`                 | `packages/scanner-adapters/test/paths.test.ts`     | **CAUGHT** | `assertNotInsideTarget throws security violation when tool resides inside targetDir`       |

---

## 2. Bidirectional Proofs (Pass on Restoration)

### Mutation C1: Pin authority guard: remote manifest mismatch must fail hard and never override pin

- **Target File:** `packages/cli/src/commands/install-tools.ts`
- **Verification Suite:** `packages/cli/test/install-tools.test.ts`
- **Applied Mutation Patch:**

```diff
-           if (remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
-             throw new Error(
-               `Security violation: Remote checksum manifest (${remoteHash}) does not match authoritative bundled pin (${asset.sha256}) for ${toolDef.name}! Aborting install to prevent trust downgrade.`
-             );
-           }
+           if (false && remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
+             throw new Error('Security violation');
+           }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `Defect D1 Defense: fails hard when remote manifest hash does not match authoritative pin`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C2: Hash compare guard: downloaded asset checksum mismatch aborts install

- **Target File:** `packages/cli/src/commands/install-tools.ts`
- **Verification Suite:** `packages/cli/test/install-tools.test.ts`
- **Applied Mutation Patch:**

```diff
-       if (computedSha !== asset.sha256.toLowerCase()) {
-         throw new Error(
-           `Cryptographic checksum mismatch! Expected SHA-256 ${asset.sha256}, got ${computedSha}. Aborting install.`
-         );
-       }
+       if (false && computedSha !== asset.sha256.toLowerCase()) {
+         throw new Error('Cryptographic checksum mismatch');
+       }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `aborts installation and removes temp file on SHA-256 integrity mismatch`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C3: SafeTarReader traversal/absolute entry guard

- **Target File:** `packages/core-engine/src/offline/tar-bundle.ts`
- **Verification Suite:** `packages/core-engine/test/bundle-offline.test.ts`
- **Applied Mutation Patch:**

```diff
-         if (
-           entryName.startsWith('/') ||
-           entryName.startsWith('\\') ||
-           entryName.includes('..') ||
-           entryName.includes('\0') ||
-           /^[a-zA-Z]:/.test(entryName)
-         ) {
-           throw new Error(
-             `Security violation: Prohibited path traversal or absolute entry '${entryName}'.`
-           );
-         }
+         if (false) {
+           throw new Error('Security violation');
+         }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects path traversal attempts in archive extraction`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C4: Ed25519 signature verification guard in offline bundle importer

- **Target File:** `packages/core-engine/src/offline/bundle-service.ts`
- **Verification Suite:** `packages/core-engine/test/bundle-offline.test.ts`
- **Applied Mutation Patch:**

```diff
-         if (!verified) {
-           throw new Error(
-             `[Security Violation] Signature verification failed for bundle '${manifest.bundleId}' against all provided trusted public keys.`
-           );
-         }
+         if (false && !verified) {
+           throw new Error('Signature verification failed');
+         }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects bundle signed with untrusted key`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C5: Anti-rollback guard: rejecting older offline bundles unless --allow-downgrade

- **Target File:** `packages/core-engine/src/offline/bundle-service.ts`
- **Verification Suite:** `packages/core-engine/test/bundle-offline.test.ts`
- **Applied Mutation Patch:**

```diff
-         if (bundleCreated < activeCreated && !options.allowDowngrade) {
-           throw new Error(
-             `[Security Violation] Anti-rollback rejected: Bundle timestamp (${manifest.createdAt}) is older than installed generation '${activeGen.id}' (${activeGen.manifest.createdAt}). Use --allow-downgrade to override.`
-           );
-         }
+         if (false && bundleCreated < activeCreated && !options.allowDowngrade) {
+           throw new Error('Anti-rollback rejected');
+         }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `enforces anti-rollback protection unless --allow-downgrade is passed`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C6: Atomic swap guard: publishing generation atomically via CURRENT pointer rename

- **Target File:** `packages/core-engine/src/offline/bundle-service.ts`
- **Verification Suite:** `packages/core-engine/test/bundle-offline.test.ts`
- **Applied Mutation Patch:**

```diff
-       // Atomic pointer swap to CURRENT
-       const tempCurrent = path.join(targetDbDir, `.CURRENT.tmp-${process.pid}`);
-       fs.writeFileSync(tempCurrent, genId);
-       fs.renameSync(tempCurrent, path.join(targetDbDir, 'CURRENT'));
+       // Atomic pointer swap to CURRENT (MUTATED: skipped rename)
+       const tempCurrent = path.join(targetDbDir, `.CURRENT.tmp-${process.pid}`);
+       fs.writeFileSync(tempCurrent, genId);
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `rejects unsigned bundle when trusted keys are required or allowUnsigned is false`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C7: Offline egress guard: strictly blocking unauthorized outbound operations

- **Target File:** `packages/core-engine/src/offline/egress-guard.ts`
- **Verification Suite:** `packages/core-engine/test/offline.test.ts`
- **Applied Mutation Patch:**

```diff
-   throw new Error(
-     `[Security Violation] Feature '${feature}' requires outbound network access and is blocked in offline mode (--offline).`
-   );
+   // MUTATION_C7: skipped egress block
+   return;
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `blocks cloud AI egress without loopback in offline mode`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C8: Stale DB guard: evaluating database expiration when age exceeds maxDbAgeDays

- **Target File:** `packages/core-engine/src/offline/freshness-evaluator.ts`
- **Verification Suite:** `packages/core-engine/test/offline.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (isExpired) {
-       status = 'EXPIRED';
-     } else if (isStale) {
+     if (false && isExpired) {
+       status = 'EXPIRED';
+     } else if (isStale) {
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `evaluates expired generation older than 30 days`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

### Mutation C9: Planted binary guard: preventing execution of binaries planted inside target directory

- **Target File:** `packages/core-engine/src/paths/index.ts`
- **Verification Suite:** `packages/scanner-adapters/test/paths.test.ts`
- **Applied Mutation Patch:**

```diff
-     if (
-       relative === '' ||
-       (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\'))
-     ) {
-       throw new Error(
-         `Security violation: Scanner binary '${candidatePath}' resides inside target directory '${targetDir}'. Execution blocked to prevent planted-binary attack.`
-       );
-     }
+     if (
+       false && (
+       relative === '' ||
+       (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\')))
+     ) {
+       throw new Error('Security violation');
+     }
```

- **Mutation Test Run (Exit Code 1 - FAILING):**
  - ❌ `assertNotInsideTarget throws security violation when tool resides inside targetDir`
- **Restored Code Run (Exit Code 0 - PASSING):**
  - ✅ Clean restoration confirmed; 0 test failures.

## 3. Detailed Patch Log

### C1: Pin authority guard: remote manifest mismatch must fail hard and never override pin

- **Target:** `packages/cli/src/commands/install-tools.ts`
- **Test Suite:** `packages/cli/test/install-tools.test.ts`

```typescript
// Applied Mutation:
if (false && remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
  throw new Error('Security violation');
}
```

**Failing Test Names:**

- `Defect D1 Defense: fails hard when remote manifest hash does not match authoritative pin`

### C2: Hash compare guard: downloaded asset checksum mismatch aborts install

- **Target:** `packages/cli/src/commands/install-tools.ts`
- **Test Suite:** `packages/cli/test/install-tools.test.ts`

```typescript
// Applied Mutation:
if (false && computedSha !== asset.sha256.toLowerCase()) {
  throw new Error('Cryptographic checksum mismatch');
}
```

**Failing Test Names:**

- `aborts installation and removes temp file on SHA-256 integrity mismatch`

### C3: SafeTarReader traversal/absolute entry guard

- **Target:** `packages/core-engine/src/offline/tar-bundle.ts`
- **Test Suite:** `packages/core-engine/test/bundle-offline.test.ts`

```typescript
// Applied Mutation:
if (false) {
  throw new Error('Security violation');
}
```

**Failing Test Names:**

- `rejects path traversal attempts in archive extraction`

### C4: Ed25519 signature verification guard in offline bundle importer

- **Target:** `packages/core-engine/src/offline/bundle-service.ts`
- **Test Suite:** `packages/core-engine/test/bundle-offline.test.ts`

```typescript
// Applied Mutation:
if (false && !verified) {
  throw new Error('Signature verification failed');
}
```

**Failing Test Names:**

- `rejects bundle signed with untrusted key`

### C5: Anti-rollback guard: rejecting older offline bundles unless --allow-downgrade

- **Target:** `packages/core-engine/src/offline/bundle-service.ts`
- **Test Suite:** `packages/core-engine/test/bundle-offline.test.ts`

```typescript
// Applied Mutation:
if (false && bundleCreated < activeCreated && !options.allowDowngrade) {
  throw new Error('Anti-rollback rejected');
}
```

**Failing Test Names:**

- `enforces anti-rollback protection unless --allow-downgrade is passed`

### C6: Atomic swap guard: publishing generation atomically via CURRENT pointer rename

- **Target:** `packages/core-engine/src/offline/bundle-service.ts`
- **Test Suite:** `packages/core-engine/test/bundle-offline.test.ts`

```typescript
// Applied Mutation:
// Atomic pointer swap to CURRENT (MUTATED: skipped rename)
const tempCurrent = path.join(targetDbDir, `.CURRENT.tmp-${process.pid}`);
fs.writeFileSync(tempCurrent, genId);
```

**Failing Test Names:**

- `rejects unsigned bundle when trusted keys are required or allowUnsigned is false`

### C7: Offline egress guard: strictly blocking unauthorized outbound operations

- **Target:** `packages/core-engine/src/offline/egress-guard.ts`
- **Test Suite:** `packages/core-engine/test/offline.test.ts`

```typescript
// Applied Mutation:
// MUTATION_C7: skipped egress block
return;
```

**Failing Test Names:**

- `blocks cloud AI egress without loopback in offline mode`

### C8: Stale DB guard: evaluating database expiration when age exceeds maxDbAgeDays

- **Target:** `packages/core-engine/src/offline/freshness-evaluator.ts`
- **Test Suite:** `packages/core-engine/test/offline.test.ts`

```typescript
// Applied Mutation:
if (false && isExpired) {
      status = 'EXPIRED';
    } else if (isStale) {
```

**Failing Test Names:**

- `evaluates expired generation older than 30 days`

### C9: Planted binary guard: preventing execution of binaries planted inside target directory

- **Target:** `packages/core-engine/src/paths/index.ts`
- **Test Suite:** `packages/scanner-adapters/test/paths.test.ts`

```typescript
// Applied Mutation:
if (
  false &&
  (relative === '' ||
    (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\')))
) {
  throw new Error('Security violation');
}
```

**Failing Test Names:**

- `assertNotInsideTarget throws security violation when tool resides inside targetDir`
