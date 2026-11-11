# SecureShip Phase B: Vulnerable Symbol Dataset Specification

**Document:** Symbol Dataset Specification, Curation Protocol, & Provenance Rules  
**Status:** PRODUCTION STANDARD  
**Author:** Principal Security Engineer & Verification Lead  
**Governing Standard:** Anti-Cheat Rules AC1–AC9 & Sound Pruning Principles F1–F10

---

## 1. Overview & Trust Philosophy

Function-level reachability refinement relies on accurate knowledge of the specific functions, methods, and properties that expose a package vulnerability. A single omitted entry point could allow an application to invoke vulnerable code while SecureShip falsely claims the vulnerability is unreached.

To prevent unsoundness and uphold **Anti-Cheat Rule AC3 (No Fabricated Data)** and **Principle F1 (Positive Evidence Required)**:

1. Every dataset entry in [`packages/reachability/data/vulnerable-symbols.json`](file:///c:/dev/SecureShip-IDE/packages/reachability/data/vulnerable-symbols.json) must be individually verified against:
   - The **official advisory text** (GHSA, OSV, or NVD).
   - The **actual public fix commit or pull request diff** in the package repository.
2. Only entry points that expose the vulnerability through the package's **public API** are registered. Internal functions (e.g. `baseTemplate`) that cannot be reached directly without calling a public wrapper are mapped to the public entry points (e.g. `template`).
3. An entry point list is marked `entryPointsComplete: true` **only** when the fix commit confirms that all public call paths to the patch have been enumerated. If any doubt exists, `entryPointsComplete` must be `false` (which prevents high-confidence pruning).
4. The dataset is cryptographically sealed with a SHA-256 manifest ([`vulnerable-symbols.manifest.json`](file:///c:/dev/SecureShip-IDE/packages/reachability/data/vulnerable-symbols.manifest.json)) and verified offline at load time.

---

## 2. Zod Schema Specification

The dataset is validated strictly against [`VulnerableSymbolsDatasetSchema`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/symbols/vulnerable-symbol.schema.ts):

```typescript
import { z } from 'zod';

export const VulnerableSymbolEntryPointSchema = z.object({
  module: z.string().default('.'), // '.' for root package or subpath like 'template'
  export: z.string(), // Exported identifier (e.g. 'template', 'get', 'load')
  kind: z.enum(['FUNCTION', 'CLASS', 'METHOD', 'PROPERTY']),
  via: z.array(z.string()).optional(), // Required when kind === 'METHOD'
});

export const VulnerableSymbolEntrySchema = z.object({
  id: z.string(), // Primary advisory ID (e.g. 'CVE-2021-23337')
  aliases: z.array(z.string()).default([]), // GHSA, OSV, or other CVE aliases
  ecosystem: z.enum(['npm', 'pypi']),
  package: z.string(), // Normalized package name (e.g. 'lodash', 'requests')
  entryPoints: z.array(VulnerableSymbolEntryPointSchema).min(1),
  triggeredOn: z.enum(['CALL', 'IMPORT_TIME', 'UNKNOWN']),
  entryPointsComplete: z.boolean(),
  sourceUrls: z.array(z.string().url()).min(1),
  fixCommitUrls: z.array(z.string().url()).min(1),
  verifiedAt: z.string(), // ISO-8601 date string (e.g. '2026-10-25')
  verifiedBy: z.string(), // Verifier handle or team
  notes: z.string().optional(),
});

export const VulnerableSymbolsDatasetSchema = z.object({
  schemaVersion: z.literal('1.0'),
  entries: z.array(VulnerableSymbolEntrySchema),
});
```

---

## 3. Field Semantics & Completeness Rules

### 3.1. `entryPoints`

An array of public API locations that trigger the vulnerable code:

- `module`: Use `.` for symbols exported from the package root. Use the subpath (e.g. `template`) for modules imported via deep paths (`lodash/template`).
- `export`: The exact identifier exported by the module (or `default`).
- `kind`:
  - `FUNCTION`: A callable top-level export (e.g. `lodash.template()`, `requests.get()`).
  - `CLASS`: A class or constructor instantiated with `new` (e.g. `new semver.Range()`).
  - `METHOD`: A method on an instantiated object. **Mandatory:** When `kind` is `METHOD`, `via` must be provided, listing the factory functions or exports that construct the instance (e.g. `via: ["chain", "runInContext"]`).
  - `PROPERTY`: A property whose read or write access triggers vulnerable logic.

### 3.2. `triggeredOn`

- `CALL`: The vulnerability is triggered only when the entry point function or method is executed. Eligible for `HIGH` confidence pruning if all preconditions hold.
- `IMPORT_TIME`: The vulnerability executes immediately upon loading or evaluating the module (e.g. module-level prototype modification or top-level exploit). **Never eligible for high-confidence pruning** (fails precondition P8; blocked under `TRIGGER_NOT_CALL`).
- `UNKNOWN`: The trigger mechanism is ambiguous. Blocked under `TRIGGER_NOT_CALL`.

### 3.3. `entryPointsComplete`

- Set to `true` **only** if:
  1. The vulnerability exists entirely within specific, isolated functions.
  2. The fix commit shows that modifying only these functions (or their callers) resolves the vulnerability.
  3. No other public methods or properties delegate to the vulnerable code.
- Set to `false` if the package contains dynamic dispatch, internal delegation through undocumented paths, or plugins. When `false`, the entry fails precondition P8 (`ENTRYPOINTS_INCOMPLETE`) and can never prune to `UNREACHABLE-HIGH`.

---

## 4. Step-by-Step Curation Workflow: Adding a New Entry

Follow this rigorous 6-step protocol to add a new vulnerability entry:

### Step 1: Advisory & Fix Commit Discovery

1. Identify the official advisory on GitHub Security Advisories (`https://github.com/advisories/<GHSA-ID>`) or NVD.
2. Locate the pull request or commit that fixed the issue in the upstream source repository.
3. Record the exact advisory URL and fix commit URL.

### Step 2: Source Code Diff Audit

1. Inspect the fix diff: Which functions, methods, or regexes were altered?
2. Trace callers within the package: What public API exports expose those internal functions?
3. If the vulnerability is in `baseTemplate`, trace back to the public export `template`.
4. If a method is only callable on an instance returned by a factory, record `kind: 'METHOD'` and specify the factory names in `via`.

### Step 3: Trigger Classification

1. Does the code execute during `require('pkg')` or `import 'pkg'`?
   - If yes: `triggeredOn: 'IMPORT_TIME'`.
   - If no: `triggeredOn: 'CALL'`.

### Step 4: Completeness Determination

1. Can the vulnerable logic be reached through any other public method?
   - If yes and all are enumerated: `entryPointsComplete: true`.
   - If unknown or the library has dynamic dispatch: `entryPointsComplete: false`.

### Step 5: Append Entry to `vulnerable-symbols.json`

Add the JSON object to `packages/reachability/data/vulnerable-symbols.json`:

```json
{
  "id": "CVE-2021-23337",
  "aliases": ["GHSA-35jh-r3h4-6jhm"],
  "ecosystem": "npm",
  "package": "lodash",
  "entryPoints": [
    { "module": ".", "export": "template", "kind": "FUNCTION" },
    { "module": "template", "export": "default", "kind": "FUNCTION" }
  ],
  "triggeredOn": "CALL",
  "entryPointsComplete": true,
  "sourceUrls": ["https://github.com/advisories/GHSA-35jh-r3h4-6jhm"],
  "fixCommitUrls": [
    "https://github.com/lodash/lodash/commit/3469357cff928a5888147d82e205b4d6f3259ad4"
  ],
  "verifiedAt": "2026-10-25",
  "verifiedBy": "security-team",
  "notes": "Command injection via lodash.template imports or template subpath."
}
```

### Step 6: Regenerate Manifest & Verify Offline

Run the automated verification script:

```bash
# 1. Update SHA-256 digest in vulnerable-symbols.manifest.json
node -e "const fs = require('fs'), crypto = require('crypto'); const content = fs.readFileSync('packages/reachability/data/vulnerable-symbols.json'); const sha = crypto.createHash('sha256').update(content).digest('hex'); fs.writeFileSync('packages/reachability/data/vulnerable-symbols.manifest.json', JSON.stringify({ manifestVersion: '1.0', datasetFile: 'vulnerable-symbols.json', sha256: sha, generatedAt: new Date().toISOString() }, null, 2));"

# 2. Run offline validation suite (asserts schema, SHA-256, URL syntax, zero network)
pnpm verify:symbols
```

---

## 5. Offline Integrity Verification (`pnpm verify:symbols`)

SecureShip enforces an immutable offline verification gate:

- Located at [`scripts/verify-symbols.mjs`](file:///c:/dev/SecureShip-IDE/scripts/verify-symbols.mjs).
- Calculates the cryptographic SHA-256 hash of `vulnerable-symbols.json` and asserts exact byte equality against `vulnerable-symbols.manifest.json`.
- Validates that every entry satisfies `VulnerableSymbolEntrySchema`.
- Asserts that all `sourceUrls` and `fixCommitUrls` are valid HTTP/HTTPS URLs.
- Asserts zero duplicate IDs or package collisions.
- **Zero Network Invariant:** The verification script performs **no outbound HTTP requests**. It executes purely locally and deterministically.
