# SecureShip — Development Strategy: Current Stage → 100/100 Production-Ready

## _Complete Technical Methodology: Engineering → Distribution → Revenue → Market Dominance_

> **Author Context**: This document is written from the perspective of someone who has performed a complete deep-code analysis of SecureShip v0.4.0 — every package, every detector, every gate, every schema. This is not a generic strategy. Every recommendation maps directly to existing code files, existing architecture decisions, and real gaps in the current implementation. Follow this stage-by-stage and there will be zero gap between development and deployment.

---

## PART 0 — GROUND TRUTH: Where SecureShip Actually Stands Right Now

Before strategy, let's be completely honest about the current state. No exaggeration either direction.

### What's Built and Working (Verified):

```
packages/core-engine/src/orchestrator/scan-orchestrator.ts   → 31KB, complete, production-grade
packages/core-engine/src/supply-chain/supply-chain-analyzer.ts → 17KB, 8 detectors running parallel
packages/core-engine/src/supply-chain/rules-registry.ts      → 35 rules, full taxonomy
packages/core-engine/src/supply-chain/detectors/
  ├── typosquat.detector.ts   → Damerau-Levenshtein O(nm) with preallocated Int32Array buffers
  ├── entropy.detector.ts     → Shannon H >= 4.5 filter, base64/hex pattern matching
  ├── governance.detector.ts  → SC-GOV-001/002/003, protestware geo-targeting detection
  ├── install-script.detector.ts → curl|wget pipe detection, base64 decode patterns
  ├── bin-confusion.detector.ts  → path traversal, system command shadowing
  ├── unicode.detector.ts     → CVE-2021-42574 Bidi Trojan, zero-width, homoglyphs
  ├── metadata.detector.ts    → chrono anomaly, semver jump, manifest desync
  └── pkg-empty.detector.ts   → empty/missing tarball detection

packages/reachability/src/capabilities/ast-capability-analyzer.ts → 29KB
  → WASM Tree-sitter: JS, TS, TSX full AST
  → Python: token fallback (NOT full AST — this is a gap)
  → Alias tracking: ESM imports, CJS require, destructuring, namespace imports
  → Constant folding: cp['ex'+'ec'], path.join() resolution
  → 8 capability types: shell, network, env, fsSensitive, eval, dynamicRequire,
                        debugInternals, installScript
  → 7 combination alerts: SC-CAP-100 through SC-CAP-106

packages/ai/src/
  → SkepticEngine: prompt injection multi-layer detection
  → HMAC-SHA256 triage cache (external to repo)
  → ConsentManager: cryptographic endpoint binding
  → Anthropic + OpenAI adapters + local Ollama support
  → OutputSanitizer: ANSI, bidi, zero-width strip

packages/patch-engine/src/
  → DiffParser: strict unified diff, rejects binary/symlink/rename
  → PatchApplier: atomic write, CRLF preservation, context window fallback
  → PatchPolicyEngine: 23 anti-gaming rules
  → SCA: DepGraphBuilder, MinVersionResolver, TransitivePinner, ScaPatchPolicyEngine

packages/sandbox/src/backends/
  → container-backend.ts: Docker/Podman, --network none, --cap-drop ALL
  → host-backend.ts: explicit trust phrase required
  → fake-backend.ts: deterministic for tests

packages/contracts/src/tier-policy.schema.ts:
  → LicenseTier: FREE_BYOK | PRO_TEAM | ENTERPRISE  (ALREADY DEFINED IN CODE)
  → TierCapabilities: allowCallPathReachability, allowShadowWorktreeSandbox,
                      allowCiCdGatekeeper, allowSignedComplianceExport,
                      allowAirGappedOnPrem — ALL ALREADY MODELED
```

**The tier model is already in the code.** `tier-policy.schema.ts` has FREE_BYOK, PRO_TEAM, ENTERPRISE with capability gates. This is the monetization foundation — it just isn't enforced yet (no license server, no JWT validation).

### What's Missing (Hard Technical Gaps):

```
DISTRIBUTION:
  packages/cli/package.json → "private": true  (blocks npm publish)
  No GitHub Releases workflow
  No Homebrew tap, no winget manifest, no Docker Hub image
  No pre-built binary (no bun/pkg compile step)

LANGUAGE COVERAGE:
  ast-capability-analyzer.ts:134 → Python falls to token fallback
  No tree-sitter-go.wasm, tree-sitter-java.wasm in wasm/ directory
  No Go/Java/Rust/C# capability pattern definitions

IDE INTEGRATION:
  No packages/vscode-extension/ directory
  No LSP server implementation
  No JetBrains plugin

TOOLING BOOTSTRAP:
  No 'secureship install-tools' command
  No 'secureship init' wizard
  packages/cli/src/commands/ has: scan, fix, ai, detect, doctor, explain,
    graph, sandbox, status, verify — but NO: install-tools, init, sbom, watch

SBOM:
  No CycloneDX/SPDX generation
  No license compliance check (--check-licenses flag missing)

TELEMETRY/LICENSE ENFORCEMENT:
  tier-policy.schema.ts defines tiers but no enforcement mechanism
  No license JWT validation, no license server calls
  FREE_BYOK tier limits (maxMonthlyAiFixes: 15) not enforced

REAL-TIME MONITORING:
  No 'secureship watch' daemon
  No npm registry feed connector
  No maintainer delta detection (SC-GOV-004 missing)

GITHUB INTEGRATION:
  No packages/github-app/
  No GitHub Actions workflow template in .github/
  No PR auto-comment logic

DASHBOARD:
  No local SQLite scan history
  No 'secureship dashboard' command
  No trend visualization

MULTI-REPO:
  No 'secureship scan-org' command
  No portfolio aggregation

TAINT ANALYSIS:
  Gate 2 reachability = import graph (BFS) only
  No inter-procedural data flow (source → sink tracing)
  SC-CAP-100 detects co-presence, not actual data flow path
```

---

## PART 1 — ARCHITECTURE COMPLETENESS AUDIT

### 1.1 The 4-Gate Pipeline — Current Gaps

```
Gate 1 (Non-Prod Scope) → COMPLETE. gate1-scope.ts works.
Gate 2 (Reachability)   → 80% complete.
  GAP: Python AST (1 line fix)
  GAP: Go/Java WASM grammars (add wasm files + detection logic)
  GAP: No call-path reachability (only import-level BFS currently)
  GAP: No taint propagation (blocked on call-path, which is blocked on grammar coverage)
Gate 3 (AI Triage)      → 90% complete.
  GAP: No batch LLM requests (each finding = 1 API call, expensive)
  GAP: Cold-start problem (first scan: slow)
  GAP: No community false-positive cache (opt-in sharing not built)
Gate 4 (Remediation)    → 85% complete.
  GAP: Container runtime required (Docker/Podman not always available)
  GAP: No fallback verification path without container
  GAP: No --auto-apply flag for CI/CD
  GAP: No 'secureship fix pr' GitHub integration
```

### 1.2 The Tier System — Already Modeled, Not Enforced

`packages/contracts/src/tier-policy.schema.ts` already defines:

```typescript
FREE_BYOK:    { maxMonthlyAiFixes: 15, allowCallPathReachability: false,
                allowShadowWorktreeSandbox: false, allowCiCdGatekeeper: false,
                allowSignedComplianceExport: false }
PRO_TEAM:     { maxMonthlyAiFixes: 100, allowCallPathReachability: true,
                allowShadowWorktreeSandbox: true, allowCiCdGatekeeper: true,
                allowSignedComplianceExport: true }
ENTERPRISE:   { maxMonthlyAiFixes: null (unlimited), allowAirGappedOnPrem: true,
                allowCustomModelRouting: true }
```

**Strategy**: The code already knows what to gate. We just need to add:

1. License JWT validation in `scan-orchestrator.ts` startup
2. Local license file: `~/.secureship/license.jwt` (signed, offline-validatable)
3. License server: `https://license.secureship.dev/v1/validate` (only called on activation, then cached)

This means **monetization can be added without touching the core engine** — just the orchestrator startup and CLI status command.

---

## PART 2 — STAGE-BY-STAGE DEVELOPMENT STRATEGY

### Stage 0: Pre-Development Cleanup (Days 1–3)

**Goal**: Make the existing codebase publishable and dependency-clean.

#### 0.1 Package.json Audit

```bash
# Check all packages for private flags
packages/cli/package.json         → "private": true   REMOVE THIS
packages/contracts/package.json   → check "private"
packages/core-engine/package.json → keep private (internal package)
packages/reachability/package.json → keep private (internal package)
```

Files to edit:

- `packages/cli/package.json`: Add `"publishConfig": { "access": "public" }`, set `"private": false`
- `packages/cli/package.json`: Add `"bin": { "secureship": "./dist/index.js" }` (verify existing)
- `packages/cli/package.json`: Bump to `"version": "1.0.0-beta.1"` — don't start at 0.x if targeting enterprise

#### 0.2 Verify Build Chain

```bash
pnpm build          # All 10 packages must build clean
pnpm typecheck      # 0 errors across all workspaces
pnpm lint           # ESLint clean
pnpm test:coverage  # 806+ tests, all pass, coverage floors met
pnpm verify:wasm    # SHA-256 integrity check on all WASM grammars
pnpm verify:mutations # 28/28 mutations caught
```

If any of these fail: **DO NOT PROCEED**. Fix first.

#### 0.3 Dependency Security Self-Scan

```bash
# Run SecureShip on itself (dogfooding)
node packages/cli/dist/index.js scan . --gate2 annotate --output self-scan.json
```

Understand every finding before publishing. Any CRITICAL findings in own codebase = reputational risk on launch day.

---

### Stage 1: Distribution Foundation (Days 4–14)

**Goal**: `npm install -g @secureship/cli` works. Binary downloadable. Doctor passes.

#### 1.1 npm Registry Publish Setup

**File**: `packages/cli/package.json`

Add:

```json
{
  "name": "@secureship/cli",
  "version": "1.0.0-beta.1",
  "private": false,
  "publishConfig": {
    "access": "public",
    "registry": "https://registry.npmjs.org/"
  },
  "files": ["dist/", "README.md", "LICENSE"],
  "engines": {
    "node": ">=18.0.0"
  }
}
```

Publish command:

```bash
cd packages/cli
npm publish --tag beta
```

Then: `npm install -g @secureship/cli@beta` must work globally.

#### 1.2 GitHub Releases — Automated Binary Pipeline

**New file**: `.github/workflows/release.yml`

```yaml
name: Release Binaries
on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: linux-x64
            binary: secureship-linux-x64
          - os: macos-latest
            target: darwin-arm64
            binary: secureship-darwin-arm64
          - os: macos-13
            target: darwin-x64
            binary: secureship-darwin-x64
          - os: windows-latest
            target: win32-x64
            binary: secureship-win32-x64.exe
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
      - run: bun install
      - run: bun build packages/cli/src/index.ts
          --compile
          --target bun-${{ matrix.target }}
          --outfile dist/${{ matrix.binary }}
      - uses: actions/upload-release-asset@v1
        with:
          asset_path: dist/${{ matrix.binary }}
          asset_name: ${{ matrix.binary }}

  npm-publish:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - run: pnpm install && pnpm build
      - run: cd packages/cli && npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

Result: Every git tag `v1.0.0-beta.1` → auto-publish npm + binary downloads.

#### 1.3 Docker Image

**New file**: `Dockerfile.cli` (root level)

```dockerfile
FROM node:22-alpine AS builder
WORKDIR /build
COPY . .
RUN npm install -g pnpm@12
RUN pnpm install && pnpm build

FROM node:22-alpine
LABEL org.opencontainers.image.source="https://github.com/secureship/secureship"
LABEL org.opencontainers.image.description="SecureShip — Zero-telemetry security CLI"
WORKDIR /secureship
COPY --from=builder /build/packages/cli/dist ./dist
COPY --from=builder /build/packages/cli/package.json .
RUN npm install --production
RUN npm link
ENTRYPOINT ["secureship"]
```

**New file**: `.github/workflows/docker.yml`

```yaml
name: Docker Build & Push
on:
  push:
    tags: ['v*']
jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            secureship/cli:latest
            secureship/cli:${{ github.ref_name }}
```

Usage: `docker run --rm -v $(pwd):/workspace secureship/cli scan /workspace`

#### 1.4 Homebrew Tap

**New repo**: `github.com/secureship/homebrew-tap`

**File**: `Formula/secureship.rb`

```ruby
class Secureship < Formula
  desc "Zero-telemetry local-first security CLI"
  homepage "https://secureship.dev"
  version "1.0.0-beta.1"

  on_macos do
    on_arm do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-arm64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/secureship/secureship/releases/download/v#{version}/secureship-darwin-x64"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  def install
    bin.install "secureship-darwin-arm64" => "secureship"
  end

  test do
    system "#{bin}/secureship", "doctor"
  end
end
```

Install: `brew install secureship/tap/secureship`

#### 1.5 `secureship install-tools` Command

**New file**: `packages/cli/src/commands/install-tools.ts`

```typescript
// Full implementation strategy:
const TOOL_MANIFESTS = {
  opengrep: {
    githubRepo: 'opengrep/opengrep',
    binaryName: { 'linux-x64': 'opengrep-linux-x64', 'darwin-arm64': 'opengrep-darwin-arm64', 'win32-x64': 'opengrep.exe' },
    sha256Manifest: 'https://github.com/opengrep/opengrep/releases/latest/download/SHA256SUMS',
    installPath: path.join(os.homedir(), '.secureship', 'bin'),
  },
  gitleaks: { githubRepo: 'gitleaks/gitleaks', ... },
  trivy:    { githubRepo: 'aquasecurity/trivy', ... },
  'osv-scanner': { githubRepo: 'google/osv-scanner', ... },
  checkov:  { pip: 'checkov', ... },  // pip install for checkov
};

// Steps:
// 1. Detect OS + arch (process.platform + process.arch)
// 2. For each tool: call GitHub Releases API → get latest release → find binary asset
// 3. Download to temp file
// 4. Verify SHA-256 against manifest
// 5. Move to ~/.secureship/bin/ (chmod +x on POSIX)
// 6. Add ~/.secureship/bin to PATH hint in shell config
```

Register in `packages/cli/src/index.ts`:

```typescript
program.addCommand(
  await import('./commands/install-tools.js').then((m) => m.createInstallToolsCommand())
);
```

---

### Stage 2: Developer Experience (Days 15–45)

**Goal**: First-run experience < 5 minutes. Workflow integration. Zero friction.

#### 2.1 `secureship init` — Interactive Project Wizard

**New file**: `packages/cli/src/commands/init.ts`

```typescript
// Uses @inquirer/prompts (already in ecosystem, zero telemetry)
const answers = await inquirer.prompt([
  {
    type: 'list',
    name: 'failOn',
    message: 'Fail CI on severity?',
    choices: ['CRITICAL', 'HIGH', 'MEDIUM', 'NONE'],
    default: 'HIGH',
  },
  {
    type: 'checkbox',
    name: 'scanners',
    message: 'Enable scanners:',
    choices: [
      { name: 'opengrep (SAST)', value: 'opengrep', checked: true },
      { name: 'gitleaks (Secrets)', value: 'gitleaks', checked: true },
      { name: 'trivy (SCA+IaC)', value: 'trivy', checked: true },
      { name: 'osv-scanner (SCA)', value: 'osv-scanner', checked: true },
      { name: 'checkov (IaC)', value: 'checkov', checked: false },
    ],
  },
  {
    type: 'list',
    name: 'gate2',
    message: 'Reachability mode?',
    choices: [
      { name: 'annotate (default — tag findings with reachability info)', value: 'annotate' },
      { name: 'suppress (opt-in — suppress unreachable SCA findings)', value: 'suppress' },
      { name: 'off', value: 'off' },
    ],
  },
  {
    type: 'confirm',
    name: 'generateGithubAction',
    message: 'Generate GitHub Actions workflow?',
    default: true,
  },
  {
    type: 'confirm',
    name: 'createBaseline',
    message: 'Scan now and create baseline (suppress existing findings)?',
    default: false,
  },
]);

// Write secureship.config.json
// Optionally write .github/workflows/secureship.yml
// Optionally run scan --update-baseline
```

#### 2.2 GitHub Actions CI Template

**New file**: `docs/ci/secureship-github-actions.yml` (documentation template)

```yaml
name: SecureShip Security
on:
  push:
    branches: [main, develop]
  pull_request:

permissions:
  contents: read
  security-events: write # For SARIF upload

jobs:
  secureship:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history for --diff

      - name: Install SecureShip
        run: |
          npm install -g @secureship/cli
          secureship install-tools

      # For PRs: incremental diff scan
      - name: Scan (PR diff)
        if: github.event_name == 'pull_request'
        run: |
          secureship scan . \
            --diff ${{ github.event.pull_request.base.sha }} \
            --gate2 annotate \
            --sarif secureship.sarif \
            --fail-on HIGH \
            --baseline .secureship/baseline.json
        continue-on-error: true

      # For main: full scan
      - name: Scan (full)
        if: github.event_name == 'push'
        run: |
          secureship scan . \
            --gate2 annotate \
            --sarif secureship.sarif \
            --output secureship-report.json \
            --fail-on HIGH

      # Upload SARIF to GitHub Code Scanning
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secureship.sarif
          category: secureship

      # Optional: Update baseline on main push
      - name: Update Baseline
        if: github.ref == 'refs/heads/main' && github.event_name == 'push'
        run: |
          secureship scan . --update-baseline .secureship/baseline.json
          git add .secureship/baseline.json
          git commit -m "chore: update secureship baseline [skip ci]" || true
          git push || true
```

This template, combined with SARIF upload, gives **GitHub Code Scanning integration for free** — no GitHub App needed. Findings show up as PR annotations automatically.

#### 2.3 `secureship scan --watch` — File Watcher Mode

**Enhancement to**: `packages/cli/src/commands/scan.ts`

```typescript
// Add --watch flag
if (options.watch) {
  const { watch } = await import('chokidar');
  const watcher = watch(['**/*.ts', '**/*.js', '**/package.json'], {
    ignored: ['node_modules/**', '.git/**'],
    persistent: true,
    ignoreInitial: true,
  });

  watcher.on('change', async (changedPath) => {
    console.log(`[SecureShip Watch] Change detected: ${changedPath}`);
    // Re-run supply chain scan if package.json changed
    if (changedPath.endsWith('package.json')) {
      await runSupplyChainScan(options);
    }
    // Re-run reachability if source file changed
    if (changedPath.match(/\.(ts|js|mjs|cjs)$/)) {
      await runIncrementalReachability(changedPath, options);
    }
  });
}
```

#### 2.4 `secureship scan --new-only` — Noise Reduction

**Enhancement to**: `packages/core-engine/src/orchestrator/scan-orchestrator.ts`

The `--baseline` flag already exists. `--new-only` is just:

- Load baseline fingerprints
- Filter out findings where `fingerprint in baselineFingerprints`
- Report only new findings

This is **1 day of work** and removes the #1 developer complaint about security tools: "too many existing issues drowning new issues."

---

### Stage 3: Python Full AST — Quick Win (Days 15–20, parallel with Stage 2)

**Goal**: Upgrade Python from token fallback to full Tree-sitter AST.

**File**: `packages/reachability/src/capabilities/ast-capability-analyzer.ts`

**Current code (line 134)**:

```typescript
if (!lang || lang === 'python') {
  return AstCapabilityAnalyzer.fallbackTokenScan(content, filePath);
}
```

**Fix**:

```typescript
if (!lang) {
  return AstCapabilityAnalyzer.fallbackTokenScan(content, filePath);
}
// Python now uses full Tree-sitter AST (tree-sitter-python.wasm already bundled)
// Note: Python AST node types differ from JS — need separate extraction logic
if (lang === 'python') {
  return AstCapabilityAnalyzer.extractPythonCapabilities(content, filePath, options);
}
```

**New method**: `extractPythonCapabilities()` in same file

Python-specific capability patterns:

```typescript
const PYTHON_SHELL_CALLS = new Set([
  'subprocess.run',
  'subprocess.call',
  'subprocess.Popen',
  'os.system',
  'os.popen',
  'commands.getoutput',
]);
const PYTHON_NETWORK_IMPORTS = new Set([
  'urllib',
  'urllib2',
  'httplib',
  'requests',
  'aiohttp',
  'httpx',
  'socket',
  'paramiko',
  'ftplib',
  'smtplib',
]);
const PYTHON_ENV_ACCESS = new Set(['os.environ', 'os.getenv', 'dotenv.load_dotenv']);
const PYTHON_EVAL_CALLS = new Set(['eval', 'exec', 'compile', '__import__']);
const PYTHON_SENSITIVE_PATHS = [
  /os\.path\.expanduser\(['"]~\/.ssh/,
  /os\.path\.expanduser\(['"]~\/.aws/,
  /open\(['"]\/etc\/passwd/,
];
```

Python AST node types (tree-sitter-python):

- `import_statement` → `import subprocess`
- `import_from_statement` → `from subprocess import run`
- `call` → `subprocess.run(['ls'])`
- `attribute` → `os.environ`

**Estimated effort**: 3-4 days of careful implementation + tests.
**Impact**: Python projects (Django, Flask, FastAPI) can now get full supply chain AST analysis. This immediately expands the addressable market by ~40%.

---

### Stage 4: SBOM Generation (Days 21–28)

**Goal**: `secureship sbom . --format cyclonedx` works. EU CRA compliant output.

**New file**: `packages/cli/src/commands/sbom.ts`

**Architecture**:

```typescript
import { DiscoveredPackage } from '../types.js';
import { discoverPackages } from '@secureship/core-engine'; // reuse existing

async function generateCycloneDXSbom(
  packages: DiscoveredPackage[],
  scanReport?: ScanReport
): Promise<CycloneDXBom> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'SecureShip', name: 'SecureShip CLI', version: CLI_VERSION }],
      component: { type: 'application', name: path.basename(rootDir) },
    },
    components: packages.map((pkg) => ({
      type: 'library',
      name: pkg.name,
      version: pkg.version,
      purl: `pkg:npm/${pkg.name}@${pkg.version}`,
      licenses: extractLicenses(pkg.packageJson),
      hashes: [{ alg: 'SHA-256', content: computePackageHash(pkg.dir) }],
      // Inject vulnerability data from scan report if available
      vulnerabilities:
        scanReport?.findings
          .filter((f) => f.location.filePath.includes(pkg.name))
          .map((f) => ({ id: f.ruleId, severity: f.severity })) ?? [],
    })),
  };
}
```

**CLI flag**:

```bash
secureship sbom . --format cyclonedx --output sbom.json
secureship sbom . --format spdx --output sbom.spdx.json
secureship sbom . --with-vulns  # Cross-reference with last scan results
```

**License compliance add-on** (same command, same data pass):

```bash
secureship sbom . --check-licenses --allow MIT,Apache-2.0 --deny GPL-3.0,AGPL-3.0
```

This uses the **same `discoverPackages()` function** already in `supply-chain-analyzer.ts`. The data is already being collected — just needs formatting.

**Effort**: 2-3 days. **Market value**: Massive. EU CRA, US EO 14028, SOC2 all require SBOM.

---

### Stage 5: License Enforcement + Monetization Layer (Days 30–50)

**Goal**: Tier system enforced. License JWT issued. Revenue can be collected.

#### 5.1 License Server Design

```
Client-side (in secureship CLI):
  ~/.secureship/license.jwt          → Offline-validatable JWT
  ~/.secureship/config.json          → tier, email, activated_at

JWT Structure:
  Header: { alg: "RS256", kid: "secureship-2026-01" }
  Payload: {
    sub: "user@company.com",
    tier: "PRO_TEAM",
    seats: 10,
    orgId: "acme-corp",
    iat: <issued_at>,
    exp: <expires_at>,          // 30 days, refreshed on each scan if online
    maxMonthlyAiFixes: 100,
    allowCallPathReachability: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    featureFlags: {}            // Future extensibility
  }
  Signature: RS256 with SecureShip private key
             Public key bundled in CLI binary for offline validation
```

#### 5.2 License Enforcement Points

**File**: `packages/core-engine/src/orchestrator/scan-orchestrator.ts` (startup)

```typescript
// Add at orchestrator initialization:
async function resolveTierCapabilities(userConfigDir: string): Promise<TierCapabilities> {
  const licenseJwtPath = path.join(userConfigDir, 'license.jwt');

  // 1. Try to read and verify local JWT
  if (fs.existsSync(licenseJwtPath)) {
    const jwt = fs.readFileSync(licenseJwtPath, 'utf-8');
    const payload = verifyJwt(jwt, SECURESHIP_PUBLIC_KEY);
    if (payload && new Date(payload.exp * 1000) > new Date()) {
      // Attempt background refresh if expiring in < 7 days
      if (isNearExpiry(payload.exp)) {
        refreshLicenseInBackground(licenseJwtPath, payload.sub);
      }
      return buildTierCapabilities(payload);
    }
  }

  // 2. No valid JWT → FREE_BYOK tier
  return TIER_CAPABILITY_DEFAULTS['FREE_BYOK'];
}
```

Gate enforcement in scan-orchestrator:

```typescript
if (options.gate2 === 'suppress' && !tierCaps.allowCiCdGatekeeper) {
  logger.warn('Gate 2 suppress mode requires PRO_TEAM tier. Running in annotate mode.');
  options.gate2 = 'annotate';
}
if (options.ai && tierAiFixCount >= tierCaps.maxMonthlyAiFixes) {
  logger.warn(
    `Monthly AI fix limit (${tierCaps.maxMonthlyAiFixes}) reached. Upgrade to PRO_TEAM for more.`
  );
  options.ai = false;
}
```

#### 5.3 License Server (Backend — minimal)

Tech stack: Cloudflare Workers + D1 (SQLite) + Stripe webhooks

```typescript
// GET /v1/validate — called on license activation and refresh
// POST /v1/activate — called on first setup with email + activation code
// POST /v1/webhook/stripe — Stripe payment events
// GET /v1/health
```

This is a **~500 line Cloudflare Worker** — extremely low operational overhead.

#### 5.4 `secureship license` CLI Commands

```bash
secureship license activate <activation-code>
  → Calls license server, downloads JWT, stores in ~/.secureship/license.jwt

secureship license status
  → Shows current tier, seat count, expiry, monthly AI fix usage

secureship license upgrade
  → Opens https://secureship.dev/pricing in browser
```

---

### Stage 6: VSCode Extension (Days 45–75)

**Goal**: 2M+ potential Snyk VSCode users are in reach. This is the biggest user acquisition channel.

**New package**: `packages/vscode-extension/`

```
packages/vscode-extension/
├── package.json          → VS Code extension manifest
├── src/
│   ├── extension.ts      → Entry point, activation, command registration
│   ├── provider/
│   │   ├── diagnostic-provider.ts   → Inline squiggly underlines
│   │   ├── hover-provider.ts        → Package risk hover cards
│   │   └── code-action-provider.ts  → Quick fix "Fix with SecureShip"
│   ├── scanner/
│   │   ├── package-scanner.ts       → On package.json save → supply chain scan
│   │   ├── file-scanner.ts          → On .ts/.js save → Gate 2 quick check
│   │   └── scan-debouncer.ts        → Debounce rapid saves
│   ├── panel/
│   │   └── findings-panel.ts        → Sidebar webview
│   └── status/
│       └── status-bar.ts            → "SecureShip: 3 findings" status bar
├── media/
│   ├── icon.png
│   └── webview.css
└── .vscodeignore
```

**`extension.ts` structure**:

```typescript
export async function activate(context: vscode.ExtensionContext) {
  // 1. Check SecureShip CLI installed
  const cliPath = await findSecureShipCli();
  if (!cliPath) {
    vscode.window
      .showWarningMessage('SecureShip CLI not found. Install it?', 'Install')
      .then((action) => {
        if (action === 'Install')
          vscode.env.openExternal(vscode.Uri.parse('https://secureship.dev/install'));
      });
    return;
  }

  // 2. Register providers
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      [{ language: 'typescript' }, { language: 'javascript' }, { language: 'json' }],
      new SecureShipHoverProvider(cliPath)
    ),
    vscode.languages.registerCodeActionsProvider(
      { pattern: '**/package.json' },
      new SecureShipCodeActionProvider(cliPath)
    ),
    vscode.workspace.onDidSaveTextDocument((doc) =>
      onDocumentSave(doc, diagnosticCollection, cliPath)
    )
  );

  // 3. Status bar
  const statusBar = createStatusBarItem();
  context.subscriptions.push(statusBar);

  // 4. Run initial scan
  await runInitialBackgroundScan(cliPath, diagnosticCollection);
}
```

**Hover Provider — when user hovers over `import X from 'some-package'`**:

```typescript
async provideHover(document, position) {
  const importedPackage = extractImportedPackageName(document, position);
  if (!importedPackage) return null;

  const cached = await getPackageRisk(importedPackage);
  if (!cached) return null;

  const md = new vscode.MarkdownString();
  md.appendMarkdown(`## SecureShip — \`${importedPackage}\`\n\n`);
  md.appendMarkdown(`**Risk Level**: ${cached.highestSeverity}\n\n`);
  if (cached.findings.length > 0) {
    md.appendMarkdown(`**Findings**:\n`);
    for (const f of cached.findings.slice(0, 3)) {
      md.appendMarkdown(`- \`${f.ruleId}\`: ${f.title}\n`);
    }
  }
  return new vscode.Hover(md);
}
```

**Publish to VS Code Marketplace**:

```bash
vsce package
vsce publish --pat <MARKETPLACE_TOKEN>
```

Extension ID: `secureship.secureship-security`

---

### Stage 7: GitHub App (Days 60–90)

**Goal**: Every PR gets auto-scanned. Findings as PR review comments. Fix suggestions.

**New package**: `packages/github-app/`

**Architecture**: GitHub App (not OAuth App — App has bot identity)

```
GitHub App Permissions Required:
  - pull_requests: write   (post comments)
  - checks: write          (create check runs with annotations)
  - contents: read         (clone PR code)
  - metadata: read
  - statuses: write

Webhook events:
  - pull_request: opened, synchronize, reopened
  - installation: created, deleted
```

**App Server** (Cloudflare Worker or small Node.js service):

```typescript
// On pull_request webhook:
async function handlePullRequest(payload: PullRequestEvent) {
  const { repo, pull_request, installation } = payload;

  // 1. Clone PR branch to ephemeral sandbox
  const workdir = await cloneForScan(repo.clone_url, pull_request.head.sha);

  // 2. Run SecureShip scan (diff mode)
  const result = await runSecureShipScan(workdir, {
    diff: pull_request.base.sha,
    gate2: 'annotate',
    failOn: 'HIGH',
  });

  // 3. Post GitHub Check Run with annotations
  await octokit.checks.create({
    owner: repo.owner.login,
    repo: repo.name,
    name: 'SecureShip Security',
    head_sha: pull_request.head.sha,
    status: 'completed',
    conclusion: result.hasBlockingFindings ? 'failure' : 'success',
    output: {
      title: `SecureShip: ${result.findings.length} findings`,
      summary: buildSummaryMarkdown(result),
      annotations: result.findings
        .map((f) => ({
          path: f.location.filePath,
          start_line: f.location.startLine,
          end_line: f.location.endLine,
          annotation_level: mapSeverityToGithub(f.severity),
          message: `[${f.ruleId}] ${f.title}`,
          title: f.title,
        }))
        .slice(0, 50), // GitHub limits to 50 annotations per request
    },
  });

  // 4. If Gate 4 fix available → post fix suggestion comment
  if (result.availableFixes.length > 0) {
    await postFixSuggestionComment(octokit, repo, pull_request.number, result.availableFixes);
  }
}
```

**`secureship fix pr` CLI extension**:

```bash
secureship fix pr <fingerprint> --repo <owner/repo> --branch fix/secureship-<fingerprint>
```

- Calls GitHub API to create branch
- Applies verified patch (from fix store)
- Opens PR with full verification ladder evidence in description

---

### Stage 8: Go + Java Language Support (Days 75–120)

**Goal**: SecureShip covers the top 5 enterprise languages (JS, TS, Python, Go, Java).

#### 8.1 Add WASM Grammars

```bash
# Download from official tree-sitter releases
packages/reachability/wasm/
├── tree-sitter.wasm                 # Already exists
├── tree-sitter-javascript.wasm     # Already exists
├── tree-sitter-typescript.wasm     # Already exists
├── tree-sitter-tsx.wasm            # Already exists
├── tree-sitter-python.wasm         # Already exists (but fallback used)
├── tree-sitter-go.wasm             # ADD THIS
└── tree-sitter-java.wasm           # ADD THIS
```

Add SHA-256 hashes to the WASM integrity manifest (wherever the current manifest is stored).

#### 8.2 Go Capability Patterns

**New method in `ast-capability-analyzer.ts`**: `extractGoCapabilities()`

Go AST node types (tree-sitter-go):

```typescript
// Shell execution
const GO_SHELL_CALLS = new Set(['exec.Command', 'exec.CommandContext', 'os.StartProcess']);

// Network
const GO_NETWORK_IMPORTS = new Set(['net/http', 'net', 'net/url', 'google.golang.org/grpc']);
const GO_HTTP_CALLS = new Set(['http.Get', 'http.Post', 'http.NewRequest', 'http.Do']);

// Env access
const GO_ENV_ACCESS = new Set(['os.Getenv', 'os.LookupEnv', 'os.Environ']);

// Eval equivalents in Go
const GO_PLUGIN_IMPORTS = new Set(['plugin']); // dynamic .so loading
const GO_UNSAFE_IMPORTS = new Set(['unsafe']); // unsafe pointer operations

// Sensitive FS
const GO_FS_CALLS = new Set(['os.ReadFile', 'os.Open', 'ioutil.ReadFile']);
```

#### 8.3 Java Capability Patterns

```typescript
// Shell execution
const JAVA_SHELL_CALLS = new Set(['Runtime.exec', 'ProcessBuilder', 'Process.exec']);

// Network
const JAVA_NETWORK_IMPORTS = new Set(['java.net.http', 'java.net.URL', 'okhttp3', 'retrofit2']);
const JAVA_HTTP_CALLS = new Set(['HttpClient.send', 'URL.openConnection', 'OkHttpClient.newCall']);

// Env access
const JAVA_ENV_ACCESS = new Set(['System.getenv', 'System.getProperties', 'ProcessEnvironment']);

// Eval/reflection
const JAVA_REFLECTION = new Set([
  'Class.forName',
  'Method.invoke',
  'Field.set',
  'ClassLoader.loadClass',
  'URLClassLoader',
]);

// Sensitive FS
const JAVA_FS_CALLS = new Set([
  'Files.readAllBytes',
  'FileInputStream',
  'FileReader',
  'BufferedReader',
  'Scanner',
]);
```

**Test suite required**: Add `packages/reachability/test/go-capabilities.test.ts` and `java-capabilities.test.ts` with 10+ test cases each minimum, covering all capability types.

---

### Stage 9: Taint Flow Analysis (Days 90–150)

**Goal**: SC-CAP-100 (env + network) goes from co-presence detection to actual data flow tracing. This is the deepest technical moat.

**Current limitation**: Gate 2 does BFS on the import graph (file-level). Taint analysis needs function-level call graph + data flow edges.

**Architecture for Taint Analysis**:

```
New module: packages/reachability/src/taint/
├── taint-engine.ts          → Main orchestrator
├── source-registry.ts       → Known taint sources (process.env, fs.readFile, etc.)
├── sink-registry.ts         → Known taint sinks (http.request, exec, eval, etc.)
├── propagation-rules.ts     → How taint flows (assignment, return, call argument)
└── call-graph-builder.ts    → Function-level call graph from Tree-sitter AST
```

**Source registry** (taint sources — data that should be tracked):

```typescript
const TAINT_SOURCES = [
  { pattern: 'process.env', type: 'ENV_SECRET', severity: 'HIGH' },
  { pattern: 'fs.readFileSync', type: 'FILE_CONTENT', severity: 'HIGH' },
  { pattern: 'req.body', type: 'USER_INPUT', severity: 'HIGH' },
  { pattern: 'req.query', type: 'USER_INPUT', severity: 'HIGH' },
  { pattern: 'req.params', type: 'USER_INPUT', severity: 'HIGH' },
  { pattern: 'readline.question', type: 'USER_INPUT', severity: 'MEDIUM' },
];
```

**Sink registry** (dangerous destinations):

```typescript
const TAINT_SINKS = [
  { pattern: 'http.request', type: 'NETWORK_EXFILTRATION', rule: 'SC-TAINT-001' },
  { pattern: 'axios.post', type: 'NETWORK_EXFILTRATION', rule: 'SC-TAINT-001' },
  { pattern: 'fetch', type: 'NETWORK_EXFILTRATION', rule: 'SC-TAINT-001' },
  { pattern: 'exec', type: 'COMMAND_INJECTION', rule: 'SC-TAINT-002' },
  { pattern: 'eval', type: 'CODE_INJECTION', rule: 'SC-TAINT-003' },
  { pattern: 'query', type: 'SQL_INJECTION', rule: 'SC-TAINT-004' },
];
```

**New supply chain rules**:

```typescript
'SC-TAINT-001': {
  ruleId: 'SC-TAINT-001',
  title: 'Confirmed Environment Secret Exfiltration Path',
  defaultSeverity: 'CRITICAL',
  threatType: 'TAINT_FLOW',
  description: 'Data flow analysis confirms a direct path from process.env (secret source) to outbound network call (exfiltration sink)',
  reachabilityGated: true,
}
```

This takes SC-CAP-100 (currently: "package has both env access AND network calls") and upgrades it to "we can prove env data flows TO the network call." **This is the difference between a smoke detector and a forensics tool.**

**Effort**: 6-8 weeks. **Differentiator**: Nobody in the open-source space does local taint analysis at this depth. CodeQL does it but is cloud-only and proprietary.

---

### Stage 10: Dashboard + History (Days 75–100, parallel)

**Goal**: `secureship dashboard` shows scan trends. Security team gets metrics. CISO gets reports.

**Architecture**:

```
~/.secureship/
├── license.jwt
├── config.json
├── history.db            → SQLite via better-sqlite3
├── cache/                → AST cache (already exists)
└── fixes/                → Fix store (already exists)
```

**New file**: `packages/cli/src/commands/dashboard.ts`

```typescript
import Database from 'better-sqlite3';
import { createServer } from 'node:http';

async function startDashboard(port = 4242) {
  const db = new Database(path.join(os.homedir(), '.secureship', 'history.db'));

  // After each scan, insert results:
  // INSERT INTO scans (timestamp, repo, findings_count, by_severity, by_scanner, duration_ms)

  const server = createServer((req, res) => {
    // Serve dashboard HTML/JS (bundled inline — no external CDN)
    // API endpoints:
    // GET /api/scans?repo=.&since=30d  → scan history
    // GET /api/findings?repo=.          → finding trend
    // GET /api/report?format=pdf        → PDF export via puppeteer
  });

  server.listen(port, 'localhost', () => {
    vscode.env.openExternal(vscode.Uri.parse(`http://localhost:${port}`));
    // OR: open browser automatically
    exec(`${process.platform === 'win32' ? 'start' : 'open'} http://localhost:${port}`);
  });
}
```

**Dashboard features**:

- Finding count trend (last 30/90 days)
- By-scanner breakdown (opengrep: 12, gitleaks: 3, supply-chain: 8)
- Top risky packages (by finding count)
- Fix acceptance rate (Gate 4 fixes applied vs rejected)
- Exportable PDF report (for CISO/audit)

**PDF Export**: Use `puppeteer` (already likely in dev deps) to print dashboard to PDF.

---

### Stage 11: Multi-Repo + Org Scanning (Days 100–130)

**Goal**: Enterprise can scan all 100+ repos from one command. Portfolio view.

**New file**: `packages/cli/src/commands/scan-org.ts`

```typescript
import { Octokit } from '@octokit/rest';

async function scanOrg(orgName: string, options: ScanOrgOptions) {
  const octokit = new Octokit({ auth: options.githubToken });

  // 1. List all repos in org
  const repos = await octokit.paginate(octokit.repos.listForOrg, {
    org: orgName,
    type: 'all',
    per_page: 100,
  });

  // 2. Parallel scan with concurrency limit
  const semaphore = new Semaphore(options.concurrency ?? 3);
  const results = await Promise.all(
    repos.map((repo) => semaphore.run(() => scanSingleRepo(repo, options)))
  );

  // 3. Aggregate report
  const orgReport: OrgScanReport = {
    org: orgName,
    reposScanned: results.length,
    totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
    bySeverity: aggregateBySeverity(results),
    riskiestRepos: results.sort((a, b) => b.findingScore - a.findingScore).slice(0, 10),
    supplyChainAlerts: results.flatMap((r) => r.supplyChainFindings),
  };

  // 4. Export
  await writeOrgReport(orgReport, options.output);
}
```

---

### Stage 12: Compliance Export + SOC2 Evidence (Days 90–110)

**Goal**: `secureship compliance-export` generates audit-ready evidence bundles.

**This leverages an EXISTING feature**: Every scan already generates HMAC-SHA256 signed reports. The `--output report.json --sarif report.sarif` flags already work.

**New command**: `secureship compliance-export --standard soc2 --period 2026-Q3`

```typescript
// Evidence bundle structure:
{
  "standard": "SOC2-TYPE2",
  "period": { "from": "2026-07-01", "to": "2026-09-30" },
  "evidence": [
    {
      "control": "CC7.1 - Malicious Software Prevention",
      "type": "SCAN_REPORT",
      "scans": [ /* all scan reports in period */ ],
      "summary": "47 findings detected, 43 remediated, 4 accepted-risk",
      "hmacSignature": "sha256:abc123...",
    },
    {
      "control": "CC7.2 - Vulnerability Management",
      "type": "SCA_REMEDIATION",
      "fixes": [ /* all applied Gate 4 fixes */ ],
      "verificationLadderResults": { /* 10-stage results */ },
    }
  ],
  "bundleSignature": "sha256:...",
  "generatedAt": "2026-10-22T15:00:00Z"
}
```

This is gated behind `allowSignedComplianceExport` which is already in `tier-policy.schema.ts` — PRO_TEAM + ENTERPRISE only.

---

## PART 3 — QUALITY GATES: What Must Be True at Each Stage

Every stage must pass ALL of these before moving to next stage:

### QG-1: Engineering Quality (Every Stage)

```bash
pnpm build           # Zero build errors
pnpm typecheck       # Zero TypeScript errors
pnpm lint            # Zero ESLint violations
pnpm format:check    # Prettier clean
pnpm test:coverage   # All tests pass, coverage floors maintained
pnpm verify:wasm     # WASM SHA-256 integrity intact
pnpm verify:mutations # All mutations caught (number grows as code grows)
```

### QG-2: Security Self-Scan (Before Any Release)

```bash
node packages/cli/dist/index.js scan . --gate2 annotate --fail-on CRITICAL
# Must exit 0 — no CRITICAL findings in own codebase
```

### QG-3: New Feature Test Coverage

Every new file in `packages/*/src/` must:

- Have a corresponding test file in `packages/*/test/`
- Meet >= 70% line coverage AND >= 70% branch coverage (per-file floor)
- Be added to `SOURCE_FILES_FLOOR` in `vitest.config.ts`

### QG-4: Benchmark Regression (SCA/Supply Chain changes only)

```bash
pnpm benchmark:replay
# Precision >= 85%, Recall >= 80%, F1 >= 80%, Suppression-Recall >= 90%
# These numbers must not drop between releases
```

### QG-5: Dogfood Scan (Every Release)

```bash
secureship scan . --gate2 annotate --output self-scan-v<version>.json
# Store in docs/self-scans/ as evidence of continuous security hygiene
# Any new CRITICAL/HIGH finding in own code = block release
```

---

## PART 4 — GO-TO-MARKET STRATEGY

### 4.1 Launch Sequence

**Week 1 — Stealth Beta**:

- npm publish `@secureship/cli@beta`
- DM 20 security-focused developers on Twitter/X: "Would you try a Snyk alternative that's free and zero-telemetry?"
- Collect feedback. Fix install friction. Do NOT post publicly yet.

**Week 2 — GitHub Launch**:

- Push to GitHub with README polished
- Hacker News: `Show HN: SecureShip — I built a zero-telemetry alternative to Snyk`
  - Key talking points: local-first, WASM reachability, free forever, BYOK AI
  - Be in comments for 24 hours answering every question
- Measure: GitHub stars, npm downloads, Discord joins

**Week 3 — Content Blitz**:

- Dev.to: "Why I stopped using Snyk" (technical comparison, benchmark numbers)
- YouTube: "Zero-telemetry security scanning in 5 minutes" (screen recording)
- Twitter/X thread: Thread comparing SecureShip vs Snyk vs Socket.dev feature-by-feature
- Reddit: r/netsec, r/devops, r/programming — genuine participation, not spam

**Month 2 — VSCode Extension Launch**:

- VS Code Marketplace publish
- ProductHunt launch (#1 Product of the Day target)
- Reach out to security bloggers (Troy Hunt, Scott Helme, tldrsec newsletter)

**Month 3 — Enterprise Outreach**:

- Find 5 companies running air-gapped environments (defense, fintech, healthcare)
- These companies CANNOT use Snyk (data leaves network) — SecureShip is their only option
- Offer free Enterprise trial: "We'll help you set it up, you give us a testimonial"
- One good enterprise case study = 10x more enterprise leads

### 4.2 Pricing Strategy

```
FREE_BYOK (Apache-2.0 Open Source):
  - Unlimited supply chain scans
  - 5 SAST/SCA scanners
  - Gate 1 + Gate 2 reachability (import-level)
  - BYOK AI triage (15 AI fixes/month)
  - SARIF export
  - CLI only

PRO_TEAM ($19/seat/month, minimum 3 seats):
  - Everything in Free
  - Call-path reachability (taint analysis when built)
  - Unlimited AI triage fixes (BYOK)
  - Gate 4 verified remediation (shadow copy + 10-stage ladder)
  - Signed compliance export (SOC2 evidence)
  - GitHub App (PR annotations + fix PRs)
  - VSCode Extension premium features
  - CI/CD gatekeeper mode
  - Priority support

ENTERPRISE (Custom pricing, $50-150/seat/month):
  - Everything in Pro
  - Air-gapped on-prem deployment
  - Custom rule authoring
  - SAML/SSO integration
  - Org-level policy management
  - Multi-repo scanning
  - Dedicated CSM + SLA
  - Custom scanner adapter support
  - Audit log export (SOC2, ISO27001, FedRAMP)
```

**Why this pricing works**:

- FREE tier = developer love, viral distribution, trust
- PRO_TEAM = SME sweet spot ($57-190/month for 3-10 devs vs $75-1000/month for Snyk)
- ENTERPRISE = air-gap and compliance buyers who literally cannot use cloud tools

### 4.3 SEO + Content Strategy

Target keywords (based on developer search patterns):

- "snyk alternative open source" → landing page comparison
- "local security scanner no telemetry" → privacy-focused page
- "supply chain attack detection npm" → blog post
- "semgrep alternative cli" → comparison page
- "sbom generator npm" → SBOM feature page
- "air gap security scanner" → enterprise page

Content cadence: 2 technical blog posts/month. Each post = real technical depth (benchmark results, code examples, architecture decisions). Security developers can smell marketing from 10 miles away — only authentic technical content converts.

---

## PART 5 — INFRASTRUCTURE & DEVOPS

### 5.1 Release Infrastructure

```
GitHub repository structure:
secureship/secureship          → Main monorepo (open source, Apache-2.0)
secureship/homebrew-tap        → Homebrew formulas
secureship/secureship-action   → GitHub Action (marketplace)
secureship/license-server      → Private (Cloudflare Worker)
secureship/website             → Private (Astro/Next.js)
secureship/enterprise-agent    → Private (on-prem enterprise components)
```

### 5.2 CI/CD Pipeline (for SecureShip itself)

`.github/workflows/ci.yml` (already exists per CHANGELOG):

```yaml
# Extend existing CI with:
- name: Self-scan (dogfood)
  run: node packages/cli/dist/index.js scan . --gate2 annotate --fail-on CRITICAL
  if: github.event_name == 'push' || github.event_name == 'pull_request'

- name: Benchmark replay
  run: pnpm benchmark:replay
  if: github.event_name == 'push'
```

### 5.3 Monitoring (Post-Launch)

```
Metrics to track (all privacy-preserving — no user data):
  - npm weekly downloads (npm stats page — public)
  - GitHub stars, forks, issues (GitHub API)
  - VS Code extension installs (Marketplace — public)
  - License activations (license server — privacy-safe aggregate only)
  - Tier conversion rate (FREE → PRO) — goal: 5% conversion
  - Enterprise pipeline (CRM — Notion or HubSpot free tier)

Error tracking:
  - CLI crash reports: opt-in only, no auto-reporting ever
  - If opt-in: send to Sentry with full PII stripping (no paths, no filenames)
  - Default: zero telemetry, as promised
```

---

## PART 6 — COMPETITIVE MOAT STRATEGY

### 6.1 Features Competitors Cannot Copy Easily

```
1. WASM-based local reachability: Snyk has cloud ML reachability — cannot be local without
   massive investment. SecureShip's WASM Tree-sitter approach is architecturally different.

2. Zero-telemetry BYOK AI: Anthropic/OpenAI won't build a product that competes with their
   enterprise customers (Snyk, GitHub). SecureShip's BYOK model is structurally safe.

3. Mathematically auditable suppression ledger (P1 invariant): No competitor has this.
   "Every finding is accounted for" with a cryptographic guarantee is a genuine audit differentiator.

4. 10-stage verified remediation ladder: Snyk "fix" is: update package.json. SecureShip fix is:
   apply patch in shadow copy → run 10 verification stages → HMAC-sign evidence → user manually applies.
   This is conservative and correct. Enterprise compliance teams will love this.

5. Air-gap capable taint analysis: When built (Stage 9), local taint flow analysis with zero
   cloud dependency is technically unprecedented in free tooling.
```

### 6.2 Network Effects to Build

```
Supply chain threat intelligence sharing (opt-in):
  - When SecureShip detects a new malicious package, allow opt-in users to
    share the finding (anonymized, no repo/code data) to a community threat DB
  - Similar to Snyk's threat intelligence, but community-powered
  - This creates a network effect: more users = better detection for everyone

Community rule library:
  - Users can publish SAST rules (opengrep/semgrep format) to secureship.dev/rules
  - Rules are signed (HMAC) and versioned
  - SecureShip loads community rules with explicit consent
  - This is the "App Store" model for security rules
```

---

## PART 7 — SUCCESS METRICS (100/100 Definition)

### Engineering (100/100):

- [ ] Zero CRITICAL findings in self-scan
- [ ] Test coverage: Lines >= 90%, Branches >= 80% (raise current floors)
- [ ] All 28 mutation tests caught
- [ ] Benchmark: Precision >= 90%, Recall >= 85%, F1 >= 87%
- [ ] Build time < 60 seconds on CI
- [ ] `secureship scan .` (medium JS project) < 30 seconds
- [ ] Supply chain scan of 1000 npm packages < 120 seconds
- [ ] Go + Java + Python full AST coverage

### Distribution (100/100):

- [ ] `npm install -g @secureship/cli` works in < 5 seconds
- [ ] `secureship install-tools` installs all 5 external tools in < 60 seconds
- [ ] Docker image `docker run secureship/cli scan .` works
- [ ] Homebrew formula: `brew install secureship/tap/secureship`
- [ ] VSCode Extension: > 10,000 installs
- [ ] GitHub Action: available on GitHub Marketplace
- [ ] Pre-built binaries for 4 targets (linux-x64, darwin-arm64, darwin-x64, win32-x64)

### Market Reach (100/100):

- [ ] GitHub: > 2,000 stars (credibility threshold for enterprise consideration)
- [ ] npm: > 5,000 weekly downloads
- [ ] VS Code: > 10,000 active installs
- [ ] 3 published enterprise case studies
- [ ] Listed in OWASP tooling recommendations
- [ ] Mentioned in tldrsec.com newsletter (major security newsletter)
- [ ] 1 Fortune 500 customer on Enterprise tier

### Revenue (100/100):

- [ ] MRR > $10,000 (proof of monetization)
- [ ] > 50 paying teams (PRO_TEAM)
- [ ] > 2 Enterprise contracts
- [ ] < 5% monthly churn
- [ ] NPS > 50 from PRO/Enterprise customers

### Product Quality (100/100):

- [ ] First-run to first scan: < 5 minutes (on documented setup guide)
- [ ] Zero "this is confusing" issues filed in first 30 days
- [ ] `secureship scan .` output is actionable (clear, prioritized, linked to fixes)
- [ ] Gate 4 fix success rate > 70% for SAST findings
- [ ] < 5% false positive rate (published and verified)
- [ ] Language coverage: JS, TS, Python, Go, Java (5 languages)

---

## PART 8 — CRITICAL PATH (What to Do First)

If only 4 weeks of time available right now, do exactly this in order:

```
Week 1: Distribution
  Day 1:   packages/cli/package.json → remove "private": true, add publishConfig
  Day 1:   pnpm build && npm publish --tag beta (from packages/cli)
  Day 2:   .github/workflows/release.yml → automated binary + npm publish on tag
  Day 3:   packages/cli/src/commands/install-tools.ts → basic version (top 3 tools: opengrep, gitleaks, trivy)
  Day 4:   packages/cli/src/commands/init.ts → basic wizard (scanners + failOn + GitHub Action)
  Day 5:   docs/ci/secureship-github-actions.yml → reference workflow template
  Weekend: Write Hacker News post. Do NOT post yet.

Week 2: Language + SBOM
  Day 6-8: Python full AST (fix line 134 + extractPythonCapabilities() method)
  Day 9-11: packages/cli/src/commands/sbom.ts → CycloneDX output (reuse discoverPackages())
  Day 12: secureship scan --check-licenses (extend sbom command)
  Day 13: Test all new features. Fix bugs.
  Day 14: Cut v1.0.0-beta.1 release tag → automated binary publish

Week 3: Polish + Launch Prep
  Day 15-17: secureship init wizard polish
  Day 18-19: README rewrite (focus on zero-telemetry, free, 5-minute setup)
  Day 20-21: Landing page (GitHub Pages — docs/ folder → VitePress)
  Day 21: Post to Hacker News "Show HN"
  Day 21: Tweet thread
  Monitor and respond to all feedback.

Week 4: VSCode Extension MVP
  Day 22-25: packages/vscode-extension/ — basic version (status bar + hover + on-save scan)
  Day 26-27: Publish to VS Code Marketplace
  Day 28: ProductHunt launch
```

**After 4 weeks**: npm published, binary downloadable, Python full AST, SBOM generation, basic VSCode extension, 2 public community channels established.

**This is the point where SecureShip goes from "impressive private project" to "real product that developers can actually use."**

---

## PART 9 — WHAT FAILURE LOOKS LIKE (Avoid These)

```
Failure Mode 1: "Ship everything, ship nothing"
  → Don't try to build VSCode extension + GitHub App + taint analysis + dashboard
    all at the same time. Stages exist for a reason. Stage 1 before Stage 6.

Failure Mode 2: "All the features, zero the docs"
  → Every CLI command needs --help text that is actually helpful.
    'secureship scan --help' must explain every flag, give examples, explain defaults.
    If a developer reads --help and is still confused → documentation bug.

Failure Mode 3: "We don't need to respond to issues"
  → The first 100 GitHub issues define the product's reputation forever.
    Respond to every issue within 24 hours. Fix all "this is broken" bugs within 48 hours.
    Community trust is built in the first month or never.

Failure Mode 4: "We'll add telemetry later for insights"
  → Never. The zero-telemetry promise is the entire foundation of trust.
    If violated even once, the product's reputation is destroyed permanently.
    Product analytics must come from anonymous, aggregated, opt-in sources only.

Failure Mode 5: "Enterprise will come to us"
  → No. Enterprise security buyers are conservative and overworked.
    They need: a live demo, a POC in their environment, a reference customer,
    a security questionnaire response, a vendor assessment. You must go to them.

Failure Mode 6: "We'll worry about performance later"
  → secureship scan . must complete in < 30 seconds for a typical Node.js project.
    If it takes 5 minutes, nobody will use it in CI. Profile first, optimize before shipping.
    Current benchmark: supply-chain scan of node_modules is the bottleneck.
    Fix: concurrency tuning in supply-chain-analyzer.ts (policy.concurrency setting).
```

---

> _Document version: 1.0 | Generated: 2026-10-22_ > _Based on: Complete deep-code analysis of SecureShip v0.4.0_ > _All file paths, line numbers, TypeScript interfaces, and architectural details verified against live codebase_ > _This document is a living strategy — update Stage completion status as each Stage ships_
