import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { NormalizedFinding, IScannerAdapter, LicenseJwtPayload } from '@secureship/contracts';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import { generateLicenseKeyPair, signLicenseJwt } from '../src/license/license-keys.js';

function createLodashFinding(props?: Partial<NormalizedFinding>): NormalizedFinding {
  return {
    id: 'finding-lodash-vuln-1',
    fingerprint: 'c'.repeat(64),
    ruleId: 'CVE-2021-23337',
    scannerName: 'trivy',
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: 'Command Injection in lodash.template',
    description: 'Lodash vulnerable to command injection via template',
    cweIds: [],
    package: {
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
    },
    aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
    evidence: [
      {
        scannerName: 'trivy',
        scannerRuleId: 'CVE-2021-23337',
        message: 'Lodash vulnerable to command injection via template',
      },
    ],
    createdAt: new Date().toISOString(),
    location: {
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
    },
    ...props,
  };
}

describe('ScanOrchestrator Function-Level Wiring & Fixture Variants Suite', () => {
  let tempDir: string;
  let licenseDir: string;
  let proLicensePath: string;
  let prevPubKey: string | undefined;
  const { publicKeyPem, privateKeyPem } = generateLicenseKeyPair();

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-wiring-test-'));
    licenseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-wiring-lic-'));
    proLicensePath = path.join(licenseDir, 'license.jwt');

    prevPubKey = process.env.SECURESHIP_PUBLIC_KEY;
    process.env.SECURESHIP_PUBLIC_KEY = publicKeyPem;

    const proPayload: LicenseJwtPayload = {
      sub: 'usr_wiring_pro@secureship.com',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'corp-wiring',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };
    const proToken = signLicenseJwt(proPayload, privateKeyPem);
    fs.writeFileSync(proLicensePath, proToken, 'utf-8');
  });

  afterEach(() => {
    process.env.SECURESHIP_PUBLIC_KEY = prevPubKey;
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
      fs.rmSync(licenseDir, { recursive: true, force: true });
    } catch {}
  });

  const setupFixture = (name: string, indexJs: string, extraFiles: Record<string, string> = {}) => {
    const projDir = path.join(tempDir, name);
    fs.mkdirSync(path.join(projDir, 'src'), { recursive: true });

    fs.writeFileSync(
      path.join(projDir, 'package.json'),
      JSON.stringify({
        name,
        version: '1.0.0',
        main: 'src/index.js',
        dependencies: { lodash: '^4.17.20' },
      })
    );

    fs.writeFileSync(
      path.join(projDir, 'package-lock.json'),
      JSON.stringify({
        name,
        lockfileVersion: 3,
        packages: {
          '': { name, dependencies: { lodash: '^4.17.20' } },
          'node_modules/lodash': { version: '4.17.20' },
        },
      })
    );

    // Dummy node_modules to satisfy bin check
    fs.mkdirSync(path.join(projDir, 'node_modules', 'lodash'), { recursive: true });
    fs.writeFileSync(
      path.join(projDir, 'node_modules', 'lodash', 'package.json'),
      JSON.stringify({ name: 'lodash', version: '4.17.20' })
    );

    fs.writeFileSync(path.join(projDir, 'src', 'index.js'), indexJs);

    for (const [relPath, content] of Object.entries(extraFiles)) {
      const full = path.join(projDir, relPath);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }

    return projDir;
  };

  const createMockAdapter = (finding: NormalizedFinding): IScannerAdapter => ({
    name: 'trivy',
    category: 'SCA',
    version: async () => '0.50.0',
    supportsProject: () => true,
    async isAvailable() {
      return true;
    },
    async scan() {
      return {
        status: 'SUCCESS',
        scannerName: 'trivy',
        exitCode: 0,
        timedOut: false,
        durationMs: 5,
        findings: [finding],
      };
    },
  });

  // 1. WIRING PROOF TEST
  it('Wiring Proof: asserts ScanOrchestrator calls ScaReachabilityAnalyzer function-level logic', async () => {
    const projDir = setupFixture(
      'wiring-proof',
      "import _ from 'lodash';\nexport function test() { return _.isEqual(1, 1); }\ntest();"
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    expect(report.summary.functionLevel).toBeDefined();
    expect(report.summary.functionLevel?.evaluated).toBe(1);
    expect(report.summary.functionLevel?.uninvoked).toBe(1);
  });

  // 2. VARIANT 1: calls only isEqual (uninvoked symbol) -> UNREACHABLE
  it('Variant 1: calls only isEqual -> UNREACHABLE / UNINVOKED_SYMBOL', async () => {
    const projDir = setupFixture(
      'v1-is-equal',
      "import _ from 'lodash';\nexport function run() { return _.isEqual(1, 1); }\nrun();"
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toBe('UNREACHABLE');
    expect(f.reachabilityDetail?.evidence.kind).toBe('UNINVOKED_SYMBOL');
    expect(report.summary.functionLevel?.uninvoked).toBe(1);
  });

  // 3. VARIANT 2: calls template -> REACHABLE
  it('Variant 2: calls template -> REACHABLE / SYMBOL_CALL_PATH or SYMBOL_REFERENCED', async () => {
    const projDir = setupFixture(
      'v2-template',
      "import _ from 'lodash';\nexport function run() { return _.template('hello')(); }\nrun();"
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(['SYMBOL_CALL_PATH', 'SYMBOL_REFERENCED']).toContain(
      f.reachabilityDetail?.evidence.kind
    );
    const provenOrRef =
      (report.summary.functionLevel?.callPathProven ?? 0) +
      (report.summary.functionLevel?.symbolReferenced ?? 0);
    expect(provenOrRef).toBe(1);
  });

  // 4. VARIANT 3: passes _ to function -> REACHABLE_IMPORT (NAMESPACE_ESCAPES)
  it('Variant 3: passes _ to a function -> REACHABLE_IMPORT / NAMESPACE_ESCAPES', async () => {
    const projDir = setupFixture(
      'v3-escape-arg',
      "import _ from 'lodash';\nfunction helper(x) { return x; }\nhelper(_);\n"
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(f.reachabilityDetail?.evidence.kind).toBe('NAMESPACE_ESCAPES');
  });

  // 5. VARIANT 4: uses _.chain -> reaches via member call / escape
  it('Variant 4: uses _.chain with method -> reaches via method via-chain', async () => {
    const projDir = setupFixture(
      'v4-chain',
      "import _ from 'lodash';\nexport function main() { return _.chain({ a: 1 }).template().value(); }\nmain();\n"
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(['SYMBOL_CALL_PATH', 'SYMBOL_REFERENCED']).toContain(
      f.reachabilityDetail?.evidence.kind
    );
  });

  // 6. VARIANT 5: deep import lodash.template -> REACHABLE
  it('Variant 5: deep import lodash.template matches dataset entryPoint', async () => {
    const projDir = setupFixture(
      'v5-deep-import',
      "import template from 'lodash.template';\ntemplate('hi');\n"
    );

    const finding = createLodashFinding({
      package: { name: 'lodash.template', version: '4.5.0', ecosystem: 'npm' },
    });

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(finding)],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
  });

  // 7. VARIANT 6: dependents present -> blocked by NOT_LEAF_PACKAGE
  it('Variant 6: dependents present in lockfile -> blockedBy NOT_LEAF_PACKAGE', async () => {
    const projDir = setupFixture('v6-dependents', "import _ from 'lodash';\n_.isEqual(1, 1);\n", {
      'package-lock.json': JSON.stringify({
        name: 'v6-dependents',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.20', 'my-subdep': '^1.0.0' } },
          'node_modules/lodash': { version: '4.17.20' },
          'node_modules/my-subdep': {
            version: '1.0.0',
            dependencies: { lodash: '^4.17.20' },
          },
        },
      }),
    });

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(f.reachabilityDetail?.evidence.blockedBy).toBe('NOT_LEAF_PACKAGE');
  });

  // 8. VARIANT 7: test-only usage -> uninvoked in production -> UNREACHABLE
  it('Variant 7: test-only usage -> UNREACHABLE (uninvoked in production)', async () => {
    const projDir = setupFixture(
      'v7-test-only',
      "import _ from 'lodash';\nexport function main() { return _.isEqual(1, 1); }\nmain();\n",
      {
        'src/index.test.js': "import _ from 'lodash';\n_.template('test');\n",
      }
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toBe('UNREACHABLE');
    expect(f.reachabilityDetail?.evidence.kind).toBe('UNINVOKED_SYMBOL');
  });

  // 9. VARIANT 8: usage inside dead file -> REACHABLE (still counts as used)
  it('Variant 8: usage in dead file -> REACHABLE (dead file still counts as used)', async () => {
    const projDir = setupFixture(
      'v8-dead-file',
      "import _ from 'lodash';\nexport function main() { return _.isEqual(1, 1); }\nmain();\n",
      {
        'src/dead.js': "import _ from 'lodash';\n_.template('hello')();\n",
      }
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(report.summary.functionLevel?.symbolReferenced).toBe(1);
  });

  // 10. VARIANT 9: reference inside unparsed framework file (.vue) -> blocked by CONFIG_REFERENCE
  it('Variant 9: mention inside .vue file -> reference scan blocks pruning (CONFIG_REFERENCE)', async () => {
    const projDir = setupFixture(
      'v9-vue',
      "import _ from 'lodash';\nexport function main() { return _.isEqual(1, 1); }\nmain();\n",
      {
        'src/Component.vue':
          "<template><div>Hello</div></template>\n<script>import 'lodash';</script>\n",
      }
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    const f = report.findings[0]!;
    expect(f.reachability).toMatch(/^REACHABLE/);
    expect(f.reachabilityDetail?.evidence.blockedBy).toBe('CONFIG_REFERENCE');
  });

  // 11. TIER GATING (FREE tier skips stage, prints notice)
  it('Tier Gating: Free tier skips function-level reachability and records skippedTier', async () => {
    const projDir = setupFixture('tier-free', "import _ from 'lodash';\n_.isEqual(1, 1);");

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      functionLevel: true,
      // No PRO license provided -> defaults to FREE
    });

    expect(report.summary.functionLevel?.skippedTier).toBe(1);
    expect(report.summary.functionLevel?.evaluated).toBe(0);
    const f = report.findings[0]!;
    expect(f.reachabilityDetail?.evidence.kind).toBe('PACKAGE_IMPORTED');
  });

  // 12. TRUST CANARIES: repo config and repo dataset ignored
  it('Trust Canaries: repo config attempting to override reachability or symbols is rejected', async () => {
    const projDir = setupFixture(
      'trust-canary',
      "import _ from 'lodash';\nexport function main() { return _.isEqual(1, 1); }\nmain();",
      {
        'secureship.config.json': JSON.stringify({
          reachability: { functionLevel: 'off' },
          symbolDataset: './evil-symbols.json',
        }),
        'evil-symbols.json': JSON.stringify({ version: '1.0.0', entries: [] }),
      }
    );

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(createLodashFinding())],
      licensePath: proLicensePath,
      functionLevel: true,
    });

    // Repo config reachability key was stripped by ConfigLoader
    expect(report.summary.functionLevel?.evaluated).toBe(1);
  });

  // 13. SUPPRESSION LEDGER DETAIL (B24 mutation catcher)
  it('Suppression Ledger: suppressed finding includes symbol and source detail in ledger', async () => {
    const projDir = setupFixture(
      'ledger-detail',
      "import _ from 'lodash';\nexport function run() { return _.isEqual(1, 1); }\nrun();"
    );

    const finding = createLodashFinding({ severity: 'MEDIUM' });

    const report = await ScanOrchestrator.scan({
      targetDir: projDir,
      adapters: [createMockAdapter(finding)],
      licensePath: proLicensePath,
      functionLevel: true,
      gate2Mode: 'suppress',
    });

    expect(report.findings.length).toBe(0);
    expect(report.suppressed.length).toBe(1);
    const supp = report.suppressed[0]!;
    expect(supp.detail).toContain('template');
    expect(supp.detail).toContain('from source CURATED_DB is not invoked');
    expect(supp.detail).toContain('https://github.com/advisories/GHSA-35jh-r3h4-6jhm');
  });
});
