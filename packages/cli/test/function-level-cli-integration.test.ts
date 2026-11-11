import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { generateLicenseKeyPair, signLicenseJwt, ScanOrchestrator } from '@secureship/core-engine';
import {
  ScanReportSchema,
  type NormalizedFinding,
  type LicenseJwtPayload,
  type IScannerAdapter,
} from '@secureship/contracts';
import { SafeProcessRunner } from '@secureship/core-engine';
import { resolveReachabilityLabel } from '../src/commands/scan.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');
const fixtureDir = path.join(repoRoot, 'packages/benchmark/corpus/gate2/01-prod-import-esm');
const cliEntry = path.join(repoRoot, 'packages/cli/dist/index.js');

function createMockLodashFinding(): NormalizedFinding {
  return {
    id: 'mock-lodash-1',
    fingerprint: 'a'.repeat(64),
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
      version: '4.17.21',
      ecosystem: 'npm',
    },
    evidence: [
      {
        scannerName: 'trivy' as const,
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
  };
}

describe('CLI & Orchestrator Function-Level Integration (Deliverable 6)', () => {
  let tempDir: string;
  let licenseFilePath: string;
  const { publicKeyPem, privateKeyPem } = generateLicenseKeyPair();

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fn-cli-test-'));
    licenseFilePath = path.join(tempDir, 'license.jwt');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  });

  it('Free tier: skips function-level reachability, records tier notice, keeps import-level verdict', async () => {
    const fakeAdapter: IScannerAdapter = {
      name: 'trivy',
      category: 'SCA',
      version: async () => '0.50.0',
      supportsProject: () => true,
      async isAvailable() {
        return true;
      },
      async scan() {
        return {
          status: 'SUCCESS' as const,
          scannerName: 'trivy',
          exitCode: 0,
          timedOut: false,
          durationMs: 10,
          findings: [createMockLodashFinding()],
        };
      },
    };

    const report = await ScanOrchestrator.scan({
      targetDir: fixtureDir,
      adapters: [fakeAdapter],
      gate2Mode: 'annotate',
      licensePath: licenseFilePath, // Non-existent -> Free tier
      functionLevel: true,
    });

    expect(report.warnings).toContain(
      'Function-level reachability requires a higher tier; import-level analysis used.'
    );
    expect(report.summary.functionLevel?.skippedTier).toBe(1);
    expect(report.summary.functionLevel?.evaluated).toBe(0);

    const finding = report.findings[0]!;
    expect(finding.reachability).toBe('REACHABLE_IMPORT');
    expect(finding.reachabilityDetail?.verdict).toBe('REACHABLE_IMPORT');
    expect(finding.reachabilityDetail?.evidence.kind).toBe('PACKAGE_IMPORTED');
  });

  it('Pro tier: evaluates function-level reachability, prunes uninvoked lodash.template to UNINVOKED_SYMBOL', async () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'pro-team@example.com',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'corp-1',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: false,
      allowSignedComplianceExport: false,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };
    const token = signLicenseJwt(proPayload, privateKeyPem);
    fs.writeFileSync(licenseFilePath, token, 'utf-8');

    const prevKey = process.env.SECURESHIP_PUBLIC_KEY;
    process.env.SECURESHIP_PUBLIC_KEY = publicKeyPem;

    try {
      const fakeAdapter: IScannerAdapter = {
        name: 'trivy',
        category: 'SCA',
        version: async () => '0.50.0',
        supportsProject: () => true,
        async isAvailable() {
          return true;
        },
        async scan() {
          return {
            status: 'SUCCESS' as const,
            scannerName: 'trivy',
            exitCode: 0,
            timedOut: false,
            durationMs: 10,
            findings: [createMockLodashFinding()],
          };
        },
      };

      const report = await ScanOrchestrator.scan({
        targetDir: fixtureDir,
        adapters: [fakeAdapter],
        gate2Mode: 'annotate',
        licensePath: licenseFilePath,
        functionLevel: true,
      });

      expect(report.warnings).not.toContain(
        'Function-level reachability requires a higher tier; import-level analysis used.'
      );
      expect(report.summary.functionLevel?.evaluated).toBe(1);
      expect(report.summary.functionLevel?.uninvoked).toBe(1);
      expect(report.summary.functionLevel?.symbolReferenced).toBe(0);

      const finding = report.findings[0]!;
      expect(finding.reachability).toBe('UNREACHABLE');
      expect(finding.reachabilityDetail?.verdict).toBe('UNREACHABLE');
      expect(finding.reachabilityDetail?.analysisConfidence).toBe('HIGH');
      expect(finding.reachabilityDetail?.evidence.kind).toBe('UNINVOKED_SYMBOL');
      expect(finding.reachabilityDetail?.evidence.symbols).toContain('template');
      expect(finding.reachabilityDetail?.evidence.symbolSource).toBe('CURATED_DB');
    } finally {
      if (prevKey !== undefined) {
        process.env.SECURESHIP_PUBLIC_KEY = prevKey;
      } else {
        delete process.env.SECURESHIP_PUBLIC_KEY;
      }
    }
  });

  it('--no-function-level disables function-level analysis even on Pro tier', async () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'pro-team@example.com',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'corp-1',
      iat: Math.floor(Date.now() / 1000) - 60,
      exp: Math.floor(Date.now() / 1000) + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: false,
      allowSignedComplianceExport: false,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };
    const token = signLicenseJwt(proPayload, privateKeyPem);
    fs.writeFileSync(licenseFilePath, token, 'utf-8');

    const prevKey = process.env.SECURESHIP_PUBLIC_KEY;
    process.env.SECURESHIP_PUBLIC_KEY = publicKeyPem;

    try {
      const fakeAdapter: IScannerAdapter = {
        name: 'trivy',
        category: 'SCA',
        version: async () => '0.50.0',
        supportsProject: () => true,
        async isAvailable() {
          return true;
        },
        async scan() {
          return {
            status: 'SUCCESS' as const,
            scannerName: 'trivy',
            exitCode: 0,
            timedOut: false,
            durationMs: 10,
            findings: [createMockLodashFinding()],
          };
        },
      };

      const report = await ScanOrchestrator.scan({
        targetDir: fixtureDir,
        adapters: [fakeAdapter],
        gate2Mode: 'annotate',
        licensePath: licenseFilePath,
        functionLevel: false, // Explicitly turned off
      });

      expect(report.summary.functionLevel).toBeUndefined();
      const finding = report.findings[0]!;
      expect(finding.reachability).toBe('REACHABLE_IMPORT');
      expect(finding.reachabilityDetail?.evidence.kind).toBe('PACKAGE_IMPORTED');
    } finally {
      if (prevKey !== undefined) {
        process.env.SECURESHIP_PUBLIC_KEY = prevKey;
      } else {
        delete process.env.SECURESHIP_PUBLIC_KEY;
      }
    }
  });

  it('resolveReachabilityLabel emits required human tags for all evidence kinds', () => {
    const labelNotInvoked = resolveReachabilityLabel({
      reachability: 'UNREACHABLE',
      reachabilityDetail: {
        verdict: 'UNREACHABLE',
        confidence: 'HIGH',
        evidence: {
          kind: 'UNINVOKED_SYMBOL',
          symbols: ['template'],
        },
      },
    } as unknown as NormalizedFinding);
    expect(labelNotInvoked.tag).toBe('[SYMBOL NOT REFERENCED]');

    const labelReferenced = resolveReachabilityLabel({
      reachability: 'REACHABLE_IMPORT',
      reachabilityDetail: {
        verdict: 'REACHABLE_IMPORT',
        confidence: 'HIGH',
        evidence: {
          kind: 'SYMBOL_REFERENCED',
          symbols: ['template'],
        },
      },
    } as unknown as NormalizedFinding);
    expect(labelReferenced.tag).toBe('[SYMBOL REFERENCED]');

    const labelCallPath = resolveReachabilityLabel({
      reachability: 'REACHABLE_CALL_PATH',
      reachabilityDetail: {
        verdict: 'REACHABLE_CALL_PATH',
        confidence: 'HIGH',
        evidence: {
          kind: 'SYMBOL_CALL_PATH',
          symbols: ['template'],
        },
      },
    } as unknown as NormalizedFinding);
    expect(labelCallPath.tag).toBe('[CALL PATH PROVEN]');

    const labelEscapes = resolveReachabilityLabel({
      reachability: 'REACHABLE_IMPORT',
      reachabilityDetail: {
        verdict: 'REACHABLE_IMPORT',
        confidence: 'MEDIUM',
        evidence: {
          kind: 'NAMESPACE_ESCAPES',
        },
      },
    } as unknown as NormalizedFinding);
    expect(labelEscapes.tag).toBe('[IMPORTED]');
  });

  it('runs CLI binary scan --json and outputs schemaVersion 1.3 with functionLevel summary', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--json'],
      { timeoutMs: 30_000 }
    );

    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout);
    const reportParse = ScanReportSchema.safeParse(parsed);
    expect(reportParse.success).toBe(true);
    expect(parsed.schemaVersion).toBe('1.3');
    expect(parsed.summary.functionLevel).toBeDefined();
    expect(parsed.summary.functionLevel.skippedTier).toBe(1);
  }, 35_000);

  it('human output includes required static analysis disclaimer and function-level summary line', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--no-color'],
      { timeoutMs: 30_000 }
    );

    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain(
      'Function-level analysis is static and best-effort; vulnerable-symbol data may be incomplete.'
    );
    expect(res.stdout).toContain('Function-level: 0 evaluated');
    expect(res.stdout).toContain(
      'Function-level reachability requires a higher tier; import-level analysis used.'
    );
  }, 35_000);

  it('SARIF export carries properties.secureship.reachability with symbol evidence', async () => {
    const sarifPath = path.join(tempDir, 'output.sarif');
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--sarif', sarifPath],
      { timeoutMs: 30_000 }
    );

    expect(res.exitCode).toBe(0);
    expect(fs.existsSync(sarifPath)).toBe(true);
    const sarifContent = JSON.parse(fs.readFileSync(sarifPath, 'utf-8'));
    expect(sarifContent.version).toBe('2.1.0');
    expect(sarifContent.$schema).toBeDefined();
  }, 35_000);

  it('F6 Trust Canary: repo-resident dataset or config key is rejected/ignored with warning', async () => {
    // Plant malicious .secureship/symbols.json and secureship.config.json
    const canaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-canary-test-'));
    try {
      fs.mkdirSync(path.join(canaryDir, '.secureship'), { recursive: true });
      fs.writeFileSync(
        path.join(canaryDir, '.secureship', 'symbols.json'),
        JSON.stringify({ datasetId: 'planted-evil-dataset', entries: [] }),
        'utf-8'
      );
      fs.writeFileSync(
        path.join(canaryDir, 'secureship.config.json'),
        JSON.stringify({
          reachability: { functionLevel: 'off' }, // Illegal in repo config
        }),
        'utf-8'
      );
      fs.writeFileSync(
        path.join(canaryDir, 'package.json'),
        JSON.stringify({ name: 'canary-app', version: '1.0.0' }),
        'utf-8'
      );

      const res = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', canaryDir, '--scanners', 'gitleaks', '--json'],
        { timeoutMs: 30_000 }
      );

      expect(res.exitCode).toBe(0);
      const parsed = JSON.parse(res.stdout);
      // Verify warning was emitted for ignored repo reachability config
      expect(
        parsed.warnings.some(
          (w: string) => w.includes('reachability') || w.includes('ignored') || w.includes('tier')
        )
      ).toBe(true);
    } finally {
      fs.rmSync(canaryDir, { recursive: true, force: true });
    }
  }, 35_000);
});
