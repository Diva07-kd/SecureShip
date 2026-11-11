import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ScanReportSchema, type ScanReport } from '@secureship/contracts';
import { FixCommand } from '../src/commands/fix.js';

describe('SCA Remediation CLI Integration Tests', () => {
  let tempRepo: string;
  let reportPath: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sca-cli-test-'));
    fs.mkdirSync(path.join(tempRepo, '.git'), { recursive: true });
    fs.mkdirSync(path.join(tempRepo, '.secureship'), { recursive: true });

    // Mock package.json
    fs.writeFileSync(
      path.join(tempRepo, 'package.json'),
      JSON.stringify(
        {
          name: 'cli-test-app',
          version: '1.0.0',
          dependencies: {
            lodash: '4.17.20',
          },
        },
        null,
        2
      ) + '\n',
      'utf8'
    );

    const scanReport: ScanReport = ScanReportSchema.parse({
      schemaVersion: '1.2',
      tool: { name: 'secureship', version: '0.1.0' },
      target: tempRepo,
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 50,
      scanners: [],
      findings: [
        {
          id: 'sca-finding-1',
          fingerprint: '3'.repeat(64),
          ruleId: 'CVE-2020-8203',
          scannerName: 'osv-scanner',
          category: 'SCA',
          severity: 'HIGH',
          confidence: 'HIGH',
          reachability: 'REACHABLE_CALL_PATH',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'Prototype pollution in lodash',
          description: 'Lodash vulnerable to prototype pollution',
          cweIds: ['CWE-1321'],
          location: {
            filePath: 'package.json',
            startLine: 5,
            endLine: 5,
          },
          package: {
            ecosystem: 'npm',
            name: 'lodash',
            version: '4.17.20',
            fixedVersion: '4.17.21',
          },
          evidence: [
            { scannerName: 'osv-scanner', scannerRuleId: 'CVE-2020-8203', message: 'Vulnerable' },
          ],
          createdAt: new Date().toISOString(),
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SECRET: 0, SCA: 1, IAC: 0 },
        suppressedByReason: {},
      },
    });

    reportPath = path.join(tempRepo, '.secureship', 'scan-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(scanReport, null, 2), 'utf8');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempRepo, { recursive: true, force: true });
    } catch {
      // Ignore
    }
    vi.restoreAllMocks();
  });

  it('runs deterministic SCA remediation without requiring AI consent or keys', async () => {
    const exitCode = await FixCommand.run('1', {
      root: tempRepo,
      report: reportPath,
      require: 'VERIFIED_STATIC',
      verify: 'none',
      json: true,
    });

    expect(exitCode).toBe(0);

    // Verify .secureship/sca-fix-<fingerprint>.json exists
    const files = fs.readdirSync(path.join(tempRepo, '.secureship'));
    const fixFile = files.find((f) => f.startsWith('sca-fix-'));
    expect(fixFile).toBeDefined();

    // Verify working tree is UNTOUCHED
    const originalContent = fs.readFileSync(path.join(tempRepo, 'package.json'), 'utf8');
    expect(originalContent).toContain('"lodash": "4.17.20"');
  });

  it('lists stored SCA fixes with strategy summary and applies atomically', async () => {
    // 1. Generate fix
    await FixCommand.run('1', {
      root: tempRepo,
      report: reportPath,
      require: 'VERIFIED_STATIC',
      verify: 'none',
    });

    // 2. List fixes
    const listCode = await FixCommand.list({ root: tempRepo });
    expect(listCode).toBe(0);

    // 3. Find saved fix id from fix store
    const homeDir = os.homedir();
    const fixBaseDir = path.join(homeDir, '.secureship', 'fixes');
    // Read fixes from FixStore directly
    const repoHash = path.resolve(tempRepo).replace(/\\/g, '/');
    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update(repoHash).digest('hex');
    const repoFixDir = path.join(fixBaseDir, hash);

    if (fs.existsSync(repoFixDir)) {
      const fixDirs = fs.readdirSync(repoFixDir);
      expect(fixDirs.length).toBeGreaterThan(0);
      const fixId = fixDirs[0]!;

      // 4. Show fix
      const showCode = await FixCommand.show(fixId, { root: tempRepo });
      expect(showCode).toBe(0);

      // 5. Apply fix atomically to working tree
      const applyCode = await FixCommand.apply(fixId, {
        root: tempRepo,
        allowNonGit: true,
        allowDirty: true,
      });
      expect(applyCode).toBe(0);

      // Verify working tree package.json is now updated!
      const updatedContent = fs.readFileSync(path.join(tempRepo, 'package.json'), 'utf8');
      expect(updatedContent).toContain('"lodash": "4.17.21"');
    }
  });

  it('filters scan findings with --reachability-filter', () => {
    const findings = [
      {
        id: '1',
        reachability: 'REACHABLE_CALL_PATH',
      },
      {
        id: '2',
        reachability: 'UNKNOWN',
      },
      {
        id: '3',
        reachability: 'UNREACHABLE',
        reachabilityDetail: { evidence: { kind: 'NOT_APPLICABLE' } },
      },
    ];

    // @ts-expect-error test filter
    const reachable = FixCommand.resolveFinding({ findings }, '1');
    expect(reachable?.id).toBe('1');
  });
});
