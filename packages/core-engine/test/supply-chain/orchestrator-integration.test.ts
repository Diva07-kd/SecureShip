import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { IScannerAdapter, ScanExecutionResult } from '@secureship/contracts';
import { ScanOrchestrator } from '../../src/orchestrator/scan-orchestrator.js';

class MockScannerAdapter implements IScannerAdapter {
  public readonly name = 'generic' as const;
  public readonly category = 'SAST' as const;

  public async version(): Promise<string> {
    return '1.0.0';
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public supportsProject(): boolean {
    return true;
  }

  public async scan(): Promise<ScanExecutionResult> {
    return {
      scannerName: 'generic',
      status: 'SUCCESS',
      findings: [],
      durationMs: 5,
      exitCode: 0,
      timedOut: false,
    };
  }
}

describe('ScanOrchestrator Supply Chain Integration & Invariant P1 (WP1 & WP3)', () => {
  function setupTestDir(): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-orch-sc-'));
    const nm = path.join(root, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });

    // Package 1: Malicious postinstall script
    const pkg1 = path.join(nm, 'risky-dep');
    fs.mkdirSync(pkg1, { recursive: true });
    fs.writeFileSync(
      path.join(pkg1, 'package.json'),
      JSON.stringify({
        name: 'risky-dep',
        version: '1.0.0',
        scripts: {
          postinstall: 'node setup.js',
        },
      }),
      'utf-8'
    );
    fs.writeFileSync(path.join(pkg1, 'setup.js'), 'console.log("setup");', 'utf-8');

    // Package 2: Allowlisted package
    const pkg2 = path.join(nm, 'allowlisted-dep');
    fs.mkdirSync(pkg2, { recursive: true });
    fs.writeFileSync(
      path.join(pkg2, 'package.json'),
      JSON.stringify({
        name: 'allowlisted-dep',
        version: '1.0.0',
        scripts: {
          install: 'node build.js',
        },
      }),
      'utf-8'
    );
    fs.writeFileSync(path.join(pkg2, 'build.js'), 'console.log("build");', 'utf-8');

    return root;
  }

  it('preserves Invariant P1 and reports SUPPLY_CHAIN findings in scan report', async () => {
    const targetDir = setupTestDir();
    try {
      const expectedScriptHash = crypto.createHash('sha256').update('node build.js').digest('hex');

      // Write secureship.config.json with supplyChain policy and allowlist
      const config = {
        supplyChain: {
          enabled: true,
          allowlist: [
            {
              packageName: 'allowlisted-dep',
              versionRange: '*',
              ruleId: 'SC-INSTALL-001',
              scriptHash: expectedScriptHash,
              reason: 'Audited build platform install script',
              expires: '2027-01-01T00:00:00Z',
            },
          ],
        },
      };

      const configPath = path.join(targetDir, 'secureship.config.json');
      fs.writeFileSync(configPath, JSON.stringify(config), 'utf-8');

      const report = await ScanOrchestrator.scan({
        targetDir,
        configPath,
        supplyChain: true,
        adapters: [new MockScannerAdapter()],
        includeSuppressed: true,
      });

      // 1. Invariant P1 verification
      expect(report.summary.totalRaw).toBe(
        report.summary.totalReported +
          report.summary.totalSuppressed +
          report.summary.totalOutOfScope
      );

      // 2. Category counts
      expect(report.summary.byCategory.SUPPLY_CHAIN).toBeGreaterThanOrEqual(1);

      // 3. Verify reported findings contain category SUPPLY_CHAIN
      const reportedSc = report.findings.filter((f) => f.category === 'SUPPLY_CHAIN');
      expect(reportedSc.length).toBeGreaterThanOrEqual(1);
      expect(reportedSc.some((f) => f.package?.name === 'risky-dep')).toBe(true);

      // 4. Verify allowlist suppression
      expect(report.suppressed).toBeDefined();
      const suppressedAllowlisted = report.suppressed.filter(
        (s) => s.reasonCode === 'SUPPLY_CHAIN_ALLOWLISTED'
      );
      expect(suppressedAllowlisted.length).toBeGreaterThanOrEqual(1);
      expect(suppressedAllowlisted.some((s) => s.finding.package?.name === 'allowlisted-dep')).toBe(
        true
      );
      expect(report.summary.suppressedByReason.SUPPLY_CHAIN_ALLOWLISTED).toBeGreaterThanOrEqual(1);
    } finally {
      fs.rmSync(targetDir, { recursive: true, force: true });
    }
  });
});
