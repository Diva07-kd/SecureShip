import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ScanReportSchema, type FixReport, type ScanReport } from '@secureship/contracts';
import { FixCommand } from '../src/commands/fix.js';
import { VerifyCommand } from '../src/commands/verify.js';
import { SandboxCommand } from '../src/commands/sandbox.js';
import { FixStore, VerificationLadder } from '@secureship/core-engine';

describe('Remediation CLI Commands', () => {
  let tempRepo: string;
  let reportPath: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cli-test-'));
    fs.mkdirSync(path.join(tempRepo, 'src'), { recursive: true });
    fs.mkdirSync(path.join(tempRepo, '.secureship'), { recursive: true });

    fs.writeFileSync(
      path.join(tempRepo, 'src', 'app.ts'),
      'export function run(val: string) {\n  const q = "SELECT * FROM users WHERE id = " + val;\n  return q;\n}\n'
    );

    const scanReport: ScanReport = ScanReportSchema.parse({
      schemaVersion: '1.2',
      tool: { name: 'secureship', version: '0.1.0' },
      target: tempRepo,
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 100,
      scanners: [],
      findings: [
        {
          id: 'finding-1',
          fingerprint: '1'.repeat(64),
          ruleId: 'rules.sqli',
          scannerName: 'semgrep',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'SQLi',
          description: 'SQL injection',
          cweIds: ['CWE-89'],
          location: {
            filePath: 'src/app.ts',
            startLine: 2,
            endLine: 2,
          },
          evidence: [{ scannerName: 'semgrep', scannerRuleId: 'rules.sqli', message: 'SQLi' }],
          createdAt: new Date().toISOString(),
        },
        {
          id: 'finding-secret',
          fingerprint: '2'.repeat(64),
          ruleId: 'rules.secret',
          scannerName: 'gitleaks',
          category: 'SECRET',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'API Key',
          description: 'Secret key leak',
          cweIds: ['CWE-798'],
          location: {
            filePath: 'src/app.ts',
            startLine: 1,
            endLine: 1,
          },
          evidence: [{ scannerName: 'gitleaks', scannerRuleId: 'rules.secret', message: 'Secret' }],
          createdAt: new Date().toISOString(),
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 2,
        totalReported: 2,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SECRET: 1, SCA: 0, IAC: 0 },
        suppressedByReason: {},
      },
    });

    reportPath = path.join(tempRepo, '.secureship', 'report.json');
    fs.writeFileSync(reportPath, JSON.stringify(scanReport, null, 2));
  });

  afterEach(() => {
    fs.rmSync(tempRepo, { recursive: true, force: true });
  });

  describe('FixCommand', () => {
    it('returns exit code 2 when target finding is missing or not provided', async () => {
      const code = await FixCommand.run(undefined, { root: tempRepo });
      expect(code).toBe(2);

      const codeNotFound = await FixCommand.run('non-existent-fp', { root: tempRepo });
      expect(codeNotFound).toBe(2);
    });

    it('rejects SECRET category findings with exit code 2', async () => {
      const code = await FixCommand.run('finding-secret', { root: tempRepo });
      expect(code).toBe(2);
    });

    it('handles fix list and show for stored fixes', async () => {
      const listCode = await FixCommand.list({ root: tempRepo });
      expect(listCode).toBe(0);

      const showMissing = await FixCommand.show('bad-id', { root: tempRepo });
      expect(showMissing).toBe(2);

      const discardMissing = await FixCommand.discard('bad-id', { root: tempRepo });
      expect(discardMissing).toBe(2);
    });

    it('applies stored fix with --allow-non-git', async () => {
      const store = new FixStore();
      const filePath = 'src/app.ts';
      const fullPath = path.join(tempRepo, filePath);
      const sha256 = crypto.createHash('sha256').update(fs.readFileSync(fullPath)).digest('hex');

      const diff =
        '--- a/src/app.ts\n+++ b/src/app.ts\n@@ -2,1 +2,1 @@\n-  const q = "SELECT * FROM users WHERE id = " + val;\n+  const q = "SELECT * FROM users WHERE id = $1";';
      const patchSha256 = crypto.createHash('sha256').update(diff).digest('hex');

      const unsignedReport: Omit<FixReport, 'signature'> = {
        schemaVersion: '1.0',
        tool: 'secureship',
        findingRef: {
          fingerprint: '1'.repeat(64),
          ruleId: 'rules.sqli',
          category: 'SAST',
          severity: 'HIGH',
          file: filePath,
          line: 2,
        },
        patchSha256,
        proposalSummary: 'Use parameterized query',
        baseFiles: [{ path: filePath, sha256 }],
        status: 'VERIFIED_STATIC',
        requirement: 'VERIFIED_STATIC',
        requirementMet: true,
        stages: [{ id: 'APPLY', outcome: 'PASS', detail: 'OK', durationMs: 1 }],
        sandbox: { backend: 'container', networkMode: 'none', limits: {}, runtime: 'auto' },
        scanners: [{ name: 'semgrep', version: '1.0.0' }],
        attempts: 1,
        limitations: [],
        disclaimer: 'Disclaimer',
        createdAt: new Date().toISOString(),
      };

      const signature = VerificationLadder.signReport(unsignedReport);
      const report = { ...unsignedReport, signature };

      const fixId = await store.saveFix(tempRepo, report, diff);

      // Without --allow-non-git on non-git repo => 2
      const exitNoFlag = await FixCommand.apply(fixId, { root: tempRepo, allowNonGit: false });
      expect(exitNoFlag).toBe(2);

      // With --allow-non-git => 0
      const exitClean = await FixCommand.apply(fixId, { root: tempRepo, allowNonGit: true });
      expect(exitClean).toBe(0);

      const patchedContent = fs.readFileSync(fullPath, 'utf8');
      expect(patchedContent).toContain('WHERE id = $1');
    });
  });

  describe('VerifyCommand', () => {
    it('returns exit code 2 when patch file or finding is missing', async () => {
      const noFile = await VerifyCommand.run(undefined, {});
      expect(noFile).toBe(2);

      const nonExistent = await VerifyCommand.run('non_existent.patch', {});
      expect(nonExistent).toBe(2);
    });

    it('returns exit code 2 when diff is malformed', async () => {
      const badPatch = path.join(tempRepo, 'bad.patch');
      fs.writeFileSync(badPatch, 'not a unified diff');

      const code = await VerifyCommand.run(badPatch, { finding: 'finding-1', root: tempRepo });
      expect(code).toBe(2);
    });

    it('verifies human-authored patch cleanly', async () => {
      const goodPatch = path.join(tempRepo, 'fix.patch');
      fs.writeFileSync(
        goodPatch,
        '--- a/src/app.ts\n+++ b/src/app.ts\n@@ -2,1 +2,1 @@\n-  const q = "SELECT * FROM users WHERE id = " + val;\n+  const q = "SELECT * FROM users WHERE id = $1";\n'
      );

      const codeUnverified = await VerifyCommand.run(goodPatch, {
        finding: 'finding-1',
        root: tempRepo,
        verify: 'none',
        require: 'UNVERIFIED',
      });

      expect(codeUnverified).toBe(0);

      // With mock scanner adapter and static verification
      const mockScanner = {
        name: 'semgrep' as const,
        category: 'SAST' as const,
        version: async () => '1.0.0',
        isAvailable: async () => true,
        supportsProject: () => true,
        scan: async (dir: string) => {
          const content = fs.readFileSync(path.join(dir, 'src', 'app.ts'), 'utf8');
          const hasVuln = content.includes('WHERE id = " + val');
          return {
            scannerName: 'semgrep' as const,
            status: 'SUCCESS' as const,
            findings: hasVuln
              ? [
                  {
                    id: 'finding-1',
                    fingerprint: '1'.repeat(64),
                    ruleId: 'rules.sqli',
                    scannerName: 'semgrep' as const,
                    category: 'SAST' as const,
                    severity: 'HIGH' as const,
                    confidence: 'HIGH' as const,
                    reachability: 'UNKNOWN' as const,
                    upstreamValidationStatus: 'UNKNOWN' as const,
                    verificationStatus: 'UNVERIFIED' as const,
                    scopeTag: 'PRODUCTION' as const,
                    title: 'SQLi',
                    description: 'SQL injection',
                    cweIds: ['CWE-89'],
                    location: { filePath: 'src/app.ts', startLine: 2, endLine: 2 },
                    evidence: [
                      {
                        scannerName: 'semgrep' as const,
                        scannerRuleId: 'rules.sqli',
                        message: 'SQLi',
                      },
                    ],
                    createdAt: new Date().toISOString(),
                  },
                ]
              : [],
            durationMs: 1,
            exitCode: 0,
            timedOut: false,
          };
        },
      };

      const codeStatic = await VerifyCommand.run(goodPatch, {
        finding: 'finding-1',
        root: tempRepo,
        adapters: [mockScanner],
        verify: 'static',
        require: 'VERIFIED_STATIC',
      });

      expect(codeStatic).toBe(0);
    });
  });

  describe('SandboxCommand', () => {
    it('displays status and doctor cleanly', async () => {
      const statusCode = await SandboxCommand.status();
      expect(statusCode).toBe(0);

      const doctorCode = await SandboxCommand.doctor();
      expect(doctorCode).toBe(0);
    });

    it('enables and disables sandbox backend', async () => {
      const disableCode = await SandboxCommand.setBackend('none');
      expect(disableCode).toBe(0);

      const enableCode = await SandboxCommand.setBackend('container');
      expect(enableCode).toBe(0);
    });

    it('refuses trust-host when confirmation phrase is incorrect', async () => {
      const refuseCode = await SandboxCommand.trustHost(tempRepo, 'Wrong phrase');
      expect(refuseCode).toBe(2);
    });

    it('grants trust-host when exact confirmation phrase is provided', async () => {
      const canonical = path.resolve(tempRepo).replace(/\\/g, '/');
      const phrase = `I trust repository ${canonical} to run un-sandboxed code on my machine`;

      const grantCode = await SandboxCommand.trustHost(tempRepo, phrase);
      expect(grantCode).toBe(0);
    });
  });
});
