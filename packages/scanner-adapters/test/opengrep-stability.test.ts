import { describe, it, expect } from 'vitest';
import { existsSync, mkdtempSync, rmSync, cpSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { SafeProcessRunner } from '@secureship/core-engine';
import { OpengrepAdapter } from '../src/adapters/opengrep.adapter.js';
import { SarifParser } from '../src/sarif/sarif-parser.js';
import { ContextSlicer } from '../../context-slicer/src/index.js';
import { BaselineEvaluator, FindingCorrelator } from '@secureship/core-engine';

describe('Opengrep Rule-ID Stability & Real Output Verification (R2)', () => {
  const repoRoot = path.resolve(__dirname, '../../../');
  const targetFixture = path.resolve(
    repoRoot,
    'rules/secureship-sast/fixtures/secureship-js-hardcoded-jwt-secret.positive.js'
  );

  it('runs real opengrep from two different cwds and with rule pack in a different directory => identical ruleIds, fingerprints, and titles (R2)', async () => {
    const adapter = new OpengrepAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.warn('Opengrep not available or blocked on system; skipping real execution test');
      return;
    }
    const opengrepBin = adapter.resolveBinary(repoRoot);
    if (!opengrepBin) {
      console.warn('Opengrep not installed on system; skipping real execution test');
      return;
    }

    const tempRoot = mkdtempSync(path.join(tmpdir(), 'secureship-opengrep-test-'));

    try {
      const sarif1 = path.join(tempRoot, 'run1.sarif');
      const sarif2 = path.join(tempRoot, 'run2.sarif');

      // Run 1: cwd = repoRoot, config = rules/secureship-sast
      const res1 = await SafeProcessRunner.run(
        opengrepBin,
        [
          'scan',
          '--config',
          path.resolve(repoRoot, 'rules/secureship-sast'),
          `--sarif-output=${sarif1}`,
          '--disable-version-check',
          '--no-git-ignore',
          '--jobs=1',
          targetFixture,
        ],
        { cwd: repoRoot, timeoutMs: 30_000 }
      );
      expect(res1.exitCode).toBe(0);
      expect(existsSync(sarif1)).toBe(true);

      // Run 2: Copy rules to an arbitrary temp directory, run from a different cwd (rulesDir)
      const customRuleDir = path.join(tempRoot, 'external-rulepack-dir');
      cpSync(path.resolve(repoRoot, 'rules/secureship-sast'), customRuleDir, { recursive: true });

      const res2 = await SafeProcessRunner.run(
        opengrepBin,
        [
          'scan',
          '--config',
          customRuleDir,
          `--sarif-output=${sarif2}`,
          '--disable-version-check',
          '--no-git-ignore',
          '--jobs=1',
          targetFixture,
        ],
        { cwd: path.join(repoRoot, 'rules'), timeoutMs: 30_000 }
      );
      expect(res2.exitCode).toBe(0);
      expect(existsSync(sarif2)).toBe(true);

      // Parse both SARIF reports
      const parsed1 = SarifParser.parseFile(sarif1, {
        scannerName: 'opengrep',
        category: 'SAST',
        targetDir: repoRoot,
      });

      const parsed2 = SarifParser.parseFile(sarif2, {
        scannerName: 'opengrep',
        category: 'SAST',
        targetDir: repoRoot,
      });

      expect(parsed1.findings.length).toBeGreaterThan(0);
      expect(parsed1.findings.length).toBe(parsed2.findings.length);

      for (let i = 0; i < parsed1.findings.length; i++) {
        const f1 = parsed1.findings[i]!;
        const f2 = parsed2.findings[i]!;

        // 1. Normalized ruleId must be stable across directories
        expect(f1.ruleId).toBe('secureship-js-hardcoded-jwt-secret');
        expect(f2.ruleId).toBe('secureship-js-hardcoded-jwt-secret');
        expect(f1.ruleId).toBe(f2.ruleId);

        // 2. Deterministic fingerprint must match identically
        expect(f1.fingerprint).toBe(f2.fingerprint);

        // 3. Original scannerRuleId preserved in evidence
        expect(f1.evidence[0]!.scannerRuleId).toContain('secureship-js-hardcoded-jwt-secret');
        expect(f2.evidence[0]!.scannerRuleId).toContain('secureship-js-hardcoded-jwt-secret');

        // 4. Finding title must use rule message, NOT "Opengrep Finding: <id>"
        expect(f1.title).not.toMatch(/^Opengrep Finding:/i);
        expect(f2.title).not.toMatch(/^Opengrep Finding:/i);
        expect(f1.title).toContain('Hardcoded secret string passed to JWT');

        // 5. Credential-class skip works on REAL opengrep output
        const isCredClass1 = ContextSlicer.isCredentialClassFinding(f1);
        const isCredClass2 = ContextSlicer.isCredentialClassFinding(f2);
        expect(isCredClass1).toBe(true);
        expect(isCredClass2).toBe(true);
      }

      // 6. Baselines match both old prefixed IDs and new normalized IDs on read
      const baselineFileOld = path.join(tempRoot, 'baseline-old.json');
      const f1 = parsed1.findings[0]!;

      // Create an old-format baseline entry with the prefixed ruleId and legacy fingerprint
      const oldRuleId = 'rules.secureship-sast.secureship-js-hardcoded-jwt-secret';
      const oldFingerprint = FindingCorrelator.generateFingerprint(
        f1.location.filePath,
        oldRuleId,
        f1.location.redactedSnippet
      );

      writeFileSync(
        baselineFileOld,
        JSON.stringify(
          {
            schemaVersion: '1.0',
            updatedAt: new Date().toISOString(),
            findings: [
              {
                fingerprint: oldFingerprint,
                ruleId: oldRuleId,
                filePath: f1.location.filePath,
                firstSeen: '2026-01-01T00:00:00.000Z',
              },
            ],
          },
          null,
          2
        )
      );

      const evaluatorOld = new BaselineEvaluator(baselineFileOld);
      // Finding with normalized ruleId MUST match the legacy baseline!
      expect(evaluatorOld.isKnownInBaseline(f1)).toBe(true);

      // And a new baseline matches both runs
      const baselineFileNew = path.join(tempRoot, 'baseline-new.json');
      BaselineEvaluator.writeBaseline(baselineFileNew, [f1]);
      const evaluatorNew = new BaselineEvaluator(baselineFileNew);
      expect(evaluatorNew.isKnownInBaseline(parsed2.findings[0]!)).toBe(true);
    } finally {
      try {
        rmSync(tempRoot, { recursive: true, force: true });
      } catch {}
    }
  }, 60_000);
});
