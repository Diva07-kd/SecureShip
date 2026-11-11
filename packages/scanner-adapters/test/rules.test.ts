import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { OpengrepAdapter } from '../src/adapters/opengrep.adapter.js';

describe('Secureship SAST Rule Pack Suite', () => {
  const rulesDir = path.resolve('rules/secureship-sast');
  const fixturesDir = path.join(rulesDir, 'fixtures');

  it('validates all 10 bundled SAST rules have required metadata, CWEs, and license headers', () => {
    expect(existsSync(rulesDir)).toBe(true);

    const ruleFiles = readdirSync(rulesDir).filter((f) => f.endsWith('.yml'));
    expect(ruleFiles.length).toBeGreaterThanOrEqual(10);

    for (const rf of ruleFiles) {
      const content = readFileSync(path.join(rulesDir, rf), 'utf-8');

      // Check license header
      expect(content).toContain('SPDX-License-Identifier: Apache-2.0');

      // Check rule ID
      expect(content).toContain('id: secureship-');

      // Check message and CWE metadata
      expect(content).toContain('message:');
      expect(content).toContain('cwe:');
      expect(content).toContain('CWE-');
      expect(content).toContain('security-severity:');
    }
  });

  it('validates positive and negative test fixtures exist for all rules', () => {
    expect(existsSync(fixturesDir)).toBe(true);
    const fixtureFiles = readdirSync(fixturesDir);

    const ruleFiles = readdirSync(rulesDir).filter((f) => f.endsWith('.yml'));
    for (const rf of ruleFiles) {
      const ruleBase = rf.replace('.yml', '');
      const hasPositive = fixtureFiles.some(
        (ff) => ff.startsWith(ruleBase) && ff.includes('.positive.')
      );
      const hasNegative = fixtureFiles.some(
        (ff) => ff.startsWith(ruleBase) && ff.includes('.negative.')
      );

      expect(hasPositive).toBe(true);
      expect(hasNegative).toBe(true);
    }
  });

  it('runs rules against fixtures when opengrep or semgrep is available', async () => {
    const adapter = new OpengrepAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping live rule runner: opengrep/semgrep binary not installed.');
      return;
    }

    const res = await adapter.scan(fixturesDir, {
      rulePaths: [rulesDir],
    });

    expect(res.status).toBe('SUCCESS');
    expect(res.findings.length).toBeGreaterThan(0);
  }, 120_000);
});
