import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { IgnoreRulesEvaluator } from '../src/suppression/ignore-rules.js';
import { BaselineEvaluator, type BaselineDocument } from '../src/suppression/baseline.js';
import { FindingCorrelator } from '../src/normalizer/finding-correlator.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Ignore Rules & Baseline Unit Suite', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(path.join(tmpdir(), 'baseline-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  function makeFinding(filePath: string, ruleId: string, sink?: string): NormalizedFinding {
    const fp = FindingCorrelator.generateFingerprint(filePath, ruleId, sink);
    return {
      id: `f-${fp.slice(0, 8)}`,
      fingerprint: fp,
      ruleId,
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath, startLine: 10, endLine: 10, redactedSnippet: sink },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Test',
      description: 'Test',
      cweIds: [],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: ruleId, message: 'Test' }],
      createdAt: new Date().toISOString(),
    };
  }

  it('IgnoreRules: matches by ruleId, fingerprint, and glob pattern', () => {
    const f1 = makeFinding('src/legacy/db.ts', 'raw-sql-query');
    const f2 = makeFinding('src/auth.ts', 'insecure-crypto');

    const rules = [
      {
        pathGlob: 'src/legacy/**',
        reason: 'Legacy database modules to be refactored next sprint',
        expires: '2027-01-01',
      },
      {
        fingerprint: f2.fingerprint,
        reason: 'Accepted risk for custom cipher wrapper',
        expires: '2027-01-01',
      },
    ];

    const evaluator = new IgnoreRulesEvaluator(rules);

    const res1 = evaluator.evaluate(f1);
    expect(res1.isIgnored).toBe(true);
    expect(res1.detail).toContain('Legacy database modules');

    const res2 = evaluator.evaluate(f2);
    expect(res2.isIgnored).toBe(true);

    const f3 = makeFinding('src/other.ts', 'other-rule');
    const res3 = evaluator.evaluate(f3);
    expect(res3.isIgnored).toBe(false);
  });

  it('IgnoreRules: does not apply expired rules and emits warnings', () => {
    const f = makeFinding('src/api.ts', 'rule-a');
    const rules = [
      {
        ruleId: 'rule-a',
        reason: 'Temporary exemption during migration',
        expires: '2020-01-01', // EXPIRED!
      },
      {
        ruleId: 'rule-unused',
        reason: 'Rule for component that was deleted',
        expires: '2027-01-01', // UNUSED!
      },
    ];

    const evaluator = new IgnoreRulesEvaluator(rules);
    const res = evaluator.evaluate(f);

    expect(res.isIgnored).toBe(false); // Expired rule did not suppress!

    const warnings = evaluator.collectWarnings();
    expect(warnings.some((w) => w.includes('expired on 2020-01-01'))).toBe(true);
    expect(warnings.some((w) => w.includes("rule-unused' did not match any findings"))).toBe(true);
  });

  it('Baseline: fingerprints remain stable across line shifts', () => {
    const sink = 'eval(dynamicInput)';
    // Original finding at line 10
    const fp1 = FindingCorrelator.generateFingerprint('src/utils.ts', 'eval-rule', sink);

    // After adding 50 lines at the top of the file, finding is now at line 60
    const fp2 = FindingCorrelator.generateFingerprint('src/utils.ts', 'eval-rule', sink);

    expect(fp1).toBe(fp2); // Fingerprint is unaffected by line shifts!
  });

  it('Baseline: suppresses known findings and preserves firstSeen on updates', () => {
    const baselineFile = path.join(tempDir, 'baseline.json');
    const f1 = makeFinding('src/a.ts', 'r1', 'sink1');
    const f2 = makeFinding('src/b.ts', 'r2', 'sink2');

    // Write initial baseline with f1
    BaselineEvaluator.writeBaseline(baselineFile, [f1]);

    const evaluator = new BaselineEvaluator(baselineFile);
    expect(evaluator.isKnownInBaseline(f1)).toBe(true);
    expect(evaluator.isKnownInBaseline(f2)).toBe(false); // New finding!

    // Wait a brief moment and update baseline with both f1 and f2
    BaselineEvaluator.writeBaseline(baselineFile, [f1, f2]);

    const updatedDoc: BaselineDocument = JSON.parse(readFileSync(baselineFile, 'utf-8'));
    expect(updatedDoc.findings).toHaveLength(2);

    const f1Entry = updatedDoc.findings.find((e) => e.fingerprint === f1.fingerprint);
    const f2Entry = updatedDoc.findings.find((e) => e.fingerprint === f2.fingerprint);

    expect(f1Entry).toBeDefined();
    expect(f2Entry).toBeDefined();
    // f1 firstSeen was preserved
    expect(f1Entry!.firstSeen).toBe(f1.createdAt);

    // Test getBaselineEntry
    const entry = evaluator.getBaselineEntry(f1);
    expect(entry).toBeDefined();
    expect(entry!.ruleId).toBe(f1.ruleId);
  });

  it('Baseline: handles corrupted baseline file and nested path creation cleanly', () => {
    // 1. Nested directory creation
    const nestedFile = path.join(tempDir, 'nested', 'sub', 'deep', 'baseline.json');
    const f = makeFinding('src/nested.ts', 'r-nested', 'sink-nested');
    BaselineEvaluator.writeBaseline(nestedFile, [f]);
    expect(existsSync(nestedFile)).toBe(true);

    // 2. Corrupt baseline JSON file is handled gracefully without throwing
    const corruptFile = path.join(tempDir, 'corrupt-baseline.json');
    writeFileSync(corruptFile, 'INVALID_JSON_CONTENT{{{', 'utf-8');

    expect(() => new BaselineEvaluator(corruptFile)).not.toThrow();
    const evaluator = new BaselineEvaluator(corruptFile);
    expect(evaluator.isKnownInBaseline(f)).toBe(false);

    // Writing to a corrupt existing baseline ignores parse error and overwrites safely
    expect(() => BaselineEvaluator.writeBaseline(corruptFile, [f])).not.toThrow();
  });
});
