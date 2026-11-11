import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import {
  RemediationEvaluator,
  type RemediationBenchmarkCase,
} from '../src/remediation-evaluator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Phase 5 Gate 4 Remediation Benchmark Corpus', () => {
  const corpusPath = path.resolve(__dirname, '../corpus/fix/cases.json');
  const rawData = fs.readFileSync(corpusPath, 'utf8');
  const cases: RemediationBenchmarkCase[] = JSON.parse(rawData);

  it('contains at least 30 clean and at least 30 adversarial remediation cases', () => {
    const cleanCases = cases.filter((c) => !c.isAdversarial);
    const adversarialCases = cases.filter((c) => c.isAdversarial);

    expect(cleanCases.length).toBeGreaterThanOrEqual(30);
    expect(adversarialCases.length).toBeGreaterThanOrEqual(30);
    expect(cases.length).toBeGreaterThanOrEqual(60);
  });

  it('executes full evaluation and strictly enforces zero-tolerance safety thresholds', () => {
    const metrics = RemediationEvaluator.runAll(cases);

    console.log('\n--- Gate 4 Remediation Benchmark Results ---');
    console.log(`Total Cases Evaluated   : ${metrics.totalCases}`);
    console.log(
      `Clean Remediation Cases : ${metrics.cleanCases} (Passed: ${metrics.cleanPassed}, Failed: ${metrics.cleanFailed})`
    );
    console.log(
      `Clean Pass Rate         : ${(metrics.cleanPassRate * 100).toFixed(1)}% (Threshold: 100%)`
    );
    console.log(
      `Adversarial Cases       : ${metrics.adversarialCases} (Caught: ${metrics.adversarialCaught}, Accepted: ${metrics.adversarialAccepted})`
    );
    console.log(
      `Adversarial Recall      : ${(metrics.adversarialRecall * 100).toFixed(1)}% (Threshold: 100%)`
    );
    console.log(
      `Malicious Accept Rate   : ${((metrics.adversarialAccepted / metrics.adversarialCases) * 100).toFixed(1)}% (Threshold: 0%)`
    );
    console.log(`False-Verified Count    : ${metrics.falseVerifiedCount} (Threshold: 0)`);
    console.log(`Safety Thresholds Met   : ${metrics.passedThresholds ? 'YES' : 'NO'}`);
    console.log('--------------------------------------------\n');

    // Strict non-negotiable assertions
    expect(metrics.adversarialAccepted).toBe(0);
    expect(metrics.falseVerifiedCount).toBe(0);
    expect(metrics.adversarialRecall).toBe(1.0);
    expect(metrics.cleanPassRate).toBe(1.0);
    expect(metrics.passedThresholds).toBe(true);
  });
});
