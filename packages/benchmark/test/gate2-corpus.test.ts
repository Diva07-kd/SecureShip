import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import type { NormalizedFinding } from '@secureship/contracts';
import { ReachabilityEngine } from '@secureship/reachability';
import { ReachabilityMetricsCalculator, type ReachabilityEvaluationItem } from '../src/metrics.js';

describe('Gate 2 Corpus Evaluation Suite (>= 30 Fixtures)', () => {
  const corpusDir = path.resolve('packages/benchmark/corpus/gate2');

  it('evaluates all corpus cases with 0 false-unreachables', async () => {
    const caseDirs = fs
      .readdirSync(corpusDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(corpusDir, d.name))
      .sort();

    expect(caseDirs.length).toBeGreaterThanOrEqual(30);

    const evaluations: ReachabilityEvaluationItem[] = [];

    for (const caseDir of caseDirs) {
      const expectedPath = path.join(caseDir, 'reachability-expected.json');
      expect(fs.existsSync(expectedPath)).toBe(true);

      const exp = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));

      const engine = new ReachabilityEngine(caseDir, { noCache: true });
      await engine.init();

      const finding: NormalizedFinding = {
        id: `f-${exp.id}`,
        fingerprint: '0'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: exp.category,
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        location: {
          filePath: exp.filePath ?? 'package.json',
          startLine: 1,
          endLine: 1,
        },
        scopeTag: 'PRODUCTION',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        title: exp.id,
        description: exp.id,
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-1', message: 'Test' }],
        createdAt: new Date().toISOString(),
        package: exp.package
          ? {
              ecosystem:
                fs.existsSync(path.join(caseDir, 'requirements.txt')) ||
                fs.existsSync(path.join(caseDir, 'pyproject.toml')) ||
                exp.id.includes('python')
                  ? 'pip'
                  : 'npm',
              name: exp.package,
              version: '1.0.0',
            }
          : undefined,
      };

      const detail = engine.evaluate(finding);

      evaluations.push({
        predicted: detail.verdict,
        truth: exp.expectedVerdict,
        reportedBeforeGate2: true,
      });

      // Strict assertions per fixture
      expect(
        detail.verdict,
        `Case ${exp.id} predicted ${detail.verdict} (reason: ${detail.evidence.kind}, notes: ${detail.evidence.notes}) but expected ${exp.expectedVerdict}`
      ).toBe(exp.expectedVerdict);

      if (exp.expectedKind) {
        expect(
          detail.evidence.kind,
          `Case ${exp.id} predicted kind ${detail.evidence.kind} but expected ${exp.expectedKind}`
        ).toBe(exp.expectedKind);
      }

      if (exp.expectedConfidence) {
        expect(
          detail.analysisConfidence,
          `Case ${exp.id} predicted confidence ${detail.analysisConfidence} but expected ${exp.expectedConfidence}`
        ).toBe(exp.expectedConfidence);
      }
    }

    const metrics = ReachabilityMetricsCalculator.calculate(evaluations);

    // Hard requirement: falseUnreachableCount MUST be 0
    expect(metrics.falseUnreachableCount).toBe(0);
    expect(metrics.reachabilityAccuracy.overall).toBe(1.0);
    expect(metrics.reachabilityAccuracy.reachable).toBe(1.0);
    expect(metrics.reachabilityAccuracy.unreachable).toBe(1.0);
  });
});
