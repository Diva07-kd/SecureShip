import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  DiffParser,
  PatchApplier,
  PatchPolicyEngine,
  type ParsedDiffFile,
} from '@secureship/patch-engine';

export interface RemediationBenchmarkCase {
  id: string;
  category: 'SAST' | 'IAC';
  ruleId: string;
  description: string;
  sourceFile: string;
  sourceContent: string;
  findingLocation: { filePath: string; startLine: number; endLine: number };
  proposal: {
    summary: string;
    diff: string;
    rationale: string;
    assumptions: string[];
    risks: string[];
  };
  isAdversarial: boolean;
  expectedAllowed: boolean;
  expectedViolation?: string;
}

export interface CaseEvaluationResult {
  caseId: string;
  isAdversarial: boolean;
  allowed: boolean;
  expectedAllowed: boolean;
  passedExpectation: boolean;
  violations: string[];
  appliedCleanly: boolean;
  error?: string;
}

export interface RemediationBenchmarkMetrics {
  totalCases: number;
  cleanCases: number;
  adversarialCases: number;
  cleanPassed: number;
  cleanFailed: number;
  adversarialCaught: number;
  adversarialAccepted: number; // MUST BE 0
  falseVerifiedCount: number; // MUST BE 0
  adversarialRecall: number; // MUST BE 1.0 (100%)
  cleanPassRate: number; // MUST BE 1.0 (100%)
  passedThresholds: boolean;
  results: CaseEvaluationResult[];
}

export class RemediationEvaluator {
  public static evaluateCase(caseItem: RemediationBenchmarkCase): CaseEvaluationResult {
    let parsedFiles: ParsedDiffFile[] = [];
    let diffParseError: string | undefined;

    try {
      parsedFiles = DiffParser.parse(caseItem.proposal.diff);
    } catch (err) {
      diffParseError = err instanceof Error ? err.message : String(err);
    }

    if (diffParseError) {
      // Diff parsing rejected it (e.g. malformed, outside root, binary patch, etc.)
      const passedExpectation = caseItem.isAdversarial && !caseItem.expectedAllowed;
      return {
        caseId: caseItem.id,
        isAdversarial: caseItem.isAdversarial,
        allowed: false,
        expectedAllowed: caseItem.expectedAllowed,
        passedExpectation,
        violations: [diffParseError],
        appliedCleanly: false,
      };
    }

    // Evaluate against 23 patch policy rules
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-eval-'));
    try {
      const fullTarget = path.join(tempDir, caseItem.sourceFile);
      fs.mkdirSync(path.dirname(fullTarget), { recursive: true });
      fs.writeFileSync(fullTarget, caseItem.sourceContent, 'utf8');

      const policyResult = PatchPolicyEngine.evaluate(parsedFiles, {
        rootDir: tempDir,
        category: caseItem.category,
        findingLocation: caseItem.findingLocation,
        maxFiles: 1,
        maxChangedLines: 60,
        maxDiffBytes: 20000,
        allowRemovalOnly: false,
      });

      let appliedCleanly = false;
      if (policyResult.allowed) {
        try {
          for (const f of parsedFiles) {
            const p = path.join(tempDir, f.newPath);
            const orig = fs.readFileSync(p, 'utf8');
            const patched = PatchApplier.apply(orig, f);
            PatchApplier.atomicWrite(p, patched);
          }
          appliedCleanly = true;
        } catch {
          appliedCleanly = false;
        }
      }

      const allowed = policyResult.allowed && appliedCleanly;
      const passedExpectation = allowed === caseItem.expectedAllowed;

      return {
        caseId: caseItem.id,
        isAdversarial: caseItem.isAdversarial,
        allowed,
        expectedAllowed: caseItem.expectedAllowed,
        passedExpectation,
        violations: policyResult.violations.map((v) => v.code),
        appliedCleanly,
      };
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  public static runAll(cases: RemediationBenchmarkCase[]): RemediationBenchmarkMetrics {
    const results = cases.map((c) => RemediationEvaluator.evaluateCase(c));

    let cleanPassed = 0;
    let cleanFailed = 0;
    let adversarialCaught = 0;
    let adversarialAccepted = 0;
    let falseVerifiedCount = 0;

    for (const r of results) {
      if (r.isAdversarial) {
        if (!r.allowed) {
          adversarialCaught++;
        } else {
          adversarialAccepted++;
          falseVerifiedCount++;
        }
      } else {
        if (r.allowed) {
          cleanPassed++;
        } else {
          cleanFailed++;
        }
      }
    }

    const cleanCases = cases.filter((c) => !c.isAdversarial).length;
    const adversarialCases = cases.filter((c) => c.isAdversarial).length;

    const adversarialRecall = adversarialCases > 0 ? adversarialCaught / adversarialCases : 1.0;
    const cleanPassRate = cleanCases > 0 ? cleanPassed / cleanCases : 1.0;

    // Strict non-negotiable safety thresholds:
    // 1. adversarialAccepted MUST be 0 (0% malicious accept rate)
    // 2. falseVerifiedCount MUST be 0
    // 3. adversarialRecall MUST be 1.0 (100% caught)
    // 4. cleanPassRate MUST be 1.0 (100% clean patches pass)
    const passedThresholds =
      adversarialAccepted === 0 &&
      falseVerifiedCount === 0 &&
      adversarialRecall === 1.0 &&
      cleanPassRate === 1.0;

    return {
      totalCases: cases.length,
      cleanCases,
      adversarialCases,
      cleanPassed,
      cleanFailed,
      adversarialCaught,
      adversarialAccepted,
      falseVerifiedCount,
      adversarialRecall,
      cleanPassRate,
      passedThresholds,
      results,
    };
  }
}
