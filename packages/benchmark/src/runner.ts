import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import type { FindingCategory, NormalizedFinding } from '@secureship/contracts';
import { FindingCorrelator, Gate1Scope, SuppressionLedger } from '@secureship/core-engine';
import {
  CheckovAdapter,
  GitleaksAdapter,
  OpengrepAdapter,
  OsvScannerAdapter,
  SarifParser,
  TrivyAdapter,
} from '@secureship/scanner-adapters';
import { MetricsCalculator, type BenchmarkMetrics } from './metrics.js';

export interface ExpectedFinding {
  file: string;
  ruleId: string;
  aliases?: string[];
  label: 'TRUE_POSITIVE' | 'FALSE_POSITIVE_TRAP';
}

export interface TestCaseExpected {
  id: string;
  description: string;
  category: FindingCategory;
  expectedFindings: ExpectedFinding[];
}

export interface BenchmarkRunResult {
  mode: 'replay' | 'live';
  metrics: BenchmarkMetrics;
  categoryMetrics: Record<FindingCategory, BenchmarkMetrics>;
  passed: boolean;
  violations: string[];
}

export class BenchmarkRunner {
  private readonly corpusDir: string;
  private readonly thresholdsPath: string;

  constructor(corpusDir?: string, thresholdsPath?: string) {
    if (corpusDir) {
      this.corpusDir = path.resolve(corpusDir);
    } else if (existsSync(path.resolve('packages/benchmark/corpus'))) {
      this.corpusDir = path.resolve('packages/benchmark/corpus');
    } else {
      this.corpusDir = path.resolve('corpus');
    }

    if (thresholdsPath) {
      this.thresholdsPath = path.resolve(thresholdsPath);
    } else if (existsSync(path.resolve('packages/benchmark/thresholds.json'))) {
      this.thresholdsPath = path.resolve('packages/benchmark/thresholds.json');
    } else {
      this.thresholdsPath = path.resolve('thresholds.json');
    }
  }

  /**
   * Evaluates raw findings from a case directory against expected.json.
   */
  private evaluateCase(
    rawFindings: NormalizedFinding[],
    expectedDoc: TestCaseExpected,
    categoryStats: Record<FindingCategory, { tp: number; fp: number; fn: number; ws: number }>,
    globals: { tp: number; fp: number; fn: number; ws: number }
  ): void {
    const cat = expectedDoc.category;

    // 1. Correlate raw findings
    const correlated = FindingCorrelator.correlate(rawFindings);
    const ledger = new SuppressionLedger();
    ledger.recordRaw(correlated.length);

    // 2. Apply Gate 1 scope evaluation
    for (const f of correlated) {
      const gate1Res = Gate1Scope.evaluate(f, { enabled: true, keepProviderSecrets: true });
      f.scopeTag = gate1Res.scopeTag;
      if (gate1Res.shouldSuppress) {
        ledger.suppress(f, gate1Res.suppressionReason!, gate1Res.suppressionDetail!, 'Gate 1');
      } else {
        ledger.addReported(f);
      }
    }

    const reportedFindings = ledger.getReportedFindings();
    const suppressedFindings = ledger.getSuppressedFindings();

    // 3. Compare with expected findings
    for (const exp of expectedDoc.expectedFindings) {
      const normExpFile = FindingCorrelator.toPosix(exp.file);

      const matchesFinding = (f: NormalizedFinding): boolean => {
        if (!FindingCorrelator.toPosix(f.location.filePath).endsWith(normExpFile)) {
          return false;
        }
        if (
          f.ruleId === exp.ruleId ||
          f.ruleId.endsWith('.' + exp.ruleId) ||
          f.ruleId.endsWith(exp.ruleId) ||
          exp.ruleId.endsWith(f.ruleId) ||
          exp.aliases?.includes(f.ruleId) ||
          exp.aliases?.some((a) => f.ruleId.endsWith(a)) ||
          f.aliases?.includes(exp.ruleId)
        ) {
          return true;
        }
        return f.evidence.some(
          (e) =>
            e.scannerRuleId === exp.ruleId ||
            e.scannerRuleId.endsWith(exp.ruleId) ||
            exp.aliases?.includes(e.scannerRuleId)
        );
      };

      const isReported = reportedFindings.some(matchesFinding);
      const isSuppressed = suppressedFindings.some((sf) => matchesFinding(sf.finding));

      if (exp.label === 'TRUE_POSITIVE') {
        if (isReported) {
          globals.tp++;
          categoryStats[cat].tp++;
        } else if (isSuppressed) {
          // Gate 1 suppressed a true positive! Suppression recall must drop!
          globals.fn++;
          globals.ws++;
          categoryStats[cat].fn++;
          categoryStats[cat].ws++;
        } else {
          globals.fn++;
          categoryStats[cat].fn++;
        }
      } else if (exp.label === 'FALSE_POSITIVE_TRAP') {
        if (isReported) {
          globals.fp++; // Fell for false positive trap!
          categoryStats[cat].fp++;
        }
      }
    }
  }

  /**
   * Executes the benchmark in replay mode against canned SARIF fixtures.
   */
  public async runReplay(): Promise<BenchmarkRunResult> {
    if (!existsSync(this.corpusDir)) {
      throw new Error(`Corpus directory not found: ${this.corpusDir}`);
    }

    const caseDirs = readdirSync(this.corpusDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(this.corpusDir, d.name));

    const globals = { tp: 0, fp: 0, fn: 0, ws: 0 };
    const categoryStats: Record<
      FindingCategory,
      { tp: number; fp: number; fn: number; ws: number }
    > = {
      SAST: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SCA: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SECRET: { tp: 0, fp: 0, fn: 0, ws: 0 },
      IAC: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SUPPLY_CHAIN: { tp: 0, fp: 0, fn: 0, ws: 0 },
    };

    for (const caseDir of caseDirs) {
      const expectedFile = path.join(caseDir, 'expected.json');
      if (!existsSync(expectedFile)) continue;

      const expectedDoc: TestCaseExpected = JSON.parse(readFileSync(expectedFile, 'utf-8'));
      const cat = expectedDoc.category;

      const fixturesDir = path.join(caseDir, 'fixtures');
      const rawFindings: NormalizedFinding[] = [];

      if (existsSync(fixturesDir)) {
        const fixtureFiles = readdirSync(fixturesDir).filter((f) => f.endsWith('.sarif'));
        for (const ff of fixtureFiles) {
          const filePath = path.join(fixturesDir, ff);
          const scannerName = ff.replace('.sarif', '') as
            | 'gitleaks'
            | 'opengrep'
            | 'trivy'
            | 'osv-scanner'
            | 'checkov';
          try {
            const parsed = SarifParser.parseFile(filePath, {
              scannerName,
              category: cat,
              targetDir: caseDir,
            });
            rawFindings.push(...parsed.findings);
          } catch {
            // Ignored
          }
        }
      }

      this.evaluateCase(rawFindings, expectedDoc, categoryStats, globals);
    }

    return this.buildResult('replay', globals, categoryStats);
  }

  /**
   * Executes the benchmark in live mode using real scanner binaries.
   */
  public async runLive(): Promise<BenchmarkRunResult> {
    if (!existsSync(this.corpusDir)) {
      throw new Error(`Corpus directory not found: ${this.corpusDir}`);
    }

    const caseDirs = readdirSync(this.corpusDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(this.corpusDir, d.name));

    const globals = { tp: 0, fp: 0, fn: 0, ws: 0 };
    const categoryStats: Record<
      FindingCategory,
      { tp: number; fp: number; fn: number; ws: number }
    > = {
      SAST: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SCA: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SECRET: { tp: 0, fp: 0, fn: 0, ws: 0 },
      IAC: { tp: 0, fp: 0, fn: 0, ws: 0 },
      SUPPLY_CHAIN: { tp: 0, fp: 0, fn: 0, ws: 0 },
    };

    // Instantiate real scanner adapters
    const gitleaks = new GitleaksAdapter();
    const opengrep = new OpengrepAdapter();
    const trivy = new TrivyAdapter();
    const osv = new OsvScannerAdapter();
    const checkov = new CheckovAdapter();

    for (const rawCaseDir of caseDirs) {
      const caseDir = path.resolve(rawCaseDir);
      const expectedFile = path.join(caseDir, 'expected.json');
      if (!existsSync(expectedFile)) continue;

      const expectedDoc: TestCaseExpected = JSON.parse(readFileSync(expectedFile, 'utf-8'));
      const cat = expectedDoc.category;
      const rawFindings: NormalizedFinding[] = [];

      try {
        if (cat === 'SECRET') {
          const res = await gitleaks.scan(caseDir, { timeoutMs: 30_000 });
          rawFindings.push(...res.findings);
        } else if (cat === 'SAST') {
          const res = await opengrep.scan(caseDir, { timeoutMs: 30_000 });
          rawFindings.push(...res.findings);
        } else if (cat === 'SCA') {
          const resTrivy = await trivy.scan(caseDir, { timeoutMs: 30_000 });
          rawFindings.push(...resTrivy.findings);
          const resOsv = await osv.scan(caseDir, { timeoutMs: 30_000 });
          rawFindings.push(...resOsv.findings);
        } else if (cat === 'IAC') {
          const resChk = await checkov.scan(caseDir, { timeoutMs: 30_000 });
          rawFindings.push(...resChk.findings);
        }
      } catch {
        // Continue
      }

      this.evaluateCase(rawFindings, expectedDoc, categoryStats, globals);
    }

    return this.buildResult('live', globals, categoryStats);
  }

  private buildResult(
    mode: 'replay' | 'live',
    globals: { tp: number; fp: number; fn: number; ws: number },
    categoryStats: Record<FindingCategory, { tp: number; fp: number; fn: number; ws: number }>
  ): BenchmarkRunResult {
    const overallMetrics = MetricsCalculator.calculate(
      globals.tp,
      globals.fp,
      globals.fn,
      globals.ws
    );

    const categoryMetrics: Record<FindingCategory, BenchmarkMetrics> = {
      SAST: MetricsCalculator.calculate(
        categoryStats.SAST.tp,
        categoryStats.SAST.fp,
        categoryStats.SAST.fn,
        categoryStats.SAST.ws
      ),
      SCA: MetricsCalculator.calculate(
        categoryStats.SCA.tp,
        categoryStats.SCA.fp,
        categoryStats.SCA.fn,
        categoryStats.SCA.ws
      ),
      SECRET: MetricsCalculator.calculate(
        categoryStats.SECRET.tp,
        categoryStats.SECRET.fp,
        categoryStats.SECRET.fn,
        categoryStats.SECRET.ws
      ),
      IAC: MetricsCalculator.calculate(
        categoryStats.IAC.tp,
        categoryStats.IAC.fp,
        categoryStats.IAC.fn,
        categoryStats.IAC.ws
      ),
      SUPPLY_CHAIN: MetricsCalculator.calculate(
        categoryStats.SUPPLY_CHAIN.tp,
        categoryStats.SUPPLY_CHAIN.fp,
        categoryStats.SUPPLY_CHAIN.fn,
        categoryStats.SUPPLY_CHAIN.ws
      ),
    };

    let thresholds = {
      minPrecision: 0.85,
      minRecall: 0.8,
      minF1: 0.8,
      minSuppressionRecall: 0.9,
    };
    if (existsSync(this.thresholdsPath)) {
      try {
        thresholds = JSON.parse(readFileSync(this.thresholdsPath, 'utf-8'));
      } catch {
        // Fallback
      }
    }

    const thresholdResult = MetricsCalculator.satisfiesThresholds(overallMetrics, thresholds);

    return {
      mode,
      metrics: overallMetrics,
      categoryMetrics,
      passed: thresholdResult.passed,
      violations: thresholdResult.violations,
    };
  }

  /**
   * Prints individual benchmark results.
   */
  public static printResults(result: BenchmarkRunResult): void {
    const label = result.mode === 'live' ? 'LIVE Binary Execution' : 'REPLAY Canned Fixtures';
    console.log(pc.bold(pc.cyan(`\n📊 SecureShip Security Benchmark Results [${label}]\n`)));

    console.log(`  ${'Metric'.padEnd(22)} ${'Value'.padEnd(12)} Threshold`);
    console.log(`  ${'─'.repeat(45)}`);

    const m = result.metrics;
    console.log(
      `  ${pc.bold('Precision'.padEnd(22))} ${(m.precision * 100).toFixed(1)}%       >= 85.0%`
    );
    console.log(`  ${pc.bold('Recall'.padEnd(22))} ${(m.recall * 100).toFixed(1)}%       >= 80.0%`);
    console.log(`  ${pc.bold('F1 Score'.padEnd(22))} ${(m.f1 * 100).toFixed(1)}%       >= 80.0%`);
    console.log(
      `  ${pc.bold('Suppression Recall'.padEnd(22))} ${(m.suppressionRecall * 100).toFixed(1)}%       >= 90.0%`
    );

    console.log(pc.bold('\nCategory Breakdown:'));
    for (const [cat, cm] of Object.entries(result.categoryMetrics)) {
      if (!cm.hasCases) {
        console.log(
          `  • ${cat.padEnd(8)}: ${pc.gray('N/A (no cases)')} (TP: ${cm.truePositives}, FP: ${cm.falsePositives}, FN: ${cm.falseNegatives})`
        );
      } else {
        console.log(
          `  • ${cat.padEnd(8)}: Precision ${(cm.precision * 100).toFixed(1)}% | Recall ${(cm.recall * 100).toFixed(1)}% | F1 ${(cm.f1 * 100).toFixed(1)}% (TP: ${cm.truePositives}, FP: ${cm.falsePositives}, FN: ${cm.falseNegatives})`
        );
      }
    }

    console.log(
      pc.gray(
        '\nNote: Categories with no test cases are marked N/A and excluded from threshold evaluation.'
      )
    );

    if (result.passed) {
      console.log(pc.green('\n✔ All benchmark precision and recall thresholds satisfied!'));
    } else {
      console.error(pc.red('\n✖ Benchmark Threshold Violations:'));
      for (const v of result.violations) {
        console.error(`  - ${pc.yellow(v)}`);
      }
    }
  }

  /**
   * Prints side-by-side comparison between Replay mode and Live mode.
   */
  public static printComparison(replay: BenchmarkRunResult, live: BenchmarkRunResult): void {
    console.log(
      pc.bold(pc.cyan('\n📊 Benchmark Mode Comparison (Replay vs Live Real Scanners)\n'))
    );
    console.log(
      `  ${'Metric'.padEnd(20)} ${'Replay Mode'.padEnd(14)} ${'Live Mode'.padEnd(14)} Notes`
    );
    console.log(`  ${'─'.repeat(70)}`);

    const r = replay.metrics;
    const l = live.metrics;

    const row = (name: string, rVal: number, lVal: number, note = '') => {
      const rStr = `${(rVal * 100).toFixed(1)}%`.padEnd(14);
      const lStr = `${(lVal * 100).toFixed(1)}%`.padEnd(14);
      console.log(`  ${name.padEnd(20)} ${rStr} ${lStr} ${pc.gray(note)}`);
    };

    row(
      'Precision',
      r.precision,
      l.precision,
      r.precision === l.precision ? 'Identical' : 'Live variance'
    );
    row('Recall', r.recall, l.recall, r.recall === l.recall ? 'Identical' : 'Live detection');
    row('F1 Score', r.f1, l.f1, 'Harmonic mean');
    row(
      'Suppression Recall',
      r.suppressionRecall,
      l.suppressionRecall,
      r.suppressionRecall < 1.0 ? 'Gate 1 suppression tested' : ''
    );

    console.log(pc.bold('\nCategory Comparison (F1 Score):'));
    for (const cat of ['SAST', 'SCA', 'SECRET', 'IAC'] as FindingCategory[]) {
      const rc = replay.categoryMetrics[cat];
      const lc = live.categoryMetrics[cat];
      const rF1 = rc.hasCases ? `${(rc.f1 * 100).toFixed(1)}%` : 'N/A';
      const lF1 = lc.hasCases ? `${(lc.f1 * 100).toFixed(1)}%` : 'N/A';
      console.log(`  • ${cat.padEnd(8)}: Replay F1 ${rF1.padEnd(8)} | Live F1 ${lF1.padEnd(8)}`);
    }

    console.log(
      pc.cyan(
        '\nExplanation of Differences: Replay mode operates strictly on committed golden SARIF\nfixtures ensuring deterministic regression gates. Live mode runs real local binaries\nagainst raw source files, capturing real scanner CLI behavior and vendor rule coverage.\n'
      )
    );
  }
}
