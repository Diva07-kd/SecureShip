import fs from 'node:fs';
import path from 'node:path';
import { ScanOrchestrator } from '../packages/core-engine/dist/index.js';
import {
  GitleaksAdapter,
  OsvScannerAdapter,
  OpengrepAdapter,
  TrivyAdapter,
  CheckovAdapter,
} from '../packages/scanner-adapters/dist/index.js';

async function main() {
  const corpusDir = path.resolve('packages/benchmark/corpus/gate3');
  const dirs = fs
    .readdirSync(corpusDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  const adapters = [
    new GitleaksAdapter(),
    new OsvScannerAdapter(),
    new OpengrepAdapter(),
    new TrivyAdapter(),
    new CheckovAdapter(),
  ];

  console.log(`Validating ${dirs.length} Gate 3 corpus cases against real scanners...\n`);

  const results = [];

  for (const dirName of dirs) {
    const targetDir = path.join(corpusDir, dirName);
    const expPath = path.join(targetDir, 'gate3-expected.json');
    const exp = JSON.parse(fs.readFileSync(expPath, 'utf8'));

    try {
      const report = await ScanOrchestrator.scan({
        targetDir,
        adapters,
        gate2Mode: 'off',
      });

      const findingCount = report.findings.length;
      results.push({
        dirName,
        category: exp.category,
        source: exp.source,
        expectedRule: exp.ruleId,
        findingCount,
        findings: report.findings.map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          scanner: f.scannerName,
        })),
      });
      console.log(
        `[${findingCount > 0 ? 'FINDING' : 'ZERO'}] ${dirName} (source: ${exp.source}, cat: ${exp.category}) => ${findingCount} findings`
      );
      if (findingCount > 0) {
        for (const f of report.findings) {
          console.log(`    ↳ ${f.scannerName}: ${f.ruleId} (${f.severity})`);
        }
      }
    } catch (err) {
      console.error(`[ERROR] ${dirName}:`, err.message);
      results.push({
        dirName,
        category: exp.category,
        source: exp.source,
        findingCount: -1,
        error: err.message,
      });
    }
  }

  console.log('\n--- Summary ---');
  const withFindings = results.filter((r) => r.findingCount > 0);
  const zeroFindings = results.filter((r) => r.findingCount === 0);
  console.log(`Total: ${results.length}`);
  console.log(`With >= 1 finding: ${withFindings.length}`);
  console.log(`Zero findings: ${zeroFindings.length}`);
  if (zeroFindings.length > 0) {
    console.log('Zero finding cases:');
    for (const z of zeroFindings) {
      console.log(
        `  - ${z.dirName} (source: ${z.source}, cat: ${z.category}, rule: ${z.expectedRule})`
      );
    }
  }
}

main().catch(console.error);
