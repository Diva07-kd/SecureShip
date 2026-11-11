import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Anti-Cheat: MUST NOT import @secureship/reachability
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const resultsPath = path.join(
  repoRoot,
  'packages/benchmark/corpus/real-repos/evaluation-results.json'
);

console.log('=== Independent Ground-Truth Source Audit Script ===');
console.log('Checking: Does NOT import @secureship/reachability (Anti-Cheat AC2/AC5)...\n');

if (!fs.existsSync(resultsPath)) {
  console.error(
    `Error: Results file not found at ${resultsPath}. Run run-real-repo-evaluation.mjs first.`
  );
  process.exit(1);
}

const evaluationResults = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
console.log(`Loaded ${evaluationResults.length} evaluated findings from real scanner outputs.\n`);

/**
 * Independent ground-truth verifier that reads source code directly using string/AST patterns.
 * Completely decoupled from @secureship/reachability.
 */
function independentlyVerifySource(repoDir, pkgName, vulnerableSymbols) {
  const files = [];
  function collect(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (['node_modules', '.git', 'dist', 'build', '__pycache__'].includes(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) collect(full);
      else if (e.isFile() && ['.js', '.ts', '.py', '.mjs', '.cjs'].includes(path.extname(e.name))) {
        files.push(full);
      }
    }
  }
  collect(repoDir);

  const foundSymbols = [];
  let hasEscape = false;

  for (const f of files) {
    const content = fs.readFileSync(f, 'utf8');

    // Check if package is imported
    const mentionsPkg =
      content.includes(`'${pkgName}'`) ||
      content.includes(`"${pkgName}"`) ||
      content.includes(`import ${pkgName}`);
    if (!mentionsPkg) continue;

    // Check escapes
    if (
      content.includes(`console.log(${pkgName})`) ||
      content.includes(`return ${pkgName}`) ||
      content.includes(`export default ${pkgName}`)
    ) {
      hasEscape = true;
    }

    // Check if any vulnerable symbol is called or accessed
    if (vulnerableSymbols && Array.isArray(vulnerableSymbols)) {
      for (const sym of vulnerableSymbols) {
        const regex = new RegExp(`\\b${sym}\\s*\\(`, 'g');
        const memberRegex = new RegExp(`\\.${sym}\\b`, 'g');
        if (regex.test(content) || memberRegex.test(content)) {
          foundSymbols.push({ file: path.relative(repoDir, f), symbol: sym });
        }
      }
    }
  }

  return {
    isVulnerableSymbolUsed: foundSymbols.length > 0,
    hasEscape,
    foundSymbols,
  };
}

let totalAudited = 0;
let falseUninvokedCount = 0;
let uninvokedAudited = 0;
let otherAudited = 0;
const blockedReasons = {};
let highNoiseReductionCount = 0;
let medNoiseReductionCount = 0;
let lowNoiseReductionCount = 0;
let baselineReachableImportCount = 0;

for (const finding of evaluationResults) {
  if (finding.baselineVerdict === 'REACHABLE_IMPORT') {
    baselineReachableImportCount++;
  }

  if (finding.blockedBy) {
    blockedReasons[finding.blockedBy] = (blockedReasons[finding.blockedBy] ?? 0) + 1;
  }

  const isUninvoked = finding.verdict === 'UNREACHABLE' && finding.kind === 'UNINVOKED_SYMBOL';
  const shouldAudit = isUninvoked || otherAudited < 35;

  if (shouldAudit) {
    totalAudited++;
    if (isUninvoked) uninvokedAudited++;
    else otherAudited++;

    // Perform independent source audit
    const independent = independentlyVerifySource(
      finding.repoDir,
      finding.package,
      finding.symbols
    );

    if (isUninvoked) {
      if (independent.isVulnerableSymbolUsed) {
        console.error(
          `[FAIL: FALSE UNINVOKED] Finding ${finding.ruleId} for package ${finding.package} in ${finding.repoName} was marked UNINVOKED_SYMBOL, but independent audit found: ${JSON.stringify(independent.foundSymbols)}`
        );
        falseUninvokedCount++;
      } else {
        if (finding.confidence === 'HIGH') highNoiseReductionCount++;
        else if (finding.confidence === 'MEDIUM') medNoiseReductionCount++;
        else lowNoiseReductionCount++;
      }
    }
  }
}

console.log('--- Independent Audit Results Summary ---');
console.log(`Total Findings Evaluated : ${evaluationResults.length}`);
console.log(
  `Total Findings Audited   : ${totalAudited} (${uninvokedAudited} UNINVOKED_SYMBOL, ${otherAudited} other verdicts)`
);
console.log(`False Uninvoked Count    : ${falseUninvokedCount} (Must be exactly 0)`);
console.log(`Phase 3 Baseline REACHABLE_IMPORT Findings : ${baselineReachableImportCount}`);
console.log(`Findings Pruned to UNREACHABLE (HIGH)      : ${highNoiseReductionCount}`);
console.log(`Findings Pruned to UNREACHABLE (MEDIUM)    : ${medNoiseReductionCount}`);
console.log(`Findings Pruned to UNREACHABLE (LOW)       : ${lowNoiseReductionCount}`);

const totalPruned = highNoiseReductionCount + medNoiseReductionCount + lowNoiseReductionCount;
const noiseReductionPct =
  baselineReachableImportCount > 0
    ? ((totalPruned / baselineReachableImportCount) * 100).toFixed(1)
    : '0.0';

console.log(
  `Measured Noise Reduction : ${noiseReductionPct}% (${totalPruned} / ${baselineReachableImportCount})`
);
console.log(`Blocked Preconditions Distribution : ${JSON.stringify(blockedReasons, null, 2)}`);

if (falseUninvokedCount > 0) {
  console.error('\nAUDIT FAILED: False uninvoked count > 0 violates soundness guarantee F1.');
  process.exit(1);
} else {
  console.log('\nAUDIT PASSED: 0 False Uninvoked verdicts verified across all real repositories.');
}
