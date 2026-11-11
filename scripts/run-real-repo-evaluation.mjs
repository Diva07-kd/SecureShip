import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ReachabilityEngine } from '../packages/reachability/dist/index.js';
import { TrivyAdapter, OsvScannerAdapter } from '../packages/scanner-adapters/dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const realReposDir = path.join(repoRoot, 'packages/benchmark/corpus/real-repos');

console.log('=== Step 7: Real-Repository Empirical Evaluation ===\n');

// 1. Setup Repo A: lodash-selective-app (JS/TS)
const repoADir = path.join(realReposDir, 'lodash-selective-app');
fs.mkdirSync(path.join(repoADir, 'src'), { recursive: true });
fs.writeFileSync(
  path.join(repoADir, 'package.json'),
  JSON.stringify(
    {
      name: 'lodash-selective-app',
      version: '1.0.0',
      main: 'src/index.js',
      dependencies: { lodash: '4.17.20' },
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoADir, 'package-lock.json'),
  JSON.stringify(
    {
      name: 'lodash-selective-app',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '4.17.20' } },
        'node_modules/lodash': { version: '4.17.20' },
      },
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoADir, 'src/index.js'),
  `import _ from 'lodash';
export function processItems(items) {
  return _.map(items, x => x * 2);
}
export function areEqual(a, b) {
  return _.isEqual(a, b);
}
console.log(processItems([1, 2, 3]));
`
);

// 2. Setup Repo B: requests-client-service (Python)
const repoBDir = path.join(realReposDir, 'requests-client-service');
fs.mkdirSync(repoBDir, { recursive: true });
fs.writeFileSync(path.join(repoBDir, 'requirements.txt'), 'requests==2.30.0\n');
fs.writeFileSync(
  path.join(repoBDir, 'Pipfile.lock'),
  JSON.stringify(
    {
      _meta: { hash: { sha256: '0'.repeat(64) } },
      default: { requests: { version: '==2.30.0' } },
      develop: {},
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoBDir, 'app.py'),
  `import requests

def fetch_status(target_url):
    response = requests.get(target_url)
    return response.status_code

print(fetch_status('https://example.com'))
`
);

// 3. Setup Repo C: microservices-gateway (Polyglot)
const repoCDir = path.join(realReposDir, 'microservices-gateway');
fs.mkdirSync(path.join(repoCDir, 'src'), { recursive: true });
fs.writeFileSync(
  path.join(repoCDir, 'package.json'),
  JSON.stringify(
    {
      name: 'microservices-gateway',
      version: '1.0.0',
      main: 'src/gateway.js',
      dependencies: { axios: '0.21.1' },
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoCDir, 'package-lock.json'),
  JSON.stringify(
    {
      name: 'microservices-gateway',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { axios: '0.21.1' } },
        'node_modules/axios': { version: '0.21.1' },
      },
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoCDir, 'src/gateway.js'),
  `const axios = require('axios');
async function dispatch(endpoint) {
  const res = await axios.get(endpoint);
  return res.data;
}
dispatch('https://api.internal/health');
`
);
fs.writeFileSync(path.join(repoCDir, 'requirements.txt'), 'pyyaml==5.3.1\n');
fs.writeFileSync(
  path.join(repoCDir, 'Pipfile.lock'),
  JSON.stringify(
    {
      _meta: { hash: { sha256: '0'.repeat(64) } },
      default: { pyyaml: { version: '==5.3.1' } },
      develop: {},
    },
    null,
    2
  )
);
fs.writeFileSync(
  path.join(repoCDir, 'parser.py'),
  `import yaml

def safe_parse(raw_content):
    # safe_load is safe; vulnerable load / full_load is never called!
    return yaml.safe_load(raw_content)

print(safe_parse("service: gateway\\nstatus: active"))
`
);

console.log('Repositories prepared at packages/benchmark/corpus/real-repos/');

// Run real scanner engines and evaluate findings
const trivyAdapter = new TrivyAdapter();
const osvAdapter = new OsvScannerAdapter();

const repos = [
  { name: 'Repo A (lodash-selective-app)', dir: repoADir, eco: 'npm' },
  { name: 'Repo B (requests-client-service)', dir: repoBDir, eco: 'pip' },
  { name: 'Repo C (microservices-gateway)', dir: repoCDir, eco: 'polyglot' },
];

const allEvaluationResults = [];

for (const repo of repos) {
  console.log(`\n--- Scanning ${repo.name} with Real Scanner Engines ---`);

  const scannerFindings = [];

  // Run real Trivy
  try {
    const trivyRes = await trivyAdapter.scan(repo.dir);
    if (trivyRes.status === 'SUCCESS' && Array.isArray(trivyRes.findings)) {
      scannerFindings.push(...trivyRes.findings);
      console.log(`  Trivy returned ${trivyRes.findings.length} findings.`);
    }
  } catch (err) {
    console.warn(`  Trivy scan warning: ${err.message}`);
  }

  // Run real OSV-Scanner
  try {
    const osvRes = await osvAdapter.scan(repo.dir);
    if (osvRes.status === 'SUCCESS' && Array.isArray(osvRes.findings)) {
      scannerFindings.push(...osvRes.findings);
      console.log(`  OSV-Scanner returned ${osvRes.findings.length} findings.`);
    }
  } catch (err) {
    console.warn(`  OSV-Scanner scan warning: ${err.message}`);
  }

  console.log(`  Total Raw Scanner Findings: ${scannerFindings.length}`);

  // Evaluate with ReachabilityEngine (Phase B function-level)
  const engine = new ReachabilityEngine(repo.dir, { noCache: true, functionLevel: true });
  await engine.init();

  // Evaluate with Baseline Engine (Phase 3 import-level)
  const baselineEngine = new ReachabilityEngine(repo.dir, { noCache: true, functionLevel: false });
  await baselineEngine.init();

  for (const finding of scannerFindings) {
    const baselineDetail = baselineEngine.evaluate(finding);
    const functionDetail = engine.evaluate(finding);

    allEvaluationResults.push({
      repoName: repo.name,
      repoDir: repo.dir,
      findingId: finding.id,
      ruleId: finding.ruleId,
      package: finding.package?.name,
      ecosystem: finding.package?.ecosystem,
      severity: finding.severity,
      baselineVerdict: baselineDetail.verdict,
      baselineKind: baselineDetail.evidence.kind,
      verdict: functionDetail.verdict,
      kind: functionDetail.evidence.kind,
      confidence: functionDetail.analysisConfidence,
      blockedBy: functionDetail.evidence.blockedBy,
      symbols: functionDetail.evidence.symbols,
      symbolSource: functionDetail.evidence.symbolSource,
    });
  }
}

// Write evaluation results to JSON for audit script
const resultsFile = path.join(
  repoRoot,
  'packages/benchmark/corpus/real-repos/evaluation-results.json'
);
fs.writeFileSync(resultsFile, JSON.stringify(allEvaluationResults, null, 2));
console.log(
  `\nEvaluation complete. Recorded ${allEvaluationResults.length} findings to ${resultsFile}`
);
