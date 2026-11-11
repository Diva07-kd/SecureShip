import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { ImportGraph } from '../src/graph/import-graph.js';
import { LockfileTreeParser, type LockfileGraph } from '../src/lockfile/lockfile-tree-parser.js';
import { ScaReachabilityAnalyzer } from '../src/sca/sca-reachability-analyzer.js';

describe('Deliverable 5: SCA Analyzer Symbol-Level Reachability Suite (R1-R6, P1-P10)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  const createBaseProject = (prefix: string) => {
    const dir = path.join(
      os.tmpdir(),
      `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    );
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });

    fs.writeFileSync(
      path.join(dir, 'package.json'),
      JSON.stringify({
        name: prefix,
        version: '1.0.0',
        main: 'src/index.js',
        dependencies: { lodash: '^4.17.20' },
      })
    );

    // Lockfile v3 with lodash as leaf direct dependency
    fs.writeFileSync(
      path.join(dir, 'package-lock.json'),
      JSON.stringify({
        name: prefix,
        lockfileVersion: 3,
        packages: {
          '': {
            name: prefix,
            dependencies: { lodash: '^4.17.20' },
          },
          'node_modules/lodash': {
            version: '4.17.20',
          },
        },
      })
    );

    return dir;
  };

  const createLodashFinding = (aliases: string[] = ['CVE-2021-23337']): NormalizedFinding => ({
    id: 'FINDING-1',
    fingerprint: 'a'.repeat(64),
    ruleId: 'SEC-101',
    scannerName: 'trivy',
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    scopeTag: 'PRODUCTION',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    location: { filePath: 'package.json', startLine: 1, endLine: 1 },
    title: 'Command Injection in lodash.template',
    description:
      'lodash versions prior to 4.17.21 are vulnerable to Command Injection via template',
    cweIds: [],
    evidence: [],
    createdAt: new Date().toISOString(),
    package: {
      name: 'lodash',
      version: '4.17.20',
      ecosystem: 'npm',
    },
    aliases,
  });

  const getLockGraph = (dir: string): LockfileGraph | null => {
    const res = LockfileTreeParser.parse(dir);
    return res.success ? res.graph : null;
  };

  it('R1: leaves verdict as REACHABLE_IMPORT with SYMBOL_DATA_UNAVAILABLE when no symbol candidates match', async () => {
    const dir = createBaseProject('r1-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `import _ from 'lodash';\n_.isEqual(1, 1);`
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    // Finding for an unknown CVE that has no curated entry and no regex match
    const finding: NormalizedFinding = {
      ...createLodashFinding(['CVE-9999-0000']),
      title: 'General flaw in lodash',
      description: 'An unspecified flaw was discovered in the library',
    };

    const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
    expect(res.verdict).toBe('REACHABLE_IMPORT');
    expect(res.evidence.kind).toBe('PACKAGE_IMPORTED');
    expect(res.evidence.notes).toContain('symbol data unavailable');
  });

  it('R2: blocks pruning with USAGE_INCOMPLETE if any non-test source file failed extraction', async () => {
    const dir = createBaseProject('r2-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `import _ from 'lodash';\n_.isEqual(1, 1);`
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    // Simulate an incomplete file in production scope
    const node = Array.from(graph.files.values())[0]!;
    node.symbolUsage = {
      filePath: node.filePath,
      relativePath: node.relativePath,
      bindings: [],
      usageFacts: [],
      escapes: [],
      hasCreateRequire: false,
      usageIncomplete: true,
      incompleteReason: 'Simulated parser crash',
    };

    const res = ScaReachabilityAnalyzer.analyze(createLodashFinding(), graph, lockfile, dir);
    expect(res.verdict).toBe('REACHABLE_IMPORT');
    expect(res.evidence.blockedBy).toBe('USAGE_INCOMPLETE');
  });

  it('R3: upgrades to REACHABLE_CALL_PATH / SYMBOL_CALL_PATH when call path is proven from entrypoint', async () => {
    const dir = createBaseProject('r3-proven-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `
import _ from 'lodash';
export function render(tpl) {
  return _.template(tpl)();
}
render("hello");
`
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    const res = ScaReachabilityAnalyzer.analyze(createLodashFinding(), graph, lockfile, dir);
    expect(res.verdict).toBe('REACHABLE_CALL_PATH');
    expect(res.evidence.kind).toBe('SYMBOL_CALL_PATH');
    expect(res.analysisConfidence).toBe('HIGH');
    expect(res.evidence.symbols).toContain('template');
  });

  it('R3: sets REACHABLE_IMPORT / SYMBOL_REFERENCED when symbol is referenced but call path is unproven', async () => {
    const dir = createBaseProject('r3-unproven-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `
import _ from 'lodash';
// Uninvoked non-exported helper function
function unusedRenderer(tpl) {
  return _.template(tpl)();
}
export function main() {
  console.log("main running");
}
main();
`
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    const res = ScaReachabilityAnalyzer.analyze(createLodashFinding(), graph, lockfile, dir);
    expect(res.verdict).toBe('REACHABLE_IMPORT');
    expect(res.evidence.kind).toBe('SYMBOL_REFERENCED');
    expect(res.analysisConfidence).toBe('HIGH');
    expect(res.evidence.symbols).toContain('template');
  });

  it('R4: sets REACHABLE_IMPORT with NAMESPACE_ESCAPES and MEDIUM confidence on namespace escape', async () => {
    const dir = createBaseProject('r4-escape-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `
import _ from 'lodash';
// Only calls isEqual, but passes _ to external helper (escape)
function run() {
  _.isEqual(1, 1);
  externalHelper(_);
}
run();
`
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    const res = ScaReachabilityAnalyzer.analyze(createLodashFinding(), graph, lockfile, dir);
    expect(res.verdict).toBe('REACHABLE_IMPORT');
    expect(res.evidence.kind).toBe('NAMESPACE_ESCAPES');
    expect(res.analysisConfidence).toBe('MEDIUM');
  });

  it('R5 Success: prunes to UNREACHABLE / UNINVOKED_SYMBOL with HIGH confidence when only non-vulnerable symbols used and all P1-P10 hold', async () => {
    const dir = createBaseProject('r5-success-test');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `
import _ from 'lodash';
// Calls only isEqual, never template
export function main() {
  return _.isEqual({ a: 1 }, { a: 1 });
}
main();
`
    );

    // Ensure node_modules exists so bin check passes
    fs.mkdirSync(path.join(dir, 'node_modules', 'lodash'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'node_modules', 'lodash', 'package.json'),
      JSON.stringify({ name: 'lodash', version: '4.17.20' })
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    const res = ScaReachabilityAnalyzer.analyze(createLodashFinding(), graph, lockfile, dir);
    expect(res.verdict).toBe('UNREACHABLE');
    expect(res.evidence.kind).toBe('UNINVOKED_SYMBOL');
    expect(res.analysisConfidence).toBe('HIGH');
    expect(res.evidence.symbols).toContain('template');
    expect(res.limitations[0]).toContain('static first-party analysis only');
  });

  it('R5 Precondition Breaks: tests P1 to P10 individually', async () => {
    // 1. Break P2: parse error in non-test source file
    const dirP2 = createBaseProject('p2-break');
    fs.writeFileSync(
      path.join(dirP2, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1);`
    );
    fs.writeFileSync(path.join(dirP2, 'src', 'broken.js'), `function broken( { syntax error!`);

    const graphP2 = await ImportGraph.build(dirP2, { noCache: true });
    const lockfileP2 = getLockGraph(dirP2);
    const resP2 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP2,
      lockfileP2,
      dirP2
    );
    expect(resP2.verdict).toBe('REACHABLE_IMPORT');
    expect(resP2.evidence.blockedBy).toBe('PARSE_ERROR');

    // 2. Break P3: dynamic import outside tests
    const dirP3 = createBaseProject('p3-break');
    fs.writeFileSync(
      path.join(dirP3, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1); eval("1+1");`
    );
    const graphP3 = await ImportGraph.build(dirP3, { noCache: true });
    const lockfileP3 = getLockGraph(dirP3);
    const resP3 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP3,
      lockfileP3,
      dirP3
    );
    expect(resP3.verdict).toBe('REACHABLE_IMPORT');
    expect(resP3.evidence.blockedBy).toBe('DYNAMIC_IMPORT');

    // 3. Break P4: reference in build script/config
    const dirP4 = createBaseProject('p4-break');
    fs.writeFileSync(
      path.join(dirP4, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1);`
    );
    fs.writeFileSync(path.join(dirP4, 'Dockerfile'), `FROM node:18\nRUN npm install lodash\n`);
    const graphP4 = await ImportGraph.build(dirP4, { noCache: true });
    const lockfileP4 = getLockGraph(dirP4);
    const resP4 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP4,
      lockfileP4,
      dirP4
    );
    expect(resP4.verdict).toBe('REACHABLE_IMPORT');
    expect(resP4.evidence.blockedBy).toBe('CONFIG_REFERENCE');

    // 4. Break P5: package has dependents in lockfile
    const dirP5 = createBaseProject('p5-break');
    fs.writeFileSync(
      path.join(dirP5, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1);`
    );
    // Add another package depending on lodash
    fs.writeFileSync(
      path.join(dirP5, 'package-lock.json'),
      JSON.stringify({
        name: 'p5-break',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.20', 'dep-a': '^1.0.0' } },
          'node_modules/lodash': { version: '4.17.20' },
          'node_modules/dep-a': {
            version: '1.0.0',
            dependencies: { lodash: '^4.17.20' },
          },
        },
      })
    );
    const graphP5 = await ImportGraph.build(dirP5, { noCache: true });
    const lockfileP5 = getLockGraph(dirP5);
    const resP5 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP5,
      lockfileP5,
      dirP5
    );
    expect(resP5.verdict).toBe('REACHABLE_IMPORT');
    expect(resP5.evidence.blockedBy).toBe('NOT_LEAF_PACKAGE');

    // 5. Break P10: package aliased in package.json
    const dirP10 = createBaseProject('p10-break');
    fs.writeFileSync(
      path.join(dirP10, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1);`
    );
    fs.writeFileSync(
      path.join(dirP10, 'package.json'),
      JSON.stringify({
        name: 'p10-break',
        main: 'src/index.js',
        dependencies: {
          lodash: '^4.17.20',
          'my-alias': 'npm:lodash@^4.17.20',
        },
      })
    );
    const graphP10 = await ImportGraph.build(dirP10, { noCache: true });
    const lockfileP10 = getLockGraph(dirP10);
    const resP10 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP10,
      lockfileP10,
      dirP10
    );
    expect(resP10.verdict).toBe('REACHABLE_IMPORT');
    expect(resP10.evidence.blockedBy).toBe('ALIASED_PACKAGE');
    // 6. Break P1: entrypoint resolution error
    const dirP1 = createBaseProject('p1-break');
    fs.writeFileSync(
      path.join(dirP1, 'src', 'index.js'),
      `import _ from 'lodash'; _.isEqual(1, 1);`
    );
    const graphP1 = await ImportGraph.build(dirP1, { noCache: true });
    graphP1.unresolvedImports.push({
      fromFile: 'entrypoints',
      specifier: 'src/missing-entrypoint.js',
      reason: 'Could not resolve entrypoint',
    });
    const lockfileP1 = getLockGraph(dirP1);
    const resP1 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP1,
      lockfileP1,
      dirP1
    );
    expect(resP1.verdict).toBe('REACHABLE_IMPORT');
    expect(resP1.evidence.blockedBy).toBe('NO_ENTRYPOINT');
  });

  it('P6 & P9 Confidence: caps confidence at MEDIUM when bin is unknown or ecosystem is Python', async () => {
    // P6: Bin unknown (no node_modules directory created)
    const dirP6 = createBaseProject('p6-confidence');
    fs.writeFileSync(
      path.join(dirP6, 'src', 'index.js'),
      `import _ from 'lodash'; export function main() { return _.isEqual(1, 1); } main();`
    );
    // Lockfile without lodash node (so bin is unknown)
    fs.writeFileSync(
      path.join(dirP6, 'package-lock.json'),
      JSON.stringify({
        name: 'p6-confidence',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.20' } },
        },
      })
    );
    const graphP6 = await ImportGraph.build(dirP6, { noCache: true });
    const lockfileP6 = getLockGraph(dirP6);
    const resP6 = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graphP6,
      lockfileP6,
      dirP6
    );
    expect(resP6.verdict).toBe('UNREACHABLE');
    expect(resP6.analysisConfidence).toBe('MEDIUM'); // Capped by P6

    // P9: Python ecosystem capped at MEDIUM
    const dirP9 = path.join(os.tmpdir(), `p9-test-${Date.now()}`);
    fs.mkdirSync(dirP9, { recursive: true });
    fs.writeFileSync(
      path.join(dirP9, 'main.py'),
      `import yaml\ndef main():\n    return yaml.safe_load("foo: bar")\nmain()\n`
    );
    fs.writeFileSync(
      path.join(dirP9, 'poetry.lock'),
      `[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n`
    );
    const graphP9 = await ImportGraph.build(dirP9, { noCache: true });
    const lockfileP9 = getLockGraph(dirP9);
    const pyFinding: NormalizedFinding = {
      id: 'FINDING-PY',
      fingerprint: 'b'.repeat(64),
      ruleId: 'SEC-102',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      location: { filePath: 'poetry.lock', startLine: 1, endLine: 1 },
      title: 'Arbitrary Code Execution in PyYAML load',
      description: 'PyYAML load function is vulnerable to Arbitrary Code Execution',
      cweIds: [],
      evidence: [],
      createdAt: new Date().toISOString(),
      package: {
        name: 'pyyaml',
        version: '5.3.1',
        ecosystem: 'pypi',
      },
      aliases: ['CVE-2020-14343'],
    };
    const resP9 = ScaReachabilityAnalyzer.analyze(pyFinding, graphP9, lockfileP9, dirP9);
    expect(resP9.verdict).toBe('UNREACHABLE');
    expect(resP9.analysisConfidence).toBe('MEDIUM'); // Capped by P9
  });

  it('P8 Confidence: caps confidence at LOW for heuristic text candidates', async () => {
    const dir = createBaseProject('p8-heuristic');
    fs.writeFileSync(
      path.join(dir, 'src', 'index.js'),
      `import _ from 'lodash'; export function main() { return _.isEqual(1, 1); } main();`
    );
    fs.mkdirSync(path.join(dir, 'node_modules', 'lodash'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'node_modules', 'lodash', 'package.json'),
      JSON.stringify({ name: 'lodash', version: '4.17.20' })
    );

    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    // Heuristic candidate from title regex: lodash.customFunc()
    const heuristicFinding: NormalizedFinding = {
      id: 'FINDING-HEURISTIC',
      fingerprint: 'c'.repeat(64),
      ruleId: 'SEC-103',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      title: 'Vulnerability in lodash.customFunc()',
      description: 'Calling lodash.customFunc() causes a memory corruption',
      cweIds: [],
      evidence: [],
      createdAt: new Date().toISOString(),
      package: {
        name: 'lodash',
        version: '4.17.20',
        ecosystem: 'npm',
      },
      aliases: ['CVE-1999-99999'], // No curated DB entry
    };

    const res = ScaReachabilityAnalyzer.analyze(heuristicFinding, graph, lockfile, dir);
    expect(res.verdict).toBe('UNREACHABLE');
    expect(res.analysisConfidence).toBe('LOW'); // Heuristic candidates are LOW forever
    expect(res.evidence.symbolSource).toBe('HEURISTIC_TEXT');
  });

  it('R6: keeps exact existing logic for transitive packages and disabled feature', async () => {
    const dir = createBaseProject('r6-test');
    fs.writeFileSync(path.join(dir, 'src', 'index.js'), `import _ from 'lodash'; _.isEqual(1, 1);`);
    const graph = await ImportGraph.build(dir, { noCache: true });
    const lockfile = getLockGraph(dir);

    // Feature disabled via options
    const disabledRes = ScaReachabilityAnalyzer.analyze(
      createLodashFinding(),
      graph,
      lockfile,
      dir,
      {
        functionLevel: false,
      }
    );
    expect(disabledRes.verdict).toBe('REACHABLE_IMPORT');
    expect(disabledRes.evidence.kind).toBe('PACKAGE_IMPORTED');
    expect(disabledRes.evidence.blockedBy).toBeUndefined();
  });
});
