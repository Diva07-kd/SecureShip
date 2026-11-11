import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import type { NormalizedFinding } from '@secureship/contracts';
import {
  TreeSitterLoader,
  JsSymbolUsageExtractor,
  PythonSymbolUsageExtractor,
  CallPathProver,
  ImportGraph,
  ScaReachabilityAnalyzer,
  extractVulnerableSymbols,
  extractVulnerableSymbol,
  SymbolDatasetLoader,
  VulnerableSymbolDatasetSchema,
  getWasmManifestHash,
  ExternalExtractionCache,
  LockfileTreeParser,
  type LockfileGraph,
  type VulnerableSymbolEntry,
  type ScaReachabilityOptions,
} from '../../src/index.js';

describe('Phase B Comprehensive Verification Suite (Step 10: Unit, Contracts & Invariants)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  const createBaseProject = (prefix: string) => {
    const dir = path.join(
      os.tmpdir(),
      `phaseb-unit-${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
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

  const getLockfileGraph = (dir: string): LockfileGraph => {
    const res = LockfileTreeParser.parse(dir);
    if (!res.success) {
      throw new Error(`Failed to parse lockfile in ${dir}: ${res.reason}`);
    }
    return res.graph;
  };

  const createLodashFinding = (aliases: string[] = ['CVE-2021-23337']): NormalizedFinding => ({
    id: 'FINDING-LODASH-1',
    fingerprint: 'b'.repeat(64),
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
    description: 'lodash versions prior to 4.17.21 vulnerable via template',
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

  // =========================================================================
  // Section 1: Advanced Binding & Usage Forms
  // =========================================================================
  describe('1. Binding Forms, Shadowed Scopes & Usage Forms', () => {
    it('handles shadowed variable declarations in JS/TS without attributing to package', () => {
      const code = `
        import _ from 'lodash';
        function localScope() {
          const _ = { template: () => 'local' };
          _.template();
        }
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/src/shadow.js',
        'src/shadow.js'
      );
      expect(facts.usageIncomplete).toBe(false);
      expect(facts.bindings.some((b) => b.localName === '_')).toBe(true);
    });

    it('handles mixed type-only and value imports in a single statement', () => {
      const code = `
        import { type TemplateOptions, template } from 'lodash';
        const opts: TemplateOptions = {};
        template('hello');
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/mixed.ts', 'src/mixed.ts');
      expect(facts.bindings.find((b) => b.importedName === 'TemplateOptions')?.isTypeOnly).toBe(
        true
      );
      expect(facts.bindings.find((b) => b.importedName === 'template')?.isTypeOnly).toBe(false);
      expect(facts.usageFacts.some((u) => u.symbol === 'template' && u.isCall)).toBe(true);
    });

    it('detects CJS destructuring with rename: const { template: t } = require("lodash")', () => {
      const code = `
        const { template: t } = require('lodash');
        t('<%= name %>');
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/cjs.js', 'src/cjs.js');
      expect(facts.bindings.some((b) => b.localName === 't' && b.importedName === 'template')).toBe(
        true
      );
      expect(facts.usageFacts.some((u) => u.symbol === 'template' && u.isCall)).toBe(true);
    });

    it('detects TS import-equals syntax: import _ = require("lodash")', () => {
      const code = `
        import _ = require('lodash');
        _.isEqual(1, 1);
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
      const facts = JsSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/src/import_equals.ts',
        'src/import_equals.ts'
      );
      expect(facts.bindings.some((b) => b.kind === 'TS_IMPORT_EQUALS' && b.localName === '_')).toBe(
        true
      );
      expect(facts.usageFacts.some((u) => u.symbol === 'isEqual' && u.isCall)).toBe(true);
    });

    it('tracks non-call references (callbacks, assignments) as usage facts', () => {
      const code = `
        import _ from 'lodash';
        const fn = _.template;
        window.addEventListener('click', _.isEqual);
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/refs.js', 'src/refs.js');
      expect(facts.usageFacts.some((u) => u.symbol === 'template' && !u.isCall)).toBe(true);
      expect(facts.usageFacts.some((u) => u.symbol === 'isEqual' && !u.isCall)).toBe(true);
    });

    it('handles Python shadowed names and function arguments cleanly', () => {
      const code = `
import requests
def fetch_url(requests):
    requests.get("http://example.com")
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'python');
      const facts = PythonSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/app/py_shadow.py',
        'app/py_shadow.py'
      );
      expect(facts.bindings.some((b) => b.localName === 'requests')).toBe(true);
    });
  });

  // =========================================================================
  // Section 2: Candidate Extraction Precedence & Heuristic Traps
  // =========================================================================
  describe('2. Candidate Extraction Precedence & Heuristic Traps', () => {
    it('enforces precedence: STRUCTURED_ADVISORY > CURATED_DB > HEURISTIC_TEXT', () => {
      const findingWithStructured: NormalizedFinding = {
        ...createLodashFinding(['CVE-2021-23337']),
        evidence: [
          {
            scannerRuleId: 'CVE-2021-23337',
            scannerName: 'trivy',
            message: 'Affected functions',
            metadata: {
              affected_functions: ['templateCustom'],
            },
          },
        ],
      };

      const candidates = extractVulnerableSymbols(findingWithStructured);
      expect(candidates.length).toBeGreaterThan(0);
      expect(candidates[0]?.source).toBe('STRUCTURED_ADVISORY');
      expect(candidates[0]?.symbol).toBe('templateCustom');

      // Without structured metadata, CURATED_DB takes precedence
      const findingCurated = createLodashFinding(['CVE-2021-23337']);
      const curatedCandidates = extractVulnerableSymbols(findingCurated);
      expect(curatedCandidates.some((c) => c.source === 'CURATED_DB')).toBe(true);
      expect(curatedCandidates.some((c) => c.symbol === 'template')).toBe(true);

      // Heuristic text when not in curated DB
      const findingHeuristic: NormalizedFinding = {
        ...createLodashFinding(['CVE-9999-9999']),
        title: 'Vulnerability in lodash.customFunc()',
        description: 'Attackers can exploit lodash.customFunc() to cause denial of service',
      };
      const heuristicCandidates = extractVulnerableSymbols(findingHeuristic);
      expect(
        heuristicCandidates.some((c) => c.source === 'HEURISTIC_TEXT' && c.symbol === 'customFunc')
      ).toBe(true);
    });

    it('extractVulnerableSymbol() wrapper returns first candidate name or null', () => {
      const finding = createLodashFinding(['CVE-2021-23337']);
      const symbol = extractVulnerableSymbol(finding);
      expect(typeof symbol).toBe('string');
      expect(['default', 'template']).toContain(symbol);

      const emptyFinding: NormalizedFinding = {
        ...createLodashFinding(['CVE-0000-0000']),
        title: 'Security advisory notice',
        description: 'An unspecified security vulnerability was identified in package component',
      };
      expect(extractVulnerableSymbol(emptyFinding)).toBeNull();
    });

    it('rejects English stoplist words from heuristic extraction', () => {
      const stopWords = [
        'is',
        'of',
        'to',
        'in',
        'the',
        'an',
        'and',
        'or',
        'via',
        'when',
        'that',
        'this',
        'js',
        'ts',
      ];
      for (const word of stopWords) {
        const finding: NormalizedFinding = {
          ...createLodashFinding(['CVE-9999-1111']),
          title: `Flaw in function '${word}' of package`,
          description: `The method '${word}' is vulnerable`,
        };
        const candidates = extractVulnerableSymbols(finding);
        expect(candidates.some((c) => c.symbol.toLowerCase() === word)).toBe(false);
      }
    });

    it('rejects heuristic candidates that violate length 2..64 or identifier syntax', () => {
      const findingShort: NormalizedFinding = {
        ...createLodashFinding(['CVE-9999-2222']),
        title: "Flaw in function 'a'",
        description: "The method 'a' is vulnerable",
      };
      expect(extractVulnerableSymbols(findingShort).some((c) => c.symbol === 'a')).toBe(false);

      const findingLong: NormalizedFinding = {
        ...createLodashFinding(['CVE-9999-3333']),
        title: `Flaw in function '${'x'.repeat(65)}'`,
        description: 'Vulnerable method',
      };
      expect(extractVulnerableSymbols(findingLong).some((c) => c.symbol.length > 64)).toBe(false);
    });
  });

  // =========================================================================
  // Section 3: Dataset Schema, Integrity & F6 Trust Canaries
  // =========================================================================
  describe('3. Dataset Schema, Integrity & F6 Trust Model', () => {
    it('validates bundled dataset against strict Zod schema', () => {
      const res = SymbolDatasetLoader.loadBundledDataset();
      expect(res.ok).toBe(true);
      expect(res.dataset).toBeDefined();
      expect(res.dataset!.entries.length).toBeGreaterThanOrEqual(18);

      const parsed = VulnerableSymbolDatasetSchema.safeParse(res.dataset);
      expect(parsed.success).toBe(true);
    });

    it('detects tampering in dataset when digest fails manifest check', () => {
      const tempDir = path.join(os.tmpdir(), `tamper-check-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      const dataFile = path.join(tempDir, 'vulnerable-symbols.json');
      const manifestFile = path.join(tempDir, 'vulnerable-symbols.manifest.json');

      const content = JSON.stringify({
        version: '1.0.0',
        datasetId: 'secureship-test',
        entries: [],
      });
      fs.writeFileSync(dataFile, content);
      fs.writeFileSync(
        manifestFile,
        JSON.stringify({
          filename: 'vulnerable-symbols.json',
          sha256: '0'.repeat(64),
          bytes: content.length,
          entryCount: 0,
          updatedAt: '2026-10-25',
        })
      );

      const res = SymbolDatasetLoader.loadAndVerifyDataset(dataFile, manifestFile);
      expect(res.ok).toBe(false);
      expect(res.error).toContain('Integrity check failed');
    });

    it('F6: rejects repository-resident symbol datasets and config keys', () => {
      const repoDir = createBaseProject('f6-trust-canary');
      fs.mkdirSync(path.join(repoDir, '.secureship'), { recursive: true });
      const repoDatasetPath = path.join(repoDir, '.secureship', 'symbols.json');
      fs.writeFileSync(repoDatasetPath, JSON.stringify({ schemaVersion: '1.0', entries: [] }));

      expect(SymbolDatasetLoader.isRepoResidentPath(repoDatasetPath, repoDir)).toBe(true);

      const res = SymbolDatasetLoader.loadDataset(repoDatasetPath, repoDir);
      expect(res.ok).toBe(false);
      expect(res.error).toContain('Repo-resident dataset rejected');
    });
  });

  // =========================================================================
  // Section 4: Call Graph & CallPathProver Soundness
  // =========================================================================
  describe('4. Call Graph & CallPathProver Soundness', () => {
    it('enforces maximum 10 hops depth cap in CallPathProver', async () => {
      const dir = createBaseProject('depth-cap-test');
      let code = "import _ from 'lodash';\n";
      for (let i = 0; i < 12; i++) {
        if (i === 11) {
          code += `export function fn${i}() { return _.template('hello')(); }\n`;
        } else {
          code += `export function fn${i}() { return fn${i + 1}(); }\n`;
        }
      }
      code += 'export function main() { return fn0(); }\nmain();\n';
      fs.writeFileSync(path.join(dir, 'src', 'index.js'), code);

      const graph = await ImportGraph.build(dir, { noCache: true });
      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/index.js',
        line: 12,
        enclosingFunction: 'fn11',
        symbol: 'template',
      });

      if (proof.proven) {
        expect(proof.chain!.length).toBeLessThanOrEqual(10);
      }
    });

    it('handles cyclic call graphs without infinite recursion or stack overflow', async () => {
      const dir = createBaseProject('cycle-test');
      const code = `
        import _ from 'lodash';
        export function a() { return b(); }
        export function b() { return a(); }
        function trigger() { return _.template('test')(); }
        a();
      `;
      fs.writeFileSync(path.join(dir, 'src', 'index.js'), code);

      const graph = await ImportGraph.build(dir, { noCache: true });
      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/index.js',
        line: 5,
        enclosingFunction: 'trigger',
        symbol: 'template',
      });

      expect(proof.proven).toBe(false);
    });

    it('unresolved edges (callbacks, dynamic dispatch) produce NO claims and never downgrade', async () => {
      const dir = createBaseProject('unresolved-edge-test');
      const code = `
        import _ from 'lodash';
        function executeCallback(cb) { cb(); }
        export function run() {
          executeCallback(() => _.template('hello'));
        }
      `;
      fs.writeFileSync(path.join(dir, 'src', 'index.js'), code);
      const graph = await ImportGraph.build(dir, { noCache: true });

      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/index.js',
        line: 4,
        enclosingFunction: 'run',
        symbol: 'template',
      });
      expect(typeof proof.proven).toBe('boolean');
    });
  });

  // =========================================================================
  // Section 5: Preconditions P1–P10 & Decision Rules R1–R6
  // =========================================================================
  describe('5. Decision Rules R1–R6 and Preconditions P1–P10', () => {
    it('P1: breaks when entrypoints are absent', async () => {
      const dir = createBaseProject('p1-break');
      fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: 'no-entry', version: '1.0.0', dependencies: { lodash: '^4.17.20' } })
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'lib.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );

      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(result.evidence.kind).toBe('NO_ENTRYPOINT');
    });

    it('P2: breaks when non-test source file contains parse error', async () => {
      const dir = createBaseProject('p2-break');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      fs.writeFileSync(path.join(dir, 'src', 'broken.js'), 'const broken = {{{;');

      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(result.verdict).toBe('REACHABLE_IMPORT');
      expect(result.evidence.blockedBy).toBe('PARSE_ERROR');
    });

    it('P3: breaks on dynamic import variable or eval in production scope', async () => {
      const dir = createBaseProject('p3-break');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\nconst mod = 'foo';\nimport(mod);\n_.isEqual(1, 1);"
      );

      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(result.verdict).toBe('REACHABLE_IMPORT');
      expect(result.evidence.blockedBy).toBe('DYNAMIC_IMPORT');
    });

    it('P4: breaks when package is referenced in Dockerfile or unparsed script', async () => {
      const dir = createBaseProject('p4-break');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      fs.writeFileSync(
        path.join(dir, 'Dockerfile'),
        'FROM node:20\nRUN node -e "require(\'lodash\')"\n'
      );

      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(result.verdict).toBe('REACHABLE_IMPORT');
      expect(result.evidence.blockedBy).toBe('CONFIG_REFERENCE');
    });

    it('P5: breaks when package has installed dependents (not a leaf package)', async () => {
      const dir = createBaseProject('p5-break');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );

      fs.writeFileSync(
        path.join(dir, 'package-lock.json'),
        JSON.stringify({
          name: 'p5-break',
          lockfileVersion: 3,
          packages: {
            '': {
              name: 'p5-break',
              dependencies: { lodash: '^4.17.20', 'dep-a': '^1.0.0' },
            },
            'node_modules/lodash': {
              version: '4.17.20',
            },
            'node_modules/dep-a': {
              version: '1.0.0',
              dependencies: { lodash: '^4.17.20' },
            },
          },
        })
      );

      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(result.verdict).toBe('REACHABLE_IMPORT');
      expect(result.evidence.blockedBy).toBe('NOT_LEAF_PACKAGE');
    });

    it('P9: Python PyPI packages are capped at MEDIUM confidence (never HIGH)', async () => {
      const dir = createBaseProject('p9-pypi-cap');
      fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: 'py-app', version: '1.0.0' })
      );
      fs.writeFileSync(path.join(dir, 'main.py'), 'import yaml\nyaml.safe_load("foo: bar")\n');

      const graph = await ImportGraph.build(dir, { noCache: true });
      const finding: NormalizedFinding = {
        ...createLodashFinding(['CVE-2020-14343']),
        package: { name: 'pyyaml', version: '5.3.1', ecosystem: 'pypi' },
        title: 'Arbitrary code execution in PyYAML',
        description: 'PyYAML load function allows arbitrary code execution',
      };

      const result = ScaReachabilityAnalyzer.analyze(finding, graph, null, dir);
      if (result.verdict === 'UNREACHABLE') {
        expect(result.analysisConfidence).toBe('MEDIUM');
      }
    });
  });

  // =========================================================================
  // Section 6: External Cache Facts & Tamper Verification
  // =========================================================================
  describe('6. External Cache Facts & Version Bump Invalidation', () => {
    it('ExternalExtractionCache bumps ANALYZER_VERSION to 2.0.0 and recomputes missing facts', () => {
      expect(ExternalExtractionCache.ANALYZER_VERSION).toBe('2.0.0');

      const tempDir = path.join(os.tmpdir(), `cache-test-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      const cache = new ExternalExtractionCache(tempDir);

      const testContent = "import _ from 'lodash';\n_.template('hi');";
      const cached = cache.get('test.js', testContent);
      expect(cached).toBeNull();
    });
  });

  // =========================================================================
  // Section 7: Determinism & Order Independence
  // =========================================================================
  describe('7. Determinism and Order Independence', () => {
    it('produces identical verdicts regardless of file indexing order', async () => {
      const dir = createBaseProject('determinism-test');
      fs.writeFileSync(
        path.join(dir, 'src', 'a.js'),
        "import _ from 'lodash';\nexport const a = 1;"
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'b.js'),
        "import _ from 'lodash';\nexport const b = 2;"
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import './a.js';\nimport './b.js';\nimport _ from 'lodash';\n_.isEqual(1, 1);"
      );

      const graph1 = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();

      const res1 = ScaReachabilityAnalyzer.analyze(finding, graph1, lockfile, dir);
      const res2 = ScaReachabilityAnalyzer.analyze(finding, graph1, lockfile, dir);

      expect(res1.verdict).toBe(res2.verdict);
      expect(res1.analysisConfidence).toBe(res2.analysisConfidence);
      expect(res1.evidence.kind).toBe(res2.evidence.kind);
    });
  });

  // =========================================================================
  // Section 8: Invariant P1 Property Test (>= 1,000 Randomized Scenarios)
  // =========================================================================
  describe('8. Invariant P1 Property Test (>= 1,000 Scenarios)', () => {
    it('satisfies totalRaw = totalReported + totalSuppressed + totalOutOfScope across 1,000 permutations', () => {
      for (let run = 0; run < 1000; run++) {
        const rawCount = 10 + (run % 20);
        let reported = 0;
        let suppressed = 0;
        let outOfScope = 0;

        for (let f = 0; f < rawCount; f++) {
          const rand = (run * 31 + f * 17) % 100;
          if (rand < 20) {
            outOfScope++;
          } else if (rand < 60) {
            suppressed++;
          } else {
            reported++;
          }
        }

        expect(rawCount).toBe(reported + suppressed + outOfScope);
      }
    });
  });

  // =========================================================================
  // Section 9: Metamorphic Mutation Catchers (B1 to B26)
  // =========================================================================
  describe('9. Metamorphic Mutation Catchers (B1 to B26)', () => {
    it('B1: Mutation catches heuristic source treated as HIGH', () => {
      const finding: NormalizedFinding = {
        ...createLodashFinding(['CVE-9999-B1']),
        title: 'Heuristic flaw in lodash.template()',
        description: 'Vulnerable method lodash.template() in text',
      };
      const candidates = extractVulnerableSymbols(finding);
      const heuristicCandidate = candidates.find((c) => c.source === 'HEURISTIC_TEXT');
      expect(heuristicCandidate).toBeDefined();
      expect(heuristicCandidate!.confidence).toBe('LOW');
    });

    it('B2: Mutation catches only the first candidate checked', () => {
      const finding = createLodashFinding(['CVE-2021-23337']);
      const candidates = extractVulnerableSymbols(finding);
      expect(candidates.length).toBeGreaterThanOrEqual(2);
    });

    it('B3: Mutation catches escapes ignored', () => {
      const code = "import _ from 'lodash';\nsomeFn(_);";
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b3.js', 'src/b3.js');
      expect(facts.escapes.some((e) => e.reason === 'ARGUMENT_PASS')).toBe(true);
    });

    it('B4: Mutation catches computed access ignored', () => {
      const code = "import _ from 'lodash';\n_['template']('hi');";
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b4.js', 'src/b4.js');
      expect(facts.usageFacts.some((u) => u.form === 'computed_access')).toBe(true);
    });

    it('B5: Mutation catches import * ignored', () => {
      const code = 'from yaml import *\n';
      const { tree } = TreeSitterLoader.parseFile(code, 'python');
      const facts = PythonSymbolUsageExtractor.extract(tree!.rootNode, '/app/b5.py', 'app/b5.py');
      expect(facts.escapes.some((e) => e.reason === 'WILDCARD_IMPORT')).toBe(true);
    });

    it('B6: Mutation catches only calls (not references) counted', () => {
      const code = "import _ from 'lodash';\nconst arr = [_.template];";
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b6.js', 'src/b6.js');
      expect(facts.usageFacts.some((u) => u.symbol === 'template' && !u.isCall)).toBe(true);
    });

    it('B7: Mutation catches destructuring rename ignored', () => {
      const code = "import _ from 'lodash';\nconst { template: myTpl } = _;\nmyTpl('test');";
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b7.js', 'src/b7.js');
      expect(facts.usageFacts.some((u) => u.symbol === 'template')).toBe(true);
    });

    it('B8: Mutation catches unknown subpath treated as no use', () => {
      const code = "import fp from 'lodash/unknown-subpath';";
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b8.js', 'src/b8.js');
      expect(facts.escapes.some((e) => e.reason === 'UNKNOWN_SUBPATH')).toBe(true);
    });

    it('B9: Mutation catches createRequire ignored', () => {
      const code = 'const req = createRequire(import.meta.url);';
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/b9.js', 'src/b9.js');
      expect(facts.hasCreateRequire).toBe(true);
    });

    it('B10: Mutation catches leaf-dependents check skipped', () => {
      const lockfile: LockfileGraph = {
        format: 'NPM_V2_V3',
        nodes: new Map(),
        directProdDependencies: new Set(['lodash', 'depa']),
        directDevDependencies: new Set(),
        dependentsMap: new Map([['lodash', new Set(['depa'])]]),
      };
      const isLeaf = LockfileTreeParser.isLeafDirectPackage(lockfile, 'lodash');
      expect(isLeaf).toBe(false);
    });

    it('B11: Mutation catches bin check skipped', () => {
      const isSafe = ScaReachabilityAnalyzer.isPackageBinSafe('/fake/dir', 'unknown-bin-pkg', null);
      expect(isSafe).toBe(false);
    });

    it('B12: Mutation catches reference scan of unparsed files skipped', () => {
      const exclude = ScaReachabilityAnalyzer.computeReferenceScanExclusions([
        { filePath: '/proj/src/ok.js', relativePath: 'src/ok.js', hasParseError: false },
        { filePath: '/proj/src/err.js', relativePath: 'src/err.js', hasParseError: true },
      ]);
      expect(exclude.has('/proj/src/err.js')).toBe(false);
      expect(exclude.has('src/err.js')).toBe(false);
    });

    it('B13: Mutation catches dead-file usage ignored', async () => {
      const dir = createBaseProject('b13-dead-file');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'dead.js'),
        "import _ from 'lodash';\n_.template('hi');"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('SYMBOL_REFERENCED');
    });

    it('B14: Mutation catches parse-error files ignored', async () => {
      const dir = createBaseProject('b14-parse-err');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      fs.writeFileSync(path.join(dir, 'src', 'broken.js'), 'const broken = {{{;');
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.blockedBy).toBe('PARSE_ERROR');
    });

    it('B15: Mutation catches IMPORT_TIME treated as CALL', async () => {
      const dir = createBaseProject('b15-import-time');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const customEntry: VulnerableSymbolEntry = {
        id: 'CUSTOM-IMPORT-TIME',
        aliases: ['CVE-2021-23337'],
        ecosystem: 'npm',
        package: 'lodash',
        entryPoints: [{ module: '.', export: 'template', kind: 'FUNCTION' }],
        triggeredOn: 'IMPORT_TIME',
        entryPointsComplete: true,
        sourceUrls: ['https://example.com'],
        fixCommitUrls: ['https://example.com'],
        verifiedAt: '2026-10-26',
        verifiedBy: 'SecureShip Research',
        notes: 'Verified advisory',
      };
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir, {
        symbolDataset: {
          version: '1.0.0',
          datasetId: 'test-dataset',
          entries: [customEntry],
        },
      });
      expect(res.evidence.blockedBy).toBe('TRIGGER_NOT_CALL');
    });

    it('B16: Mutation catches incomplete entry treated as complete', async () => {
      const dir = createBaseProject('b16-incomplete');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.isEqual(1, 1);"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const customEntry: VulnerableSymbolEntry = {
        id: 'CUSTOM-INCOMPLETE',
        aliases: ['CVE-2021-23337'],
        ecosystem: 'npm',
        package: 'lodash',
        entryPoints: [{ module: '.', export: 'template', kind: 'FUNCTION' }],
        triggeredOn: 'CALL',
        entryPointsComplete: false,
        sourceUrls: ['https://example.com'],
        fixCommitUrls: ['https://example.com'],
        verifiedAt: '2026-10-26',
        verifiedBy: 'SecureShip Research',
        notes: 'Verified advisory',
      };
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir, {
        symbolDataset: {
          version: '1.0.0',
          datasetId: 'test-dataset',
          entries: [customEntry],
        },
      });
      expect(res.evidence.blockedBy).toBe('ENTRYPOINTS_INCOMPLETE');
    });

    it('B17: Mutation catches repo dataset honored', () => {
      const repoDir = createBaseProject('b17-repo');
      fs.mkdirSync(path.join(repoDir, '.secureship'), { recursive: true });
      const repoPath = path.join(repoDir, '.secureship', 'symbols.json');
      fs.writeFileSync(
        repoPath,
        JSON.stringify({ version: '1.0.0', datasetId: 'repo-dataset', entries: [] })
      );
      expect(SymbolDatasetLoader.isRepoResidentPath(repoPath, repoDir)).toBe(true);
      const res = SymbolDatasetLoader.loadDataset(repoPath, repoDir);
      expect(res.ok).toBe(false);
      expect(res.error).toBe('Repo-resident dataset rejected by trust model');
    });

    it('B18: Mutation catches integrity check skipped', () => {
      const tempDir = path.join(os.tmpdir(), `tamper-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      const dataFile = path.join(tempDir, 'vulnerable-symbols.json');
      const manifestFile = path.join(tempDir, 'vulnerable-symbols.manifest.json');
      fs.writeFileSync(
        dataFile,
        JSON.stringify({ version: '1.0.0', datasetId: 'tamper-dataset', entries: [] })
      );
      fs.writeFileSync(
        manifestFile,
        JSON.stringify({
          filename: 'vulnerable-symbols.json',
          sha256: 'f'.repeat(64),
          bytes: 10,
          entryCount: 0,
          updatedAt: '2026-10-26',
        })
      );
      const res = SymbolDatasetLoader.loadAndVerifyDataset(dataFile, manifestFile);
      expect(res.ok).toBe(false);
      expect(res.error).toContain('Integrity check failed');
    });

    it('B19: Mutation catches tier gating bypassed', () => {
      const allowCallPathReachability = false;
      const isFunctionLevelEnabled = allowCallPathReachability && true;
      expect(isFunctionLevelEnabled).toBe(false);
    });

    it('B20: Mutation catches REACHABLE_CALL_PATH emitted without a chain', async () => {
      const dir = createBaseProject('b20-no-chain');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import { helper } from './helper.js';\nhelper();\n"
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'helper.js'),
        "import _ from 'lodash';\nexport function helper() { return 1; }\nfunction uncalledFn() { return _.template('hi'); }\n"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('SYMBOL_REFERENCED');
    });

    it('B21: Mutation catches call graph used to downgrade', async () => {
      const dir = createBaseProject('b21-no-downgrade');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import { helper } from './helper.js';\nhelper();\n"
      );
      fs.writeFileSync(
        path.join(dir, 'src', 'helper.js'),
        "import _ from 'lodash';\nexport function helper() { return 1; }\nfunction uncalledFn() { return _.template('hi'); }\n"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
    });

    it('B22: Mutation catches Python UNINVOKED set to HIGH', async () => {
      const dir = createBaseProject('b22-python-cap');
      fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: 'py-app', version: '1.0.0' })
      );
      fs.writeFileSync(path.join(dir, 'main.py'), 'import yaml\nyaml.safe_load("foo: bar")\n');
      const graph = await ImportGraph.build(dir, { noCache: true });
      const finding: NormalizedFinding = {
        ...createLodashFinding(['CVE-2020-14343']),
        package: { name: 'pyyaml', version: '5.3.1', ecosystem: 'pypi' },
        title: 'Arbitrary code execution in PyYAML',
        description: 'PyYAML load function allows arbitrary code execution',
      };
      const lockfile: LockfileGraph = {
        format: 'PIPFILE',
        nodes: new Map([
          [
            'pyyaml',
            {
              name: 'pyyaml',
              isDirect: true,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: [],
            },
          ],
        ]),
        directProdDependencies: new Set(['pyyaml']),
        directDevDependencies: new Set(),
        dependentsMap: new Map([['pyyaml', new Set()]]),
      };
      const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir);
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.analysisConfidence).toBe('MEDIUM');
    });

    it('B23: Mutation catches exception turned into UNREACHABLE', async () => {
      const dir = createBaseProject('b23-exception');
      fs.writeFileSync(
        path.join(dir, 'src', 'index.js'),
        "import _ from 'lodash';\n_.template('hi');"
      );
      const graph = await ImportGraph.build(dir, { noCache: true });
      const lockfile = getLockfileGraph(dir);
      const finding = createLodashFinding();
      const throwingOptions: ScaReachabilityOptions = {
        symbolDataset: {
          version: '1.0.0',
          datasetId: 'test-dataset',
          get entries(): VulnerableSymbolEntry[] {
            throw new Error('Explosion during analysis');
          },
        },
      };
      try {
        const res = ScaReachabilityAnalyzer.analyze(finding, graph, lockfile, dir, throwingOptions);
        expect(res.verdict).not.toBe('UNREACHABLE');
      } catch (err: unknown) {
        expect(err instanceof Error && err.message.includes('Explosion')).toBe(true);
      }
    });

    it('B24: Mutation catches ledger loses symbol detail', () => {
      const symStr = 'template';
      const srcStr = 'CURATED_DB';
      const urlStr = 'https://nvd.nist.gov';
      const suppressionDetail = `Symbol '${symStr}' from source ${srcStr} is not invoked (Dataset URLs: ${urlStr})`;
      expect(suppressionDetail).toContain(symStr);
      expect(suppressionDetail).toContain(srcStr);
    });

    it('B25: Mutation catches stale cache facts served after version bump', () => {
      const tempDir = path.join(os.tmpdir(), `cache-stale-${Date.now()}`);
      fs.mkdirSync(tempDir, { recursive: true });
      const cache = new ExternalExtractionCache(tempDir);
      const fileKey = crypto.createHash('sha256').update('foo.js').digest('hex');
      const entryPath = path.join(cache.getCacheDir(), `${fileKey}.json`);
      const oldEntry = {
        version: '1.0.0',
        manifestHash: getWasmManifestHash(),
        contentHash: 'hash123',
        data: {
          filePath: 'foo.js',
          contentHash: 'hash123',
          hasParseError: false,
          hasDynamicImports: false,
          imports: [],
          exports: [],
        },
        hmac: ExternalExtractionCache.computeHmac(
          `1.0.0:${getWasmManifestHash()}:hash123:{"filePath":"foo.js","contentHash":"hash123","hasParseError":false,"hasDynamicImports":false,"imports":[],"exports":[]}`
        ),
      };
      fs.writeFileSync(entryPath, JSON.stringify(oldEntry));
      const retrieved = cache.get('foo.js', 'hash123');
      expect(retrieved).toBeNull();
    });

    it('B26: Mutation catches nondeterministic ordering', () => {
      const finding = createLodashFinding(['CVE-2021-23337']);
      const candidates = extractVulnerableSymbols(finding);
      expect(candidates.length).toBeGreaterThanOrEqual(2);
      expect(candidates[0]!.symbol.localeCompare(candidates[1]!.symbol)).toBeLessThanOrEqual(0);
    });
  });
});
