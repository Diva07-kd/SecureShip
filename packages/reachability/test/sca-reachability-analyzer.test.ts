import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import { ScaReachabilityAnalyzer } from '../src/sca/sca-reachability-analyzer.js';
import { ImportGraph } from '../src/graph/import-graph.js';
import type { LockfileGraph } from '../src/lockfile/lockfile-tree-parser.js';

describe('ScaReachabilityAnalyzer Unit Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-sca-analyzer-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  function createFinding(overrides: Partial<NormalizedFinding>): NormalizedFinding {
    return {
      id: 'f-sca',
      fingerprint: 'b'.repeat(64),
      ruleId: 'GHSA-1234',
      scannerName: 'trivy',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      package: { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
      title: 'Prototype Pollution in lodash',
      description: 'Desc',
      cweIds: [],
      evidence: [],
      createdAt: new Date().toISOString(),
      ...overrides,
    };
  }

  it('returns UNKNOWN UNMAPPED_PACKAGE when finding has no package name', () => {
    const finding = createFinding({ package: undefined });
    const graph = new ImportGraph();
    const result = ScaReachabilityAnalyzer.analyze(finding, graph, null, tmpDir);

    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('UNMAPPED_PACKAGE');
  });

  it('returns UNKNOWN UNMAPPED_PACKAGE for unmapped python package', () => {
    const finding = createFinding({
      package: { ecosystem: 'pypi', name: 'completely-unknown-package-xyz', version: '1.0.0' },
    });
    const graph = new ImportGraph();
    const result = ScaReachabilityAnalyzer.analyze(finding, graph, null, tmpDir);

    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('UNMAPPED_PACKAGE');
  });

  it('returns UNKNOWN NO_LOCKFILE_TREE when lockfileGraph is null', () => {
    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
    });
    const graph = new ImportGraph();
    const result = ScaReachabilityAnalyzer.analyze(finding, graph, null, tmpDir);

    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('NO_LOCKFILE_TREE');
  });

  it('returns REACHABLE_IMPORT TRANSITIVE_VIA when pulled via production direct dependency', () => {
    const finding = createFinding({ package: { ecosystem: 'npm', name: 'ms', version: '2.0.0' } });
    const graph = new ImportGraph();
    // express is imported in production
    graph.importedPackages.set('express', new Set(['src/index.ts']));

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'express',
          {
            name: 'express',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['debug'],
          },
        ],
        [
          'debug',
          {
            name: 'debug',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['ms'],
          },
        ],
        [
          'ms',
          {
            name: 'ms',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([
        ['debug', new Set(['express'])],
        ['ms', new Set(['debug'])],
      ]),
      directProdDependencies: new Set(['express']),
      directDevDependencies: new Set(),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('REACHABLE_IMPORT');
    expect(result.analysisConfidence).toBe('MEDIUM');
    expect(result.evidence.kind).toBe('TRANSITIVE_VIA');
  });

  it('returns UNREACHABLE DEV_ONLY with MEDIUM confidence when declared only in devDependencies', () => {
    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'mocha', version: '10.0.0' },
    });
    const graph = new ImportGraph();

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'mocha',
          {
            name: 'mocha',
            isDirect: true,
            isDev: true,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map(),
      directProdDependencies: new Set(),
      directDevDependencies: new Set(['mocha']),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('UNREACHABLE');
    expect(result.analysisConfidence).toBe('MEDIUM');
    expect(result.evidence.kind).toBe('DEV_ONLY');
  });

  it('returns UNKNOWN CONFIG_REFERENCE when devDependency is referenced in scripts/configs', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'pkg',
        scripts: { test: 'mocha --reporter spec' },
      })
    );

    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'mocha', version: '10.0.0' },
    });
    const graph = new ImportGraph();

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'mocha',
          {
            name: 'mocha',
            isDirect: true,
            isDev: true,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map(),
      directProdDependencies: new Set(),
      directDevDependencies: new Set(['mocha']),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.analysisConfidence).toBe('MEDIUM');
    expect(result.evidence.kind).toBe('CONFIG_REFERENCE');
  });

  it('returns UNKNOWN NO_ENTRYPOINT when graph has 0 entrypoints during NOT_IMPORTED check', () => {
    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'unused-lib', version: '1.0.0' },
    });
    const graph = new ImportGraph();
    graph.entrypoints = [];

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'unused-lib',
          {
            name: 'unused-lib',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map(),
      directProdDependencies: new Set(['unused-lib']),
      directDevDependencies: new Set(),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('NO_ENTRYPOINT');
  });

  it('returns UNKNOWN PARSE_FAILURE when production has parse errors', () => {
    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'unused-lib', version: '1.0.0' },
    });
    const graph = new ImportGraph();
    graph.entrypoints = ['src/index.ts'];
    graph.files.set('src/index.ts', {
      filePath: 'src/index.ts',
      relativePath: 'src/index.ts',
      language: 'typescript',
      isEntrypoint: true,
      isReachable: true,
      reachabilityChain: ['src/index.ts'],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: true,
    });

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'unused-lib',
          {
            name: 'unused-lib',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map(),
      directProdDependencies: new Set(['unused-lib']),
      directDevDependencies: new Set(),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('PARSE_FAILURE');
  });

  it('returns UNKNOWN DYNAMIC_UNKNOWN when production has dynamic imports or unresolved local imports', () => {
    const finding = createFinding({
      package: { ecosystem: 'npm', name: 'unused-lib', version: '1.0.0' },
    });
    const graph = new ImportGraph();
    graph.entrypoints = ['src/index.ts'];
    graph.files.set('src/index.ts', {
      filePath: 'src/index.ts',
      relativePath: 'src/index.ts',
      language: 'typescript',
      isEntrypoint: true,
      isReachable: true,
      reachabilityChain: ['src/index.ts'],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: true,
      hasParseError: false,
    });

    const lockGraph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'unused-lib',
          {
            name: 'unused-lib',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map(),
      directProdDependencies: new Set(['unused-lib']),
      directDevDependencies: new Set(),
    };

    const result = ScaReachabilityAnalyzer.analyze(finding, graph, lockGraph, tmpDir);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.evidence.kind).toBe('DYNAMIC_UNKNOWN');
  });
});
