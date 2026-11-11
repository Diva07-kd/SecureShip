import { describe, it, expect } from 'vitest';
import path from 'node:path';
import type { NormalizedFinding } from '@secureship/contracts';
import { SastReachabilityAnalyzer } from '../src/sast/sast-reachability-analyzer.js';
import { ImportGraph } from '../src/graph/import-graph.js';

describe('SastReachabilityAnalyzer Unit Suite', () => {
  const root = path.resolve('repo');

  function createFinding(overrides: Partial<NormalizedFinding>): NormalizedFinding {
    return {
      id: 'f-1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'rule-1',
      scannerName: 'opengrep',
      category: 'SAST',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      location: { filePath: 'src/app.ts', startLine: 10, endLine: 10 },
      title: 'SAST Finding',
      description: 'Desc',
      cweIds: [],
      evidence: [],
      createdAt: new Date().toISOString(),
      ...overrides,
    };
  }

  it('preserves Gate 1 TEST_OR_MOCK scopeTag as UNREACHABLE DEV_ONLY with HIGH confidence', () => {
    const finding = createFinding({
      scopeTag: 'TEST_OR_MOCK',
      location: { filePath: 'test/foo.test.ts', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);

    expect(result.verdict).toBe('UNREACHABLE');
    expect(result.analysisConfidence).toBe('HIGH');
    expect(result.evidence.kind).toBe('DEV_ONLY');
    expect(result.evidence.notes).toContain('Preserved Gate 1');
  });

  it('returns UNKNOWN UNSUPPORTED_LANGUAGE when file is not in import graph', () => {
    const finding = createFinding({
      location: { filePath: 'unknown.go', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);

    expect(result.verdict).toBe('UNKNOWN');
    expect(result.analysisConfidence).toBe('LOW');
    expect(result.evidence.kind).toBe('UNSUPPORTED_LANGUAGE');
  });

  it('returns UNKNOWN PARSE_FAILURE when file node has parse error', () => {
    const filePath = path.resolve(root, 'src/bad.ts');
    const finding = createFinding({
      location: { filePath: 'src/bad.ts', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    graph.files.set(filePath, {
      filePath,
      relativePath: 'src/bad.ts',
      language: 'typescript',
      isEntrypoint: false,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: true,
      parseErrorReason: 'Syntax error on line 5',
    });

    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.analysisConfidence).toBe('LOW');
    expect(result.evidence.kind).toBe('PARSE_FAILURE');
    expect(result.evidence.notes).toBe('Syntax error on line 5');
  });

  it('returns UNKNOWN NO_ENTRYPOINT when graph has 0 entrypoints', () => {
    const filePath = path.resolve(root, 'src/orphan.ts');
    const finding = createFinding({
      location: { filePath: 'src/orphan.ts', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    graph.files.set(filePath, {
      filePath,
      relativePath: 'src/orphan.ts',
      language: 'typescript',
      isEntrypoint: false,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: false,
    });

    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);
    expect(result.verdict).toBe('UNKNOWN');
    expect(result.analysisConfidence).toBe('LOW');
    expect(result.evidence.kind).toBe('NO_ENTRYPOINT');
  });

  it('returns REACHABLE_IMPORT when file is reachable from entrypoint', () => {
    const filePath = path.resolve(root, 'src/entry.ts');
    const finding = createFinding({
      location: { filePath: 'src/entry.ts', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    graph.entrypoints = [filePath];
    graph.files.set(filePath, {
      filePath,
      relativePath: 'src/entry.ts',
      language: 'typescript',
      isEntrypoint: true,
      isReachable: true,
      reachabilityChain: ['src/entry.ts'],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: false,
    });

    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);
    expect(result.verdict).toBe('REACHABLE_IMPORT');
    expect(result.analysisConfidence).toBe('HIGH');
    expect(result.evidence.kind).toBe('IMPORT_CHAIN');
    expect(result.evidence.chain).toEqual(['src/entry.ts']);
  });

  it('returns UNREACHABLE DEAD_FILE with LOW confidence when unreachable from entrypoint', () => {
    const entryPath = path.resolve(root, 'src/entry.ts');
    const deadPath = path.resolve(root, 'src/dead.ts');
    const finding = createFinding({
      location: { filePath: 'src/dead.ts', startLine: 1, endLine: 1 },
    });
    const graph = new ImportGraph(root);
    graph.entrypoints = [entryPath];
    graph.files.set(deadPath, {
      filePath: deadPath,
      relativePath: 'src/dead.ts',
      language: 'typescript',
      isEntrypoint: false,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set(),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: false,
    });

    const result = SastReachabilityAnalyzer.analyze(finding, graph, root);
    expect(result.verdict).toBe('UNREACHABLE');
    expect(result.analysisConfidence).toBe('LOW');
    expect(result.evidence.kind).toBe('DEAD_FILE');
    expect(result.evidence.chain).toEqual(['src/dead.ts']);
  });
});
