import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { ImportGraph } from '../src/graph/import-graph.js';

describe('ImportGraph Unit Suite', () => {
  it('builds import graph and traverses reachability BFS correctly with cycles', () => {
    const root = path.resolve('app');
    const graph = new ImportGraph(root);
    const entry = path.resolve(root, 'src/entry.ts');
    const a = path.resolve(root, 'src/a.ts');
    const b = path.resolve(root, 'src/b.ts');
    const orphan = path.resolve(root, 'src/orphan.ts');

    graph.entrypoints = [entry];

    graph.files.set(entry, {
      filePath: entry,
      relativePath: 'src/entry.ts',
      language: 'typescript',
      isEntrypoint: true,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set([a]),
      packageDependencies: new Map([['express', { isTypeOnly: false }]]),
      hasDynamicImports: false,
      hasParseError: false,
    });

    graph.files.set(a, {
      filePath: a,
      relativePath: 'src/a.ts',
      language: 'typescript',
      isEntrypoint: false,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set([b]),
      packageDependencies: new Map(),
      hasDynamicImports: false,
      hasParseError: false,
    });

    // Circular back to entry
    graph.files.set(b, {
      filePath: b,
      relativePath: 'src/b.ts',
      language: 'typescript',
      isEntrypoint: false,
      isReachable: false,
      reachabilityChain: [],
      localDependencies: new Set([entry]),
      packageDependencies: new Map([['lodash', { isTypeOnly: true }]]),
      hasDynamicImports: false,
      hasParseError: false,
    });

    graph.files.set(orphan, {
      filePath: orphan,
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

    graph.traverseReachability();

    const entryNode = graph.files.get(entry)!;
    const aNode = graph.files.get(a)!;
    const bNode = graph.files.get(b)!;
    const orphanNode = graph.files.get(orphan)!;

    expect(entryNode.isReachable).toBe(true);
    expect(aNode.isReachable).toBe(true);
    expect(bNode.isReachable).toBe(true);
    expect(orphanNode.isReachable).toBe(false);

    // Package propagation
    expect(graph.importedPackages.has('express')).toBe(true);
    expect(graph.typeOnlyPackages.has('lodash')).toBe(true);

    // computeStats
    const stats = graph.computeStats();
    expect(stats.totalFiles).toBe(4);
    expect(stats.reachableFiles).toBe(3);
    expect(stats.unreachableFiles).toBe(1);
    expect(stats.hasAnyDynamicInProduction).toBe(false);
    expect(stats.hasAnyParseErrorInProduction).toBe(false);

    // toJSON
    const json = graph.toJSON();
    expect(json.totalFiles).toBe(4);
    expect(json.entrypoints).toContain('src/entry.ts');

    // toDot
    const dot = graph.toDot();
    expect(dot).toContain('digraph ImportGraph');
    expect(dot).toContain('"src/entry.ts" -> "src/a.ts"');
  });
});
