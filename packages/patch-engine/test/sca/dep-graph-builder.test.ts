import { describe, it, expect } from 'vitest';
import type { LockfileGraph } from '@secureship/reachability';
import { DepGraphBuilder } from '../../src/sca/dep-graph-builder.js';

describe('DepGraphBuilder Unit Tests', () => {
  it('identifies direct dependencies and returns single-hop chains', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'lodash',
          {
            name: 'lodash',
            version: '4.17.20',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([['lodash', new Set()]]),
      directProdDependencies: new Set(['lodash']),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    expect(builder.isDirect('lodash')).toBe(true);
    expect(builder.isDirect('LodAsh')).toBe(true);
    expect(builder.isDirect('nonexistent')).toBe(false);

    const chains = builder.getTransitiveChains('lodash');
    expect(chains).toEqual([['root', 'lodash']]);
  });

  it('computes 2-hop transitive chains [root, middle, vuln]', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'express',
          {
            name: 'express',
            version: '4.18.2',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['body-parser'],
          },
        ],
        [
          'body-parser',
          {
            name: 'body-parser',
            version: '1.19.0',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['qs'],
          },
        ],
        [
          'qs',
          {
            name: 'qs',
            version: '6.5.2',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([
        ['body-parser', new Set(['express'])],
        ['qs', new Set(['body-parser'])],
      ]),
      directProdDependencies: new Set(['express']),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    expect(builder.isDirect('qs')).toBe(false);

    const chains = builder.getTransitiveChains('qs');
    expect(chains).toEqual([['root', 'express', 'body-parser', 'qs']]);

    const dependents = builder.getTransitiveDependents('qs');
    expect(dependents.has('body-parser')).toBe(true);
    expect(dependents.has('express')).toBe(true);
  });

  it('handles circular dependencies (A -> B -> A -> vuln) without infinite loops', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'pkg-a',
          {
            name: 'pkg-a',
            version: '1.0.0',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['pkg-b'],
          },
        ],
        [
          'pkg-b',
          {
            name: 'pkg-b',
            version: '1.0.0',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['pkg-a', 'vuln-pkg'],
          },
        ],
        [
          'vuln-pkg',
          {
            name: 'vuln-pkg',
            version: '0.1.0',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([
        ['pkg-b', new Set(['pkg-a'])],
        ['pkg-a', new Set(['pkg-b'])],
        ['vuln-pkg', new Set(['pkg-b'])],
      ]),
      directProdDependencies: new Set(['pkg-a']),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    const chains = builder.getTransitiveChains('vuln-pkg');
    expect(chains.length).toBeGreaterThan(0);
    expect(chains[0]).toEqual(['root', 'pkg-a', 'pkg-b', 'vuln-pkg']);
  });

  it('handles diamond dependencies (A -> B -> vuln, A -> C -> vuln) and returns both paths', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'root-app',
          {
            name: 'root-app',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['pkg-b', 'pkg-c'],
          },
        ],
        [
          'pkg-b',
          {
            name: 'pkg-b',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['vuln'],
          },
        ],
        [
          'pkg-c',
          {
            name: 'pkg-c',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['vuln'],
          },
        ],
        [
          'vuln',
          {
            name: 'vuln',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([['vuln', new Set(['pkg-b', 'pkg-c'])]]),
      directProdDependencies: new Set(['pkg-b', 'pkg-c']),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    const chains = builder.getTransitiveChains('vuln');
    expect(chains).toHaveLength(2);
    expect(chains).toContainEqual(['root', 'pkg-b', 'vuln']);
    expect(chains).toContainEqual(['root', 'pkg-c', 'vuln']);
  });

  it('handles missing package name gracefully by returning empty array', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map(),
      dependentsMap: new Map(),
      directProdDependencies: new Set(),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    expect(builder.getTransitiveChains('not-in-lockfile')).toEqual([]);
    expect(builder.inducedSubgraph('not-in-lockfile')).toEqual(new Map());
    expect(builder.getTransitiveDependents('not-in-lockfile')).toEqual(new Set());
  });

  it('computes minimal inducedSubgraph containing only nodes on paths to vulnerable package', () => {
    const graph: LockfileGraph = {
      format: 'NPM_V2_V3',
      nodes: new Map([
        [
          'direct-a',
          {
            name: 'direct-a',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['vuln-pkg'],
          },
        ],
        [
          'unrelated-direct',
          {
            name: 'unrelated-direct',
            isDirect: true,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: ['unrelated-child'],
          },
        ],
        [
          'unrelated-child',
          {
            name: 'unrelated-child',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
        [
          'vuln-pkg',
          {
            name: 'vuln-pkg',
            isDirect: false,
            isDev: false,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          },
        ],
      ]),
      dependentsMap: new Map([
        ['vuln-pkg', new Set(['direct-a'])],
        ['unrelated-child', new Set(['unrelated-direct'])],
      ]),
      directProdDependencies: new Set(['direct-a', 'unrelated-direct']),
      directDevDependencies: new Set(),
    };

    const builder = new DepGraphBuilder(graph);
    const subgraph = builder.inducedSubgraph('vuln-pkg');

    expect(subgraph.has('root')).toBe(true);
    expect(subgraph.get('root')).toEqual(['direct-a']);
    expect(subgraph.has('direct-a')).toBe(true);
    expect(subgraph.get('direct-a')).toEqual(['vuln-pkg']);
    expect(subgraph.has('unrelated-direct')).toBe(false);
    expect(subgraph.has('unrelated-child')).toBe(false);
  });
});
