import fs from 'node:fs';
import path from 'node:path';
import type { ImportGraph } from '../graph/import-graph.js';
import { TreeSitterLoader } from '../parsers/tree-sitter-loader.js';
import { CallGraphExtractor, type FileAnalysisSummary } from '../taint/call-graph-extractor.js';
import { AdapterRegistry } from '../adapters/adapter-registry.js';

export interface CallPathResult {
  proven: boolean;
  chain: string[] | null;
}

export interface SymbolUsageLocation {
  file: string; // Relative POSIX path
  line: number;
  enclosingFunction?: string;
  symbol: string;
}

interface CallEdge {
  target: string;
  hop: string;
}

export class CallPathProver {
  public static readonly MAX_HOPS = 10;

  /**
   * Attempts to prove a concrete entrypoint-to-call-site call chain for a symbol usage.
   * Returns proven: true with the call chain if a path exists, otherwise proven: false.
   */
  public static proveCallPath(graph: ImportGraph, usage: SymbolUsageLocation): CallPathResult {
    // 1. Locate the file node
    const targetFileNode = Array.from(graph.files.values()).find(
      (f) => f.relativePath === usage.file
    );

    if (!targetFileNode || !targetFileNode.isReachable) {
      return { proven: false, chain: null };
    }

    // 2. Top-level (module-level) usage in a reachable file is reachable by definition!
    // The chain is the file reachability import chain plus the usage site.
    if (!usage.enclosingFunction) {
      const chain = [...targetFileNode.reachabilityChain, `${usage.file}:${usage.line}`].slice(
        0,
        CallPathProver.MAX_HOPS
      );
      return { proven: true, chain };
    }

    // 3. Intra/Inter-procedural call path search to target function
    const targetNodeId = `${usage.file}#${usage.enclosingFunction}`;

    // Build the conservative inter-procedural call graph over reachable production files
    const callGraph = CallPathProver.buildCallGraph(graph);

    // Identify entrypoint root nodes
    const entrypointRoots = CallPathProver.findEntrypointRoots(graph, callGraph);

    // BFS shortest path search with deterministic sorted tie-breaks
    const queue: Array<{ current: string; path: string[]; depth: number }> = [];
    const visitedGlobal = new Set<string>();

    // Sort entrypoint roots deterministically
    const sortedRoots = Array.from(entrypointRoots).sort();
    for (const root of sortedRoots) {
      queue.push({
        current: root,
        path: [root],
        depth: 1,
      });
      visitedGlobal.add(root);
    }

    while (queue.length > 0) {
      const { current, path: currentPath, depth } = queue.shift()!;

      if (current === targetNodeId) {
        const fullChain = [...currentPath, `${usage.file}:${usage.line} (${usage.symbol})`].slice(
          0,
          CallPathProver.MAX_HOPS
        );
        return { proven: true, chain: fullChain };
      }

      if (depth >= CallPathProver.MAX_HOPS) {
        continue;
      }

      const neighbors = callGraph.edges.get(current) ?? [];
      // Deterministic sorted tie-break by target ID and hop
      const sortedNeighbors = [...neighbors].sort((a, b) => {
        const cmp = a.target.localeCompare(b.target);
        return cmp !== 0 ? cmp : a.hop.localeCompare(b.hop);
      });

      for (const edge of sortedNeighbors) {
        if (!visitedGlobal.has(edge.target)) {
          visitedGlobal.add(edge.target);
          queue.push({
            current: edge.target,
            path: [...currentPath, edge.hop],
            depth: depth + 1,
          });
        }
      }
    }

    // No proof could be established
    return { proven: false, chain: null };
  }

  private static buildCallGraph(graph: ImportGraph): {
    summaries: Map<string, FileAnalysisSummary>;
    edges: Map<string, CallEdge[]>;
  } {
    const summaries = new Map<string, FileAnalysisSummary>();
    const edges = new Map<string, CallEdge[]>();

    const addEdge = (from: string, to: string, hop: string) => {
      if (!edges.has(from)) edges.set(from, []);
      edges.get(from)!.push({ target: to, hop });
    };

    // Analyze each production-reachable file
    for (const fileNode of graph.files.values()) {
      if (!fileNode.isReachable) continue;

      let content = '';
      try {
        content = fs.readFileSync(fileNode.filePath, 'utf8');
      } catch {
        continue;
      }

      const parseRes = TreeSitterLoader.parseFile(content, fileNode.language);
      if (!parseRes.tree || parseRes.hasError) continue;

      const summary = CallGraphExtractor.extract(parseRes.tree.rootNode, fileNode.filePath);
      summaries.set(fileNode.relativePath, summary);

      // Local import resolution: map localName -> target function in local dep
      const localBindingMap = new Map<string, { depRelPath: string; exportedName: string }>();

      if (fileNode.symbolUsage) {
        for (const b of fileNode.symbolUsage.bindings) {
          if (b.rawSpecifier.startsWith('.')) {
            // Local file import
            const adapter = AdapterRegistry.getAdapter(fileNode.language);
            const resolved = adapter.resolve(b.rawSpecifier, fileNode.filePath, graph.projectRoot);
            if (resolved.type === 'LOCAL_FILE') {
              const depRel = path
                .relative(graph.projectRoot, resolved.resolvedPath)
                .replace(/\\/g, '/');
              localBindingMap.set(b.localName, {
                depRelPath: depRel,
                exportedName: b.importedName === 'default' ? 'default' : b.importedName,
              });
            }
          }
        }
      }

      // Link call sites from functions in this file
      for (const [fnName, fnSummary] of summary.functions.entries()) {
        const fromNodeId = `${fileNode.relativePath}#${fnName}`;

        for (const callSite of fnSummary.callSites) {
          const callee = callSite.calleeName;
          const hop = `${fileNode.relativePath}:${callSite.line} (${fnName} -> ${callSite.calleeExpression})`;

          // 1. Intra-file function call
          if (summary.functions.has(callee)) {
            addEdge(fromNodeId, `${fileNode.relativePath}#${callee}`, hop);
          }

          // 2. Inter-file call through imported local function
          if (localBindingMap.has(callee)) {
            const binding = localBindingMap.get(callee)!;
            addEdge(fromNodeId, `${binding.depRelPath}#${binding.exportedName}`, hop);
          }
        }
      }
    }

    return { summaries, edges };
  }

  private static findEntrypointRoots(
    graph: ImportGraph,
    callGraph: { summaries: Map<string, FileAnalysisSummary>; edges: Map<string, CallEdge[]> }
  ): Set<string> {
    const roots = new Set<string>();

    for (const ep of graph.entrypoints) {
      const epNode = graph.files.get(ep);
      if (!epNode) continue;

      const summary = callGraph.summaries.get(epNode.relativePath);
      if (!summary) continue;

      // 1. Exported functions in entrypoint file
      for (const exp of summary.exportedFunctions) {
        roots.add(`${epNode.relativePath}#${exp}`);
      }

      // 2. Top-level calls in entrypoint file (calls made outside any function)
      for (const callSite of summary.callSites) {
        if (!callSite.enclosingFunctionName) {
          if (summary.functions.has(callSite.calleeName)) {
            roots.add(`${epNode.relativePath}#${callSite.calleeName}`);
          }
        }
      }

      // 3. Standard entrypoint function names if present
      for (const name of ['main', 'run', 'handler', 'start', 'default']) {
        if (summary.functions.has(name)) {
          roots.add(`${epNode.relativePath}#${name}`);
        }
      }

      // 4. If no specific function is marked, all declared functions in entrypoint file can be potential roots
      if (roots.size === 0) {
        for (const fn of summary.functions.keys()) {
          roots.add(`${epNode.relativePath}#${fn}`);
        }
      }
    }

    return roots;
  }
}
