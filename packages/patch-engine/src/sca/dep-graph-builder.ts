import type { LockfileGraph } from '@secureship/reachability';

export class DepGraphBuilder {
  private readonly graph: LockfileGraph;

  constructor(graph: LockfileGraph) {
    this.graph = graph;
  }

  /**
   * Returns true if `pkg` appears in directProdDependencies or directDevDependencies.
   */
  public isDirect(pkg: string): boolean {
    const norm = pkg.toLowerCase();
    for (const d of this.graph.directProdDependencies) {
      if (d.toLowerCase() === norm) return true;
    }
    for (const d of this.graph.directDevDependencies) {
      if (d.toLowerCase() === norm) return true;
    }
    return false;
  }

  /**
   * Returns all ancestor node-chains leading from root to vulnerablePackage.
   * Format of each chain: [root, ..., parent, vulnerablePackage]
   * Handles diamond dependencies, detects cycles, caps at 50 paths.
   */
  public getTransitiveChains(vulnerablePackage: string): string[][] {
    const targetNodeKey = this.findNodeKey(vulnerablePackage);
    if (!targetNodeKey) {
      return [];
    }

    const paths: string[][] = [];
    const maxPaths = 50;

    // We traverse upwards from vulnerablePackage to direct dependencies using dependentsMap.
    const searchUpward = (
      currentPkg: string,
      currentPath: string[],
      visitedInPath: Set<string>
    ) => {
      if (paths.length >= maxPaths) return;

      const normCurrent = currentPkg.toLowerCase();
      if (visitedInPath.has(normCurrent)) {
        // Cycle detected - do not loop infinitely
        return;
      }

      const nextVisited = new Set(visitedInPath);
      nextVisited.add(normCurrent);
      const nextPath = [currentPkg, ...currentPath];

      // If current package is direct, it connects directly to 'root'
      if (this.isDirect(currentPkg)) {
        paths.push(['root', ...nextPath]);
        return;
      }

      // Check parents in dependentsMap
      const parents = this.graph.dependentsMap.get(currentPkg) ?? this.findDependents(currentPkg);
      if (!parents || parents.size === 0) {
        // Dead end without explicit direct parent - treat as top level if no other path
        paths.push(['root', ...nextPath]);
        return;
      }

      for (const parent of parents) {
        if (paths.length >= maxPaths) break;
        searchUpward(parent, nextPath, nextVisited);
      }
    };

    searchUpward(targetNodeKey, [], new Set());

    // Deduplicate paths
    const seen = new Set<string>();
    const uniquePaths: string[][] = [];
    for (const p of paths) {
      const key = p.join('->');
      if (!seen.has(key)) {
        seen.add(key);
        uniquePaths.push(p);
      }
    }

    return uniquePaths;
  }

  /**
   * Returns Set of all packages that transitively depend on `pkg`.
   */
  public getTransitiveDependents(pkg: string): Set<string> {
    const dependents = new Set<string>();
    const queue: string[] = [pkg];
    const visited = new Set<string>([pkg.toLowerCase()]);

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const parents = this.graph.dependentsMap.get(curr) ?? this.findDependents(curr);
      if (parents) {
        for (const p of parents) {
          const normP = p.toLowerCase();
          if (!visited.has(normP)) {
            visited.add(normP);
            dependents.add(p);
            queue.push(p);
          }
        }
      }
    }

    return dependents;
  }

  /**
   * Computes minimal induced subgraph: only nodes on paths from root to vulnerablePackage.
   * Returns a Map<string, string[]> (pkg -> its child dependencies that lie on the vuln path).
   */
  public inducedSubgraph(vulnerablePackage: string): Map<string, string[]> {
    const chains = this.getTransitiveChains(vulnerablePackage);
    const nodesOnPath = new Set<string>();

    for (const chain of chains) {
      for (const node of chain) {
        nodesOnPath.add(node);
      }
    }

    const subgraph = new Map<string, string[]>();

    for (const node of nodesOnPath) {
      if (node === 'root') {
        const prod = Array.from(this.graph.directProdDependencies);
        const dev = Array.from(this.graph.directDevDependencies);
        const rootDeps: string[] = [...prod, ...dev].filter((d: string) => nodesOnPath.has(d));
        subgraph.set('root', rootDeps);
      } else {
        const nodeInfo = this.graph.nodes.get(node) ?? this.findNode(node);
        const deps: string[] = (nodeInfo?.dependencies as string[] | undefined) ?? [];
        const childDeps: string[] = deps.filter((d: string) => nodesOnPath.has(d));
        subgraph.set(node, childDeps);
      }
    }

    return subgraph;
  }

  private findNodeKey(name: string): string | undefined {
    const norm = name.toLowerCase();
    for (const key of this.graph.nodes.keys()) {
      if (key.toLowerCase() === norm) return key;
    }
    return undefined;
  }

  private findNode(name: string) {
    const norm = name.toLowerCase();
    for (const [key, node] of this.graph.nodes.entries()) {
      if (key.toLowerCase() === norm) return node;
    }
    return undefined;
  }

  private findDependents(name: string): Set<string> | undefined {
    const norm = name.toLowerCase();
    for (const [key, set] of this.graph.dependentsMap.entries()) {
      if (key.toLowerCase() === norm) return set;
    }
    return undefined;
  }
}
