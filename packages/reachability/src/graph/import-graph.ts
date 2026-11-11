import fs from 'node:fs';
import path from 'node:path';
import {
  TreeSitterLoader,
  type SupportedLanguage,
  type ParseOptions,
} from '../parsers/tree-sitter-loader.js';
import { AdapterRegistry } from '../adapters/adapter-registry.js';
import { EntrypointDetector } from '../entrypoints/entrypoint-detector.js';
import { ExternalExtractionCache } from '../cache/external-cache.js';
import type { FileSymbolUsage } from '../symbol-usage/symbol-usage.types.js';
import { SymbolUsageExtractor } from '../symbol-usage/symbol-usage-extractor.js';

export interface FileNode {
  filePath: string; // Absolute path
  relativePath: string; // Relative POSIX path
  language: SupportedLanguage;
  isEntrypoint: boolean;
  isReachable: boolean;
  reachabilityChain: string[]; // Up to 10 POSIX paths
  hasDynamicImports: boolean;
  hasParseError: boolean;
  parseErrorReason?: string;
  localDependencies: Set<string>; // Absolute paths of local files imported
  packageDependencies: Map<string, { isTypeOnly: boolean }>; // packageName -> metadata
  symbolUsage?: FileSymbolUsage;
}

export interface UnresolvedImportRecord {
  fromFile: string;
  specifier: string;
  reason: string;
}

export interface ImportGraphStats {
  entrypoints: string[];
  totalFiles: number;
  reachableFiles: number;
  unreachableFiles: number;
  unreachableProdFiles: number;
  unreachableTestFiles: number;
  dynamicFiles: string[];
  unresolvedImports: UnresolvedImportRecord[];
  unsupportedLanguageFiles: string[];
  parseFailures: Array<{ filePath: string; reason: string }>;
  hasAnyParseErrorInProduction: boolean;
  hasAnyUnresolvedLocalImportsInProduction: boolean;
  hasAnyDynamicInProduction: boolean;
}

export class ImportGraph {
  public readonly projectRoot: string;
  public readonly files: Map<string, FileNode> = new Map(); // absPath -> FileNode
  public readonly importedPackages: Map<string, Set<string>> = new Map(); // packageName -> Set<importingFilePath>
  public readonly typeOnlyPackages: Set<string> = new Set();
  public readonly unresolvedImports: UnresolvedImportRecord[] = [];
  public readonly unsupportedLanguageFiles: string[] = [];
  public readonly parseFailures: Array<{ filePath: string; reason: string }> = [];
  public entrypoints: string[] = [];

  constructor(projectRoot: string = process.cwd()) {
    this.projectRoot = path.resolve(projectRoot);
  }

  /**
   * Builds the whole-repository import graph, traversing from discovered entrypoints.
   */
  public static async build(
    projectRoot: string,
    options: {
      userConfigEntrypoints?: string[];
      parseOptions?: ParseOptions;
      noCache?: boolean;
    } = {}
  ): Promise<ImportGraph> {
    await TreeSitterLoader.init();

    const graph = new ImportGraph(projectRoot);
    const cache = new ExternalExtractionCache(projectRoot, !options.noCache);

    // 1. Detect production entrypoints
    const entrypointRes = EntrypointDetector.detect(projectRoot, options.userConfigEntrypoints);
    graph.entrypoints = entrypointRes.entrypoints;

    for (const unres of entrypointRes.unresolvedEntrypoints) {
      graph.unresolvedImports.push({
        fromFile: 'entrypoints',
        specifier: unres,
        reason: `Could not resolve entrypoint '${unres}' to a valid source file`,
      });
    }

    // 2. Discover and parse all source files in the repository
    const allFiles: string[] = [];
    graph.collectSourceFiles(graph.projectRoot, allFiles);

    for (const filePath of allFiles) {
      const relPath = path.relative(graph.projectRoot, filePath).replace(/\\/g, '/');
      const lang = TreeSitterLoader.detectLanguage(filePath);

      if (!lang) {
        graph.unsupportedLanguageFiles.push(relPath);
        continue;
      }

      let content = '';
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch (err) {
        graph.parseFailures.push({
          filePath: relPath,
          reason: err instanceof Error ? err.message : String(err),
        });
        continue;
      }

      const contentHash = ExternalExtractionCache.computeHmac(content);
      const isEntry = graph.entrypoints.includes(filePath);

      // Check external cache
      let extraction = cache.get(relPath, contentHash);
      if (
        extraction &&
        extraction.symbolUsage === undefined &&
        (lang === 'javascript' || lang === 'typescript' || lang === 'python')
      ) {
        extraction = null; // Stale cache entry missing symbol usage facts; recompute
      }

      const adapter = AdapterRegistry.getAdapter(lang);

      if (!extraction) {
        const parseRes = TreeSitterLoader.parseFile(content, lang, options.parseOptions);

        if (parseRes.hasError || !parseRes.tree) {
          graph.parseFailures.push({
            filePath: relPath,
            reason: parseRes.errorReason ?? 'Parse failed with syntax error',
          });
        }

        const extResult = parseRes.tree
          ? adapter.extract(parseRes.tree.rootNode)
          : { imports: [], exports: [], hasDynamicImports: false };

        const symbolUsage = SymbolUsageExtractor.extract(
          parseRes.tree?.rootNode ?? null,
          filePath,
          relPath,
          lang,
          parseRes.hasError || !parseRes.tree
        );

        const newExtraction = {
          filePath: relPath,
          contentHash,
          hasParseError: parseRes.hasError,
          hasDynamicImports: extResult.hasDynamicImports,
          imports: extResult.imports.map((i) => ({
            specifier: i.specifier,
            isTypeOnly: Boolean(i.isTypeOnly),
            startLine: i.startLine,
          })),
          exports: extResult.exports.map((e) => ({
            specifier: e.specifier,
            isTypeOnly: Boolean(e.isTypeOnly),
          })),
          symbolUsage,
        };

        cache.set(relPath, newExtraction);
        extraction = newExtraction;
      } else if (extraction.hasParseError) {
        graph.parseFailures.push({
          filePath: relPath,
          reason: 'Cached entry has syntax error (rootNode.hasError is true)',
        });
      }

      // Create file node
      const node: FileNode = {
        filePath,
        relativePath: relPath,
        language: lang,
        isEntrypoint: isEntry,
        isReachable: false,
        reachabilityChain: [],
        hasDynamicImports: extraction.hasDynamicImports,
        hasParseError: extraction.hasParseError,
        localDependencies: new Set(),
        packageDependencies: new Map(),
        symbolUsage: extraction.symbolUsage,
      };

      // Resolve extracted imports via universal language adapter
      for (const imp of extraction.imports) {
        if (!imp.specifier) continue;

        const resolved = adapter.resolve(imp.specifier, filePath, graph.projectRoot);

        if (resolved.type === 'LOCAL_FILE') {
          node.localDependencies.add(resolved.resolvedPath);
        } else if (resolved.type === 'PACKAGE') {
          node.packageDependencies.set(resolved.packageName, { isTypeOnly: imp.isTypeOnly });
        } else if (resolved.type === 'UNRESOLVED') {
          graph.unresolvedImports.push({
            fromFile: relPath,
            specifier: imp.specifier,
            reason: resolved.reason,
          });
        }
        // STANDARD_LIB requires no external package tracking or unresolved warning
      }

      graph.files.set(filePath, node);
    }

    // 3. Iterative BFS Reachability Traversal from Entrypoints
    graph.traverseReachability();

    return graph;
  }

  /**
   * Iterative BFS traversal from all entrypoints to mark reachable files and package imports.
   */
  public traverseReachability(): void {
    // Sort entrypoints deterministically
    const queue: Array<{ currentPath: string; chain: string[] }> = [];

    for (const ep of this.entrypoints.sort()) {
      const node = this.files.get(ep);
      if (node) {
        node.isReachable = true;
        node.reachabilityChain = [node.relativePath];
        queue.push({ currentPath: ep, chain: [node.relativePath] });
      }
    }

    const visited = new Set<string>();

    while (queue.length > 0) {
      const { currentPath, chain } = queue.shift()!;
      if (visited.has(currentPath)) continue;
      visited.add(currentPath);

      const node = this.files.get(currentPath);
      if (!node) continue;

      // Record packages imported by this production-reachable file
      for (const [pkgName, meta] of node.packageDependencies.entries()) {
        const normPkg = pkgName.toLowerCase();
        if (!this.importedPackages.has(normPkg)) {
          this.importedPackages.set(normPkg, new Set());
        }
        this.importedPackages.get(normPkg)!.add(currentPath);

        // Also track original case
        if (!this.importedPackages.has(pkgName)) {
          this.importedPackages.set(pkgName, new Set());
        }
        this.importedPackages.get(pkgName)!.add(currentPath);

        if (meta.isTypeOnly) {
          this.typeOnlyPackages.add(normPkg);
        }
      }

      // Traverse local dependencies
      const sortedDeps = Array.from(node.localDependencies).sort();
      for (const depPath of sortedDeps) {
        const depNode = this.files.get(depPath);
        if (depNode) {
          const newChain = [...chain, depNode.relativePath].slice(0, 10);
          if (!depNode.isReachable) {
            depNode.isReachable = true;
            depNode.reachabilityChain = newChain;
          }
          if (!visited.has(depPath)) {
            queue.push({ currentPath: depPath, chain: newChain });
          }
        }
      }
    }
  }

  /**
   * Computes graph statistics and precondition statuses.
   */
  public computeStats(): ImportGraphStats {
    let reachableCount = 0;
    let unreachableCount = 0;
    let unreachableProdCount = 0;
    let unreachableTestCount = 0;
    const dynamicFiles: string[] = [];

    let hasAnyParseErrorInProd = false;
    let hasAnyUnresolvedLocalInProd = false;
    let hasAnyDynamicInProd = false;

    for (const node of this.files.values()) {
      const isTest = EntrypointDetector.isTestOrMockFile(node.relativePath);

      if (node.isReachable) {
        reachableCount++;
        if (node.hasParseError) hasAnyParseErrorInProd = true;
        if (node.hasDynamicImports) {
          dynamicFiles.push(node.relativePath);
          hasAnyDynamicInProd = true;
        }
      } else {
        unreachableCount++;
        if (isTest) {
          unreachableTestCount++;
        } else {
          unreachableProdCount++;
        }
        // If an unreachable file is in production scope (not test/mock) and has a parse error,
        // it violates the precondition: "zero parse errors anywhere in production scope"
        if (!isTest && node.hasParseError) {
          hasAnyParseErrorInProd = true;
        }
        if (node.hasDynamicImports) {
          dynamicFiles.push(node.relativePath);
        }
      }
    }

    // Check parseFailures for any file in production scope
    for (const failure of this.parseFailures) {
      if (!EntrypointDetector.isTestOrMockFile(failure.filePath)) {
        hasAnyParseErrorInProd = true;
      }
    }

    // Check if any unresolved import occurred in a production-reachable file or production-scope file
    for (const unres of this.unresolvedImports) {
      const fromNode = Array.from(this.files.values()).find(
        (f) => f.relativePath === unres.fromFile
      );
      if (fromNode && fromNode.isReachable) {
        hasAnyUnresolvedLocalInProd = true;
      } else if (!EntrypointDetector.isTestOrMockFile(unres.fromFile)) {
        hasAnyUnresolvedLocalInProd = true;
      }
    }

    return {
      entrypoints: this.entrypoints.map((p) =>
        path.relative(this.projectRoot, p).replace(/\\/g, '/')
      ),
      totalFiles: this.files.size,
      reachableFiles: reachableCount,
      unreachableFiles: unreachableCount,
      unreachableProdFiles: unreachableProdCount,
      unreachableTestFiles: unreachableTestCount,
      dynamicFiles: dynamicFiles.sort(),
      unresolvedImports: this.unresolvedImports,
      unsupportedLanguageFiles: this.unsupportedLanguageFiles.sort(),
      parseFailures: this.parseFailures,
      hasAnyParseErrorInProduction: hasAnyParseErrorInProd,
      hasAnyUnresolvedLocalImportsInProduction: hasAnyUnresolvedLocalInProd,
      hasAnyDynamicInProduction: hasAnyDynamicInProd,
    };
  }

  /**
   * Serializes the import graph summary to JSON.
   */
  public toJSON(): ImportGraphStats {
    return this.computeStats();
  }

  /**
   * Generates a GraphViz DOT representation of the import graph.
   */
  public toDot(): string {
    const lines: string[] = ['digraph ImportGraph {', '  rankdir=LR;', '  node [shape=box];'];
    for (const [, node] of this.files) {
      const color = node.isReachable ? 'green' : 'gray';
      lines.push(`  "${node.relativePath}" [label="${node.relativePath}", color="${color}"];`);
      for (const dep of node.localDependencies) {
        const depNode = this.files.get(dep);
        const depLabel = depNode
          ? depNode.relativePath
          : path.relative(this.projectRoot, dep).replace(/\\/g, '/');
        lines.push(`  "${node.relativePath}" -> "${depLabel}";`);
      }
      for (const [pkg] of node.packageDependencies) {
        lines.push(`  "${node.relativePath}" -> "pkg:${pkg}" [style=dashed];`);
      }
    }
    lines.push('}');
    return lines.join('\n');
  }

  /**
   * Recursively discovers all candidate source files in the project directory.
   */
  private collectSourceFiles(dir: string, results: string[]): void {
    const excludeDirs = new Set([
      'node_modules',
      '.git',
      '.svn',
      'dist',
      'build',
      'out',
      'coverage',
      'vendor',
      '.secureship',
      '.next',
      '.nuxt',
      '.venv',
      'venv',
      '__pycache__',
      'target',
      'bin',
      'obj',
      '.gradle',
      '.cargo',
    ]);

    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const name = entry.name;
      if (entry.isDirectory()) {
        if (!excludeDirs.has(name) && !name.startsWith('.venv')) {
          this.collectSourceFiles(path.join(dir, name), results);
        }
      } else if (entry.isFile()) {
        const lang = TreeSitterLoader.detectLanguage(name);
        if (lang) {
          results.push(path.join(dir, name));
        }
      }
    }
  }
}
