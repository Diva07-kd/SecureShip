import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';

export interface LockfileDependencyNode {
  name: string;
  version?: string;
  isDirect: boolean;
  isDev: boolean;
  isOptional: boolean;
  isPeer: boolean;
  dependencies: string[]; // names of child packages required
}

export interface LockfileGraph {
  format:
    | 'NPM_V2_V3'
    | 'PNPM_V6'
    | 'PNPM_V9'
    | 'POETRY'
    | 'PIPFILE'
    | 'VENV_METADATA'
    | 'GO_MOD'
    | 'CARGO_LOCK'
    | 'MAVEN_POM';
  nodes: Map<string, LockfileDependencyNode>; // packageName -> node
  dependentsMap: Map<string, Set<string>>; // childPackageName -> set of parent packageNames that depend on it
  directProdDependencies: Set<string>;
  directDevDependencies: Set<string>;
}

export type LockfileParseResult =
  | { success: true; graph: LockfileGraph }
  | {
      success: false;
      reason: 'NO_LOCKFILE_TREE' | 'UNSUPPORTED_FORMAT' | 'PARSE_ERROR';
      message?: string;
    };

interface NpmPackageLockEntry {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface PnpmLockPackageEntry {
  version?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export class LockfileTreeParser {
  /**
   * Parses dependency tree from package-lock.json, pnpm-lock.yaml, or Python lockfile.
   */
  public static parse(projectRoot: string): LockfileParseResult {
    const root = path.resolve(projectRoot);
    let result: LockfileParseResult;

    // 1. Check npm package-lock.json (v2/v3)
    const npmLockPath = path.join(root, 'package-lock.json');
    if (fs.existsSync(npmLockPath)) {
      result = LockfileTreeParser.parseNpmLock(npmLockPath);
    } else if (fs.existsSync(path.join(root, 'pnpm-lock.yaml'))) {
      // 2. Check pnpm-lock.yaml (v6 and v9)
      result = LockfileTreeParser.parsePnpmLock(path.join(root, 'pnpm-lock.yaml'));
    } else if (fs.existsSync(path.join(root, 'poetry.lock'))) {
      // 3. Check poetry.lock
      result = LockfileTreeParser.parsePoetryLock(path.join(root, 'poetry.lock'));
    } else if (fs.existsSync(path.join(root, 'Pipfile.lock'))) {
      // 4. Check Pipfile.lock
      result = LockfileTreeParser.parsePipfileLock(path.join(root, 'Pipfile.lock'));
    } else {
      // 5. Check local venv metadata
      const venvRes = LockfileTreeParser.parseVenvMetadata(root);
      if (venvRes.success) {
        result = venvRes;
      } else if (fs.existsSync(path.join(root, 'go.mod'))) {
        // 6. Check go.mod
        result = LockfileTreeParser.parseGoMod(path.join(root, 'go.mod'));
      } else if (fs.existsSync(path.join(root, 'Cargo.lock'))) {
        // 7. Check Cargo.lock
        result = LockfileTreeParser.parseCargoLock(path.join(root, 'Cargo.lock'));
      } else if (fs.existsSync(path.join(root, 'pom.xml'))) {
        // 8. Check pom.xml
        result = LockfileTreeParser.parseMavenPom(path.join(root, 'pom.xml'));
      } else {
        // Check for unsupported flat lockfiles
        if (
          fs.existsSync(path.join(root, 'yarn.lock')) ||
          fs.existsSync(path.join(root, 'bun.lockb')) ||
          fs.existsSync(path.join(root, 'bun.lock')) ||
          fs.existsSync(path.join(root, 'uv.lock')) ||
          fs.existsSync(path.join(root, 'requirements.txt'))
        ) {
          return {
            success: false,
            reason: 'NO_LOCKFILE_TREE',
            message:
              'Unsupported flat lockfile or tree-less format (yarn.lock, bun.lock, uv.lock, flat requirements.txt)',
          };
        }

        return {
          success: false,
          reason: 'NO_LOCKFILE_TREE',
          message: 'No supported lockfile dependency tree discovered in repository',
        };
      }
    }

    if (result && result.success) {
      LockfileTreeParser.propagateTransitiveDevDependencies(
        result.graph.nodes,
        result.graph.directProdDependencies,
        result.graph.directDevDependencies
      );
    }

    return result;
  }

  /**
   * Propagates devDependency status down through the dependency graph.
   * If a package is never reachable from any direct production dependency,
   * it is strictly a dev/test/build-time dependency.
   */
  public static propagateTransitiveDevDependencies(
    nodes: Map<string, LockfileDependencyNode>,
    directProd: Set<string>,
    directDev: Set<string>
  ): void {
    const prodReachable = new Set<string>();
    const queue: string[] = [];

    for (const prodPkg of directProd) {
      const norm = prodPkg.toLowerCase();
      prodReachable.add(norm);
      queue.push(norm);
    }

    while (queue.length > 0) {
      const current = queue.shift()!;
      const node = nodes.get(current);
      if (node && node.dependencies) {
        for (const dep of node.dependencies) {
          const normDep = dep.toLowerCase();
          if (!prodReachable.has(normDep)) {
            prodReachable.add(normDep);
            queue.push(normDep);
          }
        }
      }
    }

    for (const [name, node] of nodes.entries()) {
      const normName = name.toLowerCase();
      if (!prodReachable.has(normName)) {
        node.isDev = true;
        directDev.add(normName);
      }
    }
  }

  /**
   * Traces whether a package is a transitive dependency of any production-reachable package.
   */
  public static traceTransitiveVia(
    graph: LockfileGraph,
    targetPackage: string,
    productionImportedPackages: Set<string>
  ): { isTransitiveVia: boolean; viaChain: string[] } {
    const normTarget = targetPackage.toLowerCase();

    // BFS upwards through dependentsMap
    const visited = new Set<string>();
    const queue: Array<{ current: string; chain: string[] }> = [
      { current: normTarget, chain: [normTarget] },
    ];

    while (queue.length > 0) {
      const { current, chain } = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      const parents = graph.dependentsMap.get(current);
      if (!parents) continue;

      for (const parent of parents) {
        const newChain = [parent, ...chain];

        // If parent is directly imported in production: FOUND!
        if (
          productionImportedPackages.has(parent) ||
          productionImportedPackages.has(parent.toLowerCase())
        ) {
          return {
            isTransitiveVia: true,
            viaChain: newChain.slice(0, 5),
          };
        }

        if (!visited.has(parent)) {
          queue.push({ current: parent, chain: newChain });
        }
      }
    }

    return { isTransitiveVia: false, viaChain: [] };
  }

  /**
   * Checks if targetPackage is declared directly and has NO dependents among installed packages (Leaf Direct).
   */
  public static isLeafDirectPackage(graph: LockfileGraph, targetPackage: string): boolean {
    const norm = targetPackage.toLowerCase();
    const isDeclared =
      graph.directProdDependencies.has(norm) ||
      graph.directDevDependencies.has(norm) ||
      graph.directProdDependencies.has(targetPackage) ||
      graph.directDevDependencies.has(targetPackage);

    if (!isDeclared) return false;

    // Dependents must be empty
    const dependents = graph.dependentsMap.get(norm);
    return !dependents || dependents.size === 0;
  }

  // --- Parser Implementations ---

  private static parseNpmLock(lockPath: string): LockfileParseResult {
    try {
      const data = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      const packages = data.packages ?? {};

      // Direct dependencies from root package and all workspace packages (keys not containing node_modules/)
      for (const [pkgPath, pkgInfo] of Object.entries(packages) as [
        string,
        NpmPackageLockEntry,
      ][]) {
        if (!pkgPath.includes('node_modules/')) {
          if (pkgInfo.dependencies) {
            for (const k of Object.keys(pkgInfo.dependencies)) directProd.add(k.toLowerCase());
          }
          if (pkgInfo.devDependencies) {
            for (const k of Object.keys(pkgInfo.devDependencies)) directDev.add(k.toLowerCase());
          }
        }
      }

      // Also scan workspace package.json manifests on disk
      LockfileTreeParser.scanWorkspaceManifests(path.dirname(lockPath), directProd, directDev);

      for (const [pkgPath, pkgInfo] of Object.entries(packages) as [
        string,
        NpmPackageLockEntry,
      ][]) {
        if (!pkgPath || pkgPath === '' || !pkgPath.includes('node_modules/')) continue;

        // Extract package name from node_modules/...
        const parts = pkgPath.split('node_modules/');
        const rawName = parts[parts.length - 1];
        if (!rawName) continue;
        const name = rawName.toLowerCase();

        const childDeps: string[] = [];
        if (pkgInfo.dependencies) {
          childDeps.push(...Object.keys(pkgInfo.dependencies).map((s) => s.toLowerCase()));
        }
        if (pkgInfo.optionalDependencies) {
          childDeps.push(...Object.keys(pkgInfo.optionalDependencies).map((s) => s.toLowerCase()));
        }
        if (pkgInfo.peerDependencies) {
          childDeps.push(...Object.keys(pkgInfo.peerDependencies).map((s) => s.toLowerCase()));
        }

        nodes.set(name, {
          name,
          version: pkgInfo.version,
          isDirect: directProd.has(name) || directDev.has(name),
          isDev: Boolean(pkgInfo.dev),
          isOptional: Boolean(pkgInfo.optional),
          isPeer: Boolean(pkgInfo.peer),
          dependencies: childDeps,
        });

        // Populate dependents map: child -> parent
        for (const child of childDeps) {
          if (!dependentsMap.has(child)) {
            dependentsMap.set(child, new Set());
          }
          dependentsMap.get(child)!.add(name);
        }
      }

      return {
        success: true,
        graph: {
          format: 'NPM_V2_V3',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parsePnpmLock(lockPath: string): LockfileParseResult {
    try {
      const content = fs.readFileSync(lockPath, 'utf8');
      const docs = YAML.parseAllDocuments(content).map((d) => d.toJSON());
      if (docs.length === 0 || !docs.some(Boolean)) {
        return { success: false, reason: 'PARSE_ERROR', message: 'Empty pnpm lockfile' };
      }

      let format: 'PNPM_V6' | 'PNPM_V9' = 'PNPM_V6';
      for (const doc of docs) {
        if (!doc) continue;
        const lockfileVersion = String(doc.lockfileVersion ?? '6.0');
        if (lockfileVersion.startsWith('9')) format = 'PNPM_V9';
      }

      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      for (const doc of docs) {
        if (!doc) continue;

        // Direct dependencies from importers (all workspaces) and root
        const importers = doc.importers ?? {};
        for (const importer of Object.values(importers) as Array<{
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        }>) {
          if (importer && typeof importer === 'object') {
            if (importer.dependencies) {
              for (const k of Object.keys(importer.dependencies)) directProd.add(k.toLowerCase());
            }
            if (importer.devDependencies) {
              for (const k of Object.keys(importer.devDependencies)) directDev.add(k.toLowerCase());
            }
          }
        }
        if (!doc.importers) {
          if (doc.dependencies) {
            for (const k of Object.keys(doc.dependencies)) directProd.add(k.toLowerCase());
          }
          if (doc.devDependencies) {
            for (const k of Object.keys(doc.devDependencies)) directDev.add(k.toLowerCase());
          }
        }

        const packagesSection = doc.snapshots ?? doc.packages ?? {};

        for (const [key, pkgInfo] of Object.entries(packagesSection) as [
          string,
          PnpmLockPackageEntry,
        ][]) {
          // Parse package name from pnpm key: e.g. "/axios@1.6.0" or "@scope/pkg@1.0.0"
          let rawName = key.replace(/^\//, '');
          const atIdx = rawName.indexOf('@', 1);
          if (atIdx !== -1) {
            rawName = rawName.slice(0, atIdx);
          }
          const name = rawName.toLowerCase();

          const childDeps: string[] = [];
          if (pkgInfo && typeof pkgInfo === 'object') {
            if (pkgInfo.dependencies) {
              childDeps.push(...Object.keys(pkgInfo.dependencies).map((s) => s.toLowerCase()));
            }
            if (pkgInfo.optionalDependencies) {
              childDeps.push(
                ...Object.keys(pkgInfo.optionalDependencies).map((s) => s.toLowerCase())
              );
            }
          }

          if (!nodes.has(name)) {
            nodes.set(name, {
              name,
              version: typeof pkgInfo?.version === 'string' ? pkgInfo.version : undefined,
              isDirect: directProd.has(name) || directDev.has(name),
              isDev: Boolean(pkgInfo?.dev),
              isOptional: Boolean(pkgInfo?.optional),
              isPeer: false,
              dependencies: childDeps,
            });
          } else {
            const existing = nodes.get(name)!;
            for (const c of childDeps) {
              if (!existing.dependencies.includes(c)) existing.dependencies.push(c);
            }
          }

          for (const child of childDeps) {
            if (!dependentsMap.has(child)) {
              dependentsMap.set(child, new Set());
            }
            dependentsMap.get(child)!.add(name);
          }
        }
      }

      // Also scan workspace package.json manifests on disk
      LockfileTreeParser.scanWorkspaceManifests(path.dirname(lockPath), directProd, directDev);

      // Re-evaluate isDirect for all nodes now that workspace manifests are also scanned
      for (const [name, node] of nodes.entries()) {
        node.isDirect = directProd.has(name) || directDev.has(name);
      }

      return {
        success: true,
        graph: {
          format,
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parsePoetryLock(lockPath: string): LockfileParseResult {
    try {
      const content = fs.readFileSync(lockPath, 'utf8');
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      // Parse pyproject.toml in same dir for direct dependencies
      const pyprojectPath = path.join(path.dirname(lockPath), 'pyproject.toml');
      if (fs.existsSync(pyprojectPath)) {
        try {
          const pyproject = fs.readFileSync(pyprojectPath, 'utf8');
          const prodMatches = pyproject.matchAll(/^[a-zA-Z0-9_-]+(?=\s*=)/gm);
          for (const m of prodMatches) {
            directProd.add(m[0].toLowerCase().replace(/[-_.]+/g, '-'));
          }
          const pep621 = pyproject.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
          if (pep621 && pep621[1]) {
            const listItems = pep621[1].matchAll(/["']([a-zA-Z0-9_.-]+)/g);
            for (const it of listItems) {
              if (it[1]) {
                directProd.add(it[1].toLowerCase().replace(/[-_.]+/g, '-'));
              }
            }
          }
        } catch {
          // Ignored
        }
      }

      // Simple TOML block parser for [[package]]
      const packageBlocks = content.split('[[package]]');
      for (let i = 1; i < packageBlocks.length; i++) {
        const block = packageBlocks[i]!;
        const nameMatch = block.match(/name\s*=\s*["']([^"']+)["']/);
        const categoryMatch = block.match(/category\s*=\s*["']([^"']+)["']/);

        if (nameMatch && nameMatch[1]) {
          const name = nameMatch[1].toLowerCase().replace(/[-_.]+/g, '-');
          const isDev = categoryMatch ? categoryMatch[1] === 'dev' : false;

          const childDeps: string[] = [];
          const depsIdx = block.indexOf('[package.dependencies]');
          if (depsIdx !== -1) {
            const depsSection = block.slice(depsIdx).split('\n[');
            const depLines = depsSection[0]!.split('\n');
            for (let j = 1; j < depLines.length; j++) {
              const dm = depLines[j]!.match(/^([a-zA-Z0-9_.-]+)\s*=/);
              if (dm && dm[1]) {
                childDeps.push(dm[1].toLowerCase().replace(/[-_.]+/g, '-'));
              }
            }
          }

          nodes.set(name, {
            name,
            isDirect: directProd.has(name) || directDev.has(name),
            isDev,
            isOptional: false,
            isPeer: false,
            dependencies: childDeps,
          });

          for (const child of childDeps) {
            if (!dependentsMap.has(child)) {
              dependentsMap.set(child, new Set());
            }
            dependentsMap.get(child)!.add(name);
          }
        }
      }

      return {
        success: true,
        graph: {
          format: 'POETRY',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parsePipfileLock(lockPath: string): LockfileParseResult {
    try {
      const data = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      const defaultDeps = data.default ?? {};
      const devDeps = data.develop ?? {};

      for (const k of Object.keys(defaultDeps)) {
        const name = k.toLowerCase().replace(/[-_.]+/g, '-');
        directProd.add(name);
        nodes.set(name, {
          name,
          isDirect: true,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: [],
        });
      }

      for (const k of Object.keys(devDeps)) {
        const name = k.toLowerCase().replace(/[-_.]+/g, '-');
        directDev.add(name);
        nodes.set(name, {
          name,
          isDirect: true,
          isDev: true,
          isOptional: false,
          isPeer: false,
          dependencies: [],
        });
      }

      return {
        success: true,
        graph: {
          format: 'PIPFILE',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parseVenvMetadata(projectRoot: string): LockfileParseResult {
    const venvs = ['.venv', 'venv', 'env'];
    for (const v of venvs) {
      const sp = path.join(projectRoot, v, 'Lib', 'site-packages');
      const spLinux = path.join(projectRoot, v, 'lib');
      const targetSp = fs.existsSync(sp) ? sp : fs.existsSync(spLinux) ? spLinux : null;
      if (!targetSp) continue;

      try {
        const nodes = new Map<string, LockfileDependencyNode>();
        const dependentsMap = new Map<string, Set<string>>();
        const directProd = new Set<string>();
        const directDev = new Set<string>();

        // Recursively find .dist-info/METADATA
        const scanDistInfo = (dir: string) => {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const e of entries) {
            if (e.isDirectory() && e.name.endsWith('.dist-info')) {
              const metaPath = path.join(dir, e.name, 'METADATA');
              if (fs.existsSync(metaPath)) {
                const meta = fs.readFileSync(metaPath, 'utf8');
                const nameMatch = meta.match(/^Name:\s*([^\r\n]+)/m);
                if (nameMatch && nameMatch[1]) {
                  const pkgName = nameMatch[1]
                    .trim()
                    .toLowerCase()
                    .replace(/[-_.]+/g, '-');
                  const childDeps: string[] = [];

                  const reqMatches = meta.matchAll(/^Requires-Dist:\s*([a-zA-Z0-9_.-]+)/gm);
                  for (const rm of reqMatches) {
                    if (rm[1]) {
                      childDeps.push(rm[1].toLowerCase().replace(/[-_.]+/g, '-'));
                    }
                  }

                  nodes.set(pkgName, {
                    name: pkgName,
                    isDirect: false,
                    isDev: false,
                    isOptional: false,
                    isPeer: false,
                    dependencies: childDeps,
                  });

                  for (const child of childDeps) {
                    if (!dependentsMap.has(child)) {
                      dependentsMap.set(child, new Set());
                    }
                    dependentsMap.get(child)!.add(pkgName);
                  }
                }
              }
            } else if (e.isDirectory() && e.name.startsWith('python')) {
              scanDistInfo(path.join(dir, e.name));
            }
          }
        };

        scanDistInfo(targetSp);

        if (nodes.size > 0) {
          return {
            success: true,
            graph: {
              format: 'VENV_METADATA',
              nodes,
              dependentsMap,
              directProdDependencies: directProd,
              directDevDependencies: directDev,
            },
          };
        }
      } catch {
        // Ignored
      }
    }

    return { success: false, reason: 'NO_LOCKFILE_TREE' };
  }

  private static scanWorkspaceManifests(
    projectRoot: string,
    directProd: Set<string>,
    directDev: Set<string>
  ): void {
    const candidateDirs = ['packages', 'apps', 'libs', 'modules', 'services'];
    for (const d of candidateDirs) {
      const fullDir = path.join(projectRoot, d);
      if (fs.existsSync(fullDir)) {
        try {
          const entries = fs.readdirSync(fullDir, { withFileTypes: true });
          for (const ent of entries) {
            if (ent.isDirectory()) {
              const pkgJsonPath = path.join(fullDir, ent.name, 'package.json');
              if (fs.existsSync(pkgJsonPath)) {
                try {
                  const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
                  if (pkg.dependencies && typeof pkg.dependencies === 'object') {
                    for (const k of Object.keys(pkg.dependencies)) directProd.add(k.toLowerCase());
                  }
                  if (pkg.devDependencies && typeof pkg.devDependencies === 'object') {
                    for (const k of Object.keys(pkg.devDependencies))
                      directDev.add(k.toLowerCase());
                  }
                } catch {}
              }
            }
          }
        } catch {}
      }
    }
  }

  private static parseGoMod(goModPath: string): LockfileParseResult {
    try {
      const content = fs.readFileSync(goModPath, 'utf8');
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      const lines = content.split('\n');
      let inRequireBlock = false;

      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (line.startsWith('require (')) {
          inRequireBlock = true;
          continue;
        }
        if (inRequireBlock && line === ')') {
          inRequireBlock = false;
          continue;
        }

        let reqLine = '';
        if (inRequireBlock) {
          reqLine = line;
        } else if (line.startsWith('require ') && !line.includes('(')) {
          reqLine = line.slice(8).trim();
        }

        if (reqLine && !reqLine.startsWith('//')) {
          const isIndirect = reqLine.includes('// indirect');
          const clean = reqLine.replace(/\/\/.*$/, '').trim();
          const tokens = clean.split(/\s+/);
          if (tokens.length >= 1) {
            const pkgName = tokens[0]!;
            const version = tokens[1];
            const normName = pkgName.toLowerCase();

            if (!isIndirect) {
              directProd.add(normName);
            }

            nodes.set(normName, {
              name: normName,
              version,
              isDirect: !isIndirect,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: [],
            });
          }
        }
      }

      return {
        success: true,
        graph: {
          format: 'GO_MOD',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parseCargoLock(cargoLockPath: string): LockfileParseResult {
    try {
      const content = fs.readFileSync(cargoLockPath, 'utf8');
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      const cargoTomlPath = path.join(path.dirname(cargoLockPath), 'Cargo.toml');
      if (fs.existsSync(cargoTomlPath)) {
        try {
          const tomlContent = fs.readFileSync(cargoTomlPath, 'utf8');
          const depsIdx = tomlContent.indexOf('[dependencies]');
          if (depsIdx !== -1) {
            const section = tomlContent.slice(depsIdx).split('\n[');
            const depLines = section[0]!.split('\n');
            for (let i = 1; i < depLines.length; i++) {
              const dm = depLines[i]!.match(/^([a-zA-Z0-9_.-]+)\s*=/);
              if (dm && dm[1]) {
                directProd.add(dm[1].toLowerCase());
              }
            }
          }
          const devDepsIdx = tomlContent.indexOf('[dev-dependencies]');
          if (devDepsIdx !== -1) {
            const section = tomlContent.slice(devDepsIdx).split('\n[');
            const depLines = section[0]!.split('\n');
            for (let i = 1; i < depLines.length; i++) {
              const dm = depLines[i]!.match(/^([a-zA-Z0-9_.-]+)\s*=/);
              if (dm && dm[1]) {
                directDev.add(dm[1].toLowerCase());
              }
            }
          }
        } catch {
          // Ignored
        }
      }

      const packageBlocks = content.split('[[package]]');
      for (let i = 1; i < packageBlocks.length; i++) {
        const block = packageBlocks[i]!;
        const nameMatch = block.match(/name\s*=\s*["']([^"']+)["']/);
        const verMatch = block.match(/version\s*=\s*["']([^"']+)["']/);

        if (nameMatch && nameMatch[1]) {
          const name = nameMatch[1].toLowerCase();
          const version = verMatch ? verMatch[1] : undefined;
          const childDeps: string[] = [];

          const depsMatch = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
          if (depsMatch && depsMatch[1]) {
            const itemMatches = depsMatch[1].matchAll(/["']([^"'\s]+)(?:\s+[^"']*)?["']/g);
            for (const im of itemMatches) {
              if (im[1]) {
                childDeps.push(im[1].toLowerCase());
              }
            }
          }

          nodes.set(name, {
            name,
            version,
            isDirect: directProd.has(name) || directDev.has(name),
            isDev: directDev.has(name),
            isOptional: false,
            isPeer: false,
            dependencies: childDeps,
          });

          for (const child of childDeps) {
            if (!dependentsMap.has(child)) {
              dependentsMap.set(child, new Set());
            }
            dependentsMap.get(child)!.add(name);
          }
        }
      }

      return {
        success: true,
        graph: {
          format: 'CARGO_LOCK',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private static parseMavenPom(pomPath: string): LockfileParseResult {
    try {
      const content = fs.readFileSync(pomPath, 'utf8');
      const nodes = new Map<string, LockfileDependencyNode>();
      const dependentsMap = new Map<string, Set<string>>();
      const directProd = new Set<string>();
      const directDev = new Set<string>();

      const depRegex = /<dependency>([\s\S]*?)<\/dependency>/gi;
      let match: RegExpExecArray | null;

      while ((match = depRegex.exec(content)) !== null) {
        const block = match[1]!;
        const groupMatch = block.match(/<groupId>([^<]+)<\/groupId>/i);
        const artifactMatch = block.match(/<artifactId>([^<]+)<\/artifactId>/i);
        const versionMatch = block.match(/<version>([^<]+)<\/version>/i);
        const scopeMatch = block.match(/<scope>([^<]+)<\/scope>/i);

        if (artifactMatch && artifactMatch[1]) {
          const artifactId = artifactMatch[1].trim();
          const groupId = groupMatch ? groupMatch[1]!.trim() : '';
          const name = groupId
            ? `${groupId}:${artifactId}`.toLowerCase()
            : artifactId.toLowerCase();
          const isTest = scopeMatch ? scopeMatch[1]!.trim().toLowerCase() === 'test' : false;

          if (isTest) {
            directDev.add(name);
          } else {
            directProd.add(name);
          }

          nodes.set(name, {
            name,
            version: versionMatch ? versionMatch[1]!.trim() : undefined,
            isDirect: true,
            isDev: isTest,
            isOptional: false,
            isPeer: false,
            dependencies: [],
          });
        }
      }

      return {
        success: true,
        graph: {
          format: 'MAVEN_POM',
          nodes,
          dependentsMap,
          directProdDependencies: directProd,
          directDevDependencies: directDev,
        },
      };
    } catch (err) {
      return {
        success: false,
        reason: 'PARSE_ERROR',
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
