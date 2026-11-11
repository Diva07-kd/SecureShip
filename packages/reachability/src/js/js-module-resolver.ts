import fs from 'node:fs';
import path from 'node:path';
import { TsConfigResolver, type TsConfigPaths } from './tsconfig-resolver.js';

export type JsResolution =
  | { type: 'BUILTIN'; name: string }
  | { type: 'LOCAL_FILE'; resolvedPath: string }
  | { type: 'PACKAGE'; packageName: string; subpath?: string }
  | { type: 'UNRESOLVED'; specifier: string; reason: string };

const NODE_BUILTINS = new Set([
  'assert',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'domain',
  'events',
  'fs',
  'fs/promises',
  'http',
  'http2',
  'https',
  'inspector',
  'module',
  'net',
  'os',
  'path',
  'path/posix',
  'path/win32',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'repl',
  'stream',
  'stream/consumers',
  'stream/promises',
  'stream/web',
  'string_decoder',
  'test',
  'timers',
  'timers/promises',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'util/types',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib',
]);

const RESOLUTION_EXTENSIONS = [
  '',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
  '.json',
];

export class JsModuleResolver {
  private readonly projectRoot: string;
  private readonly tsconfig: TsConfigPaths;
  private readonly workspacePackages: Map<string, string> = new Map(); // pkgName -> absPath

  constructor(projectRoot: string, tsconfig?: TsConfigPaths) {
    this.projectRoot = path.resolve(projectRoot);
    this.tsconfig = tsconfig ?? TsConfigResolver.load(this.projectRoot);
    this.scanWorkspacePackages();
  }

  /**
   * Detects Node.js built-in modules (including node: prefix).
   */
  public static isBuiltin(specifier: string): boolean {
    if (specifier.startsWith('node:')) return true;
    return NODE_BUILTINS.has(specifier);
  }

  /**
   * Extracts package name from a bare specifier.
   * e.g. "@scope/foo/bar" -> "@scope/foo", "lodash/fp" -> "lodash"
   */
  public static extractPackageName(specifier: string): { packageName: string; subpath?: string } {
    if (specifier.startsWith('@')) {
      const parts = specifier.split('/');
      const packageName = parts.slice(0, 2).join('/');
      const subpath = parts.length > 2 ? parts.slice(2).join('/') : undefined;
      return { packageName, subpath };
    }
    const slashIdx = specifier.indexOf('/');
    if (slashIdx === -1) {
      return { packageName: specifier };
    }
    return {
      packageName: specifier.slice(0, slashIdx),
      subpath: specifier.slice(slashIdx + 1),
    };
  }

  /**
   * Resolves an import specifier to a local file, package, builtin, or unresolved error.
   */
  public resolve(specifier: string, fromFilePath: string): JsResolution {
    // 1. Built-in modules
    if (JsModuleResolver.isBuiltin(specifier)) {
      return { type: 'BUILTIN', name: specifier };
    }

    const fromDir = path.dirname(fromFilePath);

    // 2. Relative imports (./, ../)
    if (specifier.startsWith('./') || specifier.startsWith('../')) {
      const targetPath = path.resolve(fromDir, specifier);
      return this.resolveLocalPath(targetPath, specifier);
    }

    // 3. package.json subpath imports (#alias)
    if (specifier.startsWith('#')) {
      const packageJsonPath = path.join(this.projectRoot, 'package.json');
      if (fs.existsSync(packageJsonPath)) {
        try {
          const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
          if (pkg.imports && pkg.imports[specifier]) {
            const mapped =
              typeof pkg.imports[specifier] === 'string'
                ? pkg.imports[specifier]
                : pkg.imports[specifier].default;
            if (typeof mapped === 'string') {
              const absTarget = path.resolve(this.projectRoot, mapped);
              return this.resolveLocalPath(absTarget, specifier);
            }
          }
        } catch {
          // Ignored
        }
      }
      return { type: 'UNRESOLVED', specifier, reason: `Unresolved subpath import ${specifier}` };
    }

    // 4. tsconfig path aliases (@/*, etc.)
    const aliasedCandidate = TsConfigResolver.resolveAlias(
      specifier,
      this.tsconfig,
      this.projectRoot
    );
    if (aliasedCandidate) {
      const resolved = this.resolveLocalPath(aliasedCandidate, specifier);
      if (resolved.type === 'LOCAL_FILE') {
        return resolved;
      }
    }

    // 5. Monorepo workspace package resolution
    const { packageName, subpath } = JsModuleResolver.extractPackageName(specifier);
    const workspaceTarget = this.workspacePackages.get(packageName);
    if (workspaceTarget) {
      if (subpath) {
        const subPathResolved = path.resolve(workspaceTarget, subpath);
        const resolved = this.resolveLocalPath(subPathResolved, specifier);
        if (resolved.type === 'LOCAL_FILE') {
          return resolved;
        }
      } else {
        const resolved = this.resolveLocalPath(workspaceTarget, specifier);
        if (resolved.type === 'LOCAL_FILE') {
          return resolved;
        }
      }
    }

    // 6. Bare third-party dependency
    return {
      type: 'PACKAGE',
      packageName,
      subpath,
    };
  }

  /**
   * Resolves a candidate path against extensions and directory index files.
   * Strictly enforces that the path must not escape projectRoot (Principle G4).
   */
  private resolveLocalPath(candidatePath: string, originalSpecifier: string): JsResolution {
    const realRoot = fs.existsSync(this.projectRoot)
      ? fs.realpathSync(this.projectRoot)
      : this.projectRoot;

    // Upfront security check: prevent escaping project root
    const relCandidate = path.relative(realRoot, candidatePath);
    if (relCandidate.startsWith('..') || path.isAbsolute(relCandidate)) {
      return {
        type: 'UNRESOLVED',
        specifier: originalSpecifier,
        reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
      };
    }

    const candidateVariants = [candidatePath];
    // In TypeScript ESM, imports often use .js while the source file is .ts or .tsx
    if (candidatePath.endsWith('.js')) {
      candidateVariants.push(
        candidatePath.replace(/\.js$/, '.ts'),
        candidatePath.replace(/\.js$/, '.tsx')
      );
    } else if (candidatePath.endsWith('.mjs')) {
      candidateVariants.push(candidatePath.replace(/\.mjs$/, '.mts'));
    } else if (candidatePath.endsWith('.cjs')) {
      candidateVariants.push(candidatePath.replace(/\.cjs$/, '.cts'));
    }

    // Check direct file with extensions
    for (const cPath of candidateVariants) {
      for (const ext of RESOLUTION_EXTENSIONS) {
        const full = `${cPath}${ext}`;
        if (fs.existsSync(full)) {
          try {
            const stat = fs.statSync(full);
            if (stat.isFile()) {
              const realTarget = fs.realpathSync(full);
              const rel = path.relative(realRoot, realTarget);
              if (rel.startsWith('..') || path.isAbsolute(rel)) {
                return {
                  type: 'UNRESOLVED',
                  specifier: originalSpecifier,
                  reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
                };
              }
              return { type: 'LOCAL_FILE', resolvedPath: realTarget };
            }
          } catch {
            // Ignored
          }
        }
      }
    }

    // Check directory with index files
    if (fs.existsSync(candidatePath)) {
      try {
        const stat = fs.statSync(candidatePath);
        if (stat.isDirectory()) {
          for (const ext of RESOLUTION_EXTENSIONS.filter(Boolean)) {
            const indexFull = path.join(candidatePath, `index${ext}`);
            if (fs.existsSync(indexFull)) {
              const realTarget = fs.realpathSync(indexFull);
              const rel = path.relative(realRoot, realTarget);
              if (rel.startsWith('..') || path.isAbsolute(rel)) {
                return {
                  type: 'UNRESOLVED',
                  specifier: originalSpecifier,
                  reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
                };
              }
              return { type: 'LOCAL_FILE', resolvedPath: realTarget };
            }
          }
        }
      } catch {
        // Ignored
      }
    }

    return {
      type: 'UNRESOLVED',
      specifier: originalSpecifier,
      reason: `Could not resolve local file for '${originalSpecifier}'`,
    };
  }

  /**
   * Discovers monorepo workspace packages (pnpm/npm/yarn) inside the project root.
   */
  private scanWorkspacePackages(): void {
    const candidateDirs = ['packages', 'apps', 'libs'];
    for (const d of candidateDirs) {
      const parent = path.join(this.projectRoot, d);
      if (!fs.existsSync(parent)) continue;

      try {
        const entries = fs.readdirSync(parent);
        for (const entry of entries) {
          const pkgDir = path.join(parent, entry);
          const pkgJson = path.join(pkgDir, 'package.json');
          if (fs.existsSync(pkgJson)) {
            try {
              const data = JSON.parse(fs.readFileSync(pkgJson, 'utf8'));
              if (data.name) {
                // Find entrypoint of workspace package
                const entryFile =
                  data.main || data.module || (data.exports && data.exports['.']) || 'src/index.ts';
                const resolvedEntry =
                  typeof entryFile === 'string'
                    ? path.resolve(pkgDir, entryFile)
                    : path.join(pkgDir, 'src', 'index.ts');
                this.workspacePackages.set(data.name, resolvedEntry);
              }
            } catch {
              // Ignored
            }
          }
        }
      } catch {
        // Ignored
      }
    }
  }
}
