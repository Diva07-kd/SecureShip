import fs from 'node:fs';
import path from 'node:path';

export interface EntrypointDetectionResult {
  entrypoints: string[]; // absolute POSIX paths to production source entrypoint files
  unresolvedEntrypoints: string[]; // declared entrypoints that could not be resolved to source files
}

export class EntrypointDetector {
  /**
   * Discovers all production entrypoint source files for the repository.
   */
  public static detect(
    projectRoot: string,
    userConfigEntrypoints?: string[]
  ): EntrypointDetectionResult {
    const entrypoints = new Set<string>();
    const unresolvedEntrypoints: string[] = [];
    const root = path.resolve(projectRoot);

    // 1. User config entrypoints (secureship.config.json gate2.entrypoints)
    if (userConfigEntrypoints && userConfigEntrypoints.length > 0) {
      for (const ep of userConfigEntrypoints) {
        const abs = path.isAbsolute(ep) ? ep : path.resolve(root, ep);
        if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
          entrypoints.add(abs);
        } else {
          unresolvedEntrypoints.push(ep);
        }
      }
    }

    // Load tsconfig outDir / rootDir mappings to resolve build output back to source
    const tsMapping = EntrypointDetector.loadTsBuildMapping(root);

    // 2. JavaScript / TypeScript package.json entrypoints
    EntrypointDetector.detectFromPackageJson(root, tsMapping, entrypoints, unresolvedEntrypoints);

    // 3. HTML script tag entrypoints (index.html <script src="...">)
    EntrypointDetector.detectFromHtml(root, entrypoints);

    // 4. Framework conventions (Next.js, Remix, Nuxt)
    EntrypointDetector.detectFrameworkConventions(root, entrypoints);

    // 5. Python entrypoints: __main__.py, pyproject.toml, setup.py, manage.py, wsgi, asgi, app.py
    EntrypointDetector.detectPythonEntrypoints(root, entrypoints, unresolvedEntrypoints);

    // 6. Dockerfile CMD / ENTRYPOINT targets
    EntrypointDetector.detectFromDockerfile(root, tsMapping, entrypoints);

    // 7. Go entrypoints: main.go, cmd/*/main.go
    EntrypointDetector.detectGoEntrypoints(root, entrypoints);

    // 8. Rust entrypoints: src/main.rs, src/lib.rs, Cargo.toml targets
    EntrypointDetector.detectRustEntrypoints(root, entrypoints);

    // 9. Java entrypoints: Main.java, *Application.java
    EntrypointDetector.detectJavaEntrypoints(root, entrypoints);

    // 10. C# entrypoints: Program.cs, Startup.cs
    EntrypointDetector.detectCsharpEntrypoints(root, entrypoints);

    // Filter out test/mock/doc files from being production entrypoints
    const filtered = Array.from(entrypoints).filter((ep) => {
      const rel = path.relative(root, ep);
      return !EntrypointDetector.isTestOrMockFile(rel);
    });

    return {
      entrypoints: filtered.sort(),
      unresolvedEntrypoints: unresolvedEntrypoints.sort(),
    };
  }

  /**
   * Checks whether a relative file path belongs to test, mock, fixture, or doc scope.
   */
  public static isTestOrMockFile(relPath: string): boolean {
    const rel = relPath.replace(/\\/g, '/').toLowerCase();
    return (
      rel.includes('/test/') ||
      rel.includes('/tests/') ||
      rel.includes('/__tests__/') ||
      rel.includes('/mock/') ||
      rel.includes('/mocks/') ||
      rel.includes('/docs/') ||
      rel.includes('/examples/') ||
      rel.includes('/fixtures/') ||
      rel.includes('/corpus/') ||
      rel.startsWith('test/') ||
      rel.startsWith('tests/') ||
      rel.startsWith('mock/') ||
      rel.startsWith('mocks/') ||
      rel.startsWith('docs/') ||
      rel.startsWith('examples/') ||
      rel.startsWith('fixtures/') ||
      rel.startsWith('corpus/') ||
      rel.endsWith('.test.ts') ||
      rel.endsWith('.test.js') ||
      rel.endsWith('.test.jsx') ||
      rel.endsWith('.test.tsx') ||
      rel.endsWith('.spec.ts') ||
      rel.endsWith('.spec.js') ||
      rel.endsWith('.spec.jsx') ||
      rel.endsWith('.spec.tsx') ||
      rel.endsWith('_test.py') ||
      rel.startsWith('test_') ||
      rel.endsWith('_test.go') ||
      rel.endsWith('test.java') ||
      rel.endsWith('tests.java') ||
      rel.endsWith('testcase.java') ||
      rel.endsWith('test.cs') ||
      rel.endsWith('tests.cs')
    );
  }

  /**
   * Reads tsconfig.json to discover outDir and rootDir mappings.
   */
  private static loadTsBuildMapping(root: string): { outDir?: string; rootDir?: string } {
    const tsconfigPath = path.join(root, 'tsconfig.json');
    if (!fs.existsSync(tsconfigPath)) return {};
    try {
      const content = fs.readFileSync(tsconfigPath, 'utf8');
      const cleanJson = content.replace(/\/\*[\s\S]*?\*\/|([^:]|^)\/\/.*$/gm, '$1');
      const parsed = JSON.parse(cleanJson);
      return {
        outDir: parsed.compilerOptions?.outDir,
        rootDir: parsed.compilerOptions?.rootDir ?? 'src',
      };
    } catch {
      return {};
    }
  }

  /**
   * Maps a file path pointing to build output (dist/lib) back to source (src/).
   */
  private static mapBuildToSource(
    candidatePath: string,
    root: string,
    mapping: { outDir?: string; rootDir?: string }
  ): string | null {
    const extensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs'];

    const rel = path.relative(root, candidatePath).replace(/\\/g, '/');
    const isBuildOutput = /(?:^|[\\/])(dist|lib|build|out)(?:$|[\\/])/i.test(candidatePath);

    // If it's not build output and exists, it's already a source file
    if (!isBuildOutput && fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
      return candidatePath;
    }

    // If candidate is in outDir (e.g. dist/index.js -> src/index.ts)
    const outDirs = [mapping.outDir?.replace(/^\.\//, ''), 'dist', 'lib', 'build', 'out'].filter(
      Boolean
    ) as string[];
    const rootDir = mapping.rootDir?.replace(/^\.\//, '') ?? 'src';

    for (const out of outDirs) {
      if (rel.startsWith(`${out}/`) || rel === out) {
        const sub = rel.slice(out.length + 1);
        const subNoExt = sub.replace(/\.[^/.]+$/, '').replace(/\.d$/, '');

        for (const ext of extensions) {
          const srcCandidate = path.join(root, rootDir, `${subNoExt}${ext}`);
          if (fs.existsSync(srcCandidate) && fs.statSync(srcCandidate).isFile()) {
            return srcCandidate;
          }
          const srcIndex = path.join(root, rootDir, subNoExt, `index${ext}`);
          if (fs.existsSync(srcIndex) && fs.statSync(srcIndex).isFile()) {
            return srcIndex;
          }
        }
      }
    }

    // Try swapping extensions in same directory (if not in build output)
    if (!isBuildOutput) {
      const noExt = candidatePath.replace(/\.[^/.]+$/, '');
      for (const ext of extensions) {
        const f = `${noExt}${ext}`;
        if (fs.existsSync(f) && fs.statSync(f).isFile()) {
          return f;
        }
      }
    }

    // Fallback: If build output file exists and no source file found, return candidatePath
    if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
      return candidatePath;
    }

    return null;
  }

  /**
   * Detects entrypoints from package.json files (root and workspace packages).
   */
  private static detectFromPackageJson(
    root: string,
    mapping: { outDir?: string; rootDir?: string },
    entrypoints: Set<string>,
    unresolved: string[]
  ): void {
    // 1. Root package.json
    EntrypointDetector.detectFromSinglePackageJson(root, root, mapping, entrypoints, unresolved);

    // 2. Discover workspace package.json entrypoints (pnpm/npm/yarn monorepos)
    const candidateDirs = ['packages', 'apps', 'libs'];
    for (const d of candidateDirs) {
      const parent = path.join(root, d);
      if (!fs.existsSync(parent)) continue;

      try {
        const entries = fs.readdirSync(parent, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const pkgDir = path.join(parent, entry.name);
            EntrypointDetector.detectFromSinglePackageJson(
              pkgDir,
              root,
              mapping,
              entrypoints,
              unresolved
            );
          }
        }
      } catch {
        // Ignored
      }
    }
  }

  private static detectFromSinglePackageJson(
    pkgDir: string,
    root: string,
    mapping: { outDir?: string; rootDir?: string },
    entrypoints: Set<string>,
    unresolved: string[]
  ): void {
    const pkgJsonPath = path.join(pkgDir, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return;

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));

      const candidates: string[] = [];

      if (typeof pkg.main === 'string') candidates.push(pkg.main);
      if (typeof pkg.module === 'string') candidates.push(pkg.module);

      if (pkg.bin) {
        if (typeof pkg.bin === 'string') {
          candidates.push(pkg.bin);
        } else if (typeof pkg.bin === 'object') {
          for (const b of Object.values(pkg.bin)) {
            if (typeof b === 'string') candidates.push(b);
          }
        }
      }

      if (pkg.exports) {
        const collectExports = (exp: unknown) => {
          if (typeof exp === 'string') {
            candidates.push(exp);
          } else if (typeof exp === 'object' && exp !== null) {
            for (const v of Object.values(exp)) {
              collectExports(v);
            }
          }
        };
        collectExports(pkg.exports);
      }

      for (const cand of candidates) {
        if (EntrypointDetector.isNonCodeAsset(cand)) {
          continue;
        }

        if (cand.includes('*')) {
          // Attempt to expand glob or ignore if no code files match (R7)
          const basePattern = path.resolve(pkgDir, cand).replace(/\\/g, '/');
          const dirPart = path.dirname(basePattern.replace(/\*.*$/, 'dummy'));
          if (fs.existsSync(dirPart)) {
            try {
              const files = fs.readdirSync(dirPart);
              let matchedCode = false;
              for (const f of files) {
                const fullP = path.join(dirPart, f);
                const codeExts = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py'];
                if (codeExts.some((ext) => f.endsWith(ext))) {
                  entrypoints.add(fullP);
                  matchedCode = true;
                }
              }
              if (matchedCode) continue;
            } catch {}
          }
          // If non-code glob, ignore
          continue;
        }

        const abs = path.resolve(pkgDir, cand);
        const pkgMapping = fs.existsSync(path.join(pkgDir, 'tsconfig.json'))
          ? EntrypointDetector.loadTsBuildMapping(pkgDir)
          : mapping;
        const resolved =
          EntrypointDetector.mapBuildToSource(abs, pkgDir, pkgMapping) ??
          EntrypointDetector.mapBuildToSource(abs, root, mapping);
        if (resolved) {
          entrypoints.add(resolved);
        } else {
          unresolved.push(cand);
        }
      }
    } catch {
      // Ignored
    }
  }

  /**
   * Identifies non-code asset files or globs that should not be treated as entrypoints.
   */
  public static isNonCodeAsset(cand: string): boolean {
    const nonCodeExts = [
      '.wasm',
      '.json',
      '.css',
      '.scss',
      '.sass',
      '.less',
      '.html',
      '.png',
      '.jpg',
      '.jpeg',
      '.svg',
      '.gif',
      '.ico',
      '.woff',
      '.woff2',
      '.ttf',
      '.eot',
      '.md',
      '.txt',
      '.map',
    ];
    const clean = cand.replace(/\\/g, '/').toLowerCase();
    if (nonCodeExts.some((ext) => clean.endsWith(ext) || clean.includes(`${ext}/*`))) {
      return true;
    }
    if (
      clean.includes('/wasm/') ||
      clean.startsWith('wasm/') ||
      clean.startsWith('./wasm/') ||
      clean.includes('/assets/') ||
      clean.startsWith('assets/') ||
      clean.startsWith('./assets/') ||
      clean.includes('/static/') ||
      clean.startsWith('static/') ||
      clean.startsWith('./static/')
    ) {
      return true;
    }
    return false;
  }

  /**
   * Detects entrypoints from index.html (<script src="...">).
   */
  private static detectFromHtml(root: string, entrypoints: Set<string>): void {
    const htmlFiles = [path.join(root, 'index.html'), path.join(root, 'public', 'index.html')];
    for (const h of htmlFiles) {
      if (!fs.existsSync(h)) continue;
      try {
        const html = fs.readFileSync(h, 'utf8');
        const scriptMatches = html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi);
        for (const match of scriptMatches) {
          const src = match[1];
          if (src && !src.startsWith('http://') && !src.startsWith('https://')) {
            const cleanSrc = src.replace(/^\//, '');
            const candidate = path.resolve(root, cleanSrc);
            if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
              entrypoints.add(candidate);
            }
          }
        }
      } catch {
        // Ignored
      }
    }
  }

  /**
   * Detects Next.js and frontend framework convention entrypoints.
   */
  private static detectFrameworkConventions(root: string, entrypoints: Set<string>): void {
    const patterns = [
      'src/index.ts',
      'src/index.js',
      'src/main.ts',
      'src/main.js',
      'src/App.tsx',
      'src/App.jsx',
      'index.ts',
      'index.js',
      'main.ts',
      'main.js',
      'app/page.tsx',
      'app/page.js',
      'app/layout.tsx',
      'pages/index.tsx',
      'pages/index.js',
      'pages/_app.tsx',
      'pages/_app.js',
    ];

    for (const p of patterns) {
      const full = path.join(root, p);
      if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        entrypoints.add(full);
      }
    }
  }

  /**
   * Detects Python entrypoints: __main__.py, pyproject.toml, setup.py, manage.py, wsgi, asgi, app.py
   */
  private static detectPythonEntrypoints(
    root: string,
    entrypoints: Set<string>,
    unresolved: string[]
  ): void {
    const pythonFiles = [
      '__main__.py',
      'app.py',
      'main.py',
      'manage.py',
      'wsgi.py',
      'asgi.py',
      'cli.py',
      'src/__main__.py',
      'src/main.py',
      'src/app.py',
    ];

    for (const pf of pythonFiles) {
      const full = path.join(root, pf);
      if (fs.existsSync(full) && fs.statSync(full).isFile()) {
        entrypoints.add(full);
      }
    }

    // Check pyproject.toml [project.scripts] or [tool.poetry.scripts]
    const pyprojectPath = path.join(root, 'pyproject.toml');
    const hasPyProject = fs.existsSync(pyprojectPath);
    const hasSetupPy = fs.existsSync(path.join(root, 'setup.py'));

    if (hasPyProject) {
      try {
        const content = fs.readFileSync(pyprojectPath, 'utf8');
        const scriptsSectionMatch = content.match(
          /\[(?:project\.scripts|project\.gui-scripts|tool\.poetry\.scripts)\]([\s\S]*?)(?=\n\[|$)/i
        );
        const scriptMatches =
          scriptsSectionMatch && scriptsSectionMatch[1]
            ? scriptsSectionMatch[1].matchAll(
                /^[a-zA-Z0-9_-]+\s*=\s*["']([^"':]+)(?::[a-zA-Z0-9_]+)?["']/gm
              )
            : [];
        for (const match of scriptMatches) {
          const mod = match[1];
          if (mod) {
            const relPath = path.join(...mod.split('.'));
            const candidates = [
              path.join(root, `${relPath}.py`),
              path.join(root, 'src', `${relPath}.py`),
              path.join(root, relPath, '__init__.py'),
              path.join(root, 'src', relPath, '__init__.py'),
            ];
            let found = false;
            for (const cand of candidates) {
              if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
                entrypoints.add(cand);
                found = true;
                break;
              }
            }
            if (!found) {
              unresolved.push(mod);
            }
          }
        }
      } catch {
        // Ignored
      }
    }

    // For Python libraries with pyproject.toml or setup.py:
    // Detect top-level package directories containing __init__.py (Amendment A7)
    if (hasPyProject || hasSetupPy) {
      const searchDirs = [root, path.join(root, 'src')];
      const excludedDirs = new Set([
        'tests',
        'test',
        'docs',
        'doc',
        'examples',
        'build',
        'dist',
        '.git',
        '.venv',
        'venv',
        'site-packages',
      ]);

      for (const sDir of searchDirs) {
        if (!fs.existsSync(sDir)) continue;
        try {
          const entries = fs.readdirSync(sDir, { withFileTypes: true });
          for (const ent of entries) {
            if (
              ent.isDirectory() &&
              !excludedDirs.has(ent.name.toLowerCase()) &&
              !ent.name.startsWith('.')
            ) {
              const initPy = path.join(sDir, ent.name, '__init__.py');
              if (fs.existsSync(initPy)) {
                entrypoints.add(initPy);
              }
            }
          }
        } catch {
          // Ignored
        }
      }
    }
  }

  /**
   * Detects entrypoints from Dockerfile CMD / ENTRYPOINT.
   */
  private static detectFromDockerfile(
    root: string,
    mapping: { outDir?: string; rootDir?: string },
    entrypoints: Set<string>
  ): void {
    const dockerfiles = [path.join(root, 'Dockerfile'), path.join(root, 'docker', 'Dockerfile')];
    for (const df of dockerfiles) {
      if (!fs.existsSync(df)) continue;
      try {
        const content = fs.readFileSync(df, 'utf8');
        const matches = content.matchAll(/(?:CMD|ENTRYPOINT)\s+\[([^\]]+)\]/gi);
        for (const m of matches) {
          const raw = m[1];
          if (raw) {
            const tokens = raw.split(',').map((t) => t.trim().replace(/^["']|["']$/g, ''));
            for (const t of tokens) {
              if (
                t.endsWith('.js') ||
                t.endsWith('.ts') ||
                t.endsWith('.py') ||
                t.endsWith('.mjs')
              ) {
                const abs = path.resolve(root, t);
                const resolved = EntrypointDetector.mapBuildToSource(abs, root, mapping);
                if (resolved) {
                  entrypoints.add(resolved);
                }
              }
            }
          }
        }
      } catch {
        // Ignored
      }
    }
  }

  /**
   * Detects Go entrypoints: main.go, cmd/ main packages.
   */
  private static detectGoEntrypoints(root: string, entrypoints: Set<string>): void {
    const rootMain = path.join(root, 'main.go');
    if (fs.existsSync(rootMain) && fs.statSync(rootMain).isFile()) {
      entrypoints.add(rootMain);
    }

    const cmdDir = path.join(root, 'cmd');
    if (fs.existsSync(cmdDir) && fs.statSync(cmdDir).isDirectory()) {
      try {
        const subDirs = fs.readdirSync(cmdDir, { withFileTypes: true });
        for (const sub of subDirs) {
          if (sub.isDirectory()) {
            const subMain = path.join(cmdDir, sub.name, 'main.go');
            if (fs.existsSync(subMain) && fs.statSync(subMain).isFile()) {
              entrypoints.add(subMain);
            } else {
              const dirPath = path.join(cmdDir, sub.name);
              const files = fs.readdirSync(dirPath);
              for (const f of files) {
                if (f.endsWith('.go') && !f.endsWith('_test.go')) {
                  entrypoints.add(path.join(dirPath, f));
                }
              }
            }
          }
        }
      } catch {
        // Ignored
      }
    }
  }

  /**
   * Detects Rust entrypoints: src/main.rs, src/lib.rs, Cargo.toml targets.
   */
  private static detectRustEntrypoints(root: string, entrypoints: Set<string>): void {
    const candidates = [
      path.join(root, 'src', 'main.rs'),
      path.join(root, 'src', 'lib.rs'),
      path.join(root, 'main.rs'),
      path.join(root, 'lib.rs'),
    ];

    for (const cand of candidates) {
      if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
        entrypoints.add(cand);
      }
    }

    const binDir = path.join(root, 'src', 'bin');
    if (fs.existsSync(binDir) && fs.statSync(binDir).isDirectory()) {
      try {
        const entries = fs.readdirSync(binDir);
        for (const f of entries) {
          if (f.endsWith('.rs')) {
            entrypoints.add(path.join(binDir, f));
          }
        }
      } catch {
        // Ignored
      }
    }

    const cargoToml = path.join(root, 'Cargo.toml');
    if (fs.existsSync(cargoToml)) {
      try {
        const content = fs.readFileSync(cargoToml, 'utf8');
        const binMatches = content.matchAll(/path\s*=\s*["']([^"']+\.rs)["']/gi);
        for (const m of binMatches) {
          if (m[1]) {
            const p = path.resolve(root, m[1]);
            if (fs.existsSync(p) && fs.statSync(p).isFile()) {
              entrypoints.add(p);
            }
          }
        }
      } catch {
        // Ignored
      }
    }
  }

  /**
   * Detects Java application entrypoints: Main.java, *Application.java.
   */
  private static detectJavaEntrypoints(root: string, entrypoints: Set<string>): void {
    const searchDirs = [path.join(root, 'src', 'main', 'java'), path.join(root, 'src'), root];

    function searchJava(dir: string, depth = 0): void {
      if (depth > 6) return;
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (
              entry.name !== 'test' &&
              entry.name !== 'target' &&
              entry.name !== 'build' &&
              !entry.name.startsWith('.')
            ) {
              searchJava(fullPath, depth + 1);
            }
          } else if (entry.isFile() && entry.name.endsWith('.java')) {
            const name = entry.name;
            if (name.endsWith('Application.java') || name === 'Main.java' || name === 'App.java') {
              entrypoints.add(fullPath);
            }
          }
        }
      } catch {
        // Ignored
      }
    }

    for (const d of searchDirs) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        searchJava(d);
      }
    }
  }

  /**
   * Detects C# entrypoints: Program.cs, Startup.cs.
   */
  private static detectCsharpEntrypoints(root: string, entrypoints: Set<string>): void {
    const searchDirs = [root, path.join(root, 'src')];

    function searchCs(dir: string, depth = 0): void {
      if (depth > 4) return;
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            if (entry.name !== 'bin' && entry.name !== 'obj' && !entry.name.startsWith('.')) {
              searchCs(fullPath, depth + 1);
            }
          } else if (entry.isFile() && entry.name.endsWith('.cs')) {
            const name = entry.name;
            if (name === 'Program.cs' || name === 'Startup.cs') {
              entrypoints.add(fullPath);
            }
          }
        }
      } catch {
        // Ignored
      }
    }

    for (const d of searchDirs) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        searchCs(d);
      }
    }
  }
}
