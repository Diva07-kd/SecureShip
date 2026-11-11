import fs from 'node:fs';
import path from 'node:path';

export interface ReferenceMatch {
  isReferenced: boolean;
  matchedFile?: string;
  matchedLine?: number;
  sampleSnippet?: string;
  incompleteScan?: boolean;
  incompleteReason?: string;
}

export interface ReferenceScanOptions {
  maxFileBytes?: number;
  maxTotalBytes?: number;
  timeoutMs?: number;
  excludeFiles?: Set<string>;
}

const EXCLUDE_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
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
  'docs',
  'documentation',
  'doc',
  'reports',
  'test-results',
  'artifacts',
  'data',
  'datasets',
  'dataset',
  'corpus',
]);

const LOCKFILES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'poetry.lock',
  'pipfile.lock',
  'bun.lockb',
]);

export class ReferenceScanner {
  /**
   * Scans repository non-ignored text files for package or module name references.
   * Per Amendment A5 and Fix C6:
   * - Deterministic sorting
   * - 1 MB per-file size cap
   * - 50 MB repository byte budget
   * - Wall-clock timeout bound
   * - Any error or cap hit degrades to incompleteScan: true
   */
  public static scan(
    projectRoot: string,
    packageName: string,
    moduleNames: string[] = [],
    options?: ReferenceScanOptions
  ): ReferenceMatch {
    const searchTerms = Array.from(
      new Set(
        [
          packageName,
          packageName.toLowerCase(),
          ...moduleNames,
          ...moduleNames.map((m) => m.toLowerCase()),
        ].filter(Boolean)
      )
    );

    if (searchTerms.length === 0) {
      return { isReferenced: false };
    }

    // Build regex to match whole word/identifier or quoted string
    // e.g. "package-name", 'package-name', package_name
    const escapedTerms = searchTerms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const pattern = new RegExp(`(?:['"\`]|\\b)(${escapedTerms.join('|')})(?:['"\`]|\\b)`);

    const filesToScan: string[] = [];
    ReferenceScanner.collectFiles(path.resolve(projectRoot), filesToScan);
    filesToScan.sort();

    const maxFileBytes = options?.maxFileBytes ?? 1_048_576; // 1 MB cap per C6
    const maxTotalBytes = options?.maxTotalBytes ?? 52_428_800; // 50 MB repository budget
    const timeoutMs = options?.timeoutMs ?? 10_000; // 10s wall-clock bound
    const startTime = Date.now();
    let totalBytesRead = 0;

    for (const file of filesToScan) {
      const relFile = path.relative(projectRoot, file).replace(/\\/g, '/');
      if (options?.excludeFiles) {
        if (options.excludeFiles.has(file) || options.excludeFiles.has(relFile)) {
          continue;
        }
      }

      if (Date.now() - startTime > timeoutMs) {
        return {
          isReferenced: false,
          incompleteScan: true,
          incompleteReason: `Reference scan exceeded wall-clock timeout of ${timeoutMs}ms`,
        };
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(file);
      } catch (err) {
        return {
          isReferenced: false,
          incompleteScan: true,
          incompleteReason: `Cannot stat file ${path.relative(projectRoot, file)}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }

      if (stat.size > maxFileBytes) {
        return {
          isReferenced: false,
          incompleteScan: true,
          incompleteReason: `File ${path.relative(projectRoot, file)} exceeds 1 MB limit (${stat.size} bytes)`,
        };
      }

      totalBytesRead += stat.size;
      if (totalBytesRead > maxTotalBytes) {
        return {
          isReferenced: false,
          incompleteScan: true,
          incompleteReason: `Repository byte budget exceeded (${totalBytesRead} > ${maxTotalBytes} bytes)`,
        };
      }

      try {
        const baseName = path.basename(file).toLowerCase();

        // Special handling for package.json: Amendment A5 specifies "package.json scripts" and "bin"
        if (baseName === 'package.json') {
          const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
          // Check scripts
          if (pkg.scripts && typeof pkg.scripts === 'object') {
            for (const [scriptName, scriptCmd] of Object.entries(pkg.scripts)) {
              if (typeof scriptCmd === 'string' && pattern.test(scriptCmd)) {
                const relFile = path.relative(projectRoot, file).replace(/\\/g, '/');
                return {
                  isReferenced: true,
                  matchedFile: relFile,
                  sampleSnippet: `scripts.${scriptName}: ${scriptCmd}`,
                };
              }
            }
          }
          // Check bin
          if (pkg.bin) {
            const binStr = JSON.stringify(pkg.bin);
            if (pattern.test(binStr)) {
              const relFile = path.relative(projectRoot, file).replace(/\\/g, '/');
              return {
                isReferenced: true,
                matchedFile: relFile,
                sampleSnippet: `bin: ${binStr}`,
              };
            }
          }
          continue;
        }

        // Special handling for pyproject.toml: check scripts/config, but skip dependency declaration lines
        if (baseName === 'pyproject.toml') {
          const content = fs.readFileSync(file, 'utf8');
          const lines = content.split(/\r?\n/);
          let inDepsSection = false;
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i]!;
            const trimmed = line.trim();
            if (trimmed.startsWith('[')) {
              inDepsSection =
                trimmed.includes('dependencies') ||
                trimmed.includes('optional-dependencies') ||
                trimmed.includes('tool.poetry.dependencies') ||
                trimmed.includes('tool.poetry.group');
            }
            if (inDepsSection || (trimmed.startsWith('dependencies') && trimmed.includes('='))) {
              continue;
            }
            if (pattern.test(line)) {
              const relFile = path.relative(projectRoot, file).replace(/\\/g, '/');
              return {
                isReferenced: true,
                matchedFile: relFile,
                matchedLine: i + 1,
                sampleSnippet: line.trim().slice(0, 120),
              };
            }
          }
          continue;
        }

        // Special handling for requirements*.txt: standard dependency declaration files
        if (
          baseName === 'requirements.txt' ||
          (baseName.startsWith('requirements') && baseName.endsWith('.txt'))
        ) {
          continue;
        }

        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split(/\r?\n/);

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Only in legacy mode without excludeFiles, skip pure import statements
          if (!options?.excludeFiles) {
            const trimmed = line.trim();
            if (
              trimmed.startsWith('import ') ||
              trimmed.startsWith('from ') ||
              trimmed.startsWith('export ') ||
              (trimmed.startsWith('const ') && trimmed.includes('= require('))
            ) {
              continue;
            }
          }

          if (pattern.test(line)) {
            const relFile = path.relative(projectRoot, file).replace(/\\/g, '/');
            return {
              isReferenced: true,
              matchedFile: relFile,
              matchedLine: i + 1,
              sampleSnippet: line.trim().slice(0, 120),
            };
          }
        }
      } catch (err) {
        return {
          isReferenced: false,
          incompleteScan: true,
          incompleteReason: `Cannot read file ${path.relative(projectRoot, file)}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    return { isReferenced: false };
  }

  private static collectFiles(dir: string, results: string[]): void {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
      entries.sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      return;
    }

    for (const entry of entries) {
      const name = entry.name;
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(name) && !name.startsWith('.venv')) {
          ReferenceScanner.collectFiles(path.join(dir, name), results);
        }
      } else if (entry.isFile()) {
        if (LOCKFILES.has(name.toLowerCase())) continue;
        if (name === 'reachability-expected.json' || name === 'expected.json') continue;
        if (name.endsWith('.min.js') || name.endsWith('.bundle.js')) continue;

        // Skip documentation markdown files (README, docs, changelogs), scan reports, and test files
        const lowerName = name.toLowerCase();
        if (
          lowerName.endsWith('.md') ||
          lowerName.endsWith('.rst') ||
          lowerName.endsWith('.adoc') ||
          lowerName.endsWith('.sarif') ||
          lowerName.endsWith('.sarif.json') ||
          lowerName.includes('report') ||
          lowerName.includes('baseline') ||
          lowerName.includes('.test.') ||
          lowerName.includes('.spec.') ||
          lowerName.startsWith('test_') ||
          lowerName.endsWith('_test.py') ||
          lowerName.endsWith('_test.go')
        ) {
          continue;
        }

        // Collect text and config file extensions
        const ext = path.extname(name).toLowerCase();
        const isCandidate =
          name === 'Dockerfile' ||
          name.startsWith('Dockerfile.') ||
          name === 'Makefile' ||
          name.startsWith('.env') ||
          name.includes('rc') ||
          name.includes('config') ||
          name.startsWith('.') ||
          [
            '.json',
            '.yml',
            '.yaml',
            '.toml',
            '.ini',
            '.cfg',
            '.sh',
            '.bash',
            '.html',
            '.js',
            '.ts',
            '.tsx',
            '.jsx',
            '.py',
            '.cjs',
            '.mjs',
            '.txt',
            '.vue',
            '.svelte',
          ].includes(ext);

        if (isCandidate) {
          results.push(path.join(dir, name));
        }
      }
    }
  }
}
