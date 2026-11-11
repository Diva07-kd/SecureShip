import { existsSync, readdirSync, statSync, realpathSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ignore from 'ignore';
import { ProjectProfileSchema } from '@secureship/contracts';
import type {
  DetectedLanguage,
  DetectedPackageManager,
  ProjectProfile,
  ScannerName,
} from '@secureship/contracts';

export interface DetectorOptions {
  maxDepth?: number;
  includeIgnored?: boolean;
}

const TEST_DIR_REGEX =
  /(?:^|[\\/])(?:test|tests|__tests__|mocks|__mocks__|fixtures|fixture|spec|specs|e2e|testdata)(?:$|[\\/])/i;

export class ProjectDetector {
  /**
   * Normalizes paths to POSIX forward slashes.
   */
  public static toPosix(p: string): string {
    return p.replace(/\\/g, '/');
  }

  /**
   * Safely detects project characteristics, languages, lockfiles, and recommendations.
   */
  public static detect(targetDir: string, options: DetectorOptions = {}): ProjectProfile {
    const rawRoot = path.resolve(targetDir);
    if (!existsSync(rawRoot)) {
      throw new Error(`Workspace path does not exist: ${rawRoot}`);
    }

    const realWorkspaceRoot = realpathSync(rawRoot);
    const maxDepth = options.maxDepth ?? 8;

    // Load .gitignore if present
    const ig = ignore();
    // Default system ignores
    ig.add([
      '.git',
      'node_modules',
      'dist',
      'build',
      'coverage',
      '.turbo',
      '.secureship-shadow',
      '*.log',
    ]);

    const gitignorePath = path.join(realWorkspaceRoot, '.gitignore');
    if (existsSync(gitignorePath)) {
      try {
        const content = readFileSync(gitignorePath, 'utf-8');
        ig.add(content);
      } catch {
        // Ignore read errors
      }
    }

    const languages = new Set<DetectedLanguage>();
    const packageManagers = new Set<DetectedPackageManager>();
    const lockfiles: string[] = [];
    const iacManifests: string[] = [];
    const testDirectories = new Set<string>();
    let totalFilesScanned = 0;

    // Recursive traversal with traversal protection
    const traverse = (currentDir: string, depth: number) => {
      if (depth > maxDepth) return;

      let entries: string[];
      try {
        entries = readdirSync(currentDir);
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry);

        // Security check: Verify resolved realpath is within realWorkspaceRoot
        let realEntryPath: string;
        try {
          realEntryPath = realpathSync(fullPath);
        } catch {
          continue; // Broken symlink
        }

        // Enforce boundary check to prevent symlink traversal outside workspace root
        const relativeToRoot = path.relative(realWorkspaceRoot, realEntryPath);
        if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
          // Traversal detected: outside workspace root
          continue;
        }

        const repoRelativePath = ProjectDetector.toPosix(
          path.relative(realWorkspaceRoot, fullPath)
        );

        if (!options.includeIgnored && ig.ignores(repoRelativePath)) {
          continue;
        }

        let stat;
        try {
          stat = statSync(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          // Check if this directory is a test or mock directory
          if (TEST_DIR_REGEX.test(repoRelativePath)) {
            testDirectories.add(repoRelativePath);
          }
          traverse(fullPath, depth + 1);
        } else if (stat.isFile()) {
          totalFilesScanned++;
          const lowerName = entry.toLowerCase();
          const ext = path.extname(entry).toLowerCase();

          // Check for languages
          if (ext === '.ts' || ext === '.tsx' || lowerName === 'tsconfig.json') {
            languages.add('TypeScript');
          }
          if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') {
            languages.add('JavaScript');
          }
          if (
            ext === '.py' ||
            lowerName === 'requirements.txt' ||
            lowerName === 'pyproject.toml' ||
            lowerName === 'pipfile'
          ) {
            languages.add('Python');
          }
          if (ext === '.go' || lowerName === 'go.mod') {
            languages.add('Go');
          }
          if (ext === '.java' || lowerName === 'pom.xml' || lowerName.includes('gradle')) {
            languages.add('Java');
          }
          if (ext === '.rs' || lowerName === 'cargo.toml') {
            languages.add('Rust');
          }
          if (ext === '.php' || lowerName === 'composer.json') {
            languages.add('PHP');
          }
          if (ext === '.rb' || lowerName === 'gemfile') {
            languages.add('Ruby');
          }

          // Check for package managers & lockfiles
          if (lowerName === 'pnpm-lock.yaml') {
            packageManagers.add('pnpm');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'package-lock.json') {
            packageManagers.add('npm');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'yarn.lock') {
            packageManagers.add('yarn');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'requirements.txt' || lowerName === 'pipfile.lock') {
            packageManagers.add('pip');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'poetry.lock') {
            packageManagers.add('poetry');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'go.sum') {
            packageManagers.add('go');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'pom.xml') {
            packageManagers.add('maven');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'cargo.lock') {
            packageManagers.add('cargo');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'composer.lock') {
            packageManagers.add('composer');
            lockfiles.push(repoRelativePath);
          } else if (lowerName === 'gemfile.lock') {
            packageManagers.add('bundler');
            lockfiles.push(repoRelativePath);
          }

          // Check for IaC manifests
          if (
            lowerName === 'dockerfile' ||
            lowerName.startsWith('dockerfile.') ||
            lowerName.includes('docker-compose')
          ) {
            iacManifests.push(repoRelativePath);
          } else if (ext === '.tf' || ext === '.tfvars') {
            iacManifests.push(repoRelativePath);
          } else if (
            (repoRelativePath.includes('k8s') ||
              repoRelativePath.includes('kubernetes') ||
              repoRelativePath.includes('helm') ||
              lowerName.includes('pod') ||
              lowerName.includes('deploy') ||
              lowerName.includes('service') ||
              lowerName.includes('daemonset') ||
              lowerName.includes('statefulset')) &&
            (ext === '.yaml' || ext === '.yml')
          ) {
            iacManifests.push(repoRelativePath);
          } else if (ext === '.yaml' || ext === '.yml') {
            try {
              const head = readFileSync(fullPath, 'utf8').slice(0, 1024);
              if (head.includes('apiVersion:') && head.includes('kind:')) {
                iacManifests.push(repoRelativePath);
              }
            } catch {
              // Ignore read errors
            }
          }
        }
      }
    };

    traverse(realWorkspaceRoot, 0);

    // Recommend scanners based on detected profile
    const recommendedScanners: ScannerName[] = ['gitleaks'];

    if (languages.size > 0) {
      recommendedScanners.push('opengrep');
    }
    if (lockfiles.length > 0 || packageManagers.size > 0) {
      recommendedScanners.push('osv-scanner');
      recommendedScanners.push('trivy');
    }
    if (iacManifests.length > 0) {
      recommendedScanners.push('checkov');
      if (!recommendedScanners.includes('trivy')) {
        recommendedScanners.push('trivy');
      }
    }

    const hasGit = existsSync(path.join(realWorkspaceRoot, '.git'));

    const rawProfile = {
      workspaceRoot: ProjectDetector.toPosix(realWorkspaceRoot),
      languages: Array.from(languages),
      frameworks: [],
      packageManagers: Array.from(packageManagers),
      lockfiles,
      iacManifests,
      testDirectories: Array.from(testDirectories),
      recommendedScanners,
      totalFilesScanned,
      hasGit,
    };

    return ProjectProfileSchema.parse(rawProfile);
  }
}
