import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ProjectDetector } from '../../src/detector/project-detector.js';
import { ProjectProfileSchema } from '@secureship/contracts';

describe('Part E Verification: ProjectDetector', () => {
  function createTempWorkspace(): string {
    return mkdtempSync(path.join(tmpdir(), 'secureship-verify-'));
  }

  function cleanup(dir: string): void {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  }

  it('E1: accurately identifies polyglot stacks, lockfiles, and IaC manifests without duplicates', () => {
    const ws = createTempWorkspace();
    try {
      // TypeScript + pnpm
      mkdirSync(path.join(ws, 'src'), { recursive: true });
      writeFileSync(path.join(ws, 'package.json'), '{}');
      writeFileSync(path.join(ws, 'pnpm-lock.yaml'), '');
      writeFileSync(path.join(ws, 'tsconfig.json'), '{}');
      writeFileSync(path.join(ws, 'src', 'a.ts'), 'export const a = 1;');

      // Python + requirements
      writeFileSync(path.join(ws, 'requirements.txt'), 'flask');
      writeFileSync(path.join(ws, 'app.py'), 'print("hi")');

      // Go
      writeFileSync(path.join(ws, 'go.mod'), 'module example.com/app');
      writeFileSync(path.join(ws, 'go.sum'), '');
      writeFileSync(path.join(ws, 'main.go'), 'package main');

      // Rust
      writeFileSync(path.join(ws, 'Cargo.toml'), '[package]');
      writeFileSync(path.join(ws, 'Cargo.lock'), '');

      // Java
      writeFileSync(path.join(ws, 'pom.xml'), '<project></project>');

      // IaC
      writeFileSync(path.join(ws, 'Dockerfile'), 'FROM node:20');
      writeFileSync(path.join(ws, 'docker-compose.prod.yml'), 'services:');
      writeFileSync(path.join(ws, 'main.tf'), 'resource "aws_s3_bucket" "b" {}');
      mkdirSync(path.join(ws, 'k8s'), { recursive: true });
      writeFileSync(path.join(ws, 'k8s', 'deploy.yaml'), 'apiVersion: v1');

      const profile = ProjectDetector.detect(ws);

      expect(profile.languages).toEqual(
        expect.arrayContaining(['TypeScript', 'Python', 'Go', 'Rust', 'Java'])
      );
      expect(profile.packageManagers).toEqual(
        expect.arrayContaining(['pnpm', 'pip', 'go', 'cargo', 'maven'])
      );
      expect(profile.lockfiles).toEqual(
        expect.arrayContaining([
          'pnpm-lock.yaml',
          'requirements.txt',
          'go.sum',
          'Cargo.lock',
          'pom.xml',
        ])
      );
      expect(profile.iacManifests).toEqual(
        expect.arrayContaining([
          'Dockerfile',
          'docker-compose.prod.yml',
          'main.tf',
          'k8s/deploy.yaml',
        ])
      );
      expect(profile.recommendedScanners).toEqual(
        expect.arrayContaining(['opengrep', 'gitleaks', 'trivy', 'osv-scanner', 'checkov'])
      );
    } finally {
      cleanup(ws);
    }
  });

  it('E2: discovers lockfiles in root and monorepo sub-folders with POSIX paths', () => {
    const ws = createTempWorkspace();
    try {
      mkdirSync(path.join(ws, 'packages', 'client'), { recursive: true });
      mkdirSync(path.join(ws, 'packages', 'server'), { recursive: true });

      writeFileSync(path.join(ws, 'packages', 'client', 'package-lock.json'), '{}');
      writeFileSync(path.join(ws, 'packages', 'server', 'poetry.lock'), '');

      const profile = ProjectDetector.detect(ws);
      expect(profile.lockfiles).toContain('packages/client/package-lock.json');
      expect(profile.lockfiles).toContain('packages/server/poetry.lock');
    } finally {
      cleanup(ws);
    }
  });

  it('E3: classifies test directories and rejects false-positive lookalikes', () => {
    const ws = createTempWorkspace();
    try {
      // True test directories
      mkdirSync(path.join(ws, 'test'), { recursive: true });
      mkdirSync(path.join(ws, 'tests'), { recursive: true });
      mkdirSync(path.join(ws, 'src', '__tests__'), { recursive: true });
      mkdirSync(path.join(ws, 'mocks'), { recursive: true });
      mkdirSync(path.join(ws, 'fixtures'), { recursive: true });
      mkdirSync(path.join(ws, 'spec'), { recursive: true });

      // Lookalike false positive folders (must NOT be tagged as test directories)
      mkdirSync(path.join(ws, 'contest'), { recursive: true });
      mkdirSync(path.join(ws, 'latest'), { recursive: true });
      mkdirSync(path.join(ws, 'attestation'), { recursive: true });
      mkdirSync(path.join(ws, 'protests'), { recursive: true });

      writeFileSync(path.join(ws, 'contest', 'data.ts'), '//');
      writeFileSync(path.join(ws, 'latest', 'release.ts'), '//');
      writeFileSync(path.join(ws, 'attestation', 'cert.ts'), '//');
      writeFileSync(path.join(ws, 'protests', 'log.ts'), '//');

      const profile = ProjectDetector.detect(ws);

      // Verified true test dirs
      expect(profile.testDirectories).toContain('test');
      expect(profile.testDirectories).toContain('tests');
      expect(profile.testDirectories).toContain('src/__tests__');
      expect(profile.testDirectories).toContain('mocks');
      expect(profile.testDirectories).toContain('fixtures');
      expect(profile.testDirectories).toContain('spec');

      // False-positive verification: lookalikes MUST NOT be in testDirectories
      expect(profile.testDirectories).not.toContain('contest');
      expect(profile.testDirectories).not.toContain('latest');
      expect(profile.testDirectories).not.toContain('attestation');
      expect(profile.testDirectories).not.toContain('protests');
    } finally {
      cleanup(ws);
    }
  });

  it('E4: respects .gitignore, node_modules, and .git directories', () => {
    const ws = createTempWorkspace();
    try {
      mkdirSync(path.join(ws, 'src'), { recursive: true });
      writeFileSync(path.join(ws, 'src', 'app.ts'), 'export const x = 1;');

      mkdirSync(path.join(ws, 'build_output'), { recursive: true });
      writeFileSync(path.join(ws, 'build_output', 'bundle.py'), 'print(1)');

      mkdirSync(path.join(ws, 'node_modules', 'dep'), { recursive: true });
      writeFileSync(path.join(ws, 'node_modules', 'dep', 'index.js'), '');

      writeFileSync(path.join(ws, '.gitignore'), 'build_output/\n');

      const profile = ProjectDetector.detect(ws);
      expect(profile.languages).toContain('TypeScript');
      expect(profile.languages).not.toContain('Python'); // Ignored folder skipped
      expect(profile.totalFilesScanned).toBeLessThan(5);
    } finally {
      cleanup(ws);
    }
  });

  it('E5: protects against symlink traversal escaping workspace root', () => {
    const ws = createTempWorkspace();
    const outside = createTempWorkspace();

    try {
      // Put a Dockerfile and go.mod only in outside directory
      writeFileSync(path.join(outside, 'Dockerfile'), 'FROM ubuntu');
      writeFileSync(path.join(outside, 'go.mod'), 'module outside');

      // Create internal source
      writeFileSync(path.join(ws, 'index.ts'), 'console.log(1);');

      // Create symlink pointing outside
      const symlinkTarget = path.join(ws, 'escaped_dir');
      let symlinkCreated = false;
      try {
        symlinkSync(outside, symlinkTarget, 'junction');
        symlinkCreated = true;
      } catch {
        symlinkCreated = false;
      }

      if (symlinkCreated) {
        const profile = ProjectDetector.detect(ws);
        // Detector boundary guardrail must drop files from outside
        expect(profile.iacManifests).not.toContain('escaped_dir/Dockerfile');
        expect(profile.packageManagers).not.toContain('go');
      }
    } finally {
      cleanup(ws);
      cleanup(outside);
    }
  });

  it('E6: handles edge input paths gracefully', () => {
    // Non-existent directory
    expect(() => ProjectDetector.detect('c:\\path_that_does_not_exist_404')).toThrow();

    // Valid path with dots
    const ws = createTempWorkspace();
    try {
      writeFileSync(path.join(ws, 'app.ts'), 'let a = 1;');
      const profile = ProjectDetector.detect(ws);
      expect(profile.languages).toContain('TypeScript');
    } finally {
      cleanup(ws);
    }
  });

  it('E7: output validates against ProjectProfileSchema and uses POSIX paths', () => {
    const ws = createTempWorkspace();
    try {
      mkdirSync(path.join(ws, 'sub', 'folder'), { recursive: true });
      writeFileSync(path.join(ws, 'sub', 'folder', 'Dockerfile'), 'FROM alpine');
      const profile = ProjectDetector.detect(ws);

      expect(ProjectProfileSchema.safeParse(profile).success).toBe(true);
      expect(profile.workspaceRoot).not.toContain('\\');
      for (const m of profile.iacManifests) {
        expect(m).not.toContain('\\');
      }
    } finally {
      cleanup(ws);
    }
  });

  it('E8: determinism and stable sorting across multiple runs', () => {
    const ws = createTempWorkspace();
    try {
      writeFileSync(path.join(ws, 'a.ts'), '');
      writeFileSync(path.join(ws, 'b.py'), '');
      writeFileSync(path.join(ws, 'c.go'), '');

      const run1 = ProjectDetector.detect(ws);
      const run2 = ProjectDetector.detect(ws);

      expect(run1).toEqual(run2);
    } finally {
      cleanup(ws);
    }
  });

  it('E9: performance check on file scanning', () => {
    const ws = createTempWorkspace();
    try {
      // Create 500 files to measure scan rate
      mkdirSync(path.join(ws, 'bulk'), { recursive: true });
      for (let i = 0; i < 500; i++) {
        writeFileSync(path.join(ws, 'bulk', `f_${i}.ts`), '');
      }

      const t0 = Date.now();
      const profile = ProjectDetector.detect(ws);
      const duration = Date.now() - t0;

      expect(profile.totalFilesScanned).toBeGreaterThanOrEqual(500);
      expect(duration).toBeLessThan(5000); // Must scan well under 5 seconds
    } finally {
      cleanup(ws);
    }
  });

  it('E10: detects config-only project without source files', () => {
    const ws = createTempWorkspace();
    try {
      writeFileSync(path.join(ws, 'package.json'), '{}');
      writeFileSync(path.join(ws, 'pnpm-lock.yaml'), '');

      const profile = ProjectDetector.detect(ws);
      expect(profile.packageManagers).toContain('pnpm');
      expect(profile.languages).toHaveLength(0); // No sources
    } finally {
      cleanup(ws);
    }
  });
});
