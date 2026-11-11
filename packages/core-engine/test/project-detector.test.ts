import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ProjectDetector } from '../src/detector/project-detector.js';

describe('ProjectDetector', () => {
  let testWorkspace: string;

  beforeEach(() => {
    testWorkspace = mkdtempSync(path.join(tmpdir(), 'secureship-test-'));
  });

  afterEach(() => {
    try {
      rmSync(testWorkspace, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows
    }
  });

  it('should accurately detect TypeScript polyglot project with lockfiles and IaC', () => {
    // Create project structure
    mkdirSync(path.join(testWorkspace, 'src'), { recursive: true });
    writeFileSync(path.join(testWorkspace, 'src', 'index.ts'), 'console.log("hello");');
    writeFileSync(path.join(testWorkspace, 'tsconfig.json'), '{}');

    // Lockfile
    writeFileSync(path.join(testWorkspace, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0');

    // Python file
    writeFileSync(path.join(testWorkspace, 'app.py'), 'print("hi")');
    writeFileSync(path.join(testWorkspace, 'requirements.txt'), 'flask==3.0.0');

    // IaC
    writeFileSync(path.join(testWorkspace, 'Dockerfile'), 'FROM node:20');

    // Test and Mock directories
    mkdirSync(path.join(testWorkspace, 'tests', 'unit'), { recursive: true });
    writeFileSync(path.join(testWorkspace, 'tests', 'unit', 'app.test.ts'), '// test');

    mkdirSync(path.join(testWorkspace, '__mocks__'), { recursive: true });
    writeFileSync(path.join(testWorkspace, '__mocks__', 'api.ts'), '// mock');

    const profile = ProjectDetector.detect(testWorkspace);

    expect(profile.languages).toContain('TypeScript');
    expect(profile.languages).toContain('Python');
    expect(profile.packageManagers).toContain('pnpm');
    expect(profile.packageManagers).toContain('pip');
    expect(profile.lockfiles).toContain('pnpm-lock.yaml');
    expect(profile.lockfiles).toContain('requirements.txt');
    expect(profile.iacManifests).toContain('Dockerfile');
    expect(profile.recommendedScanners).toContain('gitleaks');
    expect(profile.recommendedScanners).toContain('opengrep');
    expect(profile.recommendedScanners).toContain('trivy');
    expect(profile.recommendedScanners).toContain('osv-scanner');
    expect(profile.recommendedScanners).toContain('checkov');

    // Test directories
    const hasTestDir = profile.testDirectories.some(
      (d) => d.includes('tests') || d.includes('mocks')
    );
    expect(hasTestDir).toBe(true);
  });

  it('should respect .gitignore and exclude ignored files', () => {
    mkdirSync(path.join(testWorkspace, 'src'), { recursive: true });
    writeFileSync(path.join(testWorkspace, 'src', 'index.ts'), 'export const a = 1;');

    mkdirSync(path.join(testWorkspace, 'temp_build'), { recursive: true });
    writeFileSync(path.join(testWorkspace, 'temp_build', 'bundle.js'), 'var x = 1;');

    // Add .gitignore
    writeFileSync(path.join(testWorkspace, '.gitignore'), 'temp_build/\n');

    const profile = ProjectDetector.detect(testWorkspace);
    expect(profile.languages).toContain('TypeScript');
    // bundle.js should be ignored, so JavaScript language not added if only inside temp_build
    expect(profile.languages).not.toContain('JavaScript');
  });
});
