import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cliPackageJsonPath = path.resolve(__dirname, '../../package.json');

interface PackageJsonStructure {
  name: string;
  version: string;
  bin?: Record<string, string>;
  files?: string[];
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

describe('Layer A - CLI Package Manifest Suite (DEV-1 / F-DIS-001)', () => {
  const packageJson: PackageJsonStructure = JSON.parse(
    fs.readFileSync(cliPackageJsonPath, 'utf-8')
  );

  it('A1: no key under dependencies, optionalDependencies, or peerDependencies starts with @secureship/', () => {
    const runtimeDeps = Object.keys(packageJson.dependencies || {});
    const optionalDeps = Object.keys(packageJson.optionalDependencies || {});
    const peerDeps = Object.keys(packageJson.peerDependencies || {});

    const leakedRuntimeSecureship = runtimeDeps.filter((k) => k.startsWith('@secureship/')).sort();
    const leakedOptionalSecureship = optionalDeps
      .filter((k) => k.startsWith('@secureship/'))
      .sort();
    const leakedPeerSecureship = peerDeps.filter((k) => k.startsWith('@secureship/')).sort();

    expect(leakedRuntimeSecureship).toEqual([]);
    expect(leakedOptionalSecureship).toEqual([]);
    expect(leakedPeerSecureship).toEqual([]);
  });

  it('A2: exactly the 9 workspace packages appear in devDependencies with workspace:* specifier', () => {
    const expectedWorkspacePackages = [
      '@secureship/ai',
      '@secureship/context-slicer',
      '@secureship/contracts',
      '@secureship/core-engine',
      '@secureship/fleet',
      '@secureship/patch-engine',
      '@secureship/reachability',
      '@secureship/sandbox',
      '@secureship/scanner-adapters',
    ].sort();

    const devDeps = packageJson.devDependencies || {};
    const actualWorkspacePackages = Object.keys(devDeps)
      .filter((k) => k.startsWith('@secureship/'))
      .sort();

    expect(actualWorkspacePackages).toEqual(expectedWorkspacePackages);
    expect(actualWorkspacePackages.length).toEqual(9);

    for (const pkgName of expectedWorkspacePackages) {
      expect(devDeps[pkgName]).toEqual('workspace:*');
    }
  });

  it('A3: runtime dependencies sorted keys deep-equal the exact allowed 9-entry production list', () => {
    const expectedDependencies = [
      '@inquirer/prompts',
      'chokidar',
      'commander',
      'fast-glob',
      'ignore',
      'picocolors',
      'web-tree-sitter',
      'yaml',
      'zod',
    ].sort();

    const actualDependencies = Object.keys(packageJson.dependencies || {}).sort();

    expect(actualDependencies).toEqual(expectedDependencies);
    expect(actualDependencies.length).toEqual(9);
  });

  it('A4: files includes dist/ and bin.secureship points to ./dist/index.js', () => {
    const files = packageJson.files || [];
    expect(files).toContain('dist/');
    expect(packageJson.bin).toEqual({ secureship: './dist/index.js' });
  });
});
