import { describe, it, expect } from 'vitest';
// @ts-expect-error JavaScript module without type declaration
import { verifyPackedArtifact } from '../../../../scripts/verify-packed-artifact.mjs';

describe('Layer F - Packed Artifact Suite (DEV-1 / DEV-2 / F-DIS-001 / F-PKG-001)', () => {
  it('F1 & F2: npm pack produces self-contained artifact with zero @secureship/* deps, required assets, and no leakages', () => {
    const result = verifyPackedArtifact();

    // Must be completely successful with 0 violations
    expect(result.violations).toEqual([]);
    expect(result.success).toEqual(true);

    // F1: Mandatory assets present
    const files = result.files;
    expect(files).toContain('dist/index.js');
    expect(files).toContain('dist/data/vulnerable-symbols.json');
    expect(files).toContain('dist/data/vulnerable-symbols.manifest.json');
    expect(files).toContain('dist/tools.lock.json');
    expect(files).toContain('README.md');
    expect(files).toContain('LICENSE');
    expect(files).toContain('package.json');

    // Rules present
    const ruleFiles = files.filter(
      (f: string) =>
        f.startsWith('dist/rules/secureship-sast/') && (f.endsWith('.yml') || f.endsWith('.yaml'))
    );
    expect(ruleFiles.length).toBeGreaterThanOrEqual(10);

    // WASM files present
    const wasmFiles = files.filter(
      (f: string) => f.startsWith('dist/wasm/') && f.endsWith('.wasm')
    );
    expect(wasmFiles.length).toBeGreaterThanOrEqual(9);

    // No leaks
    const srcFiles = files.filter((f: string) => f.startsWith('src/') || f.includes('/src/'));
    const testFiles = files.filter((f: string) => f.startsWith('test/') || f.includes('/test/'));
    const envFiles = files.filter((f: string) => f.startsWith('.env') || f.includes('/.env'));
    const gitleaksReports = files.filter((f: string) => f.includes('gitleaks-report'));

    expect(srcFiles).toEqual([]);
    expect(testFiles).toEqual([]);
    expect(envFiles).toEqual([]);
    expect(gitleaksReports).toEqual([]);

    // F2: Zero @secureship/* dependencies in packed package.json
    const pkg = result.packageJson;
    const runtimeSecureship = Object.keys(pkg.dependencies || {}).filter((k) =>
      k.startsWith('@secureship/')
    );
    const optionalSecureship = Object.keys(pkg.optionalDependencies || {}).filter((k) =>
      k.startsWith('@secureship/')
    );
    const peerSecureship = Object.keys(pkg.peerDependencies || {}).filter((k) =>
      k.startsWith('@secureship/')
    );

    expect(runtimeSecureship).toEqual([]);
    expect(optionalSecureship).toEqual([]);
    expect(peerSecureship).toEqual([]);

    // Record tarball size in assertions
    expect(result.tarballSize).toBeGreaterThan(1000000); // ~1.8MB
    expect(result.unpackedSize).toBeGreaterThan(10000000); // ~14MB
  });
});
