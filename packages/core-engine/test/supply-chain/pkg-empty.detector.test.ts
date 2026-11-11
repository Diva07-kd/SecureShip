import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { detectEmptyPackage } from '../../src/supply-chain/detectors/pkg-empty.detector.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('PkgEmptyDetector (SC-PKG-*)', () => {
  const ctx: DetectorContext = {
    packageName: 'empty-test-pkg',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: '',
    now: () => new Date('2026-10-21T00:00:00Z'),
  };

  it('reports 0 hits when executable code files exist', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-valid-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'package.json'), '{}', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'README.md'), '# Readme', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'index.js'), 'module.exports = 42;', 'utf-8');

      const hits = detectEmptyPackage(tempDir, {}, { ...ctx, packageDir: tempDir });
      expect(hits).toHaveLength(0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('flags package containing only documentation and license files (SC-PKG-001)', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-empty-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'package.json'), '{}', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'README.md'), '# Placeholder', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'LICENSE'), 'MIT License', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'CHANGELOG.md'), '# Changelog', 'utf-8');

      const hits = detectEmptyPackage(tempDir, {}, { ...ctx, packageDir: tempDir });
      expect(hits).toHaveLength(1);
      expect(hits[0]!.ruleId).toBe('SC-PKG-001');
      expect(hits[0]!.severity).toBe('MEDIUM');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('handles non-existent directory safely', () => {
    const hits = detectEmptyPackage('/non/existent/path/12345', {}, ctx);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.ruleId).toBe('SC-PKG-001');
  });

  it('ignores node_modules and hidden directories, but counts nested source code in src/', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-nested-'));
    try {
      // node_modules has a js file (should be ignored)
      const nmDir = path.join(tempDir, 'node_modules');
      fs.mkdirSync(nmDir, { recursive: true });
      fs.writeFileSync(path.join(nmDir, 'dep.js'), 'code', 'utf-8');

      // .hidden has a js file (should be ignored)
      const dotDir = path.join(tempDir, '.hidden');
      fs.mkdirSync(dotDir, { recursive: true });
      fs.writeFileSync(path.join(dotDir, 'secret.js'), 'code', 'utf-8');

      // Only doc files in root
      fs.writeFileSync(path.join(tempDir, 'README.txt'), 'notes', 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'DOCS.rst'), 'docs', 'utf-8');

      const hitsEmpty = detectEmptyPackage(tempDir, {}, ctx);
      expect(hitsEmpty).toHaveLength(1);

      // Now add nested src/index.ts (should be found and counted)
      const srcDir = path.join(tempDir, 'src');
      fs.mkdirSync(srcDir, { recursive: true });
      fs.writeFileSync(path.join(srcDir, 'index.ts'), 'export const x = 1;', 'utf-8');

      const hitsWithCode = detectEmptyPackage(tempDir, {}, ctx);
      expect(hitsWithCode).toHaveLength(0);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
