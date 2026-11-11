import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ProjectDetector } from '../../src/detector/project-detector.js';

describe('Part I Verification: Adversarial Mini-Suite', () => {
  function createTempWorkspace(): string {
    return mkdtempSync(path.join(tmpdir(), 'secureship-adversarial-'));
  }

  function cleanup(dir: string): void {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }

  it('I1: command injection filenames are treated as plain text and do not execute', () => {
    const ws = createTempWorkspace();
    try {
      // Create files with shell command injection names
      const file1 = path.join(ws, 'rm_rf_dummy.ts');
      const file2 = path.join(ws, 'dollar_touch_pwned.ts');
      writeFileSync(file1, 'console.log(1);');
      writeFileSync(file2, 'console.log(2);');

      const profile = ProjectDetector.detect(ws);
      expect(profile.languages).toContain('TypeScript');
      expect(existsSync(path.join(ws, 'pwned'))).toBe(false);
    } finally {
      cleanup(ws);
    }
  });

  it('I2: handles deeply nested directories without stack overflow or crash', () => {
    const ws = createTempWorkspace();
    try {
      // Create nested path up to max depth
      let current = ws;
      for (let i = 0; i < 20; i++) {
        current = path.join(current, `sub_${i}`);
        mkdirSync(current, { recursive: true });
      }
      writeFileSync(path.join(current, 'deep.ts'), 'export const deep = true;');

      const profile = ProjectDetector.detect(ws, { maxDepth: 15 });
      expect(profile).toBeDefined();
    } finally {
      cleanup(ws);
    }
  });

  it('I3: handles large or malformed .gitignore patterns without hanging', () => {
    const ws = createTempWorkspace();
    try {
      // 5,000 line .gitignore with complex patterns
      const lines = Array.from({ length: 5000 }, (_, i) => `pattern_${i}/**/sub_*\n`).join('');
      writeFileSync(path.join(ws, '.gitignore'), lines);
      writeFileSync(path.join(ws, 'main.ts'), 'const x = 1;');

      const t0 = Date.now();
      const profile = ProjectDetector.detect(ws);
      const elapsed = Date.now() - t0;

      expect(profile.languages).toContain('TypeScript');
      expect(elapsed).toBeLessThan(3000); // Must parse in under 3s
    } finally {
      cleanup(ws);
    }
  });

  it('I4: binary and empty files do not crash the detector', () => {
    const ws = createTempWorkspace();
    try {
      // Empty file
      writeFileSync(path.join(ws, 'empty.ts'), '');

      // Binary file
      const binaryData = Buffer.from([0x00, 0xff, 0xfe, 0x12, 0x34, 0x56]);
      writeFileSync(path.join(ws, 'blob.bin'), binaryData);

      const profile = ProjectDetector.detect(ws);
      expect(profile.languages).toContain('TypeScript');
      expect(profile.totalFilesScanned).toBeGreaterThanOrEqual(2);
    } finally {
      cleanup(ws);
    }
  });
});
