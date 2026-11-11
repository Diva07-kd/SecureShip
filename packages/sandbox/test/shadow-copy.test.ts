import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ShadowCopy } from '../src/shadow/shadow-copy.js';

describe('ShadowCopy Isolated Filtered Copy Builder', () => {
  let tempBase: string;
  let sourceDir: string;

  beforeEach(() => {
    tempBase = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-shadow-test-'));
    sourceDir = path.join(tempBase, 'source');
    fs.mkdirSync(sourceDir, { recursive: true });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempBase, { recursive: true, force: true });
    } catch {}
  });

  it('creates filtered shadow copy excluding .git, node_modules, and sensitive files', () => {
    // Setup source files
    fs.writeFileSync(path.join(sourceDir, 'index.ts'), 'const x = 1;\n');
    fs.mkdirSync(path.join(sourceDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(sourceDir, 'src/app.ts'), 'export const app = 1;\n');

    // Excluded items
    fs.mkdirSync(path.join(sourceDir, '.git'), { recursive: true });
    fs.writeFileSync(path.join(sourceDir, '.git/config'), 'gitconfig');

    fs.mkdirSync(path.join(sourceDir, 'node_modules/pkg'), { recursive: true });
    fs.writeFileSync(path.join(sourceDir, 'node_modules/pkg/index.js'), 'module');

    fs.mkdirSync(path.join(sourceDir, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(sourceDir, 'dist/bundle.js'), 'bundle');

    fs.writeFileSync(path.join(sourceDir, '.env'), 'SECRET_KEY=12345');
    fs.writeFileSync(path.join(sourceDir, 'id_rsa'), 'PRIVATE_KEY');

    const shadow = ShadowCopy.create({ sourceDir });

    try {
      // Source files exist in shadow
      expect(fs.existsSync(path.join(shadow.shadowDir, 'index.ts'))).toBe(true);
      expect(fs.existsSync(path.join(shadow.shadowDir, 'src/app.ts'))).toBe(true);

      // Excluded files do NOT exist in shadow
      expect(fs.existsSync(path.join(shadow.shadowDir, '.git'))).toBe(false);
      expect(fs.existsSync(path.join(shadow.shadowDir, 'node_modules'))).toBe(false);
      expect(fs.existsSync(path.join(shadow.shadowDir, 'dist'))).toBe(false);
      expect(fs.existsSync(path.join(shadow.shadowDir, '.env'))).toBe(false);
      expect(fs.existsSync(path.join(shadow.shadowDir, 'id_rsa'))).toBe(false);

      // Verify original tree unchanged
      expect(shadow.verifyOriginalUnchanged()).toBe(true);
    } finally {
      shadow.cleanup();
    }
  });

  it('excludes files exceeding size threshold (5MB)', () => {
    fs.writeFileSync(path.join(sourceDir, 'normal.txt'), 'small file');
    // Write 5.5MB file
    const bigBuf = Buffer.alloc(5.5 * 1024 * 1024, 'a');
    fs.writeFileSync(path.join(sourceDir, 'big.bin'), bigBuf);

    const shadow = ShadowCopy.create({ sourceDir });

    try {
      expect(fs.existsSync(path.join(shadow.shadowDir, 'normal.txt'))).toBe(true);
      expect(fs.existsSync(path.join(shadow.shadowDir, 'big.bin'))).toBe(false);
    } finally {
      shadow.cleanup();
    }
  });

  it('detects tampering in source directory via verifyOriginalUnchanged()', () => {
    const file = path.join(sourceDir, 'tracked.ts');
    fs.writeFileSync(file, 'original content');

    const shadow = ShadowCopy.create({ sourceDir });

    try {
      expect(shadow.verifyOriginalUnchanged()).toBe(true);

      // Modify original file
      fs.writeFileSync(file, 'tampered content');
      expect(() => shadow.verifyOriginalUnchanged()).toThrow(
        /modified in original repository tree/
      );
    } finally {
      shadow.cleanup();
    }
  });

  it('refuses to create shadow copy if destination is inside source', () => {
    expect(() => {
      // Direct call constructor protection test: source is os.tmpdir() where mkdtemp creates inside
      ShadowCopy.create({ sourceDir: os.tmpdir() });
    }).toThrow(/destination is inside source repository/);
  });
});
