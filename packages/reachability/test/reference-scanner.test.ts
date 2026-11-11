import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ReferenceScanner } from '../src/reference/reference-scanner.js';

describe('ReferenceScanner Suite (Amendment A5)', () => {
  const tmpDir = path.join(os.tmpdir(), `secureship-ref-test-${Date.now()}`);

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  it('detects package references in package.json scripts', () => {
    const pkgJson = {
      name: 'app',
      scripts: {
        build: 'webpack --mode production',
        lint: 'eslint .',
      },
    };
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const res1 = ReferenceScanner.scan(tmpDir, 'webpack', ['webpack']);
    expect(res1.isReferenced).toBe(true);
    expect(res1.matchedFile).toBe('package.json');

    const res2 = ReferenceScanner.scan(tmpDir, 'unrelated-lib', ['unrelated-lib']);
    expect(res2.isReferenced).toBe(false);
  });

  it('detects package references in Dockerfile and CI configuration files', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'Dockerfile'),
      'FROM node:20\nRUN npx tailwindcss -o out.css\n'
    );

    const res = ReferenceScanner.scan(tmpDir, 'tailwindcss');
    expect(res.isReferenced).toBe(true);
    expect(res.matchedFile).toBe('Dockerfile');
  });

  it('detects string literals in production configuration files', () => {
    const configContent = `
module.exports = {
  plugins: ['babel-plugin-transform'],
};
`;
    fs.writeFileSync(path.join(tmpDir, 'babel.config.js'), configContent);

    const res = ReferenceScanner.scan(tmpDir, 'babel-plugin-transform');
    expect(res.isReferenced).toBe(true);
    expect(res.matchedFile).toBe('babel.config.js');
  });

  it('ignores matches inside node_modules and .git', () => {
    const nmDir = path.join(tmpDir, 'node_modules', 'some-pkg');
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, 'index.js'), 'const secretRef = "hidden-lib";');

    const res = ReferenceScanner.scan(tmpDir, 'hidden-lib');
    expect(res.isReferenced).toBe(false);
  });

  it('Defect I1-01: flags incompleteScan when a file exceeds size cap', () => {
    fs.writeFileSync(path.join(tmpDir, 'huge.js'), 'x'.repeat(2000));
    const res = ReferenceScanner.scan(tmpDir, 'some-pkg', [], { maxFileBytes: 1000 });
    expect(res.incompleteScan).toBe(true);
    expect(res.incompleteReason).toContain('exceeds 1 MB limit');
  });

  it('Defect I1-01: flags incompleteScan when total repository byte budget is exceeded', () => {
    fs.writeFileSync(path.join(tmpDir, 'file1.js'), 'a'.repeat(500));
    fs.writeFileSync(path.join(tmpDir, 'file2.js'), 'b'.repeat(600));
    const res = ReferenceScanner.scan(tmpDir, 'some-pkg', [], { maxTotalBytes: 800 });
    expect(res.incompleteScan).toBe(true);
    expect(res.incompleteReason).toContain('Repository byte budget exceeded');
  });

  it('Defect I1-01: flags incompleteScan when wall-clock timeout is exceeded', () => {
    fs.writeFileSync(path.join(tmpDir, 'file1.js'), 'a'.repeat(100));
    const res = ReferenceScanner.scan(tmpDir, 'some-pkg', [], { timeoutMs: -1 });
    expect(res.incompleteScan).toBe(true);
    expect(res.incompleteReason).toContain('exceeded wall-clock timeout');
  });
});
