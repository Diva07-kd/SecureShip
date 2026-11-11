import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { PythonPackageMap } from '../src/python/package-map.js';

describe('PythonPackageMap Unit Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-pkgmap-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  it('maps known PyPI packages via static mapping', () => {
    const yamlRes = PythonPackageMap.getImportableModuleNames('PyYAML', tmpDir);
    expect(yamlRes.modules).toContain('yaml');
    expect(yamlRes.source).toBe('STATIC');

    const pillowRes = PythonPackageMap.getImportableModuleNames('Pillow', tmpDir);
    expect(pillowRes.modules).toContain('PIL');
    expect(pillowRes.source).toBe('STATIC');

    const bs4Res = PythonPackageMap.getImportableModuleNames('beautifulsoup4', tmpDir);
    expect(bs4Res.modules).toContain('bs4');
    expect(bs4Res.source).toBe('STATIC');

    const sklearnRes = PythonPackageMap.getImportableModuleNames('scikit-learn', tmpDir);
    expect(sklearnRes.modules).toContain('sklearn');

    const dateutilRes = PythonPackageMap.getImportableModuleNames('python-dateutil', tmpDir);
    expect(dateutilRes.modules).toContain('dateutil');

    const opencvRes = PythonPackageMap.getImportableModuleNames('opencv-python', tmpDir);
    expect(opencvRes.modules).toContain('cv2');
  });

  it('reads top_level.txt from local virtual environment', () => {
    const distInfoDir = path.join(
      tmpDir,
      '.venv',
      'lib',
      'python3.11',
      'site-packages',
      'my_custom_dist-1.0.0.dist-info'
    );
    fs.mkdirSync(distInfoDir, { recursive: true });
    fs.writeFileSync(path.join(distInfoDir, 'top_level.txt'), 'custom_mod\nother_mod\n');

    const res = PythonPackageMap.getImportableModuleNames('my-custom-dist', tmpDir);
    expect(res.modules).toContain('custom_mod');
    expect(res.modules).toContain('other_mod');
    expect(res.source).toBe('VENV');
  });

  it('returns CANONICAL for direct module identifier and UNMAPPED for invalid identifier', () => {
    const res = PythonPackageMap.getImportableModuleNames('my-cool-package', tmpDir);
    expect(res.source).toBe('CANONICAL');
    expect(res.modules).toContain('my_cool_package');

    const invalidRes = PythonPackageMap.getImportableModuleNames('123-invalid-!!!', tmpDir);
    expect(invalidRes.source).toBe('UNMAPPED');
    expect(invalidRes.modules.length).toBe(0);
  });
});
