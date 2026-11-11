import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PythonModuleResolver } from '../src/python/python-module-resolver.js';
import { PythonPackageMap } from '../src/python/package-map.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('PythonModuleResolver & PackageMap Suite', () => {
  it('identifies Python standard library builtins', () => {
    const resolver = new PythonModuleResolver(__dirname);
    const fromFile = path.join(__dirname, 'test.py');

    expect(resolver.resolve('os', fromFile, false, 0).type).toBe('BUILTIN');
    expect(resolver.resolve('sys', fromFile, false, 0).type).toBe('BUILTIN');
    expect(resolver.resolve('pathlib', fromFile, false, 0).type).toBe('BUILTIN');
    expect(resolver.resolve('json', fromFile, false, 0).type).toBe('BUILTIN');
  });

  it('maps PyPI distribution names to top-level imported module names via static table', () => {
    expect(PythonPackageMap.getImportableModuleNames('PyYAML').modules).toEqual(['yaml']);
    expect(PythonPackageMap.getImportableModuleNames('Pillow').modules).toEqual(['PIL']);
    expect(PythonPackageMap.getImportableModuleNames('beautifulsoup4').modules).toEqual(['bs4']);
    expect(PythonPackageMap.getImportableModuleNames('scikit-learn').modules).toEqual(['sklearn']);
    expect(PythonPackageMap.getImportableModuleNames('opencv-python').modules).toEqual(['cv2']);
    expect(PythonPackageMap.getImportableModuleNames('python-dateutil').modules).toEqual([
      'dateutil',
    ]);
    expect(PythonPackageMap.getImportableModuleNames('attrs').modules).toEqual(['attr', 'attrs']);
  });

  it('normalizes package names per PEP 503', () => {
    expect(PythonPackageMap.normalizePackageName('Python_DateUtil')).toBe('python-dateutil');
    expect(PythonPackageMap.normalizePackageName('py.yaml')).toBe('py-yaml');
    expect(PythonPackageMap.toModuleIdentifier('python-dateutil')).toBe('python_dateutil');
  });

  it('blocks path traversal attacks attempting to escape project root', () => {
    const resolver = new PythonModuleResolver(__dirname);
    const fromFile = path.join(__dirname, 'test.py');

    const res = resolver.resolve('../../../../../../../etc/passwd', fromFile, true, 5);
    expect(res.type).toBe('UNRESOLVED');
    if (res.type === 'UNRESOLVED') {
      expect(res.reason).toContain('escapes project root');
    }
  });

  it('resolves relative imports and local module/package hierarchies correctly', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'py-resolver-test-'));
    try {
      const pkgDir = path.join(tmp, 'my_pkg');
      const subDir = path.join(pkgDir, 'sub');
      fs.mkdirSync(subDir, { recursive: true });

      fs.writeFileSync(path.join(tmp, 'app.py'), 'import my_pkg\n');
      fs.writeFileSync(path.join(tmp, 'standalone.py'), 'print("root mod")\n');
      fs.writeFileSync(path.join(pkgDir, '__init__.py'), 'from . import utils\n');
      fs.writeFileSync(path.join(pkgDir, 'utils.py'), 'def help(): pass\n');
      fs.writeFileSync(path.join(subDir, '__init__.py'), '# sub init\n');
      fs.writeFileSync(path.join(subDir, 'helper.py'), 'from .. import utils\n');
      fs.writeFileSync(path.join(subDir, 'caller.py'), 'from .helper import help\n');

      const resolver = new PythonModuleResolver(tmp);

      // 1. Resolve root standalone file
      const resRoot = resolver.resolve('standalone', path.join(tmp, 'app.py'), false, 0);
      expect(resRoot.type).toBe('LOCAL_FILE');
      if (resRoot.type === 'LOCAL_FILE') {
        expect(resRoot.resolvedPath).toContain('standalone.py');
      }

      // 2. Resolve package directory with __init__.py from root
      const resPkg = resolver.resolve('my_pkg', path.join(tmp, 'app.py'), false, 0);
      expect(resPkg.type).toBe('LOCAL_FILE');
      if (resPkg.type === 'LOCAL_FILE') {
        expect(resPkg.resolvedPath).toContain('__init__.py');
      }

      // 3. Resolve module inside package: my_pkg.utils
      const resSubMod = resolver.resolve('my_pkg.utils', path.join(tmp, 'app.py'), false, 0);
      expect(resSubMod.type).toBe('LOCAL_FILE');
      if (resSubMod.type === 'LOCAL_FILE') {
        expect(resSubMod.resolvedPath).toContain('utils.py');
      }

      // 4. Resolve relative sibling: from . import utils (relativeLevel 1)
      const resRelSibling = resolver.resolve('.utils', path.join(pkgDir, '__init__.py'), true, 1);
      expect(resRelSibling.type).toBe('LOCAL_FILE');
      if (resRelSibling.type === 'LOCAL_FILE') {
        expect(resRelSibling.resolvedPath).toContain('utils.py');
      }

      // 5. Resolve relative parent: from .. import utils (relativeLevel 2)
      const resRelParent = resolver.resolve('..utils', path.join(subDir, 'helper.py'), true, 2);
      expect(resRelParent.type).toBe('LOCAL_FILE');
      if (resRelParent.type === 'LOCAL_FILE') {
        expect(resRelParent.resolvedPath).toContain('utils.py');
      }

      // 6. Resolve relative directory with __init__.py: from . import sub
      const resRelDir = resolver.resolve('.sub', path.join(pkgDir, 'utils.py'), true, 1);
      expect(resRelDir.type).toBe('LOCAL_FILE');
      if (resRelDir.type === 'LOCAL_FILE') {
        expect(resRelDir.resolvedPath).toContain('__init__.py');
      }

      // 7. Relative traversal escaping root
      const resEscape = resolver.resolve('....outside', path.join(subDir, 'caller.py'), true, 4);
      expect(resEscape.type).toBe('UNRESOLVED');
      if (resEscape.type === 'UNRESOLVED') {
        expect(resEscape.reason).toContain('escapes project root');
      }

      // 8. Third-party package mapping
      const resPypi = resolver.resolve('yaml', path.join(tmp, 'app.py'), false, 0);
      expect(resPypi.type).toBe('PACKAGE');
      if (resPypi.type === 'PACKAGE') {
        expect(resPypi.packageName).toBe('yaml');
      }

      // 9. Directory without __init__.py fails to resolve as python module
      fs.mkdirSync(path.join(tmp, 'empty_dir'));
      const resEmptyDir = resolver.resolve('empty_dir', path.join(tmp, 'app.py'), false, 0);
      expect(resEmptyDir.type).toBe('PACKAGE'); // Fallback to package

      // 10. Candidate .py is actually a directory (stat.isFile() is false)
      fs.mkdirSync(path.join(tmp, 'dir_with_py.py'));
      const resDirPy = resolver.resolve('dir_with_py', path.join(tmp, 'app.py'), false, 0);
      expect(resDirPy.type).toBe('PACKAGE');

      // 11. Symlink escape check if symlinks supported
      let symlinkCreated = false;
      let outsideDir = '';
      try {
        outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-py-'));
        fs.writeFileSync(path.join(outsideDir, 'escaped.py'), 'print("escaped")\n');
        fs.symlinkSync(path.join(outsideDir, 'escaped.py'), path.join(tmp, 'symlink_escape.py'));
        symlinkCreated = true;
      } catch {
        // Symlinks may require elevated privileges on Windows; ignore if unsupported
      }
      if (symlinkCreated) {
        const resSym = resolver.resolve('symlink_escape', path.join(tmp, 'app.py'), false, 0);
        expect(resSym.type).toBe('UNRESOLVED');
        fs.rmSync(outsideDir, { recursive: true, force: true });
      }

      // 12. Bare dot import (from . import something / .)
      const resBareDot = resolver.resolve('.', path.join(pkgDir, 'utils.py'), true, 1);
      expect(resBareDot.type).toBe('LOCAL_FILE');
      if (resBareDot.type === 'LOCAL_FILE') {
        expect(resBareDot.resolvedPath).toContain('__init__.py');
      }

      // 13. isRelative false but starts with dot
      const resLeadDot = resolver.resolve('.utils', path.join(pkgDir, '__init__.py'), false, 0);
      expect(resLeadDot.type).toBe('LOCAL_FILE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
