import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JsModuleResolver } from '../src/js/js-module-resolver.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testWorkspaceRoot = path.resolve(__dirname, '..', '..', '..');

describe('JsModuleResolver & TsConfigResolver Suite', () => {
  it('identifies Node builtins correctly', () => {
    expect(JsModuleResolver.isBuiltin('fs')).toBe(true);
    expect(JsModuleResolver.isBuiltin('node:path')).toBe(true);
    expect(JsModuleResolver.isBuiltin('crypto')).toBe(true);
    expect(JsModuleResolver.isBuiltin('express')).toBe(false);
  });

  it('extracts package names for bare specifiers', () => {
    expect(JsModuleResolver.extractPackageName('lodash')).toEqual({
      packageName: 'lodash',
      subpath: undefined,
    });
    expect(JsModuleResolver.extractPackageName('lodash/fp')).toEqual({
      packageName: 'lodash',
      subpath: 'fp',
    });
    expect(JsModuleResolver.extractPackageName('@secureship/contracts')).toEqual({
      packageName: '@secureship/contracts',
      subpath: undefined,
    });
    expect(JsModuleResolver.extractPackageName('@secureship/contracts/schema')).toEqual({
      packageName: '@secureship/contracts',
      subpath: 'schema',
    });
  });

  it('resolves relative imports within project root', () => {
    const resolver = new JsModuleResolver(path.resolve(__dirname, '..'));
    const fromFile = path.resolve(__dirname, '..', 'src', 'index.ts');

    const res = resolver.resolve('./manifest/wasm-manifest.js', fromFile);
    expect(res.type).toBe('LOCAL_FILE');
    if (res.type === 'LOCAL_FILE') {
      expect(res.resolvedPath).toContain('wasm-manifest');
    }
  });

  it('blocks path traversal attacks attempting to escape root (Principle G4)', () => {
    const resolver = new JsModuleResolver(path.resolve(__dirname, '..'));
    const fromFile = path.resolve(__dirname, '..', 'src', 'index.ts');

    const res = resolver.resolve('../../../../../../../etc/passwd', fromFile);
    expect(res.type).toBe('UNRESOLVED');
    if (res.type === 'UNRESOLVED') {
      expect(res.reason).toContain('escapes project root');
    }
  });

  it('resolves workspace package names', () => {
    const resolver = new JsModuleResolver(testWorkspaceRoot);
    const fromFile = path.resolve(testWorkspaceRoot, 'packages', 'reachability', 'src', 'index.ts');

    const res = resolver.resolve('@secureship/contracts', fromFile);
    expect(res.type).toBe('LOCAL_FILE');
  });
});
