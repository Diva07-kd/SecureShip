import { describe, it, expect, beforeAll } from 'vitest';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { JsImportExtractor } from '../src/js/js-import-extractor.js';

describe('JsImportExtractor Syntax Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('extracts standard ESM import forms', () => {
    const code = `
      import defaultExport from "module-a";
      import { foo, bar as baz } from 'module-b';
      import * as all from './local/module-c.js';
      import './side-effect.css';
    `;
    const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
    const res = JsImportExtractor.extract(tree!.rootNode);

    expect(res.hasDynamicImports).toBe(false);
    expect(res.imports).toHaveLength(4);
    expect(res.imports.map((i) => i.specifier)).toEqual([
      'module-a',
      'module-b',
      './local/module-c.js',
      './side-effect.css',
    ]);
    expect(res.imports.every((i) => !i.isTypeOnly)).toBe(true);
  });

  it('detects type-only imports in TypeScript per Amendment A4', () => {
    const code = `
      import type { User } from 'type-pkg-1';
      import type DefaultType from 'type-pkg-2';
      import { type A, type B } from 'type-pkg-3';
      import { type A, runtimeB } from 'mixed-pkg';
    `;
    const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
    const res = JsImportExtractor.extract(tree!.rootNode);

    const type1 = res.imports.find((i) => i.specifier === 'type-pkg-1');
    expect(type1?.isTypeOnly).toBe(true);

    const type2 = res.imports.find((i) => i.specifier === 'type-pkg-2');
    expect(type2?.isTypeOnly).toBe(true);

    const type3 = res.imports.find((i) => i.specifier === 'type-pkg-3');
    expect(type3?.isTypeOnly).toBe(true);

    const mixed = res.imports.find((i) => i.specifier === 'mixed-pkg');
    expect(mixed?.isTypeOnly).toBe(false); // Has runtimeB so it's not strictly type-only
  });

  it('extracts re-exports and export-from statements', () => {
    const code = `
      export { utils } from './utils.js';
      export * from 'lib-all';
      export type { Token } from 'token-types';
    `;
    const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
    const res = JsImportExtractor.extract(tree!.rootNode);

    expect(res.exports).toHaveLength(3);
    const tokenExport = res.exports.find((e) => e.specifier === 'token-types');
    expect(tokenExport?.isTypeOnly).toBe(true);
  });

  it('extracts CommonJS require with string literal', () => {
    const code = `
      const fs = require('fs');
      const lodash = require("lodash");
      const sub = require(\`sub-module\`);
    `;
    const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
    const res = JsImportExtractor.extract(tree!.rootNode);

    expect(res.hasDynamicImports).toBe(false);
    expect(res.imports.map((i) => i.specifier)).toEqual(['fs', 'lodash', 'sub-module']);
  });

  it('extracts dynamic import with string literal', () => {
    const code = `
      async function load() {
        const mod = await import('dynamic-lib');
      }
    `;
    const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
    const res = JsImportExtractor.extract(tree!.rootNode);

    expect(res.hasDynamicImports).toBe(false);
    expect(res.imports[0]?.specifier).toBe('dynamic-lib');
  });

  it('flags non-literal require, non-literal import, eval, and Function as dynamic', () => {
    const dynamicRequire = `const m = require(getModuleName());`;
    const tree1 = TreeSitterLoader.parseFile(dynamicRequire, 'javascript').tree!;
    expect(JsImportExtractor.extract(tree1.rootNode).hasDynamicImports).toBe(true);

    const dynamicImport = `const m = import(variablePath);`;
    const tree2 = TreeSitterLoader.parseFile(dynamicImport, 'javascript').tree!;
    expect(JsImportExtractor.extract(tree2.rootNode).hasDynamicImports).toBe(true);

    const evalCode = `eval("require('hidden')");`;
    const tree3 = TreeSitterLoader.parseFile(evalCode, 'javascript').tree!;
    expect(JsImportExtractor.extract(tree3.rootNode).hasDynamicImports).toBe(true);

    const functionCode = `const fn = new Function("return 1;");`;
    const tree4 = TreeSitterLoader.parseFile(functionCode, 'javascript').tree!;
    expect(JsImportExtractor.extract(tree4.rootNode).hasDynamicImports).toBe(true);
  });
});
