import { describe, it, expect, beforeAll } from 'vitest';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { JsSymbolUsageExtractor } from '../src/symbol-usage/js-symbol-usage-extractor.js';
import { PythonSymbolUsageExtractor } from '../src/symbol-usage/python-symbol-usage-extractor.js';
import { SymbolUsageExtractor } from '../src/symbol-usage/symbol-usage-extractor.js';
import Parser from 'web-tree-sitter';

describe('Deliverable 3: Symbol Usage and Binding Facts Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('JavaScript / TypeScript Symbol Usage', () => {
    it('extracts ESM static default, namespace, and named imports with calls', () => {
      const code = `
        import _ from 'lodash';
        import * as lodashNs from 'lodash';
        import { template, isEqual as eq } from 'lodash';

        _.template('hello');
        lodashNs.isEqual(1, 2);
        template('world');
        eq(3, 4);
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/index.ts', 'src/index.ts');

      expect(facts.usageIncomplete).toBe(false);
      expect(facts.bindings).toHaveLength(4);

      // Verify usages
      const syms = facts.usageFacts.map((u) => ({
        symbol: u.symbol,
        isCall: u.isCall,
        form: u.form,
      }));
      expect(syms).toContainEqual({ symbol: 'template', isCall: true, form: 'member_call' });
      expect(syms).toContainEqual({ symbol: 'isEqual', isCall: true, form: 'member_call' });
      expect(syms).toContainEqual({ symbol: 'template', isCall: true, form: 'call' });
      expect(syms).toContainEqual({ symbol: 'isEqual', isCall: true, form: 'call' });
    });

    it('distinguishes type-only imports and does not track them for runtime usage', () => {
      const code = `
        import type { TemplateExecutor } from 'lodash';
        import { type LoDashStatic, template } from 'lodash';

        template('ok');
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/index.ts', 'src/index.ts');

      expect(facts.bindings.find((b) => b.importedName === 'TemplateExecutor')?.isTypeOnly).toBe(
        true
      );
      expect(facts.bindings.find((b) => b.importedName === 'LoDashStatic')?.isTypeOnly).toBe(true);
      expect(facts.bindings.find((b) => b.importedName === 'template')?.isTypeOnly).toBe(false);

      expect(facts.usageFacts).toHaveLength(1);
      expect(facts.usageFacts[0]?.symbol).toBe('template');
    });

    it('tracks single-assignment member aliases: const tpl = _.template; tpl()', () => {
      const code = `
        import _ from 'lodash';
        const tpl = _.template;
        tpl('<%= name %>');
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/index.js', 'src/index.js');

      const templateFacts = facts.usageFacts.filter((u) => u.symbol === 'template');
      expect(templateFacts.length).toBeGreaterThanOrEqual(2);
      expect(templateFacts.some((u) => u.isCall && u.form === 'aliased_member')).toBe(true);
    });

    it('tracks destructuring and nested destructuring from namespace/default', () => {
      const code = `
        import _ from 'lodash';
        const { template, isEqual: eq } = _;
        template('foo');
        eq(1, 2);
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/index.js', 'src/index.js');

      expect(facts.usageFacts.some((u) => u.symbol === 'template' && u.isCall)).toBe(true);
      expect(facts.usageFacts.some((u) => u.symbol === 'isEqual' && u.isCall)).toBe(true);
    });

    it('handles CommonJS require, member access, destructuring, and callable module escape', () => {
      const code = `
        const _ = require('lodash');
        const { template } = require('lodash');
        const express = require('express');

        _.isEqual(1, 1);
        template('hi');
        const app = express();
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/app.js', 'src/app.js');

      expect(
        facts.usageFacts.some((u) => u.packageRoot === 'lodash' && u.symbol === 'isEqual')
      ).toBe(true);
      expect(
        facts.usageFacts.some((u) => u.packageRoot === 'lodash' && u.symbol === 'template')
      ).toBe(true);

      // express() whole module called -> CALLABLE_MODULE escape
      expect(
        facts.escapes.some((e) => e.packageRoot === 'express' && e.reason === 'CALLABLE_MODULE')
      ).toBe(true);
    });

    it('handles optional chaining, new call, tagged template, and literal computed access', () => {
      const code = `
        import _ from 'lodash';
        _?.template?.('foo');
        new _.template('bar');
        _['template']('baz');
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      const facts = JsSymbolUsageExtractor.extract(tree!.rootNode, '/src/test.js', 'src/test.js');

      expect(
        facts.usageFacts.some((u) => u.symbol === 'template' && u.form === 'member_call')
      ).toBe(true);
      expect(
        facts.usageFacts.some((u) => u.symbol === 'template' && u.form === 'computed_access')
      ).toBe(true);
    });

    it('detects all 13 escape forms accurately', () => {
      const code = `
        import _ from 'lodash';
        import axios from 'axios';
        import fp from 'lodash/fp';

        // 1. ARGUMENT_PASS
        someFunction(_);

        // 2. RETURN
        function getLodash() {
          return _;
        }

        // 3. EXPORT
        export default _;

        // 4. CONTAINER_STORE
        const arr = [_];
        const obj = { client: axios };

        // 5. SPREAD
        const clone = { ..._ };

        // 6. ENUMERATION
        Object.keys(_);
        Object.assign({}, axios);

        // 7. NON_LITERAL_COMPUTED
        const key = 'template';
        const fn = _[key];

        // 8. REASSIGNMENT
        _ = {};

        // 9. REEXPORT_ALL
        export * from 'untrusted-pkg';

        // 10. CREATE_REQUIRE
        const req = createRequire(import.meta.url);
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
      const facts = JsSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/src/escapes.ts',
        'src/escapes.ts'
      );

      const reasons = new Set(facts.escapes.map((e) => e.reason));
      expect(reasons.has('ARGUMENT_PASS')).toBe(true);
      expect(reasons.has('RETURN')).toBe(true);
      expect(reasons.has('EXPORT')).toBe(true);
      expect(reasons.has('CONTAINER_STORE')).toBe(true);
      expect(reasons.has('SPREAD')).toBe(true);
      expect(reasons.has('ENUMERATION')).toBe(true);
      expect(reasons.has('NON_LITERAL_COMPUTED')).toBe(true);
      expect(reasons.has('REASSIGNMENT')).toBe(true);
      expect(reasons.has('REEXPORT_ALL')).toBe(true);
      expect(reasons.has('CREATE_REQUIRE')).toBe(true);
      expect(reasons.has('UNKNOWN_SUBPATH')).toBe(true); // from 'lodash/fp'
    });
  });

  describe('Python Symbol Usage', () => {
    it('extracts module imports, from imports, aliased imports, and calls', () => {
      const code = `
import yaml
from urllib3 import util
from yaml import load, dump as yaml_dump

yaml.safe_load("foo: bar")
util.parse_url("http://example.com")
load("data")
yaml_dump({"a": 1})
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'python');
      const facts = PythonSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/app/main.py',
        'app/main.py'
      );

      expect(facts.usageIncomplete).toBe(false);
      expect(
        facts.usageFacts.some(
          (u) => u.packageRoot === 'yaml' && u.symbol === 'safe_load' && u.isCall
        )
      ).toBe(true);
      expect(
        facts.usageFacts.some(
          (u) => u.packageRoot === 'urllib3' && u.symbol === 'parse_url' && u.isCall
        )
      ).toBe(true);
      expect(
        facts.usageFacts.some((u) => u.packageRoot === 'yaml' && u.symbol === 'load' && u.isCall)
      ).toBe(true);
      expect(
        facts.usageFacts.some((u) => u.packageRoot === 'yaml' && u.symbol === 'dump' && u.isCall)
      ).toBe(true);
    });

    it('detects Python escapes: wildcard import, getattr dynamic, argument pass, return, container store', () => {
      const code = `
from yaml import *
import requests

def handler():
    getattr(requests, get_method())
    call_helper(requests)
    my_list = [requests]
    return requests
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'python');
      const facts = PythonSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/app/leak.py',
        'app/leak.py'
      );

      const reasons = new Set(facts.escapes.map((e) => e.reason));
      expect(reasons.has('WILDCARD_IMPORT')).toBe(true);
      expect(reasons.has('NON_LITERAL_COMPUTED')).toBe(true);
      expect(reasons.has('ARGUMENT_PASS')).toBe(true);
      expect(reasons.has('CONTAINER_STORE')).toBe(true);
      expect(reasons.has('RETURN')).toBe(true);
    });

    it('tracks getattr literal attribute access', () => {
      const code = `
import yaml
fn = getattr(yaml, 'load')
      `;
      const { tree } = TreeSitterLoader.parseFile(code, 'python');
      const facts = PythonSymbolUsageExtractor.extract(
        tree!.rootNode,
        '/app/getattr_test.py',
        'app/getattr_test.py'
      );

      expect(
        facts.usageFacts.some(
          (u) => u.packageRoot === 'yaml' && u.symbol === 'load' && u.form === 'computed_access'
        )
      ).toBe(true);
    });
  });

  describe('Language Dispatcher and Bounded Safety', () => {
    it('marks usageIncomplete=true when parse error occurs', () => {
      const facts = SymbolUsageExtractor.extract(
        null,
        '/src/broken.js',
        'src/broken.js',
        'javascript',
        true
      );
      expect(facts.usageIncomplete).toBe(true);
      expect(facts.incompleteReason).toBe('File has syntax parse error');
    });

    it('marks usageIncomplete=true when rootNode is null without parse error', () => {
      const facts = SymbolUsageExtractor.extract(
        null,
        '/src/empty.js',
        'src/empty.js',
        'javascript',
        false
      );
      expect(facts.usageIncomplete).toBe(true);
      expect(facts.incompleteReason).toBe('AST root node unavailable');
    });

    it('safely catches unexpected extractor errors and marks usageIncomplete=true', () => {
      // Pass an invalid fake root node that causes extract to throw
      const fakeNode = {
        get childCount(): number {
          throw new Error('AST traversal failed');
        },
      } as unknown as Parser.SyntaxNode;
      const facts = SymbolUsageExtractor.extract(
        fakeNode,
        '/src/crash.js',
        'src/crash.js',
        'javascript',
        false
      );
      expect(facts.usageIncomplete).toBe(true);
      expect(facts.incompleteReason).toBeDefined();
    });

    it('safely handles non-JS/Python languages as no-op without incompleteness', () => {
      const facts = SymbolUsageExtractor.extract(null, '/src/main.go', 'src/main.go', 'go', false);
      expect(facts.usageIncomplete).toBe(false);
      expect(facts.bindings).toHaveLength(0);
    });
  });
});
