import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { CallGraphExtractor } from '../src/taint/call-graph-extractor.js';
import { CallPathProver } from '../src/symbol-usage/call-path-prover.js';
import { ImportGraph } from '../src/graph/import-graph.js';

describe('Deliverable 4: Call Graph Hardening & CallPathProver Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('CallGraphExtractor Hardening & Performance', () => {
    it('handles 10,000-line file with deep nesting without stack overflow', () => {
      // Generate a 10,000-line file with deep nesting
      const lines: string[] = ['function outer() {'];
      const depth = 200;
      for (let i = 0; i < depth; i++) {
        lines.push(`${'  '.repeat(i + 1)}if (true) {`);
      }
      lines.push(`${'  '.repeat(depth + 1)}console.log("deep");`);
      for (let i = depth - 1; i >= 0; i--) {
        lines.push(`${'  '.repeat(i + 1)}}`);
      }
      // Add more lines up to 10,000
      for (let i = 0; i < 9600; i++) {
        lines.push(`const v_${i} = ${i};`);
      }
      lines.push('}');
      lines.push('outer();');

      const code = lines.join('\n');
      const { tree } = TreeSitterLoader.parseFile(code, 'javascript');
      expect(tree).not.toBeNull();

      // Must execute iteratively and return summary without throwing RangeError (stack overflow)
      const summary = CallGraphExtractor.extract(tree!.rootNode, 'deep-nesting.js');
      expect(summary.functions.has('outer')).toBe(true);
      expect(summary.callSites.length).toBeGreaterThanOrEqual(1);
    });

    it('resolves complex callees: member chains, optional chains, new expressions, Python calls', () => {
      const jsCode = `
        const u = user?.profile?.getAccount();
        const client = new ApiClient();
        obj.method.nested();
      `;
      const { tree: jsTree } = TreeSitterLoader.parseFile(jsCode, 'javascript');
      const jsSummary = CallGraphExtractor.extract(jsTree!.rootNode, 'callees.js');

      const calleeNames = jsSummary.callSites.map((c) => c.calleeName);
      expect(calleeNames).toContain('getAccount');
      expect(calleeNames).toContain('ApiClient');
      expect(calleeNames).toContain('nested');

      const pyCode = `
import service
service.api.fetch_data()
      `;
      const { tree: pyTree } = TreeSitterLoader.parseFile(pyCode, 'python');
      const pySummary = CallGraphExtractor.extract(pyTree!.rootNode, 'callees.py');
      expect(pySummary.callSites.some((c) => c.calleeName === 'fetch_data')).toBe(true);
    });
  });

  describe('CallPathProver Chains', () => {
    it('proves call path from entrypoint to helper function containing symbol call', async () => {
      const tempDir = path.join(os.tmpdir(), `call-path-test-${Date.now()}`);
      fs.mkdirSync(path.join(tempDir, 'src'), { recursive: true });

      // package.json
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({
          name: 'call-path-test',
          main: 'src/index.js',
          dependencies: { lodash: '^4.17.21' },
        })
      );

      // src/helper.js
      fs.writeFileSync(
        path.join(tempDir, 'src', 'helper.js'),
        `
import _ from 'lodash';
export function runTemplate(data) {
  return _.template(data)();
}
`
      );

      // src/index.js (Entrypoint)
      fs.writeFileSync(
        path.join(tempDir, 'src', 'index.js'),
        `
import { runTemplate } from './helper.js';

export function handleRequest(req) {
  return runTemplate(req.body);
}

handleRequest({ body: 'test' });
`
      );

      const graph = await ImportGraph.build(tempDir, { noCache: true });

      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/helper.js',
        line: 4,
        enclosingFunction: 'runTemplate',
        symbol: 'template',
      });

      expect(proof.proven).toBe(true);
      expect(proof.chain).not.toBeNull();
      expect(proof.chain!.length).toBeGreaterThan(0);
      expect(proof.chain!.some((hop) => hop.includes('runTemplate'))).toBe(true);
    });

    it('proves module-level (top-level) usage in reachable file by definition using file import chain', async () => {
      const tempDir = path.join(os.tmpdir(), `top-level-test-${Date.now()}`);
      fs.mkdirSync(path.join(tempDir, 'src'), { recursive: true });

      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({
          name: 'top-level-test',
          main: 'src/index.js',
          dependencies: { lodash: '^4.17.21' },
        })
      );

      fs.writeFileSync(
        path.join(tempDir, 'src', 'config.js'),
        `
import _ from 'lodash';
// Top-level usage outside of any function
export const compiled = _.template("hello <%= user %>");
`
      );

      fs.writeFileSync(
        path.join(tempDir, 'src', 'index.js'),
        `
import { compiled } from './config.js';
console.log(compiled({ user: 'world' }));
`
      );

      const graph = await ImportGraph.build(tempDir, { noCache: true });

      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/config.js',
        line: 4,
        enclosingFunction: undefined, // Top level
        symbol: 'template',
      });

      expect(proof.proven).toBe(true);
      expect(proof.chain).not.toBeNull();
      expect(proof.chain).toContain('src/index.js');
      expect(proof.chain).toContain('src/config.js');
    });

    it('returns proven: false when no call chain reaches the enclosing function (uninvoked helper)', async () => {
      const tempDir = path.join(os.tmpdir(), `dead-helper-test-${Date.now()}`);
      fs.mkdirSync(path.join(tempDir, 'src'), { recursive: true });

      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({
          name: 'dead-helper-test',
          main: 'src/index.js',
          dependencies: { lodash: '^4.17.21' },
        })
      );

      fs.writeFileSync(
        path.join(tempDir, 'src', 'helper.js'),
        `
import _ from 'lodash';
// Uninvoked function
export function unusedHelper() {
  _.template("not called");
}
`
      );

      fs.writeFileSync(
        path.join(tempDir, 'src', 'index.js'),
        `
// Helper is imported but unusedHelper is never called
import * as h from './helper.js';
export function main() {
  console.log("running main");
}
main();
`
      );

      const graph = await ImportGraph.build(tempDir, { noCache: true });

      const proof = CallPathProver.proveCallPath(graph, {
        file: 'src/helper.js',
        line: 5,
        enclosingFunction: 'unusedHelper',
        symbol: 'template',
      });

      expect(proof.proven).toBe(false);
      expect(proof.chain).toBeNull();
    });
  });
});
