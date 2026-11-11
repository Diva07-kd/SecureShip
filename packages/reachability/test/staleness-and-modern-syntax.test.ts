import { describe, it, expect, beforeAll } from 'vitest';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { ReachabilityEngine } from '../src/reachability-engine.js';
import type { NormalizedFinding } from '@secureship/contracts';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Grammar Version Staleness & Modern Syntax Handling (Amendment A13)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('tests Python 3.12 PEP 695 type statement syntax in tree-sitter parser', () => {
    const code = `
# Python 3.12 type statement
type Point[T] = tuple[T, T]

def distance(p: Point[float]) -> float:
    return (p[0] ** 2 + p[1] ** 2) ** 0.5
`;
    const res = TreeSitterLoader.parseFile(code, 'python');
    // If the bundled grammar has an error node for newer syntax, hasError must be true
    // If future grammar supports it, hasError is false. In neither case does it throw or crash.
    expect(res.tree).not.toBeNull();
    expect(res.tree!.rootNode.type).toBe('module');
  });

  it('tests Python 3.12 arbitrary nested f-strings syntax', () => {
    const code = `
items = ['apple', 'banana']
msg = f"Fruits: {', '.join([f'{x.upper()}' for x in items])}"
`;
    const res = TreeSitterLoader.parseFile(code, 'python');
    expect(res.tree).not.toBeNull();
    expect(res.tree!.rootNode.type).toBe('module');
  });

  it('tests TypeScript 5.0 satisfies operator syntax', () => {
    const code = `
type Colors = 'red' | 'green' | 'blue';
const palette = {
  red: [255, 0, 0],
  green: '#00ff00',
  blue: [0, 0, 255]
} satisfies Record<Colors, unknown>;
`;
    const res = TreeSitterLoader.parseFile(code, 'typescript');
    expect(res).toBeDefined();
    expect(res.tree).not.toBeNull();
  });

  it('confirms project containing syntax errors in modern syntax degrades to UNKNOWN, never UNREACHABLE', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-stale-'));
    try {
      fs.writeFileSync(
        path.join(tempDir, 'package.json'),
        JSON.stringify({
          name: 'stale-test',
          main: 'main.py',
        })
      );
      // Syntax that produces a parse error in python
      fs.writeFileSync(
        path.join(tempDir, 'main.py'),
        `# Syntax error in Python
def invalid_modern_syntax(: %%%%%
    pass
`
      );

      const finding: NormalizedFinding = {
        id: 'vuln-stale-1',
        fingerprint: 'a'.repeat(64),
        scannerName: 'trivy',
        ruleId: 'CVE-2024-TEST',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Test vuln',
        description: 'Test vuln',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'CVE-2024-TEST', message: 'Test vuln' }],
        createdAt: new Date().toISOString(),
        package: { name: 'pyyaml', version: '6.0', ecosystem: 'pypi' },
        location: { filePath: 'requirements.txt', startLine: 1, endLine: 1 },
      };

      const engine = new ReachabilityEngine(tempDir);
      await engine.init();
      const verdict = engine.evaluate(finding);

      // Must degrade to UNKNOWN, NEVER UNREACHABLE
      expect(verdict.verdict).toBe('UNKNOWN');
      expect(verdict.verdict).not.toBe('UNREACHABLE');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
