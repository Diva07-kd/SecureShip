import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import ts from 'typescript';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { UserConfigSchema, type UserConfig } from '@secureship/contracts';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';

interface ASTViolation {
  file: string;
  kind: string;
  text: string;
  line: number;
}

function scanNodeForFakeSandbox(
  node: ts.Node,
  sourceFile: ts.SourceFile,
  filePath: string,
  violations: ASTViolation[]
): void {
  const TARGET = 'FakeSandboxBackend';

  if (ts.isImportSpecifier(node)) {
    if (node.name.text === TARGET || node.propertyName?.text === TARGET) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      violations.push({
        file: filePath,
        kind: 'ImportSpecifier',
        text: node.getText(sourceFile),
        line: line + 1,
      });
    }
  } else if (ts.isIdentifier(node)) {
    if (node.text === TARGET) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      violations.push({ file: filePath, kind: 'Identifier', text: node.text, line: line + 1 });
    }
  } else if (ts.isPropertyAccessExpression(node)) {
    if (node.name.text === TARGET) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      violations.push({
        file: filePath,
        kind: 'PropertyAccessExpression',
        text: node.name.text,
        line: line + 1,
      });
    }
  } else if (ts.isStringLiteral(node)) {
    if (node.text === TARGET) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      violations.push({ file: filePath, kind: 'StringLiteral', text: node.text, line: line + 1 });
    }
  }

  ts.forEachChild(node, (child) => scanNodeForFakeSandbox(child, sourceFile, filePath, violations));
}

function getAllTsFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...getAllTsFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      results.push(fullPath);
    }
  }
  return results;
}

describe('LAYER A & B: Source Guard & resolveBackend Contract', () => {
  let tempRepo: string;

  beforeEach(() => {
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-guard-test-'));
  });

  afterEach(() => {
    if (tempRepo && fs.existsSync(tempRepo)) {
      fs.rmSync(tempRepo, { recursive: true, force: true });
    }
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  describe('LAYER A: Source Guard (Anti-Fake AST Analysis)', () => {
    it('A1: asserts no TS file in packages/core-engine/src contains FakeSandboxBackend AST nodes', () => {
      const srcDir = path.resolve(__dirname, '../../src');
      const tsFiles = getAllTsFiles(srcDir);
      expect(tsFiles.length).toBeGreaterThan(10);

      const violations: ASTViolation[] = [];
      for (const filePath of tsFiles) {
        const content = fs.readFileSync(filePath, 'utf8');
        const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);
        scanNodeForFakeSandbox(sourceFile, sourceFile, filePath, violations);
      }

      expect(violations).toEqual([]);
    });

    it('A2: asserts body of resolveBackend in both ladder files contains no StringLiteral "fake"', () => {
      const ladderPaths = [
        path.resolve(__dirname, '../../src/remediation/verification-ladder.ts'),
        path.resolve(__dirname, '../../src/remediation/sca-verification-ladder.ts'),
      ];

      for (const ladderPath of ladderPaths) {
        const content = fs.readFileSync(ladderPath, 'utf8');
        const sourceFile = ts.createSourceFile(ladderPath, content, ts.ScriptTarget.Latest, true);

        let resolveBackendFound = false;
        let fakeLiteralCount = 0;

        function findResolveBackend(node: ts.Node): void {
          if (
            ts.isMethodDeclaration(node) &&
            node.name.getText(sourceFile) === 'resolveBackend' &&
            node.body
          ) {
            resolveBackendFound = true;
            function checkLiterals(child: ts.Node): void {
              if (ts.isStringLiteral(child) && child.text === 'fake') {
                fakeLiteralCount++;
              }
              ts.forEachChild(child, checkLiterals);
            }
            ts.forEachChild(node.body, checkLiterals);
          }
          ts.forEachChild(node, findResolveBackend);
        }

        findResolveBackend(sourceFile);
        expect(resolveBackendFound).toBe(true);
        expect(fakeLiteralCount).toBe(0);
      }
    });

    it('A3: demonstrates the AST guard is live and detects FakeSandboxBackend in synthetic source', () => {
      const syntheticCode = [
        "import { FakeSandboxBackend } from '@secureship/sandbox';",
        "import * as sandbox from '@secureship/sandbox';",
        'const alias = FakeSandboxBackend;',
        'const instance = new sandbox.FakeSandboxBackend();',
        "const nameString = 'FakeSandboxBackend';",
      ].join('\n');

      const sourceFile = ts.createSourceFile(
        'synthetic.ts',
        syntheticCode,
        ts.ScriptTarget.Latest,
        true
      );
      const violations: ASTViolation[] = [];
      scanNodeForFakeSandbox(sourceFile, sourceFile, 'synthetic.ts', violations);

      expect(violations.length).toBeGreaterThan(0);
      const kinds = violations.map((v) => v.kind);
      expect(kinds).toContain('ImportSpecifier');
      expect(kinds).toContain('Identifier');
      expect(kinds).toContain('PropertyAccessExpression');
      expect(kinds).toContain('StringLiteral');
    });
  });

  describe('LAYER B: resolveBackend Contract', () => {
    const shadowDir = path.join(os.tmpdir(), 'secureship-shadow-stub');

    it('B1: backend "none" throws exact message on both ladders and never returns an object', () => {
      const noneConfig: UserConfig = UserConfigSchema.parse({
        sandbox: { backend: 'none' },
      });

      expect(() => VerificationLadder.resolveBackend(noneConfig, tempRepo, shadowDir)).toThrowError(
        "Sandbox backend 'none' does not support command execution"
      );

      expect(() =>
        ScaVerificationLadder.resolveBackend(noneConfig, tempRepo, shadowDir)
      ).toThrowError("Sandbox backend 'none' does not support command execution");
    });

    it('B2: introspects UserConfigSchema backend enum and verifies resolveBackend for all valid values', () => {
      const sandboxShape = UserConfigSchema.shape.sandbox.removeDefault().shape;
      const backendEnum = sandboxShape.backend.removeDefault();
      const backendOptions: string[] = [...backendEnum.options];

      expect(backendOptions).toContain('container');
      expect(backendOptions).toContain('host');
      expect(backendOptions).toContain('native-isolated');
      expect(backendOptions).toContain('none');
      expect(backendOptions).toContain('auto');
      expect(backendOptions).toHaveLength(5);

      for (const backendVal of backendOptions) {
        if (backendVal === 'none') {
          continue;
        }

        const config: UserConfig = UserConfigSchema.parse({
          sandbox: { backend: backendVal },
        });

        const codeBackend = VerificationLadder.resolveBackend(config, tempRepo, shadowDir);
        const scaBackend = ScaVerificationLadder.resolveBackend(config, tempRepo, shadowDir);

        expect(typeof codeBackend).toBe('object');
        expect(typeof scaBackend).toBe('object');

        expect(codeBackend.name).not.toBe('fake');
        expect(scaBackend.name).not.toBe('fake');

        if (backendVal === 'host') {
          expect(codeBackend.name).toBe('host');
          expect(scaBackend.name).toBe('host');
        } else if (backendVal === 'native-isolated') {
          expect(codeBackend.name).toBe('native-isolated');
          expect(scaBackend.name).toBe('native-isolated');
        } else if (backendVal === 'container') {
          expect(codeBackend.name).toBe('container');
          expect(scaBackend.name).toBe('container');
        } else if (backendVal === 'auto') {
          expect(codeBackend.name).toBe('container');
          expect(scaBackend.name).toBe('container');
        } else {
          throw new Error(
            `Unexpected backend enum value not covered by resolveBackend test: ${backendVal}`
          );
        }
      }
    });

    it('B3: resolves to "container" backend when sandbox is omitted in UserConfig', () => {
      const defaultCfg: UserConfig = UserConfigSchema.parse({});

      const codeBackend = VerificationLadder.resolveBackend(defaultCfg, tempRepo, shadowDir);
      const scaBackend = ScaVerificationLadder.resolveBackend(defaultCfg, tempRepo, shadowDir);

      expect(codeBackend.name).toBe('container');
      expect(scaBackend.name).toBe('container');
    });
  });
});
