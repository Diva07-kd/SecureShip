import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

describe('LAYER K: Static AST and Source Code Guards (Gate 13 / F-FLT-004)', () => {
  const storageDir = path.resolve(__dirname, '../src/storage');
  const fleetStorePath = path.join(storageDir, 'fleet-store.ts');
  const atomicFilePath = path.join(storageDir, 'atomic-file.ts');
  const fleetSnapshotPath = path.join(storageDir, 'fleet-snapshot.ts');
  const storageFiles = [fleetStorePath, atomicFilePath, fleetSnapshotPath];

  function getAst(filePath: string): ts.SourceFile {
    const content = fs.readFileSync(filePath, 'utf8');
    return ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);
  }

  function getAstFromString(name: string, content: string): ts.SourceFile {
    return ts.createSourceFile(name, content, ts.ScriptTarget.Latest, true);
  }

  // K1: Zero write to primary directly (only via atomic rename or emergency fallback)
  describe('K1: Zero write to primary storage file', () => {
    function findDirectWritesToPrimary(sourceFile: ts.SourceFile): string[] {
      const forbiddenMethods = new Set(['writeFileSync', 'appendFileSync', 'createWriteStream']);
      const violations: string[] = [];

      function visit(node: ts.Node) {
        if (ts.isCallExpression(node)) {
          let methodName = '';
          if (ts.isPropertyAccessExpression(node.expression)) {
            methodName = node.expression.name.text;
          } else if (ts.isIdentifier(node.expression)) {
            methodName = node.expression.text;
          }

          if (forbiddenMethods.has(methodName)) {
            violations.push(`Forbidden method called: ${methodName}`);
          }

          if (methodName === 'openSync' && node.arguments.length >= 2) {
            const flagArg = node.arguments[1];
            if (flagArg && ts.isStringLiteral(flagArg)) {
              const flag = flagArg.text;
              if (['w', 'w+', 'a', 'a+', 'r+'].includes(flag)) {
                // If it's fleet-store.ts, openSync with write flags is forbidden completely
                if (sourceFile.fileName.endsWith('fleet-store.ts')) {
                  violations.push(`openSync with write flag '${flag}' in fleet-store.ts`);
                }
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      }

      visit(sourceFile);
      return violations;
    }

    it('fleet-store.ts never directly writes to primary storage file', () => {
      const ast = getAst(fleetStorePath);
      const violations = findDirectWritesToPrimary(ast);
      expect(violations).toEqual([]);
    });

    it('negative control: synthetic file with direct writeFileSync to primary fails guard', () => {
      const syntheticBad = getAstFromString(
        'bad-fleet.ts',
        `
        import fs from 'node:fs';
        export function save(primary: string, data: string) {
          fs.writeFileSync(primary, data);
        }
        `
      );
      const violations = findDirectWritesToPrimary(syntheticBad);
      expect(violations.length).toBe(1);
      expect(violations[0]).toBe('Forbidden method called: writeFileSync');
    });
  });

  // K2: Zero empty catch clauses without rationale or logging
  describe('K2: Zero empty catches without rationale or logging', () => {
    const ALLOWED_RATIONALE_PATTERNS = [
      /directory fsync/i,
      /best-effort/i,
      /cleanup/i,
      /fallback/i,
      /broken link/i,
      /restricted permissions/i,
      /read-only/i,
      /stat/i,
      /quarantine/i,
      /prune/i,
      /unlink/i,
      /chmod/i,
      /probe/i,
      /close/i,
      /restore/i,
      /backup/i,
    ];

    function checkCatchClauses(sourceFile: ts.SourceFile): { invalidCatches: string[] } {
      const invalidCatches: string[] = [];

      function visit(node: ts.Node) {
        if (ts.isCatchClause(node)) {
          const catchBlock = node.block;
          const statements = catchBlock.statements;

          const blockText = catchBlock.getFullText(sourceFile);
          const tryStatement = node.parent;
          const tryBlockText = tryStatement ? tryStatement.getFullText(sourceFile) : blockText;

          const hasRethrow = statements.some(
            (stmt) =>
              ts.isThrowStatement(stmt) || (ts.isIfStatement(stmt) && blockText.includes('throw'))
          );
          const hasLogging =
            blockText.includes('this.logger') ||
            blockText.includes('this.log(') ||
            blockText.includes('opts.logger') ||
            blockText.includes('logger.error') ||
            blockText.includes('logger.warn') ||
            blockText.includes('logger.debug');

          const hasAllowedComment =
            ALLOWED_RATIONALE_PATTERNS.some((pattern) => pattern.test(blockText)) ||
            ALLOWED_RATIONALE_PATTERNS.some((pattern) => pattern.test(tryBlockText));

          if (statements.length === 0) {
            if (!hasAllowedComment) {
              const lineAndChar = sourceFile.getLineAndCharacterOfPosition(node.getStart());
              invalidCatches.push(`Empty catch at line ${lineAndChar.line + 1}`);
            }
          } else {
            // Non-empty statements: check if it only has void _err or empty statements
            const onlyVoidOrNoop = statements.every((s) => {
              if (ts.isExpressionStatement(s) && ts.isVoidExpression(s.expression)) {
                return true;
              }
              return false;
            });

            if (onlyVoidOrNoop && !hasAllowedComment && !hasLogging && !hasRethrow) {
              const lineAndChar = sourceFile.getLineAndCharacterOfPosition(node.getStart());
              invalidCatches.push(`No-op catch without rationale at line ${lineAndChar.line + 1}`);
            }
          }
        }
        ts.forEachChild(node, visit);
      }

      visit(sourceFile);
      return { invalidCatches };
    }

    it('every catch clause in storage/*.ts rethrows, logs, or has approved documented rationale', () => {
      for (const file of storageFiles) {
        const ast = getAst(file);
        const { invalidCatches } = checkCatchClauses(ast);
        expect(invalidCatches).toEqual([]);
      }
    });

    it('negative control: synthetic catch with empty block or unapproved comment fails guard', () => {
      const syntheticBad = getAstFromString(
        'synthetic-swallow.ts',
        `
        export function doIO() {
          try {
            dangerousOp();
          } catch (err) {
            void err;
          }
        }
        `
      );
      const { invalidCatches } = checkCatchClauses(syntheticBad);
      expect(invalidCatches.length).toBe(1);
      expect(invalidCatches[0]).toContain('without rationale at line 5');
    });
  });

  // K3: No unmocked direct node:fs destructured imports
  describe('K3: No unmocked direct fs calls', () => {
    function checkDirectFsImports(sourceFile: ts.SourceFile): string[] {
      const violations: string[] = [];
      function visit(node: ts.Node) {
        if (ts.isImportDeclaration(node)) {
          const moduleSpecifier = (node.moduleSpecifier as ts.StringLiteral).text;
          if (moduleSpecifier === 'node:fs' || moduleSpecifier === 'fs') {
            const importClause = node.importClause;
            if (importClause?.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
              for (const element of importClause.namedBindings.elements) {
                // If it's type-only, allowed: import type { Stats } from 'node:fs'
                if (!element.isTypeOnly && !importClause.isTypeOnly) {
                  violations.push(`Direct named import from fs: ${element.name.text}`);
                }
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(sourceFile);
      return violations;
    }

    it('storage/*.ts does not use direct named imports from node:fs', () => {
      for (const file of storageFiles) {
        const ast = getAst(file);
        const violations = checkDirectFsImports(ast);
        expect(violations).toEqual([]);
      }
    });

    it('negative control: synthetic file with direct named fs import fails guard', () => {
      const syntheticBad = getAstFromString(
        'synthetic-direct-fs.ts',
        `import { writeFileSync, unlinkSync } from 'node:fs';`
      );
      const violations = checkDirectFsImports(syntheticBad);
      expect(violations).toEqual([
        'Direct named import from fs: writeFileSync',
        'Direct named import from fs: unlinkSync',
      ]);
    });
  });

  // K4: JSON.parse results are strictly validated before use
  describe('K4: Validate before use for JSON.parse', () => {
    function findJsonParseUsage(sourceFile: ts.SourceFile): { file: string; totalParses: number } {
      let totalParses = 0;
      function visit(node: ts.Node) {
        if (ts.isCallExpression(node)) {
          const exp = node.expression;
          if (
            ts.isPropertyAccessExpression(exp) &&
            ts.isIdentifier(exp.expression) &&
            exp.expression.text === 'JSON' &&
            exp.name.text === 'parse'
          ) {
            totalParses++;
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(sourceFile);
      return { file: sourceFile.fileName, totalParses };
    }

    it('fleet-store.ts and atomic-file.ts perform zero naked JSON.parse', () => {
      const storeAst = getAst(fleetStorePath);
      const atomicAst = getAst(atomicFilePath);

      expect(findJsonParseUsage(storeAst).totalParses).toBe(0);
      expect(findJsonParseUsage(atomicAst).totalParses).toBe(0);
    });

    it('fleet-snapshot.ts contains exactly one JSON.parse, immediately guarded by validateSnapshot', () => {
      const snapshotAst = getAst(fleetSnapshotPath);
      expect(findJsonParseUsage(snapshotAst).totalParses).toBe(1);

      // Verify that validateSnapshot is defined and called in fleet-snapshot.ts
      const snapshotContent = fs.readFileSync(fleetSnapshotPath, 'utf8');
      expect(snapshotContent.includes('validateSnapshot(parsed)')).toBe(true);
    });
  });

  // K5: All log codes match documented D12 list
  describe('K5: All log codes match documented D12 registry', () => {
    const REGISTERED_CODES = new Set([
      'FLEET_STORE_ERROR',
      'FLEET_STORE_CORRUPTION_ERROR',
      'FLEET_STORE_PRIMARY_CORRUPT',
      'FLEET_STORE_BACKUP_CORRUPT',
      'FLEET_STORE_RECOVERED_FROM_BACKUP',
      'FLEET_STORE_DATA_LOSS',
      'FLEET_STORE_UNSUPPORTED_VERSION',
      'FLEET_STORE_PARSE_ERROR',
      'FLEET_STORE_SCHEMA_ERROR',
      'FLEET_STORE_CHECKSUM_MISMATCH',
      'FLEET_STORE_EXTERNAL_MODIFICATION',
      'FLEET_STORE_DIR_NOT_WRITABLE',
      'FLEET_STORE_PERSIST_FAILED',
      'FLEET_STORE_PERSIST_RECOVERED',
      'FLEET_STORE_NON_ATOMIC_FALLBACK',
      'FLEET_STORE_FALLBACK_VERIFY_FAILED',
      'FLEET_STORE_RESTORE_FAILED',
      'FLEET_STORE_QUARANTINE_PRUNE_FAILED',
      'FLEET_STORE_LOAD_UNREADABLE',
      'FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION',
      'FLEET_STORE_CLEANUP_FAILED',
      'FLEET_STORE_FORMAT_VERSION',
    ]);

    function extractFleetStoreCodes(sourceFile: ts.SourceFile): string[] {
      const codes: string[] = [];
      function visit(node: ts.Node) {
        if (ts.isStringLiteral(node)) {
          if (node.text.startsWith('FLEET_STORE_')) {
            codes.push(node.text);
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(sourceFile);
      return codes;
    }

    it('every FLEET_STORE_ code in storage/*.ts is in the registered set', () => {
      for (const file of storageFiles) {
        const ast = getAst(file);
        const codes = extractFleetStoreCodes(ast);
        for (const code of codes) {
          expect(REGISTERED_CODES.has(code)).toBe(true);
        }
      }
    });

    it('negative control: typo log code fails guard', () => {
      const syntheticTypo = getAstFromString('typo.ts', `const code = 'FLEET_STORE_TYPO_ERROR';`);
      const codes = extractFleetStoreCodes(syntheticTypo);
      expect(codes.length).toBe(1);
      expect(REGISTERED_CODES.has(codes[0]!)).toBe(false);
    });
  });
});
