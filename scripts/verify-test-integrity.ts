#!/usr/bin/env node
/**
 * Test Integrity Auditor (T1 Production Gate)
 *
 * Enforces Anti-Fake-Test Law by scanning TypeScript test files using the TypeScript AST:
 * 1. Zero assertions in a test body
 * 2. Tautological assertions (expect(true).toBe(true), expect(x).toBe(x), assert(1))
 * 3. Weak-only assertions (assertions only on toBeDefined, not.toThrow, toBeTruthy without semantic checks)
 * 4. Skipped/focused tests (.skip, .only, xit, xdescribe, test.todo)
 * 5. Commented-out assertions (// expect(...))
 * 6. Swallowed exceptions in try/catch wrapping assertions
 * 7. Production constants/tables used as expected values in assertions
 * 8. Forbidden mocking of internal modules (supply-chain, reachability, normalizer, ladder)
 * 9. Snapshot-only tests without semantic assertions
 * 10. Async tests lacking await or returned promise
 * 11. Unfaked timer measurement in assertions
 */

import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

export interface IntegrityViolation {
  file: string;
  line: number;
  column: number;
  category:
    | 'zero-assertions'
    | 'tautology'
    | 'weak-only'
    | 'skip-only-todo'
    | 'commented-assertion'
    | 'swallowed-catch'
    | 'prod-constant-expected'
    | 'forbidden-mock'
    | 'snapshot-only'
    | 'async-missing-await'
    | 'unfaked-timer';
  testName?: string;
  message: string;
  snippet: string;
}

export interface AuditReport {
  scannedFiles: number;
  totalViolations: number;
  violationsByCategory: Record<string, number>;
  violations: IntegrityViolation[];
}

const _DEFAULT_SUPPLY_CHAIN_TEST_PATTERNS = [
  'packages/core-engine/test/supply-chain/**/*.test.ts',
  'packages/contracts/test/supply-chain*.test.ts',
  'packages/ai/test/*supply-chain*.test.ts',
  'packages/cli/test/*supply-chain*.test.ts',
  'packages/reachability/test/*capabilities*.test.ts',
];

const FORBIDDEN_MOCK_MODULES = [
  'supply-chain',
  'reachability',
  'normalizer',
  'finding-correlator',
  'ladder',
  'verification-ladder',
  'safe-tar',
];

const PROD_CONSTANT_NAMES = [
  'RULES_REGISTRY',
  'DEFAULT_POLICY',
  'defaultPolicy',
  'DEFAULT_CONFIG',
  'POPULAR_PACKAGES',
  'TYPOSQUAT_INDEX',
];

const WEAK_MATCHERS = new Set(['toBeDefined', 'toBeTruthy', 'toBeFalsy', 'not.toThrow']);

function findFiles(dir: string, pattern: RegExp): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== 'dist' && entry.name !== '.git') {
        results.push(...findFiles(fullPath, pattern));
      }
    } else if (entry.isFile() && pattern.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

export function auditTestFile(filePath: string, fileContent: string): IntegrityViolation[] {
  const violations: IntegrityViolation[] = [];
  const sourceFile = ts.createSourceFile(
    filePath,
    fileContent,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS
  );

  // 1. Commented-out assertions scan
  const commentedAssertionRegex = /(?:\/\/|\/\*)\s*(?:expect\s*\(|assert\s*\()/g;
  let match: RegExpExecArray | null;
  while ((match = commentedAssertionRegex.exec(fileContent)) !== null) {
    const pos = sourceFile.getLineAndCharacterOfPosition(match.index);
    violations.push({
      file: filePath,
      line: pos.line + 1,
      column: pos.character + 1,
      category: 'commented-assertion',
      message: 'Commented-out test assertion detected; dead assertion code is forbidden.',
      snippet: fileContent
        .slice(match.index, Math.min(match.index + 60, fileContent.length))
        .split('\n')[0],
    });
  }

  // Set of imported identifiers from production modules
  const importedProdConstants = new Set<string>();

  function inspectImport(node: ts.ImportDeclaration) {
    const moduleSpecifier = node.moduleSpecifier;
    if (ts.isStringLiteral(moduleSpecifier)) {
      const namedBindings = node.importClause?.namedBindings;
      if (namedBindings && ts.isNamedImports(namedBindings)) {
        for (const element of namedBindings.elements) {
          const importName = (element.propertyName || element.name).text;
          if (
            PROD_CONSTANT_NAMES.includes(importName) ||
            importName.startsWith('DEFAULT_') ||
            importName.endsWith('_REGISTRY') ||
            importName.endsWith('_TABLE')
          ) {
            importedProdConstants.add(element.name.text);
          }
        }
      }
    }
  }

  function checkTautology(callExpr: ts.CallExpression, testName?: string) {
    // expect(a).toBe(b)
    const exprText = callExpr.expression.getText(sourceFile);
    if (exprText.endsWith('.toBe') || exprText.endsWith('.toEqual')) {
      const parentExpect = findEnclosingExpectCall(callExpr);
      if (parentExpect && parentExpect.arguments.length > 0 && callExpr.arguments.length > 0) {
        const actualArg = parentExpect.arguments[0].getText(sourceFile).trim();
        const expectedArg = callExpr.arguments[0].getText(sourceFile).trim();
        if (
          actualArg === expectedArg ||
          (actualArg === 'true' && expectedArg === 'true') ||
          (actualArg === 'false' && expectedArg === 'false') ||
          (actualArg === '1' && expectedArg === '1')
        ) {
          const pos = sourceFile.getLineAndCharacterOfPosition(callExpr.getStart(sourceFile));
          violations.push({
            file: filePath,
            line: pos.line + 1,
            column: pos.character + 1,
            category: 'tautology',
            testName,
            message: `Tautological assertion detected: expect(${actualArg}).toBe(${expectedArg})`,
            snippet: callExpr.getText(sourceFile),
          });
        }
      }
    } else if (exprText === 'assert' && callExpr.arguments.length > 0) {
      const argText = callExpr.arguments[0].getText(sourceFile).trim();
      if (argText === 'true' || argText === '1' || argText === '!0') {
        const pos = sourceFile.getLineAndCharacterOfPosition(callExpr.getStart(sourceFile));
        violations.push({
          file: filePath,
          line: pos.line + 1,
          column: pos.character + 1,
          category: 'tautology',
          testName,
          message: `Tautological assertion: assert(${argText})`,
          snippet: callExpr.getText(sourceFile),
        });
      }
    }
  }

  function findEnclosingExpectCall(node: ts.CallExpression): ts.CallExpression | null {
    // Traverse down property access: expect(x).toBe(...)
    let current: ts.Expression = node.expression;
    while (ts.isPropertyAccessExpression(current)) {
      if (ts.isCallExpression(current.expression)) {
        const callee = current.expression.expression.getText(sourceFile);
        if (callee === 'expect') {
          return current.expression;
        }
        current = current.expression.expression;
      } else {
        break;
      }
    }
    return null;
  }

  function checkForbiddenMock(callExpr: ts.CallExpression) {
    const callee = callExpr.expression.getText(sourceFile);
    if (callee === 'vi.mock' || callee === 'jest.mock') {
      if (callExpr.arguments.length > 0) {
        const arg = callExpr.arguments[0];
        if (ts.isStringLiteral(arg)) {
          const mockTarget = arg.text;
          for (const forbidden of FORBIDDEN_MOCK_MODULES) {
            if (mockTarget.includes(forbidden)) {
              const pos = sourceFile.getLineAndCharacterOfPosition(callExpr.getStart(sourceFile));
              violations.push({
                file: filePath,
                line: pos.line + 1,
                column: pos.character + 1,
                category: 'forbidden-mock',
                message: `Forbidden mock of core engine module '${mockTarget}'. Only network/clock/fs boundary modules may be mocked.`,
                snippet: callExpr.getText(sourceFile),
              });
              break;
            }
          }
        }
      }
    }
  }

  function checkSkipOnlyTodo(callExpr: ts.CallExpression) {
    const text = callExpr.expression.getText(sourceFile);
    if (
      text === 'it.skip' ||
      text === 'it.only' ||
      text === 'it.todo' ||
      text === 'test.skip' ||
      text === 'test.only' ||
      text === 'test.todo' ||
      text === 'describe.skip' ||
      text === 'describe.only' ||
      text === 'describe.todo' ||
      text === 'xit' ||
      text === 'fit' ||
      text === 'xdescribe' ||
      text === 'fdescribe'
    ) {
      const pos = sourceFile.getLineAndCharacterOfPosition(callExpr.getStart(sourceFile));
      violations.push({
        file: filePath,
        line: pos.line + 1,
        column: pos.character + 1,
        category: 'skip-only-todo',
        message: `Forbidden test modifier '${text}' detected. Tests may not be skipped or exclusively focused.`,
        snippet: callExpr.getText(sourceFile).split('\n')[0],
      });
    }
  }

  function inspectTestBody(
    testName: string,
    body: ts.Node,
    isAsync: boolean,
    testNode: ts.CallExpression
  ) {
    let assertionCount = 0;
    let semanticAssertionCount = 0;
    let hasSnapshot = false;
    let hasAwait = false;
    let hasTimerMeasurement = false;
    let hasFakeTimers = false;

    function checkNode(node: ts.Node) {
      if (ts.isAwaitExpression(node)) {
        hasAwait = true;
      }

      if (ts.isTryStatement(node)) {
        const catchClause = node.catchClause;
        if (catchClause) {
          const catchStatements = catchClause.block.statements;
          // Look inside try block for assertions
          let tryHasAssertions = false;
          node.tryBlock.forEachChild((child) => {
            if (
              child.getText(sourceFile).includes('expect(') ||
              child.getText(sourceFile).includes('assert(')
            ) {
              tryHasAssertions = true;
            }
          });
          if (tryHasAssertions && catchStatements.length === 0) {
            const pos = sourceFile.getLineAndCharacterOfPosition(catchClause.getStart(sourceFile));
            violations.push({
              file: filePath,
              line: pos.line + 1,
              column: pos.character + 1,
              category: 'swallowed-catch',
              testName,
              message:
                'Empty catch block swallowing potential assertion failures inside try { ... }',
              snippet: catchClause.getText(sourceFile),
            });
          }
        }
      }

      if (ts.isCallExpression(node)) {
        const calleeText = node.expression.getText(sourceFile);

        if (calleeText === 'vi.useFakeTimers') {
          hasFakeTimers = true;
        }

        if (calleeText === 'Date.now' || calleeText === 'performance.now') {
          hasTimerMeasurement = true;
        }

        if (calleeText.includes('expect') || calleeText.startsWith('assert')) {
          assertionCount++;

          // Check tautology
          checkTautology(node, testName);

          // Check production constant as expected value
          if (node.arguments.length > 0) {
            for (const arg of node.arguments) {
              const argName = arg.getText(sourceFile).trim();
              if (importedProdConstants.has(argName)) {
                const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                violations.push({
                  file: filePath,
                  line: pos.line + 1,
                  column: pos.character + 1,
                  category: 'prod-constant-expected',
                  testName,
                  message: `Imported production constant '${argName}' used as expected value in assertion (violates independent oracle law).`,
                  snippet: node.getText(sourceFile),
                });
              }
            }
          }

          // Check matcher type
          if (ts.isPropertyAccessExpression(node.expression)) {
            const matcherName = node.expression.name.text;
            if (matcherName === 'toMatchSnapshot' || matcherName === 'toMatchInlineSnapshot') {
              hasSnapshot = true;
            } else if (WEAK_MATCHERS.has(matcherName)) {
              // weak matcher
            } else {
              semanticAssertionCount++;
            }
          }
        }
      }

      ts.forEachChild(node, checkNode);
    }

    checkNode(body);

    const testPos = sourceFile.getLineAndCharacterOfPosition(testNode.getStart(sourceFile));

    // Check zero assertions
    if (assertionCount === 0) {
      violations.push({
        file: filePath,
        line: testPos.line + 1,
        column: testPos.character + 1,
        category: 'zero-assertions',
        testName,
        message: `Test '${testName}' contains zero assertions. Every test must assert expected outcomes.`,
        snippet: testNode.getText(sourceFile).split('\n')[0],
      });
    }

    // Check weak-only assertions
    if (assertionCount > 0 && semanticAssertionCount === 0 && !hasSnapshot) {
      violations.push({
        file: filePath,
        line: testPos.line + 1,
        column: testPos.character + 1,
        category: 'weak-only',
        testName,
        message: `Test '${testName}' contains only weak assertions (toBeDefined/toBeTruthy/not.toThrow). Hard semantic assertions required.`,
        snippet: testNode.getText(sourceFile).split('\n')[0],
      });
    }

    // Check snapshot-only
    if (hasSnapshot && semanticAssertionCount === 0) {
      violations.push({
        file: filePath,
        line: testPos.line + 1,
        column: testPos.character + 1,
        category: 'snapshot-only',
        testName,
        message: `Test '${testName}' relies exclusively on snapshot assertions without semantic property checks.`,
        snippet: testNode.getText(sourceFile).split('\n')[0],
      });
    }

    // Check async without await
    if (isAsync && !hasAwait) {
      violations.push({
        file: filePath,
        line: testPos.line + 1,
        column: testPos.character + 1,
        category: 'async-missing-await',
        testName,
        message: `Async test '${testName}' contains no await expressions; un-awaited async tests can falsely pass.`,
        snippet: testNode.getText(sourceFile).split('\n')[0],
      });
    }

    // Check timer measurement without fake timers
    if (hasTimerMeasurement && !hasFakeTimers) {
      // Check if test asserts on elapsed time
      const bodyText = body.getText(sourceFile);
      if (/expect\([^)]*(?:elapsed|duration|diff|ms|Time)[^)]*\)/i.test(bodyText)) {
        violations.push({
          file: filePath,
          line: testPos.line + 1,
          column: testPos.character + 1,
          category: 'unfaked-timer',
          testName,
          message: `Test '${testName}' asserts on real clock elapsed time without vi.useFakeTimers(), leading to flakiness.`,
          snippet: testNode.getText(sourceFile).split('\n')[0],
        });
      }
    }
  }

  function visit(node: ts.Node) {
    if (ts.isImportDeclaration(node)) {
      inspectImport(node);
    }

    if (ts.isCallExpression(node)) {
      checkForbiddenMock(node);
      checkSkipOnlyTodo(node);

      const callee = node.expression.getText(sourceFile);
      if (
        callee === 'it' ||
        callee === 'test' ||
        callee === 'it.skip' ||
        callee === 'it.only' ||
        callee === 'test.skip' ||
        callee === 'test.only'
      ) {
        let testName = 'anonymous';
        if (node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
          testName = node.arguments[0].text;
        }

        const fnArg = node.arguments.find(
          (arg) => ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)
        );

        if (fnArg && (ts.isArrowFunction(fnArg) || ts.isFunctionExpression(fnArg))) {
          const isAsync = !!fnArg.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
          inspectTestBody(testName, fnArg.body, isAsync, node);
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return violations;
}

export function runIntegrityAudit(targetPaths?: string[]): AuditReport {
  let filesToScan: string[] = [];

  if (targetPaths && targetPaths.length > 0) {
    for (const p of targetPaths) {
      if (!fs.existsSync(p)) continue;
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        filesToScan.push(...findFiles(p, /\.test\.ts$/));
      } else if (stat.isFile() && /\.test\.ts$/.test(p)) {
        filesToScan.push(p);
      }
    }
  } else {
    // Scan supply-chain scope
    const dirs = [
      'packages/core-engine/test/supply-chain',
      'packages/contracts/test',
      'packages/ai/test',
      'packages/cli/test',
      'packages/reachability/test',
    ];
    for (const d of dirs) {
      const fullDir = path.resolve(d);
      if (fs.existsSync(fullDir)) {
        filesToScan.push(...findFiles(fullDir, /\.test\.ts$/));
      }
    }
  }

  // Deduplicate
  filesToScan = Array.from(new Set(filesToScan));

  const allViolations: IntegrityViolation[] = [];
  const violationsByCategory: Record<string, number> = {
    'zero-assertions': 0,
    tautology: 0,
    'weak-only': 0,
    'skip-only-todo': 0,
    'commented-assertion': 0,
    'swallowed-catch': 0,
    'prod-constant-expected': 0,
    'forbidden-mock': 0,
    'snapshot-only': 0,
    'async-missing-await': 0,
    'unfaked-timer': 0,
  };

  for (const file of filesToScan) {
    const content = fs.readFileSync(file, 'utf-8');
    const violations = auditTestFile(file, content);
    for (const v of violations) {
      allViolations.push(v);
      violationsByCategory[v.category] = (violationsByCategory[v.category] || 0) + 1;
    }
  }

  return {
    scannedFiles: filesToScan.length,
    totalViolations: allViolations.length,
    violationsByCategory,
    violations: allViolations,
  };
}

// CLI Execution
if (
  import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith('verify-test-integrity.ts')
) {
  const args = process.argv.slice(2);
  const targetPaths = args.length > 0 ? args : undefined;

  console.log('🛡️  SecureShip Supply-Chain Threat Engine — Test Integrity Auditor (T1)');
  console.log('Scanning test suite against Anti-Fake-Test Law requirements...\n');

  const report = runIntegrityAudit(targetPaths);

  console.log(`Scanned Test Files : ${report.scannedFiles}`);
  console.log(`Total Violations   : ${report.totalViolations}`);
  console.log('\n--- Breakdown by Violation Category ---');
  for (const [cat, count] of Object.entries(report.violationsByCategory)) {
    const status = count === 0 ? 'CLEAN' : `VIOLATION (${count})`;
    console.log(`  - ${cat.padEnd(25)}: ${status}`);
  }

  if (report.totalViolations > 0) {
    console.log('\n❌ AUDIT FAILED: Fake or weakened test patterns detected:');
    for (const v of report.violations) {
      console.log(`\n  [${v.category.toUpperCase()}] ${v.file}:${v.line}:${v.column}`);
      if (v.testName) console.log(`  Test: ${v.testName}`);
      console.log(`  Message: ${v.message}`);
      console.log(`  Code: ${v.snippet.trim()}`);
    }
    process.exit(1);
  } else {
    console.log(
      '\n✔ TEST INTEGRITY AUDIT PASSED: Zero fake tests, tautologies, swallowed errors, or forbidden mocks.'
    );
    process.exit(0);
  }
}
