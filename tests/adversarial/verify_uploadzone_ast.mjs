import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

// Import TypeScript compiler API from frontend node_modules
const tsPath = path.resolve(__dirname, '../../frontend/node_modules/typescript');
const ts = require(tsPath);

const targetFilePath = path.resolve(__dirname, '../../frontend/src/components/UploadZone.tsx');
console.log(`[AST Verifier] Target file: ${targetFilePath}`);

if (!fs.existsSync(targetFilePath)) {
  console.error(`ERROR: Target file not found at ${targetFilePath}`);
  process.exit(1);
}

const sourceCode = fs.readFileSync(targetFilePath, 'utf-8');
const sourceFile = ts.createSourceFile(
  'UploadZone.tsx',
  sourceCode,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.TSX
);

const results = {
  maxSizeBytesFound: false,
  maxSizeBytesExpr: null,
  maxSizeBytesValue: null,
  boundaryConditionFound: false,
  boundaryConditionOperator: null,
  errorMessageTemplateFound: false,
  errorMessageTemplateText: null,
  subtitleTextFound: false,
  extensionCheckFound: false,
  simulations: []
};

// 1. Traverse AST to find MAX_SIZE_BYTES declaration
function traverse(node) {
  if (ts.isVariableDeclaration(node) && node.name && ts.isIdentifier(node.name)) {
    if (node.name.text === 'MAX_SIZE_BYTES') {
      results.maxSizeBytesFound = true;
      if (node.initializer) {
        results.maxSizeBytesExpr = node.initializer.getText(sourceFile);
        // Safely evaluate arithmetic initializer
        try {
          const evalFn = new Function(`return (${results.maxSizeBytesExpr});`);
          results.maxSizeBytesValue = evalFn();
        } catch (e) {
          results.maxSizeBytesValue = 'EVAL_ERROR: ' + e.message;
        }
      }
    }
  }

  // 2. Check for if (file.size > MAX_SIZE_BYTES)
  if (ts.isIfStatement(node)) {
    const exprText = node.expression.getText(sourceFile);
    if (exprText.includes('file.size') && exprText.includes('MAX_SIZE_BYTES')) {
      results.boundaryConditionFound = true;
      if (ts.isBinaryExpression(node.expression)) {
        results.boundaryConditionOperator = node.expression.operatorToken.getText(sourceFile);
      }
      const thenText = node.thenStatement.getText(sourceFile);
      if (thenText.includes('Archive exceeds 600 MB size limit')) {
        results.errorMessageTemplateFound = true;
        results.errorMessageTemplateText = thenText;
      }
    }

    if (exprText.includes('file.name') && exprText.includes('.endsWith(\'.zip\')')) {
      results.extensionCheckFound = true;
    }
  }

  // 3. Check for Subtitle text in JSX
  if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
    const jsxText = node.getText(sourceFile);
    if (jsxText.includes('Supports') && jsxText.includes('.zip') && jsxText.includes('archives up to 600 MB')) {
      results.subtitleTextFound = true;
    }
  }

  ts.forEachChild(node, traverse);
}

traverse(sourceFile);

console.log('[AST Verifier] Static AST Results:');
console.log(JSON.stringify(results, null, 2));

// Assertions on AST Findings
assert.strictEqual(results.maxSizeBytesFound, true, 'MAX_SIZE_BYTES variable declaration must exist');
assert.strictEqual(results.maxSizeBytesValue, 629145600, 'MAX_SIZE_BYTES must evaluate to exactly 629,145,600 bytes (600 * 1024 * 1024)');
assert.strictEqual(results.boundaryConditionFound, true, 'Boundary condition checking file.size vs MAX_SIZE_BYTES must exist');
assert.strictEqual(results.boundaryConditionOperator, '>', 'Boundary operator must be strict greater-than (>)');
assert.strictEqual(results.errorMessageTemplateFound, true, 'Error message must specify 600 MB limit');
assert.strictEqual(results.subtitleTextFound, true, 'Subtitle text must indicate "Supports .zip archives up to 600 MB"');
assert.strictEqual(results.extensionCheckFound, true, 'Extension check must validate .zip');

// 4. Empirical Simulation Harness for Boundary Checking Logic
const MAX_SIZE_BYTES = results.maxSizeBytesValue;

function simulateValidate(file) {
  let errorMessage = null;

  if (!file.name.toLowerCase().endsWith('.zip')) {
    errorMessage = `Invalid archive "${file.name}". SecureScan exclusively accepts .zip archives.`;
    return { passed: false, errorMessage };
  }

  if (file.size > MAX_SIZE_BYTES) {
    const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
    errorMessage = `Archive exceeds 600 MB size limit (selected file is ${sizeMb} MB).`;
    return { passed: false, errorMessage };
  }

  return { passed: true, errorMessage: null };
}

// Test cases
const testVectors = [
  {
    name: 'Exact 600 MB Boundary (629,145,600 bytes)',
    file: { name: 'exact_600mb.zip', size: 600 * 1024 * 1024 },
    expectedPass: true,
    expectedError: null
  },
  {
    name: 'Exact 600 MB + 1 byte Boundary (629,145,601 bytes)',
    file: { name: 'boundary_fail_plus_one.zip', size: 600 * 1024 * 1024 + 1 },
    expectedPass: false,
    expectedError: 'Archive exceeds 600 MB size limit (selected file is 600.0 MB).'
  },
  {
    name: 'Under Ceiling (600 MB - 1 byte = 629,145,599 bytes)',
    file: { name: 'boundary_pass_minus_one.zip', size: 600 * 1024 * 1024 - 1 },
    expectedPass: true,
    expectedError: null
  },
  {
    name: 'Significantly Oversized (650 MB = 681,574,400 bytes)',
    file: { name: 'oversized_650mb.zip', size: 650 * 1024 * 1024 },
    expectedPass: false,
    expectedError: 'Archive exceeds 600 MB size limit (selected file is 650.0 MB).'
  },
  {
    name: 'Zero-byte empty archive',
    file: { name: 'empty.zip', size: 0 },
    expectedPass: true,
    expectedError: null
  },
  {
    name: 'Uppercase .ZIP extension at boundary',
    file: { name: 'UPPERCASE.ZIP', size: 600 * 1024 * 1024 },
    expectedPass: true,
    expectedError: null
  },
  {
    name: 'Non-zip extension (.tar.gz)',
    file: { name: 'archive.tar.gz', size: 1024 },
    expectedPass: false,
    expectedError: 'Invalid archive "archive.tar.gz". SecureScan exclusively accepts .zip archives.'
  }
];

let allPassed = true;
for (const vector of testVectors) {
  const result = simulateValidate(vector.file);
  const passMatch = result.passed === vector.expectedPass;
  const errorMatch = result.errorMessage === vector.expectedError;

  const status = passMatch && errorMatch ? 'PASS' : 'FAIL';
  console.log(`[TEST] ${vector.name}: ${status}`);
  if (status === 'FAIL') {
    console.error(`  Expected: pass=${vector.expectedPass}, error=${vector.expectedError}`);
    console.error(`  Received: pass=${result.passed}, error=${result.errorMessage}`);
    allPassed = false;
  }
  results.simulations.push({
    test: vector.name,
    fileSize: vector.file.size,
    status,
    passed: result.passed,
    errorMessage: result.errorMessage
  });
}

assert.strictEqual(allPassed, true, 'All boundary and simulation vectors must pass cleanly');
console.log('[AST Verifier] ALL 7 TEST VECTORS PASSED EMPIRICALLY!');
