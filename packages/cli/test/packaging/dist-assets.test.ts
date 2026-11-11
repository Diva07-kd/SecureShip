import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { builtinModules } from 'node:module';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../../..');

const cliPackageDir = path.resolve(repoRoot, 'packages/cli');
const cliDistDir = path.resolve(cliPackageDir, 'dist');
const cliPackageJsonPath = path.resolve(cliPackageDir, 'package.json');

const sourceReachabilityDataDir = path.resolve(repoRoot, 'packages/reachability/data');
const sourceReachabilityWasmDir = path.resolve(repoRoot, 'packages/reachability/wasm');
const sourceRulesDir = path.resolve(repoRoot, 'rules/secureship-sast');
const sourceToolsLock = path.resolve(repoRoot, 'tools.lock.json');

function getRecursiveFiles(dir: string, filter: (filePath: string) => boolean): string[] {
  if (!fs.existsSync(dir)) return [];
  const results: string[] = [];
  function walk(current: string) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (filter(full)) {
        results.push(full);
      }
    }
  }
  walk(dir);
  return results;
}

describe('Layer E - Real Build Output Verification Suite (DEV-1..DEV-4 / F-DIS-001 / F-PKG-001)', () => {
  it('E1: dist/data files exist, are byte-identical to packages/reachability/data, and hash matches manifest', () => {
    const distDataFile = path.join(cliDistDir, 'data', 'vulnerable-symbols.json');
    const distManifestFile = path.join(cliDistDir, 'data', 'vulnerable-symbols.manifest.json');
    const srcDataFile = path.join(sourceReachabilityDataDir, 'vulnerable-symbols.json');
    const srcManifestFile = path.join(
      sourceReachabilityDataDir,
      'vulnerable-symbols.manifest.json'
    );

    expect(fs.existsSync(distDataFile)).toEqual(true);
    expect(fs.existsSync(distManifestFile)).toEqual(true);

    const distDataBuffer = fs.readFileSync(distDataFile);
    const srcDataBuffer = fs.readFileSync(srcDataFile);
    expect(Buffer.compare(distDataBuffer, srcDataBuffer)).toEqual(0);

    const distManifestBuffer = fs.readFileSync(distManifestFile);
    const srcManifestBuffer = fs.readFileSync(srcManifestFile);
    expect(Buffer.compare(distManifestBuffer, srcManifestBuffer)).toEqual(0);

    const distManifest = JSON.parse(distManifestBuffer.toString('utf-8'));
    const actualDataHash = crypto.createHash('sha256').update(distDataBuffer).digest('hex');
    expect(distManifest.sha256).toEqual(actualDataHash);
    expect(distManifest.entryCount).toEqual(18);
  });

  it('E2: dist/rules/secureship-sast YAML relative path tree deep-equals source set, each byte-identical', () => {
    const isYaml = (p: string) => p.endsWith('.yaml') || p.endsWith('.yml');

    const srcFiles = getRecursiveFiles(sourceRulesDir, isYaml);
    const distRulesDir = path.join(cliDistDir, 'rules', 'secureship-sast');
    const distFiles = getRecursiveFiles(distRulesDir, isYaml);

    expect(distFiles.length).toBeGreaterThanOrEqual(10);

    const srcRelPaths = srcFiles
      .map((p) => path.relative(sourceRulesDir, p).replace(/\\/g, '/'))
      .sort();
    const distRelPaths = distFiles
      .map((p) => path.relative(distRulesDir, p).replace(/\\/g, '/'))
      .sort();

    expect(distRelPaths).toEqual(srcRelPaths);

    for (const relPath of srcRelPaths) {
      const srcFull = path.join(sourceRulesDir, relPath);
      const distFull = path.join(distRulesDir, relPath);

      const srcContent = fs.readFileSync(srcFull);
      const distContent = fs.readFileSync(distFull);
      expect(Buffer.compare(srcContent, distContent)).toEqual(0);
    }
  });

  it('E3: dist/wasm .wasm count equals source count and dist/tools.lock.json exists and is byte-identical', () => {
    const isWasm = (p: string) => p.endsWith('.wasm');
    const srcWasmFiles = fs.readdirSync(sourceReachabilityWasmDir).filter(isWasm).sort();
    const distWasmFiles = fs.readdirSync(path.join(cliDistDir, 'wasm')).filter(isWasm).sort();

    expect(distWasmFiles.length).toEqual(srcWasmFiles.length);
    expect(distWasmFiles).toEqual(srcWasmFiles);

    const distToolsLock = path.join(cliDistDir, 'tools.lock.json');
    expect(fs.existsSync(distToolsLock)).toEqual(true);

    const srcLock = fs.readFileSync(sourceToolsLock);
    const distLock = fs.readFileSync(distToolsLock);
    expect(Buffer.compare(srcLock, distLock)).toEqual(0);
  });

  it('E4: zero bare @secureship/* import/require/dynamic-import specifiers in any dist/*.js file', () => {
    const distJsFiles = fs
      .readdirSync(cliDistDir)
      .filter((f) => f.endsWith('.js'))
      .map((f) => path.join(cliDistDir, f));

    expect(distJsFiles.length).toBeGreaterThan(0);

    const bareSpecifiers = new Set<string>();

    for (const filePath of distJsFiles) {
      const code = fs.readFileSync(filePath, 'utf-8');
      const sf = ts.createSourceFile(filePath, code, ts.ScriptTarget.Latest, true);

      function visit(node: ts.Node) {
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
          bareSpecifiers.add(node.moduleSpecifier.text);
        } else if (
          ts.isExportDeclaration(node) &&
          node.moduleSpecifier &&
          ts.isStringLiteral(node.moduleSpecifier)
        ) {
          bareSpecifiers.add(node.moduleSpecifier.text);
        } else if (ts.isCallExpression(node)) {
          if (
            node.expression.kind === ts.SyntaxKind.ImportKeyword &&
            node.arguments.length > 0 &&
            ts.isStringLiteral(node.arguments[0]!)
          ) {
            bareSpecifiers.add(node.arguments[0]!.text);
          } else if (
            ts.isIdentifier(node.expression) &&
            node.expression.text === 'require' &&
            node.arguments.length > 0 &&
            ts.isStringLiteral(node.arguments[0]!)
          ) {
            bareSpecifiers.add(node.arguments[0]!.text);
          }
        }
        ts.forEachChild(node, visit);
      }

      visit(sf);
    }

    const allBare = Array.from(bareSpecifiers).filter(
      (s) => !s.startsWith('.') && !s.startsWith('/')
    );
    const leakedSecureship = allBare.filter((s) => s.startsWith('@secureship/')).sort();

    expect(leakedSecureship).toEqual([]);
  });

  it('E5: every remaining bare specifier in dist/*.js is either a Node builtin or in cli dependencies; missing list is empty', () => {
    const distJsFiles = fs
      .readdirSync(cliDistDir)
      .filter((f) => f.endsWith('.js'))
      .map((f) => path.join(cliDistDir, f));

    const bareSpecifiers = new Set<string>();

    for (const filePath of distJsFiles) {
      const code = fs.readFileSync(filePath, 'utf-8');
      const sf = ts.createSourceFile(filePath, code, ts.ScriptTarget.Latest, true);

      function visit(node: ts.Node) {
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
          bareSpecifiers.add(node.moduleSpecifier.text);
        } else if (
          ts.isExportDeclaration(node) &&
          node.moduleSpecifier &&
          ts.isStringLiteral(node.moduleSpecifier)
        ) {
          bareSpecifiers.add(node.moduleSpecifier.text);
        } else if (ts.isCallExpression(node)) {
          if (
            node.expression.kind === ts.SyntaxKind.ImportKeyword &&
            node.arguments.length > 0 &&
            ts.isStringLiteral(node.arguments[0]!)
          ) {
            bareSpecifiers.add(node.arguments[0]!.text);
          } else if (
            ts.isIdentifier(node.expression) &&
            node.expression.text === 'require' &&
            node.arguments.length > 0 &&
            ts.isStringLiteral(node.arguments[0]!)
          ) {
            bareSpecifiers.add(node.arguments[0]!.text);
          }
        }
        ts.forEachChild(node, visit);
      }

      visit(sf);
    }

    const allBare = Array.from(bareSpecifiers).filter(
      (s) => !s.startsWith('.') && !s.startsWith('/')
    );

    const cliPackageJson = JSON.parse(fs.readFileSync(cliPackageJsonPath, 'utf-8'));
    const declaredDependencies = new Set(Object.keys(cliPackageJson.dependencies || {}));

    const builtinsSet = new Set(builtinModules.concat(builtinModules.map((m) => `node:${m}`)));

    const missingSpecifiers: string[] = [];

    for (const spec of allBare) {
      // Check Node builtin
      if (builtinsSet.has(spec)) {
        continue;
      }
      // Extract package name (handles scoped packages like @inquirer/prompts or subpaths)
      let pkgName = spec;
      if (spec.startsWith('@')) {
        const parts = spec.split('/');
        pkgName = `${parts[0]}/${parts[1]}`;
      } else {
        pkgName = spec.split('/')[0]!;
      }

      if (declaredDependencies.has(pkgName)) {
        continue;
      }

      missingSpecifiers.push(spec);
    }

    missingSpecifiers.sort();
    expect(missingSpecifiers).toEqual([]);
  });
});
