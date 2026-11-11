import type Parser from 'web-tree-sitter';
import { JsImportExtractor } from '../js/js-import-extractor.js';
import type {
  ImportBinding,
  SymbolUsageFact,
  EscapeFact,
  FileSymbolUsage,
  UsageForm,
} from './symbol-usage.types.js';

export interface ParseSpecifierResult {
  packageRoot: string;
  subpath: string | null;
}

/**
 * Parses an npm package specifier into root package name and subpath.
 * e.g. '@scope/pkg/sub/dir' -> { packageRoot: '@scope/pkg', subpath: 'sub/dir' }
 *      'lodash/template'   -> { packageRoot: 'lodash', subpath: 'template' }
 *      './local/file'      -> null (local import)
 */
export function parseJsPackageSpecifier(specifier: string): ParseSpecifierResult | null {
  const trimmed = specifier.trim();
  if (
    trimmed.startsWith('.') ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('\\') ||
    /^[a-zA-Z]:/.test(trimmed)
  ) {
    return null; // Local file
  }

  if (trimmed.startsWith('@')) {
    const parts = trimmed.split('/');
    if (parts.length < 2) return null;
    const packageRoot = `${parts[0]}/${parts[1]}`;
    const subpath = parts.length > 2 ? parts.slice(2).join('/') : null;
    return { packageRoot, subpath };
  }

  const parts = trimmed.split('/');
  const packageRoot = parts[0]!;
  const subpath = parts.length > 1 ? parts.slice(1).join('/') : null;
  return { packageRoot, subpath };
}

interface StackFrame {
  node: Parser.SyntaxNode;
  isExit?: boolean;
  fnName?: string;
}

interface MemberAlias {
  packageRoot: string;
  symbol: string;
  form: UsageForm;
}

export class JsSymbolUsageExtractor {
  public static readonly MAX_NODES = 500_000;
  public static readonly MAX_TIME_MS = 10_000;

  /**
   * Iteratively extracts import bindings, symbol usage facts, and escapes from a JS/TS AST.
   */
  public static extract(
    rootNode: Parser.SyntaxNode,
    filePath: string,
    relativePath: string
  ): FileSymbolUsage {
    const startTime = Date.now();
    let nodeCount = 0;
    let usageIncomplete = false;
    let incompleteReason: string | undefined;

    const bindings: ImportBinding[] = [];
    const usageFacts: SymbolUsageFact[] = [];
    const escapes: EscapeFact[] = [];
    let hasCreateRequire = false;

    // Local name -> ImportBinding
    const boundNames = new Map<string, ImportBinding>();
    // Local alias name -> MemberAlias (e.g. const tpl = _.template or const { template } = _)
    const memberAliases = new Map<string, MemberAlias>();

    const activeFunctions: string[] = [];

    // Helper to record an escape
    const recordEscape = (
      packageRoot: string,
      reason: EscapeFact['reason'],
      line: number,
      detail?: string
    ) => {
      escapes.push({
        packageRoot,
        reason,
        file: relativePath,
        line,
        detail,
      });
    };

    // Helper to record a symbol usage fact
    const recordUsage = (
      packageRoot: string,
      symbol: string,
      form: UsageForm,
      line: number,
      isCall: boolean,
      calleeExpression?: string
    ) => {
      usageFacts.push({
        packageRoot,
        symbol,
        form,
        file: relativePath,
        line,
        calleeExpression,
        isCall,
        enclosingFunction:
          activeFunctions.length > 0 ? activeFunctions[activeFunctions.length - 1] : undefined,
      });
    };

    // Explicit stack for iterative depth-first traversal
    const stack: StackFrame[] = [{ node: rootNode }];

    while (stack.length > 0) {
      const frame = stack.pop()!;

      if (frame.isExit) {
        if (frame.fnName && activeFunctions.length > 0) {
          activeFunctions.pop();
        }
        continue;
      }

      nodeCount++;
      if (nodeCount > JsSymbolUsageExtractor.MAX_NODES) {
        usageIncomplete = true;
        incompleteReason = 'AST node count limit exceeded (500,000)';
        break;
      }

      if (Date.now() - startTime > JsSymbolUsageExtractor.MAX_TIME_MS) {
        usageIncomplete = true;
        incompleteReason = 'Extraction timeout exceeded (10s)';
        break;
      }

      const node = frame.node;

      // 1. Check if entering a function scope
      let enteredFnName: string | undefined;
      if (
        node.type === 'function_declaration' ||
        node.type === 'function_definition' ||
        node.type === 'method_definition'
      ) {
        const nameNode = node.childForFieldName('name');
        if (nameNode) enteredFnName = nameNode.text;
      } else if (node.type === 'variable_declarator') {
        const nameNode = node.childForFieldName('name');
        const valNode = node.childForFieldName('value');
        if (
          nameNode &&
          valNode &&
          (valNode.type === 'arrow_function' || valNode.type === 'function_expression')
        ) {
          enteredFnName = nameNode.text;
        }
      }

      if (enteredFnName) {
        activeFunctions.push(enteredFnName);
        stack.push({ node, isExit: true, fnName: enteredFnName });
      }

      // 2. Global markers: createRequire, module.require, require.context
      if (
        node.type === 'identifier' &&
        (node.text === 'createRequire' || node.text === 'require.context')
      ) {
        hasCreateRequire = true;
      } else if (node.type === 'member_expression') {
        if (node.text === 'module.require' || node.text === 'require.context') {
          hasCreateRequire = true;
        }
      }

      // 3. Process AST node types
      switch (node.type) {
        // ESM Import Statement
        case 'import_statement': {
          JsSymbolUsageExtractor.processEsmImport(
            node,
            bindings,
            boundNames,
            escapes,
            relativePath
          );
          break;
        }

        // TS Import Equals: import _ = require('lodash');
        case 'import_equals_declaration': {
          JsSymbolUsageExtractor.processTsImportEquals(
            node,
            bindings,
            boundNames,
            escapes,
            relativePath
          );
          break;
        }

        // ESM Export Statement: export * from 'pkg', export default _, export { _ }
        case 'export_statement': {
          JsSymbolUsageExtractor.processExportStatement(node, boundNames, recordEscape);
          break;
        }

        // Variable declarator: const _ = require('pkg'), const { a } = _, const t = _.template
        case 'variable_declarator': {
          JsSymbolUsageExtractor.processVariableDeclarator(
            node,
            bindings,
            boundNames,
            memberAliases,
            recordUsage,
            recordEscape
          );
          break;
        }

        // Call expression: _.template(), t(), require('pkg')(), fn(_)
        case 'call_expression': {
          JsSymbolUsageExtractor.processCallExpression(
            node,
            bindings,
            boundNames,
            memberAliases,
            recordUsage,
            recordEscape
          );
          break;
        }

        // Member expression: _.template (non-call), _[key]
        case 'member_expression':
        case 'subscript_expression': {
          JsSymbolUsageExtractor.processMemberOrSubscript(
            node,
            boundNames,
            memberAliases,
            recordUsage,
            recordEscape
          );
          break;
        }

        // Return statement: return _
        case 'return_statement': {
          const arg = node.namedChild(0);
          if (arg && arg.type === 'identifier' && boundNames.has(arg.text)) {
            const b = boundNames.get(arg.text)!;
            recordEscape(b.packageRoot, 'RETURN', node.startPosition.row + 1, arg.text);
          }
          break;
        }

        // Array literal / Object literal store: [ _ ], { a: _ }
        case 'array': {
          for (let i = 0; i < node.namedChildCount; i++) {
            const item = node.namedChild(i)!;
            if (item.type === 'identifier' && boundNames.has(item.text)) {
              const b = boundNames.get(item.text)!;
              recordEscape(b.packageRoot, 'CONTAINER_STORE', node.startPosition.row + 1, item.text);
            }
          }
          break;
        }

        case 'pair': {
          const val = node.childForFieldName('value');
          if (val && val.type === 'identifier' && boundNames.has(val.text)) {
            const b = boundNames.get(val.text)!;
            recordEscape(b.packageRoot, 'CONTAINER_STORE', node.startPosition.row + 1, val.text);
          }
          break;
        }

        // Spread element: ..._
        case 'spread_element': {
          const expr = node.namedChild(0);
          if (expr && expr.type === 'identifier' && boundNames.has(expr.text)) {
            const b = boundNames.get(expr.text)!;
            recordEscape(b.packageRoot, 'SPREAD', node.startPosition.row + 1, expr.text);
          }
          break;
        }

        // Assignment expression: module.exports = require('pkg'), module.exports = _, or _ = other
        case 'assignment_expression': {
          const left = node.childForFieldName('left');
          const right = node.childForFieldName('right');
          const line = node.startPosition.row + 1;

          // Reassignment: _ = other
          if (left && left.type === 'identifier' && boundNames.has(left.text)) {
            const b = boundNames.get(left.text)!;
            recordEscape(b.packageRoot, 'REASSIGNMENT', line, left.text);
          }

          // CJS Export: module.exports = require('pkg') or module.exports = _
          if (
            left &&
            (left.text === 'module.exports' ||
              left.text.startsWith('module.exports.') ||
              left.text.startsWith('exports.'))
          ) {
            if (right) {
              if (right.type === 'identifier' && boundNames.has(right.text)) {
                const b = boundNames.get(right.text)!;
                recordEscape(
                  b.packageRoot,
                  'EXPORT',
                  line,
                  `Assigned '${right.text}' to ${left.text}`
                );
              } else if (right.type === 'call_expression') {
                const fn = right.childForFieldName('function');
                const callArgs = right.childForFieldName('arguments');
                if (fn && fn.text === 'require' && callArgs && callArgs.namedChildCount > 0) {
                  const firstArg = callArgs.namedChild(0)!;
                  if (firstArg.type === 'string' || firstArg.type === 'template_string') {
                    const rawSpecifier = JsImportExtractor.unquote(firstArg.text);
                    const parsed = parseJsPackageSpecifier(rawSpecifier);
                    if (parsed) {
                      const b: ImportBinding = {
                        localName: 'module.exports',
                        importedName: 'namespace',
                        rawSpecifier,
                        packageRoot: parsed.packageRoot,
                        subpath: parsed.subpath,
                        kind: 'CJS',
                        line,
                        isTypeOnly: false,
                      };
                      bindings.push(b);
                      recordEscape(
                        parsed.packageRoot,
                        'EXPORT',
                        line,
                        `${left.text} = require('${rawSpecifier}')`
                      );
                    }
                  }
                }
              }
            }
          }
          break;
        }
      }

      // Push children in reverse order
      for (let i = node.childCount - 1; i >= 0; i--) {
        const child = node.child(i);
        if (child) {
          stack.push({ node: child });
        }
      }
    }

    // If createRequire marker is present, record escape for all imported packages in this file
    if (hasCreateRequire) {
      const distinctRoots = new Set<string>();
      for (const b of bindings) {
        distinctRoots.add(b.packageRoot);
      }
      for (const root of distinctRoots) {
        recordEscape(root, 'CREATE_REQUIRE', 1, 'File uses createRequire or module.require');
      }
    }

    return {
      filePath,
      relativePath,
      bindings,
      usageFacts,
      escapes,
      hasCreateRequire,
      usageIncomplete,
      incompleteReason,
    };
  }

  private static processEsmImport(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    escapes: EscapeFact[],
    relativePath: string
  ): void {
    const sourceNode = node.childForFieldName('source');
    if (!sourceNode) {
      const reqClause = node.children.find((c) => c.type === 'import_require_clause');
      if (reqClause) {
        const idNode = reqClause.children.find((c) => c.type === 'identifier');
        const strNode = reqClause.children.find(
          (c) => c.type === 'string' || c.type === 'string_fragment'
        );
        if (idNode && strNode) {
          const rawSpecifier = JsImportExtractor.unquote(strNode.text);
          const parsed = parseJsPackageSpecifier(rawSpecifier);
          if (parsed) {
            const line = node.startPosition.row + 1;
            const b: ImportBinding = {
              localName: idNode.text,
              importedName: 'namespace',
              rawSpecifier,
              packageRoot: parsed.packageRoot,
              subpath: parsed.subpath,
              kind: 'TS_IMPORT_EQUALS',
              line,
              isTypeOnly: false,
            };
            bindings.push(b);
            boundNames.set(b.localName, b);
            if (parsed.subpath) {
              escapes.push({
                packageRoot: parsed.packageRoot,
                reason: 'UNKNOWN_SUBPATH',
                file: relativePath,
                line,
                detail: `Import equals on subpath '${rawSpecifier}'`,
              });
            }
          }
        }
      }
      return;
    }

    const rawSpecifier = JsImportExtractor.unquote(sourceNode.text);
    const parsed = parseJsPackageSpecifier(rawSpecifier);
    const isLocal = !parsed;
    const packageRoot = parsed ? parsed.packageRoot : rawSpecifier;
    const subpath = parsed ? parsed.subpath : null;

    const line = node.startPosition.row + 1;
    const isStatementTypeOnly =
      node.text.startsWith('import type') || node.text.startsWith('import\ntype');

    const importClause = node.children.find((c) => c.type === 'import_clause');
    if (!importClause) return;

    // Check for default import: import _ from 'pkg'
    const defaultId = importClause.children.find((c) => c.type === 'identifier');
    if (defaultId) {
      const b: ImportBinding = {
        localName: defaultId.text,
        importedName: 'default',
        rawSpecifier,
        packageRoot,
        subpath,
        kind: 'ESM_STATIC',
        line,
        isTypeOnly: isStatementTypeOnly,
      };
      bindings.push(b);
      if (!isLocal && !isStatementTypeOnly) boundNames.set(b.localName, b);
      if (!isLocal && subpath && !isStatementTypeOnly) {
        escapes.push({
          packageRoot,
          reason: 'UNKNOWN_SUBPATH',
          file: relativePath,
          line,
          detail: `Default import of subpath '${rawSpecifier}'`,
        });
      }
    }

    // Check for namespace import: import * as _ from 'pkg'
    const ns = importClause.children.find((c) => c.type === 'namespace_import');
    if (ns) {
      const id = ns.children.find((c) => c.type === 'identifier');
      if (id) {
        const b: ImportBinding = {
          localName: id.text,
          importedName: 'namespace',
          rawSpecifier,
          packageRoot,
          subpath,
          kind: 'ESM_STATIC',
          line,
          isTypeOnly: isStatementTypeOnly,
        };
        bindings.push(b);
        if (!isLocal && !isStatementTypeOnly) boundNames.set(b.localName, b);
        if (!isLocal && subpath && !isStatementTypeOnly) {
          escapes.push({
            packageRoot,
            reason: 'UNKNOWN_SUBPATH',
            file: relativePath,
            line,
            detail: `Namespace import of subpath '${rawSpecifier}'`,
          });
        }
      }
    }

    // Check for named imports: import { a, b as c } from 'pkg'
    const named = importClause.children.find((c) => c.type === 'named_imports');
    if (named) {
      for (let i = 0; i < named.namedChildCount; i++) {
        const spec = named.namedChild(i)!;
        if (spec.type === 'import_specifier') {
          const nameChild = spec.childForFieldName('name') ?? spec.namedChild(0);
          const aliasChild = spec.childForFieldName('alias');
          if (nameChild) {
            const importedName = nameChild.text;
            const localName = aliasChild ? aliasChild.text : importedName;
            const isTypeOnly = isStatementTypeOnly || spec.text.startsWith('type ');
            const b: ImportBinding = {
              localName,
              importedName,
              rawSpecifier,
              packageRoot,
              subpath,
              kind: 'ESM_STATIC',
              line,
              isTypeOnly,
            };
            bindings.push(b);
            if (!isLocal && !isTypeOnly) boundNames.set(b.localName, b);
          }
        }
      }
    }
  }

  private static processTsImportEquals(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    escapes: EscapeFact[],
    relativePath: string
  ): void {
    const nameNode = node.childForFieldName('name');
    if (!nameNode) return;

    // module_reference: require('specifier')
    const modRef = node.childForFieldName('module_reference') ?? node.namedChild(1);
    if (!modRef) return;

    const stringNode = modRef.children.find(
      (c) => c.type === 'string' || c.type === 'string_fragment'
    );
    if (!stringNode) return;

    const rawSpecifier = JsImportExtractor.unquote(stringNode.text);
    const parsed = parseJsPackageSpecifier(rawSpecifier);
    if (!parsed) return;

    const line = node.startPosition.row + 1;
    const b: ImportBinding = {
      localName: nameNode.text,
      importedName: 'namespace',
      rawSpecifier,
      packageRoot: parsed.packageRoot,
      subpath: parsed.subpath,
      kind: 'TS_IMPORT_EQUALS',
      line,
      isTypeOnly: false,
    };
    bindings.push(b);
    boundNames.set(b.localName, b);
    if (parsed.subpath) {
      escapes.push({
        packageRoot: parsed.packageRoot,
        reason: 'UNKNOWN_SUBPATH',
        file: relativePath,
        line,
        detail: `Import equals on subpath '${rawSpecifier}'`,
      });
    }
  }

  private static processExportStatement(
    node: Parser.SyntaxNode,
    boundNames: Map<string, ImportBinding>,
    recordEscape: (pkg: string, reason: EscapeFact['reason'], line: number, detail?: string) => void
  ): void {
    const line = node.startPosition.row + 1;
    const sourceNode = node.childForFieldName('source');

    // Re-export: export * from 'pkg' or export * as x from 'pkg'
    if (sourceNode) {
      const rawSpecifier = JsImportExtractor.unquote(sourceNode.text);
      const parsed = parseJsPackageSpecifier(rawSpecifier);
      if (parsed) {
        if (node.text.includes('*')) {
          recordEscape(
            parsed.packageRoot,
            'REEXPORT_ALL',
            line,
            `Re-export all wildcard from ${rawSpecifier}`
          );
        }
      }
    }

    // Exporting a bound identifier: export default _ or export { _ }
    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i)!;
      if (child.type === 'identifier' && boundNames.has(child.text)) {
        const b = boundNames.get(child.text)!;
        recordEscape(b.packageRoot, 'EXPORT', line, `Exported bound identifier '${child.text}'`);
      } else if (child.type === 'export_clause') {
        for (let j = 0; j < child.namedChildCount; j++) {
          const spec = child.namedChild(j)!;
          const nameChild = spec.childForFieldName('name') ?? spec.namedChild(0);
          if (nameChild && boundNames.has(nameChild.text)) {
            const b = boundNames.get(nameChild.text)!;
            recordEscape(
              b.packageRoot,
              'EXPORT',
              line,
              `Exported bound identifier '${nameChild.text}'`
            );
          }
        }
      }
    }
  }

  private static processVariableDeclarator(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    memberAliases: Map<string, MemberAlias>,
    recordUsage: (
      pkg: string,
      sym: string,
      form: UsageForm,
      line: number,
      isCall: boolean,
      callee?: string
    ) => void,
    recordEscape: (pkg: string, reason: EscapeFact['reason'], line: number, detail?: string) => void
  ): void {
    const nameNode = node.childForFieldName('name');
    const valNode = node.childForFieldName('value');
    if (!nameNode || !valNode) return;

    const line = node.startPosition.row + 1;

    // Pattern 1: const _ = require('pkg') OR const mod = await import('pkg')
    if (valNode.type === 'call_expression' || valNode.type === 'await_expression') {
      const call =
        valNode.type === 'await_expression'
          ? valNode.children.find((c) => c.type === 'call_expression')
          : valNode;

      if (call) {
        const fn = call.childForFieldName('function');
        const args = call.childForFieldName('arguments');
        if (fn && (fn.text === 'require' || fn.text === 'import' || fn.type === 'import')) {
          if (args && args.namedChildCount > 0) {
            const firstArg = args.namedChild(0)!;
            if (firstArg.type === 'string' || firstArg.type === 'template_string') {
              const rawSpecifier = JsImportExtractor.unquote(firstArg.text);
              const parsed = parseJsPackageSpecifier(rawSpecifier);
              if (parsed) {
                const kind =
                  fn.text === 'require'
                    ? 'CJS'
                    : valNode.type === 'await_expression'
                      ? 'ESM_DYNAMIC'
                      : 'CJS';

                // Case A: const _ = require('pkg')
                if (nameNode.type === 'identifier') {
                  const b: ImportBinding = {
                    localName: nameNode.text,
                    importedName: 'namespace',
                    rawSpecifier,
                    packageRoot: parsed.packageRoot,
                    subpath: parsed.subpath,
                    kind,
                    line,
                    isTypeOnly: false,
                  };
                  bindings.push(b);
                  boundNames.set(b.localName, b);
                  if (parsed.subpath) {
                    recordEscape(
                      parsed.packageRoot,
                      'UNKNOWN_SUBPATH',
                      line,
                      `Require on subpath '${rawSpecifier}'`
                    );
                  }
                  return;
                }

                // Case B: const { template, isEqual: eq } = require('pkg')
                if (nameNode.type === 'object_pattern') {
                  JsSymbolUsageExtractor.extractDestructuringBindings(
                    nameNode,
                    parsed.packageRoot,
                    line,
                    bindings,
                    boundNames,
                    memberAliases,
                    rawSpecifier,
                    kind
                  );
                  return;
                }
              }
            }
          }
        }
      }
    }

    // Pattern 2: Member aliasing: const tpl = _.template
    if (valNode.type === 'member_expression') {
      const obj = valNode.childForFieldName('object');
      const prop = valNode.childForFieldName('property');
      if (obj && prop && boundNames.has(obj.text)) {
        const b = boundNames.get(obj.text)!;
        const sym = prop.text;
        if (nameNode.type === 'identifier') {
          memberAliases.set(nameNode.text, {
            packageRoot: b.packageRoot,
            symbol: sym,
            form: 'aliased_member',
          });
          recordUsage(b.packageRoot, sym, 'aliased_member', line, false, `${obj.text}.${sym}`);
          return;
        }
      }
    }

    // Pattern 3: Destructuring from bound namespace: const { template, a: { b } } = _
    if (nameNode.type === 'object_pattern' && valNode.type === 'identifier') {
      if (boundNames.has(valNode.text)) {
        const b = boundNames.get(valNode.text)!;
        JsSymbolUsageExtractor.extractDestructuringBindings(
          nameNode,
          b.packageRoot,
          line,
          bindings,
          boundNames,
          memberAliases,
          b.rawSpecifier,
          b.kind
        );
      }
    }
  }

  private static extractDestructuringBindings(
    patternNode: Parser.SyntaxNode,
    packageRoot: string,
    line: number,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    memberAliases: Map<string, MemberAlias>,
    rawSpecifier: string,
    kind: ImportBinding['kind']
  ): void {
    for (let i = 0; i < patternNode.namedChildCount; i++) {
      const child = patternNode.namedChild(i)!;
      // { template } or { key: alias } or { a: { b } }
      if (child.type === 'shorthand_property_identifier_pattern') {
        const sym = child.text;
        const b: ImportBinding = {
          localName: sym,
          importedName: sym,
          rawSpecifier,
          packageRoot,
          subpath: null,
          kind,
          line,
          isTypeOnly: false,
        };
        bindings.push(b);
        boundNames.set(sym, b);
        memberAliases.set(sym, { packageRoot, symbol: sym, form: 'destructured' });
      } else if (child.type === 'pair_pattern') {
        const key = child.childForFieldName('key');
        const value = child.childForFieldName('value');
        if (key && value) {
          const sym = key.text;
          if (value.type === 'identifier') {
            const alias = value.text;
            const b: ImportBinding = {
              localName: alias,
              importedName: sym,
              rawSpecifier,
              packageRoot,
              subpath: null,
              kind,
              line,
              isTypeOnly: false,
            };
            bindings.push(b);
            boundNames.set(alias, b);
            memberAliases.set(alias, { packageRoot, symbol: sym, form: 'destructured' });
          } else if (value.type === 'object_pattern') {
            // Nested destructuring: { a: { b } }
            JsSymbolUsageExtractor.extractDestructuringBindings(
              value,
              packageRoot,
              line,
              bindings,
              boundNames,
              memberAliases,
              rawSpecifier,
              kind
            );
          }
        }
      }
    }
  }

  private static processCallExpression(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    memberAliases: Map<string, MemberAlias>,
    recordUsage: (
      pkg: string,
      sym: string,
      form: UsageForm,
      line: number,
      isCall: boolean,
      callee?: string
    ) => void,
    recordEscape: (pkg: string, reason: EscapeFact['reason'], line: number, detail?: string) => void
  ): void {
    const fn = node.childForFieldName('function');
    const args = node.childForFieldName('arguments');
    const line = node.startPosition.row + 1;
    if (!fn) return;

    // 0. Dynamic import with .then: import('pkg').then(m => { ... })
    if (fn.type === 'member_expression') {
      const prop = fn.childForFieldName('property');
      const obj = fn.childForFieldName('object');
      if (prop && prop.text === 'then' && obj && obj.type === 'call_expression') {
        const innerFn = obj.childForFieldName('function');
        const innerArgs = obj.childForFieldName('arguments');
        if (
          innerFn &&
          (innerFn.text === 'import' || innerFn.type === 'import') &&
          innerArgs &&
          innerArgs.namedChildCount > 0
        ) {
          const firstArg = innerArgs.namedChild(0)!;
          if (firstArg.type === 'string' || firstArg.type === 'template_string') {
            const rawSpecifier = JsImportExtractor.unquote(firstArg.text);
            const parsed = parseJsPackageSpecifier(rawSpecifier);
            if (parsed && args && args.namedChildCount > 0) {
              const callback = args.namedChild(0)!;
              let paramId: Parser.SyntaxNode | null = null;
              if (callback.type === 'arrow_function' || callback.type === 'function_expression') {
                const params =
                  callback.childForFieldName('parameters') ??
                  callback.childForFieldName('parameter');
                if (params) {
                  if (params.type === 'identifier') {
                    paramId = params;
                  } else if (params.namedChildCount > 0) {
                    const firstParam = params.namedChild(0)!;
                    if (firstParam.type === 'identifier') {
                      paramId = firstParam;
                    }
                  }
                }
              }
              if (paramId) {
                const b: ImportBinding = {
                  localName: paramId.text,
                  importedName: 'namespace',
                  rawSpecifier,
                  packageRoot: parsed.packageRoot,
                  subpath: parsed.subpath,
                  kind: 'ESM_DYNAMIC',
                  line,
                  isTypeOnly: false,
                };
                bindings.push(b);
                boundNames.set(b.localName, b);
              }
            }
          }
        }
      }
    }

    // 1. Direct call of a bound name: e.g. template(...) or t(...) or _()
    if (fn.type === 'identifier') {
      const name = fn.text;
      // Is it a direct named import or destructured alias?
      if (memberAliases.has(name)) {
        const alias = memberAliases.get(name)!;
        recordUsage(alias.packageRoot, alias.symbol, alias.form, line, true, name);
      } else if (boundNames.has(name)) {
        const b = boundNames.get(name)!;
        if (b.importedName !== 'default' && b.importedName !== 'namespace') {
          // Direct named import: import { template } from 'lodash'
          recordUsage(b.packageRoot, b.importedName, 'call', line, true, name);
        } else if (b.subpath) {
          // Subpath direct callable: const template = require('lodash/template'); template();
          recordUsage(b.packageRoot, b.subpath, 'call', line, true, name);
        } else {
          // Whole module / default callable: const fn = require('lodash'); fn();
          recordEscape(
            b.packageRoot,
            'CALLABLE_MODULE',
            line,
            `Module '${name}' called as function`
          );
        }
      }
    }

    // 2. Member call: _.template(...) or _?.template(...) or _.chain().template(...)
    if (fn.type === 'member_expression') {
      const obj = fn.childForFieldName('object');
      const prop = fn.childForFieldName('property');
      const root = JsSymbolUsageExtractor.resolveReceiverRoot(obj, boundNames);
      if (root && prop) {
        recordUsage(
          root.packageRoot,
          prop.text,
          'member_call',
          line,
          true,
          `${root.rootName}.${prop.text}`
        );
      }
    }

    // 3. Literal computed call: _['template'](...)
    if (fn.type === 'subscript_expression') {
      const obj = fn.childForFieldName('object');
      const idx = fn.childForFieldName('index');
      if (obj && idx && boundNames.has(obj.text)) {
        const b = boundNames.get(obj.text)!;
        if (idx.type === 'string' || idx.type === 'string_fragment') {
          const sym = JsImportExtractor.unquote(idx.text);
          recordUsage(b.packageRoot, sym, 'computed_access', line, true, `${obj.text}['${sym}']`);
        } else {
          recordEscape(b.packageRoot, 'NON_LITERAL_COMPUTED', line, idx.text);
        }
      }
    }

    // 4. Direct call on require: require('pkg')() or require('pkg').template()
    if (fn.text.startsWith('require(')) {
      if (fn.type === 'call_expression') {
        // require('pkg')()
        recordEscape('UNKNOWN', 'CALLABLE_MODULE', line, 'Direct require() result called');
      } else if (fn.type === 'member_expression') {
        // require('pkg').template()
        const obj = fn.childForFieldName('object');
        const prop = fn.childForFieldName('property');
        if (obj && prop && obj.type === 'call_expression') {
          const callArgs = obj.childForFieldName('arguments');
          if (callArgs && callArgs.namedChildCount > 0) {
            const spec = JsImportExtractor.unquote(callArgs.namedChild(0)!.text);
            const parsed = parseJsPackageSpecifier(spec);
            if (parsed) {
              recordUsage(
                parsed.packageRoot,
                prop.text,
                'member_call',
                line,
                true,
                `${spec}.${prop.text}`
              );
            }
          }
        }
      }
    }

    // 5. Enumeration check: Object.keys(_), Object.assign({}, _), Object.entries(_), Object.values(_)
    if (fn.text.startsWith('Object.') && args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const arg = args.namedChild(i)!;
        if (arg.type === 'identifier' && boundNames.has(arg.text)) {
          const b = boundNames.get(arg.text)!;
          recordEscape(b.packageRoot, 'ENUMERATION', line, `${fn.text}(${arg.text})`);
        }
      }
    }

    // 6. Argument pass check: foo(_) -> ARGUMENT_PASS; foo(sym) -> reference usage
    if (args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const arg = args.namedChild(i)!;
        if (arg.type === 'identifier') {
          if (memberAliases.has(arg.text)) {
            const alias = memberAliases.get(arg.text)!;
            recordUsage(alias.packageRoot, alias.symbol, alias.form, line, false, arg.text);
          } else if (boundNames.has(arg.text)) {
            const b = boundNames.get(arg.text)!;
            if (b.importedName === 'default' || b.importedName === 'namespace') {
              recordEscape(
                b.packageRoot,
                'ARGUMENT_PASS',
                line,
                `Passed '${arg.text}' to '${fn.text}'`
              );
            } else {
              recordUsage(b.packageRoot, b.importedName, 'member_access', line, false, arg.text);
            }
          }
        }
      }
    }
  }

  private static processMemberOrSubscript(
    node: Parser.SyntaxNode,
    boundNames: Map<string, ImportBinding>,
    memberAliases: Map<string, MemberAlias>,
    recordUsage: (
      pkg: string,
      sym: string,
      form: UsageForm,
      line: number,
      isCall: boolean,
      callee?: string
    ) => void,
    recordEscape: (pkg: string, reason: EscapeFact['reason'], line: number, detail?: string) => void
  ): void {
    // If parent is a call expression where this node is the callee, it's already handled in processCallExpression
    const parent = node.parent;
    if (
      parent &&
      parent.type === 'call_expression' &&
      parent.childForFieldName('function')?.id === node.id
    ) {
      return;
    }
    // If parent is a variable_declarator where this member expression is value, handled in processVariableDeclarator
    if (
      node.type === 'member_expression' &&
      parent &&
      parent.type === 'variable_declarator' &&
      parent.childForFieldName('value')?.id === node.id
    ) {
      return;
    }

    const line = node.startPosition.row + 1;

    if (node.type === 'member_expression') {
      const obj = node.childForFieldName('object');
      const prop = node.childForFieldName('property');
      const root = JsSymbolUsageExtractor.resolveReceiverRoot(obj, boundNames);
      if (root && prop) {
        recordUsage(
          root.packageRoot,
          prop.text,
          'member_access',
          line,
          false,
          `${root.rootName}.${prop.text}`
        );
      }
    } else if (node.type === 'subscript_expression') {
      const obj = node.childForFieldName('object');
      const idx = node.childForFieldName('index');
      if (obj && idx && boundNames.has(obj.text)) {
        const b = boundNames.get(obj.text)!;
        if (idx.type === 'string' || idx.type === 'string_fragment') {
          const sym = JsImportExtractor.unquote(idx.text);
          recordUsage(b.packageRoot, sym, 'computed_access', line, false, `${obj.text}['${sym}']`);
        } else {
          recordEscape(b.packageRoot, 'NON_LITERAL_COMPUTED', line, idx.text);
        }
      }
    }
  }

  /**
   * Resolves the root receiver package and identifier for a chained member access or method call.
   * Traverses through member expressions, optional chaining, and calls (e.g. _.chain().template() or axios.create().get()).
   */
  private static resolveReceiverRoot(
    node: Parser.SyntaxNode | null,
    boundNames: Map<string, ImportBinding>
  ): { packageRoot: string; rootName: string } | null {
    if (!node) return null;

    let current: Parser.SyntaxNode | null = node;
    while (current) {
      if (current.type === 'identifier') {
        if (boundNames.has(current.text)) {
          const b = boundNames.get(current.text)!;
          return { packageRoot: b.packageRoot, rootName: current.text };
        }
        return null;
      }

      if (current.type === 'member_expression') {
        current = current.childForFieldName('object');
        continue;
      }

      if (current.type === 'call_expression') {
        current = current.childForFieldName('function');
        continue;
      }

      break;
    }

    return null;
  }
}
