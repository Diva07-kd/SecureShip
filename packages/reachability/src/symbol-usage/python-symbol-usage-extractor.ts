import type Parser from 'web-tree-sitter';
import { PythonImportExtractor } from '../python/python-import-extractor.js';
import type {
  ImportBinding,
  SymbolUsageFact,
  EscapeFact,
  FileSymbolUsage,
  UsageForm,
} from './symbol-usage.types.js';

export interface ParsePythonSpecifierResult {
  packageRoot: string;
  subpath: string | null;
}

export function parsePythonPackageSpecifier(specifier: string): ParsePythonSpecifierResult | null {
  const trimmed = specifier.trim();
  if (trimmed.startsWith('.')) {
    return null; // Local relative import
  }

  const parts = trimmed.split('.');
  const packageRoot = parts[0]!;
  const subpath = parts.length > 1 ? parts.slice(1).join('.') : null;
  return { packageRoot, subpath };
}

interface StackFrame {
  node: Parser.SyntaxNode;
  isExit?: boolean;
  fnName?: string;
}

interface PythonAlias {
  packageRoot: string;
  symbol: string;
  form: UsageForm;
}

export class PythonSymbolUsageExtractor {
  public static readonly MAX_NODES = 500_000;
  public static readonly MAX_TIME_MS = 10_000;

  /**
   * Iteratively extracts import bindings, symbol usage facts, and escapes from a Python AST.
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

    // Local name -> ImportBinding
    const boundNames = new Map<string, ImportBinding>();
    // Local alias -> PythonAlias (e.g. my_load = yaml.load)
    const aliases = new Map<string, PythonAlias>();

    const activeFunctions: string[] = [];

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
      if (nodeCount > PythonSymbolUsageExtractor.MAX_NODES) {
        usageIncomplete = true;
        incompleteReason = 'AST node count limit exceeded (500,000)';
        break;
      }

      if (Date.now() - startTime > PythonSymbolUsageExtractor.MAX_TIME_MS) {
        usageIncomplete = true;
        incompleteReason = 'Extraction timeout exceeded (10s)';
        break;
      }

      const node = frame.node;

      // 1. Function scope tracking
      if (node.type === 'function_definition') {
        const nameNode = node.childForFieldName('name');
        if (nameNode) {
          const fnName = nameNode.text;
          activeFunctions.push(fnName);
          stack.push({ node, isExit: true, fnName });
        }
      }

      // 2. Process node types
      switch (node.type) {
        // import a, b as c, d.e
        case 'import_statement': {
          PythonSymbolUsageExtractor.processImportStatement(
            node,
            bindings,
            boundNames,
            escapes,
            relativePath
          );
          break;
        }

        // from module import x, y as z, *
        case 'import_from_statement': {
          PythonSymbolUsageExtractor.processImportFromStatement(
            node,
            bindings,
            boundNames,
            aliases,
            escapes,
            relativePath
          );
          break;
        }

        // Variable assignment: fn = yaml.load
        case 'assignment': {
          PythonSymbolUsageExtractor.processAssignment(
            node,
            boundNames,
            aliases,
            recordUsage,
            recordEscape
          );
          break;
        }

        // Call: yaml.load(...), fn(...), getattr(yaml, ...)
        case 'call': {
          PythonSymbolUsageExtractor.processCall(
            node,
            boundNames,
            aliases,
            recordUsage,
            recordEscape
          );
          break;
        }

        // Attribute access outside of call: yaml.load
        case 'attribute': {
          PythonSymbolUsageExtractor.processAttribute(node, boundNames, aliases, recordUsage);
          break;
        }

        // Return: return yaml
        case 'return_statement': {
          for (let i = 0; i < node.namedChildCount; i++) {
            const child = node.namedChild(i)!;
            if (child.type === 'identifier' && boundNames.has(child.text)) {
              const b = boundNames.get(child.text)!;
              recordEscape(b.packageRoot, 'RETURN', node.startPosition.row + 1, child.text);
            }
          }
          break;
        }

        // Container stores: [yaml], {'m': yaml}, (yaml,)
        case 'list':
        case 'dictionary':
        case 'tuple':
        case 'set': {
          for (let i = 0; i < node.namedChildCount; i++) {
            const child = node.namedChild(i)!;
            if (child.type === 'identifier' && boundNames.has(child.text)) {
              const b = boundNames.get(child.text)!;
              recordEscape(
                b.packageRoot,
                'CONTAINER_STORE',
                node.startPosition.row + 1,
                child.text
              );
            } else if (child.type === 'pair') {
              const val = child.childForFieldName('value');
              if (val && val.type === 'identifier' && boundNames.has(val.text)) {
                const b = boundNames.get(val.text)!;
                recordEscape(
                  b.packageRoot,
                  'CONTAINER_STORE',
                  node.startPosition.row + 1,
                  val.text
                );
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

    return {
      filePath,
      relativePath,
      bindings,
      usageFacts,
      escapes,
      hasCreateRequire: false,
      usageIncomplete,
      incompleteReason,
    };
  }

  private static processImportStatement(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    escapes: EscapeFact[],
    relativePath: string
  ): void {
    const line = node.startPosition.row + 1;

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i)!;
      if (child.type === 'dotted_name') {
        const rawSpecifier = child.text;
        const parsed = parsePythonPackageSpecifier(rawSpecifier);
        if (!parsed) continue;

        const b: ImportBinding = {
          localName: parsed.packageRoot,
          importedName: 'namespace',
          rawSpecifier,
          packageRoot: parsed.packageRoot,
          subpath: parsed.subpath,
          kind: 'PYTHON_IMPORT',
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
            detail: `Import on subpath '${rawSpecifier}'`,
          });
        }
      } else if (child.type === 'aliased_import') {
        const nameNode = child.childForFieldName('name');
        const aliasNode = child.childForFieldName('alias');
        if (nameNode && aliasNode) {
          const rawSpecifier = nameNode.text;
          const parsed = parsePythonPackageSpecifier(rawSpecifier);
          if (!parsed) continue;

          const b: ImportBinding = {
            localName: aliasNode.text,
            importedName: 'namespace',
            rawSpecifier,
            packageRoot: parsed.packageRoot,
            subpath: parsed.subpath,
            kind: 'PYTHON_IMPORT',
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
              detail: `Aliased import on subpath '${rawSpecifier}'`,
            });
          }
        }
      }
    }
  }

  private static processImportFromStatement(
    node: Parser.SyntaxNode,
    bindings: ImportBinding[],
    boundNames: Map<string, ImportBinding>,
    aliases: Map<string, PythonAlias>,
    escapes: EscapeFact[],
    relativePath: string
  ): void {
    const line = node.startPosition.row + 1;
    const moduleNode = node.childForFieldName('module_name');
    if (!moduleNode) return;

    const rawSpecifier = moduleNode.text;
    const parsed = parsePythonPackageSpecifier(rawSpecifier);
    if (!parsed) return;

    for (let i = 0; i < node.namedChildCount; i++) {
      const child = node.namedChild(i)!;
      if (child === moduleNode) continue;

      if (child.type === 'wildcard_import') {
        escapes.push({
          packageRoot: parsed.packageRoot,
          reason: 'WILDCARD_IMPORT',
          file: relativePath,
          line,
          detail: `from ${rawSpecifier} import *`,
        });
      } else if (child.type === 'dotted_name') {
        const sym = child.text;
        const b: ImportBinding = {
          localName: sym,
          importedName: sym,
          rawSpecifier,
          packageRoot: parsed.packageRoot,
          subpath: parsed.subpath,
          kind: 'PYTHON_FROM_IMPORT',
          line,
          isTypeOnly: false,
        };
        bindings.push(b);
        boundNames.set(sym, b);
        aliases.set(sym, { packageRoot: parsed.packageRoot, symbol: sym, form: 'call' });
      } else if (child.type === 'aliased_import') {
        const nameChild = child.childForFieldName('name');
        const aliasChild = child.childForFieldName('alias');
        if (nameChild && aliasChild) {
          const sym = nameChild.text;
          const alias = aliasChild.text;
          const b: ImportBinding = {
            localName: alias,
            importedName: sym,
            rawSpecifier,
            packageRoot: parsed.packageRoot,
            subpath: parsed.subpath,
            kind: 'PYTHON_FROM_IMPORT',
            line,
            isTypeOnly: false,
          };
          bindings.push(b);
          boundNames.set(alias, b);
          aliases.set(alias, {
            packageRoot: parsed.packageRoot,
            symbol: sym,
            form: 'aliased_member',
          });
        }
      }
    }
  }

  private static processAssignment(
    node: Parser.SyntaxNode,
    boundNames: Map<string, ImportBinding>,
    aliases: Map<string, PythonAlias>,
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
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    const line = node.startPosition.row + 1;
    if (!left || !right) return;

    // Check if left is bound module reassignment: yaml = other
    if (left.type === 'identifier' && boundNames.has(left.text)) {
      const b = boundNames.get(left.text)!;
      recordEscape(b.packageRoot, 'REASSIGNMENT', line, left.text);
    }

    // Check member aliasing: my_load = yaml.load
    if (left.type === 'identifier' && right.type === 'attribute') {
      const obj = right.childForFieldName('object');
      const attr = right.childForFieldName('attribute');
      if (obj && attr && boundNames.has(obj.text)) {
        const b = boundNames.get(obj.text)!;
        aliases.set(left.text, {
          packageRoot: b.packageRoot,
          symbol: attr.text,
          form: 'aliased_member',
        });
        recordUsage(
          b.packageRoot,
          attr.text,
          'aliased_member',
          line,
          false,
          `${obj.text}.${attr.text}`
        );
      }
    }
  }

  private static processCall(
    node: Parser.SyntaxNode,
    boundNames: Map<string, ImportBinding>,
    aliases: Map<string, PythonAlias>,
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

    // 1. Direct call of alias or from-imported function: load(...) or my_load(...)
    if (fn.type === 'identifier') {
      const name = fn.text;
      if (aliases.has(name)) {
        const a = aliases.get(name)!;
        recordUsage(a.packageRoot, a.symbol, a.form, line, true, name);
      } else if (boundNames.has(name)) {
        const b = boundNames.get(name)!;
        if (b.importedName === 'namespace') {
          recordEscape(b.packageRoot, 'CALLABLE_MODULE', line, `Module '${name}' called`);
        } else {
          recordUsage(b.packageRoot, b.importedName, 'call', line, true, name);
        }
      } else if (name === 'getattr' && args && args.namedChildCount >= 2) {
        // getattr(yaml, 'load')
        const firstArg = args.namedChild(0)!;
        const secondArg = args.namedChild(1)!;
        if (firstArg.type === 'identifier' && boundNames.has(firstArg.text)) {
          const b = boundNames.get(firstArg.text)!;
          if (secondArg.type === 'string') {
            const sym = PythonImportExtractor.unquote(secondArg.text);
            recordUsage(
              b.packageRoot,
              sym,
              'computed_access',
              line,
              true,
              `getattr(${firstArg.text}, '${sym}')`
            );
          } else {
            recordEscape(b.packageRoot, 'NON_LITERAL_COMPUTED', line, secondArg.text);
          }
        }
      }
    }

    // 2. Attribute call: yaml.load(...)
    if (fn.type === 'attribute') {
      const obj = fn.childForFieldName('object');
      const attr = fn.childForFieldName('attribute');
      if (obj && attr && boundNames.has(obj.text)) {
        const b = boundNames.get(obj.text)!;
        recordUsage(
          b.packageRoot,
          attr.text,
          'member_call',
          line,
          true,
          `${obj.text}.${attr.text}`
        );
      }
    }

    // 3. Arguments pass check: func(yaml) -> ARGUMENT_PASS
    if (args) {
      for (let i = 0; i < args.namedChildCount; i++) {
        const arg = args.namedChild(i)!;
        if (arg.type === 'identifier' && boundNames.has(arg.text)) {
          const b = boundNames.get(arg.text)!;
          if (b.importedName === 'namespace') {
            recordEscape(b.packageRoot, 'ARGUMENT_PASS', line, `Passed '${arg.text}' to function`);
          }
        }
      }
    }
  }

  private static processAttribute(
    node: Parser.SyntaxNode,
    boundNames: Map<string, ImportBinding>,
    aliases: Map<string, PythonAlias>,
    recordUsage: (
      pkg: string,
      sym: string,
      form: UsageForm,
      line: number,
      isCall: boolean,
      callee?: string
    ) => void
  ): void {
    // If parent is a call where this attribute is the function, handled in processCall
    const parent = node.parent;
    if (parent && parent.type === 'call' && parent.childForFieldName('function')?.id === node.id) {
      return;
    }
    // If parent is assignment where this is right, handled in processAssignment
    if (
      parent &&
      parent.type === 'assignment' &&
      parent.childForFieldName('right')?.id === node.id
    ) {
      return;
    }

    const obj = node.childForFieldName('object');
    const attr = node.childForFieldName('attribute');
    const line = node.startPosition.row + 1;
    if (obj && attr && boundNames.has(obj.text)) {
      const b = boundNames.get(obj.text)!;
      recordUsage(
        b.packageRoot,
        attr.text,
        'member_access',
        line,
        false,
        `${obj.text}.${attr.text}`
      );
    }
  }
}
