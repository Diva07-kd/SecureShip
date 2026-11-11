import type Parser from 'web-tree-sitter';

export interface ExtractedImport {
  specifier: string;
  isTypeOnly: boolean;
  startLine: number;
}

export interface ExtractedExport {
  specifier: string;
  isTypeOnly: boolean;
}

export interface JsExtractionResult {
  imports: ExtractedImport[];
  exports: ExtractedExport[];
  hasDynamicImports: boolean;
}

export class JsImportExtractor {
  /**
   * Cleans quotes from literal string: "'foo'" -> "foo", '"@bar"' -> "@bar"
   */
  public static unquote(text: string): string {
    const trimmed = text.trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith('`') && trimmed.endsWith('`'))
    ) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  /**
   * Traverses a parsed Tree-sitter AST and extracts all imports, re-exports, and dynamic markers.
   */
  public static extract(rootNode: Parser.SyntaxNode): JsExtractionResult {
    const imports: ExtractedImport[] = [];
    const exports: ExtractedExport[] = [];
    let hasDynamicImports = false;

    function walk(node: Parser.SyntaxNode): void {
      switch (node.type) {
        // 1. ESM Import Statement: import ... from 'specifier' or import _ = require('specifier')
        case 'import_statement': {
          const sourceNode = node.childForFieldName('source');
          if (sourceNode) {
            const specifier = JsImportExtractor.unquote(sourceNode.text);
            const isTypeOnly = JsImportExtractor.isTypeOnlyImport(node);
            imports.push({
              specifier,
              isTypeOnly,
              startLine: node.startPosition.row + 1,
            });
          } else {
            // TypeScript import equals: import _ = require('specifier');
            const reqClause = node.children.find((c) => c.type === 'import_require_clause');
            if (reqClause) {
              const str = reqClause.children.find(
                (c) => c.type === 'string' || c.type === 'string_fragment'
              );
              if (str) {
                const specifier = JsImportExtractor.unquote(str.text);
                imports.push({
                  specifier,
                  isTypeOnly: false,
                  startLine: node.startPosition.row + 1,
                });
              }
            }
          }
          break;
        }

        // 2. ESM Export Statement: export ... from 'specifier';
        case 'export_statement': {
          const sourceNode = node.childForFieldName('source');
          if (sourceNode) {
            const specifier = JsImportExtractor.unquote(sourceNode.text);
            const isTypeOnly = node.text.startsWith('export type');
            exports.push({
              specifier,
              isTypeOnly,
            });
            // Re-exports also function as runtime imports if not type-only
            imports.push({
              specifier,
              isTypeOnly,
              startLine: node.startPosition.row + 1,
            });
          }
          break;
        }

        // 3. Call Expression: require('foo'), import('foo'), eval(...), etc.
        case 'call_expression': {
          const fn = node.childForFieldName('function');
          const args = node.childForFieldName('arguments');

          if (fn) {
            const fnText = fn.text;

            const isStaticString = (arg: Parser.SyntaxNode) => {
              if (arg.type === 'string') return true;
              if (arg.type === 'template_string') {
                return !arg.children.some((c) => c.type === 'template_substitution');
              }
              return false;
            };

            // CommonJS require(...)
            if (fnText === 'require') {
              if (args && args.namedChildCount > 0) {
                const firstArg = args.namedChild(0)!;
                if (isStaticString(firstArg)) {
                  imports.push({
                    specifier: JsImportExtractor.unquote(firstArg.text),
                    isTypeOnly: false,
                    startLine: node.startPosition.row + 1,
                  });
                } else {
                  // Non-literal require: require(variable), require(fn())
                  hasDynamicImports = true;
                }
              } else {
                hasDynamicImports = true;
              }
            }

            // Dynamic import(...)
            else if (fnText === 'import' || fn.type === 'import') {
              if (args && args.namedChildCount > 0) {
                const firstArg = args.namedChild(0)!;
                if (isStaticString(firstArg)) {
                  imports.push({
                    specifier: JsImportExtractor.unquote(firstArg.text),
                    isTypeOnly: false,
                    startLine: node.startPosition.row + 1,
                  });
                } else {
                  // Dynamic non-literal import: import(path)
                  hasDynamicImports = true;
                }
              } else {
                hasDynamicImports = true;
              }
            }

            // eval(...)
            else if (fnText === 'eval') {
              hasDynamicImports = true;
            }
          }
          break;
        }

        // 4. new Function(...)
        case 'new_expression': {
          const ctor = node.childForFieldName('constructor');
          if (ctor && ctor.text === 'Function') {
            hasDynamicImports = true;
          }
          break;
        }

        // 5. TS Import Equals: import _ = require('specifier');
        case 'import_equals_declaration': {
          const modRef = node.childForFieldName('module_reference') ?? node.namedChild(1);
          if (modRef) {
            const str = modRef.children.find(
              (c) => c.type === 'string' || c.type === 'string_fragment'
            );
            if (str) {
              const specifier = JsImportExtractor.unquote(str.text);
              imports.push({
                specifier,
                isTypeOnly: false,
                startLine: node.startPosition.row + 1,
              });
            }
          }
          break;
        }
      }

      for (let i = 0; i < node.childCount; i++) {
        walk(node.child(i)!);
      }
    }

    walk(rootNode);

    return {
      imports,
      exports,
      hasDynamicImports,
    };
  }

  /**
   * Checks if an import statement is strictly type-only in TypeScript.
   */
  private static isTypeOnlyImport(node: Parser.SyntaxNode): boolean {
    // 1. import type ... from '...'
    if (node.text.startsWith('import type') || node.text.startsWith('import\ntype')) {
      return true;
    }

    // 2. Check named imports where every specifier has `type` keyword
    // e.g. import { type A, type B } from '...'
    const importClause = node.children.find((c) => c.type === 'import_clause');
    if (importClause) {
      const namedImports = importClause.children.find((c) => c.type === 'named_imports');
      if (namedImports && namedImports.namedChildCount > 0) {
        let allTypeOnly = true;
        for (let i = 0; i < namedImports.namedChildCount; i++) {
          const spec = namedImports.namedChild(i)!;
          if (spec.type === 'import_specifier') {
            if (!spec.text.startsWith('type ')) {
              allTypeOnly = false;
              break;
            }
          }
        }
        if (allTypeOnly) return true;
      }
    }

    return false;
  }
}
