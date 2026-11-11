import type Parser from 'web-tree-sitter';

export interface ExtractedPythonImport {
  module: string; // e.g. "os", "yaml", "pkg.sub", ".utils"
  importedNames: string[]; // e.g. ["Path", "load"]
  isRelative: boolean;
  relativeLevel: number; // 1 for '.', 2 for '..', etc.
  startLine: number;
}

export interface PythonExtractionResult {
  imports: ExtractedPythonImport[];
  hasDynamicImports: boolean;
}

export class PythonImportExtractor {
  /**
   * Cleans quotes from literal string: "'foo'" -> "foo"
   */
  public static unquote(text: string): string {
    const trimmed = text.trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))
    ) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  /**
   * Traverses a parsed Python Tree-sitter AST and extracts all module imports and dynamic calls.
   */
  public static extract(rootNode: Parser.SyntaxNode): PythonExtractionResult {
    const imports: ExtractedPythonImport[] = [];
    let hasDynamicImports = false;

    function walk(node: Parser.SyntaxNode): void {
      switch (node.type) {
        // 1. import a, b as c, d.e
        case 'import_statement': {
          for (let i = 0; i < node.namedChildCount; i++) {
            const child = node.namedChild(i)!;
            if (child.type === 'dotted_name') {
              imports.push({
                module: child.text,
                importedNames: [],
                isRelative: false,
                relativeLevel: 0,
                startLine: node.startPosition.row + 1,
              });
            } else if (child.type === 'aliased_import') {
              const nameChild = child.childForFieldName('name');
              if (nameChild) {
                imports.push({
                  module: nameChild.text,
                  importedNames: [],
                  isRelative: false,
                  relativeLevel: 0,
                  startLine: node.startPosition.row + 1,
                });
              }
            }
          }
          break;
        }

        // 2. from module import name1, name2 OR from . import helper
        case 'import_from_statement': {
          const moduleNameNode = node.childForFieldName('module_name');
          let moduleStr = '';
          let isRelative = false;
          let relativeLevel = 0;

          if (moduleNameNode) {
            if (moduleNameNode.type === 'relative_import') {
              isRelative = true;
              // Count leading dots in relative import
              const text = moduleNameNode.text;
              const dotMatch = text.match(/^\.+/);
              relativeLevel = dotMatch ? dotMatch[0].length : 1;
              moduleStr = text;
            } else {
              moduleStr = moduleNameNode.text;
            }
          } else {
            // e.g. from . import x (no module_name field, leading dots are direct children)
            const dotChildren = node.children.filter((c) => c.text === '.');
            if (dotChildren.length > 0) {
              isRelative = true;
              relativeLevel = dotChildren.length;
              moduleStr = '.'.repeat(relativeLevel);
            }
          }

          const importedNames: string[] = [];
          for (let i = 0; i < node.namedChildCount; i++) {
            const child = node.namedChild(i)!;
            if (child.type === 'dotted_name' && child !== moduleNameNode) {
              importedNames.push(child.text);
            } else if (child.type === 'aliased_import') {
              const n = child.childForFieldName('name');
              if (n) importedNames.push(n.text);
            } else if (child.type === 'wildcard_import') {
              importedNames.push('*');
            }
          }

          imports.push({
            module: moduleStr,
            importedNames,
            isRelative,
            relativeLevel,
            startLine: node.startPosition.row + 1,
          });
          break;
        }

        // 3. Dynamic call: importlib.import_module(...), __import__(...), eval(...), exec(...)
        case 'call': {
          const fn = node.childForFieldName('function');
          const args = node.childForFieldName('arguments');

          if (fn) {
            const fnText = fn.text;

            if (
              fnText === 'importlib.import_module' ||
              fnText.endsWith('.import_module') ||
              fnText === '__import__'
            ) {
              if (args && args.namedChildCount > 0) {
                const firstArg = args.namedChild(0)!;
                if (firstArg.type === 'string') {
                  const modName = PythonImportExtractor.unquote(firstArg.text);
                  imports.push({
                    module: modName,
                    importedNames: [],
                    isRelative: modName.startsWith('.'),
                    relativeLevel: modName.startsWith('.') ? 1 : 0,
                    startLine: node.startPosition.row + 1,
                  });
                } else {
                  hasDynamicImports = true;
                }
              } else {
                hasDynamicImports = true;
              }
            } else if (fnText === 'eval' || fnText === 'exec') {
              hasDynamicImports = true;
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
      hasDynamicImports,
    };
  }
}
