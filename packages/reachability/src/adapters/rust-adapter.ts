import fs from 'node:fs';
import path from 'node:path';
import type Parser from 'web-tree-sitter';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ExtractedImport,
  ResolvedModule,
} from './language-adapter.interface.js';

export class RustLanguageAdapter implements ILanguageAdapter {
  public readonly language = 'rust' as const;

  /**
   * Traverses Rust AST and extracts use declarations and extern crates.
   */
  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const imports: ExtractedImport[] = [];

    function extractUsePath(node: Parser.SyntaxNode): string | null {
      if (node.type === 'scoped_identifier') {
        return node.text;
      }
      if (node.type === 'identifier') {
        return node.text;
      }
      if (node.type === 'scoped_use_list') {
        const pathNode = node.childForFieldName('path');
        return pathNode ? pathNode.text : (node.text.split('::')[0] ?? null);
      }
      if (node.type === 'use_wildcard') {
        const pathNode = node.children[0];
        return pathNode ? pathNode.text : null;
      }
      return null;
    }

    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'use_declaration') {
        const argNode =
          node.childForFieldName('argument') ??
          node.children.find((c) => c.type !== 'use' && c.type !== ';');
        if (argNode) {
          const spec = extractUsePath(argNode) ?? argNode.text.replace(/;$/, '').trim();
          if (spec) {
            imports.push({
              specifier: spec,
              isTypeOnly: false,
              startLine: node.startPosition.row + 1,
            });
          }
        }
      } else if (node.type === 'extern_crate_declaration') {
        const nameNode =
          node.childForFieldName('name') ?? node.children.find((c) => c.type === 'identifier');
        if (nameNode) {
          imports.push({
            specifier: nameNode.text,
            isTypeOnly: false,
            startLine: node.startPosition.row + 1,
          });
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        walk(node.namedChild(i)!);
      }
    }

    walk(rootNode);

    return {
      imports,
      exports: [],
      hasDynamicImports: false,
    };
  }

  /**
   * Resolves Rust crate/module imports to a local file, standard library, or external crate.
   */
  public resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule {
    // 1. Rust standard library
    if (
      specifier.startsWith('std::') ||
      specifier === 'std' ||
      specifier.startsWith('core::') ||
      specifier === 'core' ||
      specifier.startsWith('alloc::') ||
      specifier === 'alloc'
    ) {
      return {
        type: 'STANDARD_LIB',
        name: specifier,
      };
    }

    // 2. Local crate imports: crate::foo::bar
    if (specifier.startsWith('crate::')) {
      const subpath = specifier.slice(7).replace(/::/g, '/');
      const srcDir = path.join(projectRoot, 'src');

      const candidates = [path.join(srcDir, `${subpath}.rs`), path.join(srcDir, subpath, 'mod.rs')];

      for (const c of candidates) {
        if (fs.existsSync(c) && fs.statSync(c).isFile()) {
          return {
            type: 'LOCAL_FILE',
            resolvedPath: c,
          };
        }
      }
    }

    // 3. Local relative imports: super::foo or self::bar
    if (specifier.startsWith('super::') || specifier.startsWith('self::')) {
      const isSuper = specifier.startsWith('super::');
      const subpath = specifier.slice(isSuper ? 7 : 6).replace(/::/g, '/');
      const baseDir = isSuper
        ? path.dirname(path.dirname(fromFilePath))
        : path.dirname(fromFilePath);

      const candidates = [
        path.join(baseDir, `${subpath}.rs`),
        path.join(baseDir, subpath, 'mod.rs'),
      ];

      for (const c of candidates) {
        if (fs.existsSync(c) && fs.statSync(c).isFile()) {
          return {
            type: 'LOCAL_FILE',
            resolvedPath: c,
          };
        }
      }
    }

    // 4. External Cargo crate: first identifier before "::"
    const crateName = specifier.split('::')[0] ?? specifier;
    return {
      type: 'PACKAGE',
      packageName: crateName,
    };
  }
}
