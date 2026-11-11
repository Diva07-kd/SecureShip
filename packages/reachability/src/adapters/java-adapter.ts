import fs from 'node:fs';
import path from 'node:path';
import type Parser from 'web-tree-sitter';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ExtractedImport,
  ResolvedModule,
} from './language-adapter.interface.js';

export class JavaLanguageAdapter implements ILanguageAdapter {
  public readonly language = 'java' as const;

  /**
   * Traverses Java AST and extracts package declaration and all imports.
   */
  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const imports: ExtractedImport[] = [];
    let packageDeclaration: string | undefined;

    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'package_declaration') {
        const idNode = node.children.find(
          (c) => c.type === 'scoped_identifier' || c.type === 'identifier'
        );
        if (idNode) {
          packageDeclaration = idNode.text;
        }
      } else if (node.type === 'import_declaration') {
        const idNode = node.children.find(
          (c) => c.type === 'scoped_identifier' || c.type === 'identifier'
        );
        if (idNode) {
          imports.push({
            specifier: idNode.text,
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
      packageDeclaration,
    };
  }

  /**
   * Resolves Java import specifier to a local file, standard library, or external library.
   */
  public resolve(specifier: string, _fromFilePath: string, projectRoot: string): ResolvedModule {
    // 1. Standard Java libraries
    if (
      specifier.startsWith('java.') ||
      specifier.startsWith('javax.') ||
      specifier.startsWith('sun.')
    ) {
      return {
        type: 'STANDARD_LIB',
        name: specifier,
      };
    }

    // 2. Check for local matching Java file in standard Maven/Gradle and custom roots
    const relFile = `${specifier.replace(/\./g, '/')}.java`;
    const searchRoots = [
      path.join(projectRoot, 'src', 'main', 'java'),
      path.join(projectRoot, 'src'),
      path.join(projectRoot, 'app', 'src', 'main', 'java'),
      projectRoot,
    ];

    for (const root of searchRoots) {
      const candidate = path.resolve(root, relFile);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return {
          type: 'LOCAL_FILE',
          resolvedPath: candidate,
        };
      }
    }

    // 3. Fallback: Treat as external Maven/Gradle package
    const parts = specifier.split('.');
    const pkgName = parts.length >= 2 ? `${parts[0]}.${parts[1]}` : specifier;

    return {
      type: 'PACKAGE',
      packageName: pkgName,
    };
  }
}
