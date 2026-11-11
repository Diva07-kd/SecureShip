import fs from 'node:fs';
import path from 'node:path';
import type Parser from 'web-tree-sitter';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ExtractedImport,
  ResolvedModule,
} from './language-adapter.interface.js';

export class GoLanguageAdapter implements ILanguageAdapter {
  public readonly language = 'go' as const;
  private cachedModulePath: Map<string, string | null> = new Map();

  public static unquote(text: string): string {
    const trimmed = text.trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith('`') && trimmed.endsWith('`'))
    ) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  /**
   * Traverses Go AST and extracts package clause and all import statements.
   */
  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const imports: ExtractedImport[] = [];
    let packageDeclaration: string | undefined;

    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'package_clause') {
        const pkgIdentifier = node.children.find((c) => c.type === 'package_identifier');
        if (pkgIdentifier) {
          packageDeclaration = pkgIdentifier.text;
        }
      } else if (node.type === 'import_spec') {
        const pathNode = node.childForFieldName('path');
        if (pathNode) {
          const specifier = GoLanguageAdapter.unquote(pathNode.text);
          if (specifier) {
            imports.push({
              specifier,
              isTypeOnly: false,
              startLine: node.startPosition.row + 1,
            });
          }
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
   * Reads module path from go.mod if present.
   */
  public getGoModulePath(projectRoot: string): string | null {
    if (this.cachedModulePath.has(projectRoot)) {
      return this.cachedModulePath.get(projectRoot)!;
    }

    const goModPath = path.join(projectRoot, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const content = fs.readFileSync(goModPath, 'utf8');
        const match = content.match(/^module\s+([^\s]+)/m);
        if (match && match[1]) {
          const modName = match[1].trim();
          this.cachedModulePath.set(projectRoot, modName);
          return modName;
        }
      } catch {
        // Fallback
      }
    }

    this.cachedModulePath.set(projectRoot, null);
    return null;
  }

  /**
   * Resolves Go import specifier to either a local directory/file, standard library, or external package.
   */
  public resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule {
    const modPath = this.getGoModulePath(projectRoot);

    // 1. Check if it's an internal module import (starts with module path from go.mod)
    if (modPath && (specifier === modPath || specifier.startsWith(`${modPath}/`))) {
      const relSubDir = specifier === modPath ? '.' : specifier.slice(modPath.length + 1);
      const targetDir = path.resolve(projectRoot, relSubDir);

      if (fs.existsSync(targetDir)) {
        try {
          const entries = fs.readdirSync(targetDir);
          const goFile = entries.find((e) => e.endsWith('.go') && !e.endsWith('_test.go'));
          if (goFile) {
            return {
              type: 'LOCAL_FILE',
              resolvedPath: path.resolve(targetDir, goFile),
            };
          }
        } catch {
          // Fallback
        }
      }
    }

    // 2. Relative import e.g. "./subpkg" or "../other"
    if (specifier.startsWith('.')) {
      const targetPath = path.resolve(path.dirname(fromFilePath), specifier);
      if (fs.existsSync(targetPath)) {
        if (fs.statSync(targetPath).isDirectory()) {
          const entries = fs.readdirSync(targetPath);
          const goFile = entries.find((e) => e.endsWith('.go') && !e.endsWith('_test.go'));
          if (goFile) {
            return {
              type: 'LOCAL_FILE',
              resolvedPath: path.resolve(targetPath, goFile),
            };
          }
        } else if (targetPath.endsWith('.go')) {
          return {
            type: 'LOCAL_FILE',
            resolvedPath: targetPath,
          };
        }
      }
    }

    // 3. Third-party package: domain-prefixed (e.g. "github.com/...", "golang.org/...", "gopkg.in/...")
    const firstSlash = specifier.indexOf('/');
    const firstSegment = firstSlash !== -1 ? specifier.slice(0, firstSlash) : specifier;
    if (firstSegment.includes('.')) {
      return {
        type: 'PACKAGE',
        packageName: specifier,
      };
    }

    // 4. Standard library (e.g. "fmt", "net/http", "os/exec")
    return {
      type: 'STANDARD_LIB',
      name: specifier,
    };
  }
}
