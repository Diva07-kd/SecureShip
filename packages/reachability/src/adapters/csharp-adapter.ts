import fs from 'node:fs';
import path from 'node:path';
import type Parser from 'web-tree-sitter';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ExtractedImport,
  ResolvedModule,
} from './language-adapter.interface.js';

export class CsharpLanguageAdapter implements ILanguageAdapter {
  public readonly language = 'c_sharp' as const;

  /**
   * Traverses C# AST and extracts namespace and using directives.
   */
  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const imports: ExtractedImport[] = [];
    let packageDeclaration: string | undefined;

    function extractUsingTarget(node: Parser.SyntaxNode): string | null {
      // using_directive children typically include:
      // - 'using' keyword
      // - optional 'static'
      // - identifier or qualified_name
      // - optional alias e.g. identifier '=' (type)
      const qname = node.children.find(
        (c) => c.type === 'qualified_name' || c.type === 'identifier'
      );
      if (qname) {
        return qname.text.trim();
      }
      return null;
    }

    function walk(node: Parser.SyntaxNode): void {
      if (
        node.type === 'namespace_declaration' ||
        node.type === 'file_scoped_namespace_declaration'
      ) {
        const idNode = node.children.find(
          (c) => c.type === 'qualified_name' || c.type === 'identifier'
        );
        if (idNode) {
          packageDeclaration = idNode.text.trim();
        }
      } else if (node.type === 'using_directive') {
        const target = extractUsingTarget(node);
        if (target) {
          imports.push({
            specifier: target,
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
   * Resolves C# using directive to a local source file, standard library (.NET BCL), or NuGet package.
   */
  public resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule {
    // 1. Standard .NET Base Class Libraries
    if (
      specifier === 'System' ||
      specifier.startsWith('System.') ||
      specifier === 'Microsoft' ||
      specifier.startsWith('Microsoft.')
    ) {
      return {
        type: 'STANDARD_LIB',
        name: specifier,
      };
    }

    // 2. Local C# files
    // Convert namespace to path: Foo.Bar -> Foo/Bar.cs or Bar.cs
    const parts = specifier.split('.');
    const lastPart = parts[parts.length - 1] ?? specifier;
    const relFolder = parts.join('/');

    const searchCandidates = [
      path.resolve(path.dirname(fromFilePath), `${lastPart}.cs`),
      path.resolve(projectRoot, `${relFolder}.cs`),
      path.resolve(projectRoot, 'src', `${relFolder}.cs`),
      path.resolve(projectRoot, `${lastPart}.cs`),
      path.resolve(projectRoot, 'src', `${lastPart}.cs`),
    ];

    for (const cand of searchCandidates) {
      if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
        return {
          type: 'LOCAL_FILE',
          resolvedPath: cand,
        };
      }
    }

    // Check directory matching namespace (e.g. Models/ -> Models/User.cs)
    const dirCandidates = [
      path.resolve(path.dirname(fromFilePath), lastPart),
      path.resolve(projectRoot, relFolder),
      path.resolve(projectRoot, 'src', relFolder),
      path.resolve(projectRoot, lastPart),
    ];

    for (const d of dirCandidates) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        try {
          const files = fs.readdirSync(d);
          const csFile = files.find((f) => f.endsWith('.cs') && !f.endsWith('Tests.cs'));
          if (csFile) {
            return {
              type: 'LOCAL_FILE',
              resolvedPath: path.resolve(d, csFile),
            };
          }
        } catch {
          // Fallback
        }
      }
    }

    // 3. External NuGet package
    // Usually top 1 or 2 segments (e.g. Newtonsoft.Json -> Newtonsoft.Json)
    const pkgName = parts.length >= 2 ? `${parts[0]}.${parts[1]}` : specifier;
    return {
      type: 'PACKAGE',
      packageName: pkgName,
    };
  }
}
