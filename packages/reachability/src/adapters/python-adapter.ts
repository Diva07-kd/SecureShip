import type Parser from 'web-tree-sitter';
import { PythonImportExtractor } from '../python/python-import-extractor.js';
import { PythonModuleResolver } from '../python/python-module-resolver.js';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ResolvedModule,
} from './language-adapter.interface.js';

export class PythonLanguageAdapter implements ILanguageAdapter {
  public readonly language = 'python' as const;
  private resolverCache: Map<string, PythonModuleResolver> = new Map();

  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const res = PythonImportExtractor.extract(rootNode);
    return {
      imports: res.imports.map((i) => ({
        specifier: i.module,
        isTypeOnly: false,
        startLine: i.startLine,
      })),
      exports: [],
      hasDynamicImports: res.hasDynamicImports,
    };
  }

  public resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule {
    let resolver = this.resolverCache.get(projectRoot);
    if (!resolver) {
      resolver = new PythonModuleResolver(projectRoot);
      this.resolverCache.set(projectRoot, resolver);
    }

    const isRelative = specifier.startsWith('.');
    const relativeLevel = isRelative ? (specifier.match(/^\.+/)?.[0].length ?? 0) : 0;

    const res = resolver.resolve(specifier, fromFilePath, isRelative, relativeLevel);

    switch (res.type) {
      case 'BUILTIN':
        return { type: 'STANDARD_LIB', name: res.name };
      case 'LOCAL_FILE':
        return { type: 'LOCAL_FILE', resolvedPath: res.resolvedPath };
      case 'PACKAGE':
        return { type: 'PACKAGE', packageName: res.packageName };
      case 'UNRESOLVED':
        return { type: 'UNRESOLVED', reason: res.reason };
    }
  }
}
