import type Parser from 'web-tree-sitter';
import type { SupportedLanguage } from '../parsers/tree-sitter-loader.js';
import { JsImportExtractor } from '../js/js-import-extractor.js';
import { JsModuleResolver } from '../js/js-module-resolver.js';
import type {
  ILanguageAdapter,
  ExtractionResult,
  ResolvedModule,
} from './language-adapter.interface.js';

export class JsLanguageAdapter implements ILanguageAdapter {
  public readonly language: SupportedLanguage;
  private resolverCache: Map<string, JsModuleResolver> = new Map();

  constructor(lang: 'javascript' | 'typescript' | 'tsx' = 'typescript') {
    this.language = lang;
  }

  public extract(rootNode: Parser.SyntaxNode): ExtractionResult {
    const res = JsImportExtractor.extract(rootNode);
    return {
      imports: res.imports,
      exports: res.exports,
      hasDynamicImports: res.hasDynamicImports,
    };
  }

  public resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule {
    let resolver = this.resolverCache.get(projectRoot);
    if (!resolver) {
      resolver = new JsModuleResolver(projectRoot);
      this.resolverCache.set(projectRoot, resolver);
    }

    const res = resolver.resolve(specifier, fromFilePath);

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
