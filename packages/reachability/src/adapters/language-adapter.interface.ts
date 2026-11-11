import type Parser from 'web-tree-sitter';
import type { SupportedLanguage } from '../parsers/tree-sitter-loader.js';

export interface ExtractedImport {
  specifier: string;
  isTypeOnly?: boolean;
  startLine: number;
}

export interface ExtractedExport {
  specifier: string;
  isTypeOnly?: boolean;
}

export interface ExtractionResult {
  imports: ExtractedImport[];
  exports: ExtractedExport[];
  hasDynamicImports: boolean;
  packageDeclaration?: string;
}

export type ResolvedModule =
  | { type: 'LOCAL_FILE'; resolvedPath: string }
  | { type: 'PACKAGE'; packageName: string; isTypeOnly?: boolean }
  | { type: 'STANDARD_LIB'; name: string }
  | { type: 'UNRESOLVED'; reason: string };

export interface ILanguageAdapter {
  readonly language: SupportedLanguage;
  extract(rootNode: Parser.SyntaxNode): ExtractionResult;
  resolve(specifier: string, fromFilePath: string, projectRoot: string): ResolvedModule;
}
