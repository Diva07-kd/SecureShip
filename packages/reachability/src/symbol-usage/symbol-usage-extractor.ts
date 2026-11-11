import type Parser from 'web-tree-sitter';
import type { SupportedLanguage } from '../parsers/tree-sitter-loader.js';
import type { FileSymbolUsage } from './symbol-usage.types.js';
import { JsSymbolUsageExtractor } from './js-symbol-usage-extractor.js';
import { PythonSymbolUsageExtractor } from './python-symbol-usage-extractor.js';

export class SymbolUsageExtractor {
  /**
   * Dispatches syntax tree extraction to the appropriate language extractor.
   * For non-JS/Python languages, returns empty facts with usageIncomplete=false.
   */
  public static extract(
    rootNode: Parser.SyntaxNode | null,
    filePath: string,
    relativePath: string,
    language: SupportedLanguage | null,
    hasParseError: boolean
  ): FileSymbolUsage {
    // Other languages (Go, Java, C#, Rust) do not participate in function-level symbol reachability
    if (language !== 'javascript' && language !== 'typescript' && language !== 'python') {
      return {
        filePath,
        relativePath,
        bindings: [],
        usageFacts: [],
        escapes: [],
        hasCreateRequire: false,
        usageIncomplete: false,
      };
    }

    if (hasParseError || !rootNode) {
      return {
        filePath,
        relativePath,
        bindings: [],
        usageFacts: [],
        escapes: [],
        hasCreateRequire: false,
        usageIncomplete: true,
        incompleteReason: hasParseError
          ? 'File has syntax parse error'
          : 'AST root node unavailable',
      };
    }

    try {
      if (language === 'javascript' || language === 'typescript') {
        return JsSymbolUsageExtractor.extract(rootNode, filePath, relativePath);
      }

      // language is guaranteed to be javascript, typescript, or python by the check above
      return PythonSymbolUsageExtractor.extract(rootNode, filePath, relativePath);
    } catch (err) {
      return {
        filePath,
        relativePath,
        bindings: [],
        usageFacts: [],
        escapes: [],
        hasCreateRequire: false,
        usageIncomplete: true,
        incompleteReason: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
