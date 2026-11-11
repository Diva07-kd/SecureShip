import path from 'node:path';
import type Parser from 'web-tree-sitter';
import { TreeSitterLoader, type SupportedLanguage } from '@secureship/reachability';

export interface EnclosingScopeResult {
  scopeName?: string;
  startLine: number; // 1-indexed
  endLine: number; // 1-indexed
  sliceText: string;
}

export class AstScopeFinder {
  private static readonly SCOPE_NODE_TYPES = new Set([
    'function_declaration',
    'function_definition',
    'method_definition',
    'arrow_function',
    'class_declaration',
    'class_definition',
    'generator_function_declaration',
  ]);

  /**
   * Resolves the enclosing scope or bounded line window for a finding.
   */
  public static async findEnclosingScope(
    content: string,
    filePath: string,
    startLine: number,
    endLine: number,
    windowPadding = 30
  ): Promise<EnclosingScopeResult> {
    const lines = content.split('\n');
    const totalLines = lines.length;
    const clampedStart = Math.max(1, Math.min(startLine, totalLines));
    const clampedEnd = Math.max(clampedStart, Math.min(endLine, totalLines));

    const ext = path.extname(filePath).toLowerCase();

    // 1. Check for Tree-sitter supported languages
    const lang = AstScopeFinder.detectLanguage(ext);
    if (lang) {
      try {
        await TreeSitterLoader.init();
        const parseResult = TreeSitterLoader.parseFile(content, lang);
        if (parseResult.tree && !parseResult.hasError) {
          const rootNode = parseResult.tree.rootNode;
          // Tree-sitter uses 0-indexed row numbers
          const targetStartRow = clampedStart - 1;
          const targetEndRow = clampedEnd - 1;

          // Find the tightest enclosing scope node
          let currentNode: Parser.SyntaxNode | null = rootNode.descendantForPosition(
            { row: targetStartRow, column: 0 },
            { row: targetEndRow, column: 0 }
          );

          let foundScopeNode: Parser.SyntaxNode | null = null;
          let scopeName: string | undefined;

          while (currentNode) {
            if (AstScopeFinder.SCOPE_NODE_TYPES.has(currentNode.type)) {
              foundScopeNode = currentNode;
              const nameChild = currentNode.childForFieldName('name');
              if (nameChild) {
                scopeName = nameChild.text;
              } else if (currentNode.parent?.type === 'variable_declarator') {
                const varName = currentNode.parent.childForFieldName('name');
                if (varName) scopeName = varName.text;
              }
              break;
            }
            currentNode = currentNode.parent;
          }

          if (foundScopeNode) {
            const nodeStartLine = foundScopeNode.startPosition.row + 1;
            const nodeEndLine = foundScopeNode.endPosition.row + 1;
            const slice = lines.slice(nodeStartLine - 1, nodeEndLine).join('\n');
            return {
              scopeName: scopeName ? `${foundScopeNode.type}:${scopeName}` : foundScopeNode.type,
              startLine: nodeStartLine,
              endLine: nodeEndLine,
              sliceText: slice,
            };
          }
        }
      } catch {
        // Fall back to line window on tree-sitter load or parse failure
      }
    }

    // 2. Terraform / HCL Scope Detection
    if (ext === '.tf' || ext === '.hcl') {
      const tfResult = AstScopeFinder.findHclBlock(lines, clampedStart, clampedEnd);
      if (tfResult) return tfResult;
    }

    // 3. Fallback: Bounded Line Window (+/- windowPadding lines)
    const windowStart = Math.max(1, clampedStart - windowPadding);
    const windowEnd = Math.min(totalLines, clampedEnd + windowPadding);
    const windowSlice = lines.slice(windowStart - 1, windowEnd).join('\n');

    return {
      scopeName: 'line-window',
      startLine: windowStart,
      endLine: windowEnd,
      sliceText: windowSlice,
    };
  }

  private static detectLanguage(ext: string): SupportedLanguage | null {
    switch (ext) {
      case '.js':
      case '.mjs':
      case '.cjs':
        return 'javascript';
      case '.ts':
      case '.mts':
      case '.cts':
        return 'typescript';
      case '.tsx':
      case '.jsx':
        return 'tsx';
      case '.py':
        return 'python';
      default:
        return null;
    }
  }

  private static findHclBlock(
    lines: string[],
    startLine: number,
    endLine: number
  ): EnclosingScopeResult | null {
    // Look backwards from startLine for resource / module / data / locals header
    let blockStart = -1;
    let blockName = '';

    const blockHeaderRegex =
      /^\s*(resource|module|data|variable|output|locals)\s+["']?([^"'{}\s]+)?["']?\s*(?:["']?([^"'{}\s]+)?["']?)?\s*\{/;

    for (let i = startLine - 1; i >= 0; i--) {
      const line = lines[i] ?? '';
      const match = line.match(blockHeaderRegex);
      if (match) {
        blockStart = i + 1;
        const kind = match[1];
        const n1 = match[2] ?? '';
        const n2 = match[3] ?? '';
        blockName = `${kind}.${n1}${n2 ? `.${n2}` : ''}`;
        break;
      }
    }

    if (blockStart === -1) return null;

    // Track braces forwards to find block end
    let braceCount = 0;
    let blockEnd = -1;

    for (let i = blockStart - 1; i < lines.length; i++) {
      const line = lines[i] ?? '';
      for (const ch of line) {
        if (ch === '{') braceCount++;
        else if (ch === '}') braceCount--;
      }
      if (braceCount === 0 && i >= endLine - 1) {
        blockEnd = i + 1;
        break;
      }
    }

    if (blockEnd === -1) {
      blockEnd = Math.min(lines.length, blockStart + 60);
    }

    return {
      scopeName: blockName || 'terraform-block',
      startLine: blockStart,
      endLine: blockEnd,
      sliceText: lines.slice(blockStart - 1, blockEnd).join('\n'),
    };
  }
}
