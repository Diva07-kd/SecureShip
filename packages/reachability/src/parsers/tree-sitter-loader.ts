import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Parser from 'web-tree-sitter';
import { verifyWasmBuffer, getWasmSearchCandidates } from '../manifest/wasm-manifest.js';
import { getStandaloneExecDir } from '../standalone-exec.js';

export type SupportedLanguage =
  | 'javascript'
  | 'typescript'
  | 'tsx'
  | 'python'
  | 'go'
  | 'java'
  | 'rust'
  | 'c_sharp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface ParseOptions {
  maxFileBytes?: number;
  parseTimeoutMs?: number;
}

export interface ParseResult {
  tree: Parser.Tree | null;
  hasError: boolean;
  errorReason?: string;
}

export class TreeSitterLoader {
  private static initialized = false;
  private static initPromise: Promise<void> | null = null;
  private static wasmDir: string | null = null;
  private static languages: Map<SupportedLanguage, Parser.Language> = new Map();
  private static languageLoadErrors: Map<SupportedLanguage, string> = new Map();

  /**
   * Resolves the directory containing the bundled WASM files.
   */
  public static getWasmDirectory(): string {
    if (TreeSitterLoader.wasmDir) return TreeSitterLoader.wasmDir;

    const execDir = getStandaloneExecDir();
    const candidates = getWasmSearchCandidates({ execDir });

    for (const c of candidates) {
      if (fs.existsSync(path.join(c, 'tree-sitter.wasm'))) {
        TreeSitterLoader.wasmDir = c;
        return c;
      }
    }

    const standaloneHint = execDir
      ? ' Standalone binary detected: keep the binary inside the extracted release folder next to its wasm/, data/ and rules/ directories (do not copy the executable elsewhere).'
      : '';

    throw new Error(
      `SecureShip Tree-sitter WASM directory not found. Searched candidates: ${candidates.join(', ')}${standaloneHint}`
    );
  }

  /**
   * Initializes the WebAssembly Tree-sitter runtime and loads language grammars.
   */
  public static async init(): Promise<void> {
    if (TreeSitterLoader.initialized) return;
    if (TreeSitterLoader.initPromise) return TreeSitterLoader.initPromise;

    TreeSitterLoader.initPromise = (async () => {
      const wasmDir = TreeSitterLoader.getWasmDirectory();
      const coreWasmPath = path.join(wasmDir, 'tree-sitter.wasm');

      // 1. Verify core tree-sitter.wasm
      const coreBuf = fs.readFileSync(coreWasmPath);
      const coreCheck = verifyWasmBuffer('tree-sitter.wasm', coreBuf);
      if (!coreCheck.valid) {
        throw new Error(
          `Security violation: tree-sitter.wasm failed cryptographic SHA-256 verification.\nExpected: ${coreCheck.expectedHash}\nActual:   ${coreCheck.actualHash}`
        );
      }

      // 2. Initialize web-tree-sitter with core WASM
      await Parser.init({
        locateFile(scriptName: string) {
          if (scriptName === 'tree-sitter.wasm') {
            return coreWasmPath;
          }
          return path.join(wasmDir, scriptName);
        },
      });

      // 3. Load language grammars with integrity verification
      const grammarFiles: Record<SupportedLanguage, string> = {
        javascript: 'tree-sitter-javascript.wasm',
        typescript: 'tree-sitter-typescript.wasm',
        tsx: 'tree-sitter-tsx.wasm',
        python: 'tree-sitter-python.wasm',
        go: 'tree-sitter-go.wasm',
        java: 'tree-sitter-java.wasm',
        rust: 'tree-sitter-rust.wasm',
        c_sharp: 'tree-sitter-c_sharp.wasm',
      };

      for (const [lang, filename] of Object.entries(grammarFiles) as [
        SupportedLanguage,
        string,
      ][]) {
        const fullPath = path.join(wasmDir, filename);
        if (!fs.existsSync(fullPath)) {
          TreeSitterLoader.languageLoadErrors.set(lang, `Grammar file missing: ${filename}`);
          continue;
        }

        try {
          const buf = fs.readFileSync(fullPath);
          const check = verifyWasmBuffer(filename, buf);
          if (!check.valid) {
            TreeSitterLoader.languageLoadErrors.set(
              lang,
              `Integrity mismatch for ${filename} (expected ${check.expectedHash}, got ${check.actualHash})`
            );
            continue;
          }

          const loadedLang = await Parser.Language.load(fullPath);
          TreeSitterLoader.languages.set(lang, loadedLang);
        } catch (err) {
          TreeSitterLoader.languageLoadErrors.set(
            lang,
            err instanceof Error ? err.message : String(err)
          );
        }
      }

      TreeSitterLoader.initialized = true;
    })();

    return TreeSitterLoader.initPromise;
  }

  /**
   * Returns a ready-to-use parser for the specified language.
   */
  public static getParser(lang: SupportedLanguage): { parser: Parser; error?: string } {
    if (!TreeSitterLoader.initialized) {
      throw new Error('TreeSitterLoader.init() must be awaited before getting a parser.');
    }

    const loadError = TreeSitterLoader.languageLoadErrors.get(lang);
    if (loadError) {
      return { parser: new Parser(), error: loadError };
    }

    const language = TreeSitterLoader.languages.get(lang);
    if (!language) {
      return {
        parser: new Parser(),
        error: `Language grammar for '${lang}' is not loaded or unavailable.`,
      };
    }

    const parser = new Parser();
    parser.setLanguage(language);
    return { parser };
  }

  /**
   * Safely parses code buffer with size checks, parse timeouts, and syntax error detection.
   */
  public static parseFile(
    content: string,
    lang: SupportedLanguage,
    options: ParseOptions = {}
  ): ParseResult {
    const maxBytes = options.maxFileBytes ?? 1_048_576; // 1 MB default
    const contentBytes = Buffer.byteLength(content, 'utf8');

    if (contentBytes > maxBytes) {
      return {
        tree: null,
        hasError: true,
        errorReason: `File size (${contentBytes} bytes) exceeds configured limit (${maxBytes} bytes)`,
      };
    }

    const { parser, error } = TreeSitterLoader.getParser(lang);
    if (error || !parser) {
      return {
        tree: null,
        hasError: true,
        errorReason: error ?? 'Parser not available',
      };
    }

    // Per-file parse timeout guard
    const timeoutMs = options.parseTimeoutMs ?? 5000;
    const startTime = Date.now();

    try {
      const tree = parser.parse(content);
      const elapsed = Date.now() - startTime;

      if (elapsed > timeoutMs) {
        return {
          tree: null,
          hasError: true,
          errorReason: `Parse duration (${elapsed}ms) exceeded timeout limit (${timeoutMs}ms)`,
        };
      }

      if (!tree || !tree.rootNode) {
        return {
          tree: null,
          hasError: true,
          errorReason: 'Parse produced empty syntax tree',
        };
      }

      // Amendment A6: hasError is true if rootNode.hasError is true
      const hasSyntaxError = tree.rootNode.hasError;

      return {
        tree,
        hasError: hasSyntaxError,
        errorReason: hasSyntaxError ? 'Syntax tree contains ERROR or MISSING nodes' : undefined,
      };
    } catch (err) {
      return {
        tree: null,
        hasError: true,
        errorReason: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Maps file extensions to SupportedLanguage.
   */
  public static detectLanguage(filePath: string): SupportedLanguage | null {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.js':
      case '.mjs':
      case '.cjs':
        return 'javascript';
      case '.jsx':
        return 'javascript';
      case '.ts':
      case '.mts':
      case '.cts':
        return 'typescript';
      case '.tsx':
        return 'tsx';
      case '.py':
      case '.pyw':
        return 'python';
      case '.go':
        return 'go';
      case '.java':
        return 'java';
      case '.rs':
        return 'rust';
      case '.cs':
        return 'c_sharp';
      default:
        return null;
    }
  }
}
