import type Parser from 'web-tree-sitter';
import { TreeSitterLoader, type ParseOptions } from '../parsers/tree-sitter-loader.js';
import type { CapabilitySite, CapabilityType, FileCapabilityAnalysis } from './types.js';
import { PythonCapabilityExtractor } from './python-capability-extractor.js';

const SENSITIVE_PATH_PATTERNS = [
  /[/\\]\.ssh([/\\]|$)/i,
  /[/\\]\.aws([/\\]|$)/i,
  /[/\\]\.config[/\\]gcloud([/\\]|$)/i,
  /[/\\]\.azure([/\\]|$)/i,
  /[/\\]\.npmrc$/i,
  /[/\\]\.yarnrc$/i,
  /[/\\]\.pypirc$/i,
  /[/\\]\.netrc$/i,
  /[/\\]\.git-credentials$/i,
  /[/\\]\.docker[/\\]config\.json$/i,
  /[/\\]\.kube([/\\]|$)/i,
  /[/\\]\.bashrc$/i,
  /[/\\]\.zshrc$/i,
  /[/\\]\.profile$/i,
  /[/\\]\.bash_profile$/i,
  /[/\\]\.cshrc$/i,
  /\/etc\/passwd$/i,
  /\/etc\/shadow$/i,
  /[/\\](google-chrome|chromium|firefox)[/\\]/i,
  /[/\\](solana|metamask|exodus|electrum)([/\\]|$)/i,
  /[/\\]\.env(\.[a-zA-Z0-9_-]+)?$/i,
  /^\.env(\.[a-zA-Z0-9_-]+)?$/i,
  /^~[/\\]\.ssh/i,
  /^~[/\\]\.aws/i,
  /^~[/\\]\.npmrc/i,
  /^~[/\\]\.bashrc/i,
  /^~[/\\]\.zshrc/i,
];

const SHELL_MODULES = new Set(['child_process', 'node:child_process']);
const SHELL_METHODS = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
  'fork',
]);

const FS_MODULES = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
const FS_READ_METHODS = new Set([
  'readFile',
  'readFileSync',
  'createReadStream',
  'open',
  'openSync',
  'readdir',
  'readdirSync',
  'stat',
  'statSync',
  'lstat',
  'lstatSync',
  'access',
  'accessSync',
  'writeFile',
  'writeFileSync',
  'appendFile',
  'appendFileSync',
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
]);

const NETWORK_MODULES = new Set([
  'http',
  'node:http',
  'https',
  'node:https',
  'http2',
  'node:http2',
  'net',
  'node:net',
  'tls',
  'node:tls',
  'dgram',
  'node:dgram',
  'dns',
  'node:dns',
  'axios',
  'got',
  'node-fetch',
  'superagent',
  'undici',
  'request',
  'ws',
  'socket.io-client',
]);
const NETWORK_METHODS = new Set([
  'request',
  'get',
  'connect',
  'createConnection',
  'createServer',
  'send',
  'fetch',
]);

const VM_MODULES = new Set(['vm', 'node:vm']);
const VM_METHODS = new Set([
  'runInContext',
  'runInNewContext',
  'runInThisContext',
  'createScript',
  'Script',
]);

export class AstCapabilityAnalyzer {
  /**
   * Evaluates capabilities inside a single source file.
   * WASM Tree-sitter tree is always deleted in a try ... finally block.
   */
  public static async analyzeFile(
    content: string,
    filePath: string,
    options: ParseOptions = {}
  ): Promise<FileCapabilityAnalysis> {
    await TreeSitterLoader.init();
    const lang = TreeSitterLoader.detectLanguage(filePath);

    if (!lang) {
      return AstCapabilityAnalyzer.fallbackTokenScan(content, filePath);
    }

    // Full Python WebAssembly Tree-sitter AST extraction
    if (lang === 'python') {
      return AstCapabilityAnalyzer.extractPythonCapabilities(content, filePath, options);
    }

    // JavaScript / TypeScript AST extraction
    const parseRes = TreeSitterLoader.parseFile(content, lang, options);
    if (!parseRes.tree || parseRes.hasError) {
      if (parseRes.tree) {
        try {
          return AstCapabilityAnalyzer.extractFromAst(
            parseRes.tree.rootNode,
            content,
            filePath,
            true
          );
        } finally {
          parseRes.tree.delete();
        }
      }
      return AstCapabilityAnalyzer.fallbackTokenScan(content, filePath, true);
    }

    try {
      return AstCapabilityAnalyzer.extractFromAst(parseRes.tree.rootNode, content, filePath, false);
    } finally {
      parseRes.tree.delete();
    }
  }

  /**
   * Extracts capability analysis for a Python source file using full Tree-sitter AST.
   */
  public static async extractPythonCapabilities(
    content: string,
    filePath: string,
    options: ParseOptions = {}
  ): Promise<FileCapabilityAnalysis> {
    await TreeSitterLoader.init();
    const parseRes = TreeSitterLoader.parseFile(content, 'python', options);
    if (!parseRes.tree || parseRes.hasError) {
      if (parseRes.tree) {
        try {
          return PythonCapabilityExtractor.extract(parseRes.tree.rootNode, content, filePath, true);
        } finally {
          parseRes.tree.delete();
        }
      }
      return AstCapabilityAnalyzer.fallbackTokenScan(content, filePath, true);
    }

    try {
      return PythonCapabilityExtractor.extract(parseRes.tree.rootNode, content, filePath, false);
    } finally {
      parseRes.tree.delete();
    }
  }

  /**
   * AST traversal extracting capability sites and aliased module bindings.
   */
  private static extractFromAst(
    rootNode: Parser.SyntaxNode,
    content: string,
    filePath: string,
    hasSyntaxError: boolean
  ): FileCapabilityAnalysis {
    const sites: CapabilitySite[] = [];

    // Track module aliases: identifierName -> moduleName or methodName
    const aliases = new Map<string, { module: string; method?: string }>();
    // Track require alias: identifierName -> 'require'
    const requireAliases = new Set<string>([
      'require',
      'module.require',
      'process.mainModule.require',
    ]);

    // Pass 1: Resolve imports and require aliases
    AstCapabilityAnalyzer.collectAliases(rootNode, aliases, requireAliases);

    // Pass 2: Extract capability invocations and references
    function walk(node: Parser.SyntaxNode): void {
      const type = node.type;

      // 1. Env Access
      if (AstCapabilityAnalyzer.isEnvAccess(node)) {
        sites.push(
          AstCapabilityAnalyzer.createSite(
            'env',
            node,
            content,
            filePath,
            true,
            'HIGH',
            'process.env access detected'
          )
        );
      }

      // 2. Dynamic Eval / Function invocation
      if (type === 'call_expression') {
        const fn = node.childForFieldName('function');
        const args = node.childForFieldName('arguments');

        if (fn) {
          const fnName = fn.text;

          // eval(...)
          if (fnName === 'eval') {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'eval',
                node,
                content,
                filePath,
                true,
                'HIGH',
                'Direct eval() call'
              )
            );
          }

          // setTimeout / setInterval with string argument
          if (
            (fnName === 'setTimeout' || fnName === 'setInterval') &&
            args &&
            args.namedChildCount > 0
          ) {
            const firstArg = args.namedChild(0)!;
            if (firstArg.type === 'string' || firstArg.type === 'template_string') {
              sites.push(
                AstCapabilityAnalyzer.createSite(
                  'eval',
                  node,
                  content,
                  filePath,
                  true,
                  'HIGH',
                  `${fnName} with string argument (implicit eval)`
                )
              );
            }
          }

          // Global network calls: fetch(), navigator.sendBeacon()
          if (fnName === 'fetch') {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'network',
                node,
                content,
                filePath,
                true,
                'HIGH',
                'Global fetch() HTTP request'
              )
            );
          }
          if (fnName === 'navigator.sendBeacon' || fn.text.endsWith('.sendBeacon')) {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'network',
                node,
                content,
                filePath,
                true,
                'HIGH',
                'navigator.sendBeacon() telemetry/exfiltration'
              )
            );
          }

          // Dynamic require: require(non-literal) or requireAlias(non-literal)
          const isRequireCall =
            requireAliases.has(fnName) ||
            (fn.type === 'member_expression' &&
              (fn.text === 'module.require' || fn.text === 'process.mainModule.require'));

          if (isRequireCall && args) {
            if (args.namedChildCount > 0) {
              const arg = args.namedChild(0)!;
              const folded = AstCapabilityAnalyzer.tryConstantFoldString(arg);
              if (folded === null) {
                sites.push(
                  AstCapabilityAnalyzer.createSite(
                    'dynamicRequire',
                    node,
                    content,
                    filePath,
                    false,
                    'MEDIUM',
                    'Dynamic require with non-literal argument'
                  )
                );
              }
            } else {
              sites.push(
                AstCapabilityAnalyzer.createSite(
                  'dynamicRequire',
                  node,
                  content,
                  filePath,
                  false,
                  'LOW',
                  'Dynamic require invocation without arguments'
                )
              );
            }
          }

          // Dynamic import: import(non-literal) or import('data:...')
          if (fn.type === 'import' || fnName === 'import') {
            if (args && args.namedChildCount > 0) {
              const arg = args.namedChild(0)!;
              const folded = AstCapabilityAnalyzer.tryConstantFoldString(arg);
              if (folded !== null && folded.startsWith('data:')) {
                sites.push(
                  AstCapabilityAnalyzer.createSite(
                    'eval',
                    node,
                    content,
                    filePath,
                    true,
                    'HIGH',
                    'Dynamic import of inline data URI payload'
                  )
                );
              } else if (folded === null) {
                sites.push(
                  AstCapabilityAnalyzer.createSite(
                    'dynamicRequire',
                    node,
                    content,
                    filePath,
                    false,
                    'MEDIUM',
                    'Dynamic import with non-literal specifier'
                  )
                );
              }
            }
          }

          // Module._load / module.createRequire
          if (fn.text === 'Module._load' || fn.text === 'module.createRequire') {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'dynamicRequire',
                node,
                content,
                filePath,
                true,
                'HIGH',
                `Low-level module loader invocation: ${fn.text}`
              )
            );
          }

          // Debug Internals / Anti-Analysis
          if (
            fn.text === 'process.binding' ||
            fn.text === 'process.dlopen' ||
            fn.text.includes('Error.prepareStackTrace')
          ) {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'debugInternals',
                node,
                content,
                filePath,
                true,
                'HIGH',
                `Internal Node.js runtime hook: ${fn.text}`
              )
            );
          }

          // Method calls on aliased modules
          AstCapabilityAnalyzer.checkMethodCall(node, fn, args, aliases, content, filePath, sites);
        }
      }

      // new Function(...) or new WebSocket / XMLHttpRequest / Worker
      if (type === 'new_expression') {
        const ctor = node.childForFieldName('constructor');
        if (ctor) {
          const ctorName = ctor.text;
          if (ctorName === 'Function') {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'eval',
                node,
                content,
                filePath,
                true,
                'HIGH',
                'new Function() dynamic code constructor'
              )
            );
          } else if (
            ctorName === 'WebSocket' ||
            ctorName === 'XMLHttpRequest' ||
            ctorName === 'EventSource'
          ) {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'network',
                node,
                content,
                filePath,
                true,
                'HIGH',
                `new ${ctorName}() outbound socket/HTTP connection`
              )
            );
          } else if (ctorName === 'Worker') {
            // Check if worker has { eval: true }
            const args = node.childForFieldName('arguments');
            if (args && args.text.includes('eval:')) {
              sites.push(
                AstCapabilityAnalyzer.createSite(
                  'debugInternals',
                  node,
                  content,
                  filePath,
                  true,
                  'HIGH',
                  'Worker thread initialized with eval option'
                )
              );
            }
          }
        }
      }

      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walk(child);
      }
    }

    walk(rootNode);

    // Aggregate flags
    const capabilities = {
      hasShell: sites.some((s) => s.capability === 'shell'),
      hasNetwork: sites.some((s) => s.capability === 'network'),
      hasEnvAccess: sites.some((s) => s.capability === 'env'),
      hasFsSensitive: sites.some((s) => s.capability === 'fsSensitive'),
      hasEval: sites.some((s) => s.capability === 'eval'),
      hasDynamicRequire: sites.some((s) => s.capability === 'dynamicRequire'),
      hasInstallScript: false,
      hasDebugInternals: sites.some((s) => s.capability === 'debugInternals'),
    };

    return {
      capabilities,
      sites,
      hasSyntaxError,
    };
  }

  /**
   * Pass 1 alias collector: tracks bindings for shell, fs, network, vm, and require.
   */
  private static collectAliases(
    rootNode: Parser.SyntaxNode,
    aliases: Map<string, { module: string; method?: string }>,
    requireAliases: Set<string>
  ): void {
    function walk(node: Parser.SyntaxNode): void {
      // 1. ESM: import ... from 'mod'
      if (node.type === 'import_statement') {
        const sourceNode = node.childForFieldName('source');
        if (sourceNode) {
          const mod = AstCapabilityAnalyzer.unquote(sourceNode.text);
          for (let i = 0; i < node.childCount; i++) {
            const child = node.child(i)!;
            if (child.type === 'import_clause') {
              for (let j = 0; j < child.childCount; j++) {
                const sub = child.child(j)!;
                if (sub.type === 'identifier') {
                  // Default import: import cp from 'child_process'
                  aliases.set(sub.text, { module: mod });
                } else if (sub.type === 'namespace_import') {
                  // Namespace: import * as cp from 'child_process'
                  const id = sub.children.find((c) => c.type === 'identifier');
                  if (id) aliases.set(id.text, { module: mod });
                } else if (sub.type === 'named_imports') {
                  for (let k = 0; k < sub.namedChildCount; k++) {
                    const spec = sub.namedChild(k)!;
                    if (spec.type === 'import_specifier') {
                      const imported = spec.childForFieldName('name')?.text;
                      const local = (
                        spec.childForFieldName('alias') ?? spec.childForFieldName('name')
                      )?.text;
                      if (imported && local) {
                        aliases.set(local, { module: mod, method: imported });
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // 2. CJS: const cp = require('mod'), const { exec } = require('mod'), const r = require
      if (node.type === 'variable_declarator') {
        const idNode = node.childForFieldName('name');
        const valNode = node.childForFieldName('value');

        if (idNode && valNode) {
          // const r = require;
          if (requireAliases.has(valNode.text)) {
            requireAliases.add(idNode.text);
          }

          if (valNode.type === 'call_expression') {
            const fn = valNode.childForFieldName('function');
            const args = valNode.childForFieldName('arguments');

            if (fn && requireAliases.has(fn.text) && args && args.namedChildCount > 0) {
              const arg = args.namedChild(0)!;
              const mod = AstCapabilityAnalyzer.tryConstantFoldString(arg);
              if (mod) {
                if (idNode.type === 'identifier') {
                  aliases.set(idNode.text, { module: mod });
                } else if (idNode.type === 'object_pattern') {
                  for (let i = 0; i < idNode.namedChildCount; i++) {
                    const prop = idNode.namedChild(i)!;
                    if (prop.type === 'shorthand_property_identifier_pattern') {
                      aliases.set(prop.text, { module: mod, method: prop.text });
                    } else if (prop.type === 'pair_pattern') {
                      const key = prop.childForFieldName('key')?.text;
                      const value = prop.childForFieldName('value')?.text;
                      if (key && value) {
                        aliases.set(value, { module: mod, method: key });
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      for (let i = 0; i < node.childCount; i++) {
        const c = node.child(i);
        if (c) walk(c);
      }
    }

    walk(rootNode);
  }

  /**
   * Checks method calls against tracked module bindings.
   */
  private static checkMethodCall(
    callNode: Parser.SyntaxNode,
    fnNode: Parser.SyntaxNode,
    argsNode: Parser.SyntaxNode | null,
    aliases: Map<string, { module: string; method?: string }>,
    content: string,
    filePath: string,
    sites: CapabilitySite[]
  ): void {
    let baseModule: string | undefined;
    let methodName: string | undefined;

    if (fnNode.type === 'member_expression') {
      const objNode = fnNode.childForFieldName('object');
      const propNode = fnNode.childForFieldName('property');

      if (objNode && propNode) {
        const objText = objNode.text;
        const alias = aliases.get(objText);
        if (alias) {
          baseModule = alias.module;
          methodName = AstCapabilityAnalyzer.resolvePropertyName(propNode);
        } else if (objText === 'process') {
          if (propNode.text === 'binding' || propNode.text === 'dlopen') {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'debugInternals',
                callNode,
                content,
                filePath,
                true,
                'HIGH',
                `process.${propNode.text} runtime call`
              )
            );
          }
        }
      }
    } else if (fnNode.type === 'identifier') {
      const alias = aliases.get(fnNode.text);
      if (alias) {
        baseModule = alias.module;
        methodName = alias.method;
      }
    }

    if (!baseModule || !methodName) return;

    // Shell capability
    if (SHELL_MODULES.has(baseModule) && SHELL_METHODS.has(methodName)) {
      sites.push(
        AstCapabilityAnalyzer.createSite(
          'shell',
          callNode,
          content,
          filePath,
          true,
          'HIGH',
          `Process execution via ${baseModule}.${methodName}`
        )
      );
      return;
    }

    // Network capability
    if (NETWORK_MODULES.has(baseModule) && NETWORK_METHODS.has(methodName)) {
      sites.push(
        AstCapabilityAnalyzer.createSite(
          'network',
          callNode,
          content,
          filePath,
          true,
          'HIGH',
          `Network socket/HTTP call via ${baseModule}.${methodName}`
        )
      );
      return;
    }

    // Eval capability via VM
    if (VM_MODULES.has(baseModule) && VM_METHODS.has(methodName)) {
      sites.push(
        AstCapabilityAnalyzer.createSite(
          'eval',
          callNode,
          content,
          filePath,
          true,
          'HIGH',
          `Dynamic script evaluation via vm.${methodName}`
        )
      );
      return;
    }

    // Sensitive FS capability
    if (FS_MODULES.has(baseModule) && FS_READ_METHODS.has(methodName)) {
      const pathArg = argsNode && argsNode.namedChildCount > 0 ? argsNode.namedChild(0)! : null;
      if (pathArg) {
        const foldedPath = AstCapabilityAnalyzer.tryConstantFoldString(pathArg);
        if (foldedPath !== null) {
          const isSensitive = SENSITIVE_PATH_PATTERNS.some((p) => p.test(foldedPath));
          if (isSensitive) {
            sites.push(
              AstCapabilityAnalyzer.createSite(
                'fsSensitive',
                callNode,
                content,
                filePath,
                true,
                'HIGH',
                `Sensitive filesystem access to target '${foldedPath}' via fs.${methodName}`
              )
            );
          }
        } else {
          // Dynamic unresolvable path argument in FS call
          sites.push(
            AstCapabilityAnalyzer.createSite(
              'fsSensitive',
              callNode,
              content,
              filePath,
              false,
              'LOW',
              `Filesystem operation fs.${methodName} with dynamic path argument`
            )
          );
        }
      }
    }
  }

  /**
   * Resolves member property name including constant-folded computed properties: cp['ex' + 'ec']
   */
  private static resolvePropertyName(propNode: Parser.SyntaxNode): string | undefined {
    if (propNode.type === 'property_identifier') {
      return propNode.text;
    }
    return AstCapabilityAnalyzer.tryConstantFoldString(propNode) ?? undefined;
  }

  /**
   * Detects process.env access in AST node.
   */
  private static isEnvAccess(node: Parser.SyntaxNode): boolean {
    if (node.type === 'member_expression') {
      const obj = node.childForFieldName('object');
      const prop = node.childForFieldName('property');
      if (obj?.text === 'process' && prop?.text === 'env') {
        return true;
      }
    }
    // const { A } = process.env
    if (node.type === 'variable_declarator') {
      const val = node.childForFieldName('value');
      if (val?.text === 'process.env') {
        return true;
      }
    }
    // Object.keys(process.env)
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      const args = node.childForFieldName('arguments');
      if (
        (fn?.text === 'Object.keys' ||
          fn?.text === 'Object.values' ||
          fn?.text === 'Object.entries') &&
        args?.text.includes('process.env')
      ) {
        return true;
      }
    }
    // ...process.env
    if (node.type === 'spread_element' && node.text === '...process.env') {
      return true;
    }

    return false;
  }

  /**
   * Bounded constant folder for string literals, binary concatenation, and path joins.
   */
  public static tryConstantFoldString(node: Parser.SyntaxNode): string | null {
    if (node.type === 'string') {
      return AstCapabilityAnalyzer.unquote(node.text);
    }
    if (node.type === 'template_string') {
      // If template substitutions are absent, fold directly
      const hasSubstitutions = node.children.some((c) => c.type === 'template_substitution');
      if (!hasSubstitutions) {
        return AstCapabilityAnalyzer.unquote(node.text);
      }
      return null;
    }
    if (node.type === 'binary_expression') {
      const left = node.childForFieldName('left');
      const op = node.children.find((c) => c.text === '+');
      const right = node.childForFieldName('right');
      if (left && op && right) {
        const leftVal = AstCapabilityAnalyzer.tryConstantFoldString(left);
        const rightVal = AstCapabilityAnalyzer.tryConstantFoldString(right);
        if (leftVal !== null && rightVal !== null) {
          return leftVal + rightVal;
        }
      }
    }
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function')?.text;
      const args = node.childForFieldName('arguments');
      if ((fn === 'path.join' || fn === 'path.resolve') && args) {
        const parts: string[] = [];
        for (let i = 0; i < args.namedChildCount; i++) {
          const argVal = AstCapabilityAnalyzer.tryConstantFoldString(args.namedChild(i)!);
          if (argVal === null) return null;
          parts.push(argVal);
        }
        return parts.join('/');
      }
    }
    return null;
  }

  /**
   * Walks up parents to locate the enclosing function or method.
   */
  private static findEnclosingFunction(node: Parser.SyntaxNode): string | undefined {
    let curr: Parser.SyntaxNode | null = node.parent;
    while (curr) {
      if (curr.type === 'function_declaration') {
        const id = curr.childForFieldName('name');
        return id ? id.text : 'anonymous';
      }
      if (curr.type === 'method_definition') {
        const id = curr.childForFieldName('name');
        return id ? id.text : 'method';
      }
      if (curr.type === 'function_expression' || curr.type === 'arrow_function') {
        const parent = curr.parent;
        if (parent?.type === 'variable_declarator') {
          const id = parent.childForFieldName('name');
          if (id) return id.text;
        }
        if (parent?.type === 'pair') {
          const key = parent.childForFieldName('key');
          if (key) return key.text;
        }
        return `anon@L${curr.startPosition.row + 1}`;
      }
      curr = curr.parent;
    }
    return undefined;
  }

  private static unquote(text: string): string {
    const trimmed = text.trim();
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith('`') && trimmed.endsWith('`'))
    ) {
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  private static createSite(
    capability: CapabilityType,
    node: Parser.SyntaxNode,
    content: string,
    filePath: string,
    resolved: boolean,
    confidence: 'HIGH' | 'MEDIUM' | 'LOW',
    details: string
  ): CapabilitySite {
    const startLine = node.startPosition.row + 1;
    const startCol = node.startPosition.column;
    const endLine = node.endPosition.row + 1;
    const endCol = node.endPosition.column;

    // Visual-safe snippet extraction
    const rawSnippet = node.text.replace(/[\r\n]+/g, ' ').slice(0, 150);
    const enclosing = AstCapabilityAnalyzer.findEnclosingFunction(node);

    return {
      capability,
      file: filePath,
      startLine,
      startCol,
      endLine,
      endCol,
      snippet: rawSnippet,
      resolved,
      confidence,
      enclosingFunction: enclosing,
      details,
    };
  }

  /**
   * Bounded token-level fallback scanner for unparseable or oversized files.
   * All emitted evidence is strictly marked confidence: 'LOW'.
   */
  public static fallbackTokenScan(
    content: string,
    filePath: string,
    hasSyntaxError = false
  ): FileCapabilityAnalysis {
    const sites: CapabilitySite[] = [];
    const lines = content.split(/\r?\n/);

    for (let i = 0; i < Math.min(lines.length, 5000); i++) {
      const line = lines[i]!;
      const lineNum = i + 1;

      if (
        line.includes('process.env') ||
        line.includes('os.environ') ||
        line.includes('os.getenv')
      ) {
        sites.push({
          capability: 'env',
          file: filePath,
          startLine: lineNum,
          startCol: 0,
          endLine: lineNum,
          endCol: line.length,
          snippet: line.trim().slice(0, 150),
          resolved: false,
          confidence: 'LOW',
          details: 'Token-level pattern match: process.env or os.environ',
        });
      }

      if (/child_process|execSync|spawnSync|os\.system|subprocess/.test(line)) {
        sites.push({
          capability: 'shell',
          file: filePath,
          startLine: lineNum,
          startCol: 0,
          endLine: lineNum,
          endCol: line.length,
          snippet: line.trim().slice(0, 150),
          resolved: false,
          confidence: 'LOW',
          details: 'Token-level pattern match: shell process execution',
        });
      }

      if (/eval\(|new Function/.test(line)) {
        sites.push({
          capability: 'eval',
          file: filePath,
          startLine: lineNum,
          startCol: 0,
          endLine: lineNum,
          endCol: line.length,
          snippet: line.trim().slice(0, 150),
          resolved: false,
          confidence: 'LOW',
          details: 'Token-level pattern match: dynamic eval',
        });
      }

      if (/fetch\(|https?:\/\/|net\.connect/.test(line)) {
        sites.push({
          capability: 'network',
          file: filePath,
          startLine: lineNum,
          startCol: 0,
          endLine: lineNum,
          endCol: line.length,
          snippet: line.trim().slice(0, 150),
          resolved: false,
          confidence: 'LOW',
          details: 'Token-level pattern match: outbound network',
        });
      }

      if (SENSITIVE_PATH_PATTERNS.some((p) => p.test(line))) {
        sites.push({
          capability: 'fsSensitive',
          file: filePath,
          startLine: lineNum,
          startCol: 0,
          endLine: lineNum,
          endCol: line.length,
          snippet: line.trim().slice(0, 150),
          resolved: false,
          confidence: 'LOW',
          details: 'Token-level pattern match: sensitive filesystem path',
        });
      }
    }

    const capabilities = {
      hasShell: sites.some((s) => s.capability === 'shell'),
      hasNetwork: sites.some((s) => s.capability === 'network'),
      hasEnvAccess: sites.some((s) => s.capability === 'env'),
      hasFsSensitive: sites.some((s) => s.capability === 'fsSensitive'),
      hasEval: sites.some((s) => s.capability === 'eval'),
      hasDynamicRequire: sites.some((s) => s.capability === 'dynamicRequire'),
      hasInstallScript: false,
      hasDebugInternals: sites.some((s) => s.capability === 'debugInternals'),
    };

    return {
      capabilities,
      sites,
      hasSyntaxError,
    };
  }
}
