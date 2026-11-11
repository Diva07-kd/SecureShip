import type Parser from 'web-tree-sitter';
import type { CapabilitySite, CapabilityType, FileCapabilityAnalysis } from './types.js';

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
  /^~[/\\]\.pypirc/i,
  /^~[/\\]\.bashrc/i,
  /^~[/\\]\.zshrc/i,
];

const PYTHON_SHELL_MODULES = new Set(['subprocess', 'os', 'commands', 'pty']);
const PYTHON_SHELL_METHODS = new Set([
  'run',
  'Popen',
  'call',
  'check_output',
  'check_call',
  'system',
  'popen',
  'popen2',
  'popen3',
  'popen4',
  'spawnl',
  'spawnle',
  'spawnlp',
  'spawnlpe',
  'spawnv',
  'spawnve',
  'spawnvp',
  'spawnvpe',
  'posix_spawn',
  'posix_spawnp',
  'getoutput',
  'getstatusoutput',
  'spawn',
]);

const PYTHON_NETWORK_MODULES = new Set([
  'urllib',
  'urllib.request',
  'urllib2',
  'httplib',
  'http.client',
  'requests',
  'aiohttp',
  'httpx',
  'socket',
  'paramiko',
  'ftplib',
  'smtplib',
  'telnetlib',
  'urllib3',
]);

const PYTHON_NETWORK_METHODS = new Set([
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'head',
  'request',
  'Session',
  'urlopen',
  'urlretrieve',
  'build_opener',
  'ClientSession',
  'Client',
  'AsyncClient',
  'socket',
  'create_connection',
  'connect',
  'send',
  'sendto',
  'SSHClient',
  'FTP',
  'SMTP',
  'SMTP_SSL',
  'Telnet',
  'HTTPConnection',
  'HTTPSConnection',
  'PoolManager',
]);

const PYTHON_FS_MODULES = new Set(['os', 'pathlib', 'shutil', 'io']);
const PYTHON_FS_READ_METHODS = new Set([
  'open',
  'read_text',
  'read_bytes',
  'copy',
  'copy2',
  'copyfile',
  'copytree',
  'move',
]);

export class PythonCapabilityExtractor {
  /**
   * Traverses a parsed Tree-sitter Python syntax tree and identifies security capabilities.
   */
  public static extract(
    rootNode: Parser.SyntaxNode,
    content: string,
    filePath: string,
    hasSyntaxError: boolean
  ): FileCapabilityAnalysis {
    const sites: CapabilitySite[] = [];

    // Track module/method aliases: aliasName -> { module: string; method?: string }
    const aliases = new Map<string, { module: string; method?: string }>();

    // Pass 1: Collect import statements and aliased bindings
    PythonCapabilityExtractor.collectAliases(rootNode, aliases);

    // Pass 2: Extract capabilities across AST nodes
    function walk(node: Parser.SyntaxNode): void {
      const type = node.type;

      // 1. Environment Variable Access
      if (PythonCapabilityExtractor.isEnvAccess(node, aliases)) {
        sites.push(
          PythonCapabilityExtractor.createSite(
            'env',
            node,
            filePath,
            true,
            'HIGH',
            'Python os.environ or os.getenv access detected'
          )
        );
      }

      // 2. Function & Method Calls
      if (type === 'call') {
        const fn = node.childForFieldName('function');
        const args = node.childForFieldName('arguments');

        if (fn) {
          const fnText = fn.text;

          // 2.1 eval(), exec(), compile()
          if (fnText === 'eval' || fnText === 'exec' || fnText === 'compile') {
            const obfDetail = PythonCapabilityExtractor.detectDynamicEvalObfuscation(args, aliases);
            sites.push(
              PythonCapabilityExtractor.createSite(
                'eval',
                node,
                filePath,
                true,
                'HIGH',
                obfDetail ?? `Python built-in ${fnText}() dynamic code evaluation`
              )
            );
          } else if (fnText === 'builtins.eval' || fnText === 'builtins.exec') {
            const obfDetail = PythonCapabilityExtractor.detectDynamicEvalObfuscation(args, aliases);
            sites.push(
              PythonCapabilityExtractor.createSite(
                'eval',
                node,
                filePath,
                true,
                'HIGH',
                obfDetail ?? `Python ${fnText}() dynamic code evaluation`
              )
            );
          }

          // 2.2 Dynamic imports: importlib.import_module, __import__
          if (
            fnText === 'importlib.import_module' ||
            fnText.endsWith('.import_module') ||
            fnText === '__import__'
          ) {
            sites.push(
              PythonCapabilityExtractor.createSite(
                'dynamicRequire',
                node,
                filePath,
                true,
                'HIGH',
                `Python dynamic import invocation: ${fnText}`
              )
            );
          }

          // 2.3 Debug Internals / Introspection
          if (
            fnText === 'sys.settrace' ||
            fnText === 'sys.setprofile' ||
            fnText === 'sys._getframe' ||
            fnText.startsWith('gc.get_') ||
            fnText.startsWith('ctypes.')
          ) {
            sites.push(
              PythonCapabilityExtractor.createSite(
                'debugInternals',
                node,
                filePath,
                true,
                'HIGH',
                `Python runtime introspection / low-level hook: ${fnText}`
              )
            );
          }

          // 2.4 Sensitive File Access via built-in open() or pathlib.Path.read_text()
          if (fnText === 'open' || fnText === 'io.open') {
            PythonCapabilityExtractor.checkSensitiveOpenCall(node, args, filePath, sites);
          }

          // 2.5 Method Calls on aliased modules (subprocess, requests, etc.)
          PythonCapabilityExtractor.checkMethodCall(node, fn, args, aliases, filePath, sites);
        }
      }

      for (let i = 0; i < node.childCount; i++) {
        const child = node.child(i);
        if (child) walk(child);
      }
    }

    walk(rootNode);

    // Aggregate capabilities
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
   * Pass 1: Collects import statements:
   * - import subprocess as sp
   * - from subprocess import run, Popen as p
   */
  public static collectAliases(
    rootNode: Parser.SyntaxNode,
    aliases: Map<string, { module: string; method?: string }>
  ): void {
    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'import_statement') {
        for (let i = 0; i < node.namedChildCount; i++) {
          const child = node.namedChild(i)!;
          if (child.type === 'dotted_name') {
            aliases.set(child.text, { module: child.text });
          } else if (child.type === 'aliased_import') {
            const nameChild = child.childForFieldName('name');
            const aliasChild = child.childForFieldName('alias');
            if (nameChild && aliasChild) {
              aliases.set(aliasChild.text, { module: nameChild.text });
            }
          }
        }
      } else if (node.type === 'import_from_statement') {
        const moduleNameNode = node.childForFieldName('module_name');
        if (moduleNameNode) {
          const mod = moduleNameNode.text;
          for (let i = 0; i < node.namedChildCount; i++) {
            const child = node.namedChild(i)!;
            if (child === moduleNameNode) continue;
            if (child.type === 'dotted_name') {
              aliases.set(child.text, { module: mod, method: child.text });
            } else if (child.type === 'aliased_import') {
              const nameChild = child.childForFieldName('name');
              const aliasChild = child.childForFieldName('alias');
              if (nameChild && aliasChild) {
                aliases.set(aliasChild.text, { module: mod, method: nameChild.text });
              }
            }
          }
        }
      } else if (node.type === 'assignment') {
        const leftNode = node.childForFieldName('left');
        const rightNode = node.childForFieldName('right');
        if (leftNode && leftNode.type === 'identifier' && rightNode) {
          if (rightNode.type === 'attribute') {
            const obj = rightNode.childForFieldName('object');
            const attr = rightNode.childForFieldName('attribute');
            if (obj && attr) {
              const objText = obj.text;
              const attrText = attr.text;
              const alias = aliases.get(objText);
              const resolvedMod = alias ? alias.module : objText;
              aliases.set(leftNode.text, { module: resolvedMod, method: attrText });
            }
          } else if (rightNode.type === 'identifier') {
            const alias = aliases.get(rightNode.text);
            if (alias) {
              aliases.set(leftNode.text, { module: alias.module, method: alias.method });
            } else if (
              rightNode.text === 'eval' ||
              rightNode.text === 'exec' ||
              rightNode.text === 'compile'
            ) {
              aliases.set(leftNode.text, { module: 'builtins', method: rightNode.text });
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
  }

  /**
   * Checks whether an AST node represents environment variable access.
   */
  public static isEnvAccess(
    node: Parser.SyntaxNode,
    aliases: Map<string, { module: string; method?: string }>
  ): boolean {
    const text = node.text;

    // Direct os.environ or os.getenv
    if (
      text === 'os.environ' ||
      text.startsWith('os.environ[') ||
      text.startsWith('os.environ.get')
    ) {
      return true;
    }
    if (text.startsWith('os.getenv(') || text.startsWith('os.putenv(')) {
      return true;
    }

    // Direct dotenv access
    if (text.startsWith('dotenv.load_dotenv') || text.startsWith('dotenv.dotenv_values')) {
      return true;
    }

    // Subscript on aliased environ: environ['SECRET']
    if (node.type === 'subscript') {
      const val = node.childForFieldName('value');
      if (val) {
        if (val.text === 'os.environ' || val.text === 'environ') return true;
        const alias = aliases.get(val.text);
        if (alias && alias.module === 'os' && alias.method === 'environ') return true;
      }
    }

    // Call on aliased getenv: getenv('SECRET')
    if (node.type === 'call') {
      const fn = node.childForFieldName('function');
      if (fn) {
        if (fn.text === 'os.getenv' || fn.text === 'getenv') return true;
        const alias = aliases.get(fn.text);
        if (
          alias &&
          alias.module === 'os' &&
          (alias.method === 'getenv' || alias.method === 'environ')
        ) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Evaluates method calls against aliased modules for shell, network, or filesystem activity.
   */
  public static checkMethodCall(
    callNode: Parser.SyntaxNode,
    fnNode: Parser.SyntaxNode,
    argsNode: Parser.SyntaxNode | null,
    aliases: Map<string, { module: string; method?: string }>,
    filePath: string,
    sites: CapabilitySite[]
  ): void {
    let resolvedModule: string | null = null;
    let resolvedMethod: string | null = null;

    if (fnNode.type === 'attribute') {
      const objNode = fnNode.childForFieldName('object');
      const attrNode = fnNode.childForFieldName('attribute');

      if (objNode && attrNode) {
        let objText = objNode.text;
        if (objNode.type === 'call') {
          const callFn = objNode.childForFieldName('function');
          if (callFn) {
            objText = callFn.text;
          }
        }
        const attrText = attrNode.text;

        const alias = aliases.get(objText);
        resolvedModule = alias ? alias.module : objText;
        resolvedMethod = attrText;
      }
    } else if (fnNode.type === 'identifier') {
      const alias = aliases.get(fnNode.text);
      if (alias) {
        resolvedModule = alias.module;
        resolvedMethod = alias.method ?? null;
      }
    }

    if (!resolvedModule || !resolvedMethod) return;

    // Dynamic evaluation (eval, exec, compile aliased via builtins)
    if (
      resolvedModule === 'builtins' &&
      (resolvedMethod === 'eval' || resolvedMethod === 'exec' || resolvedMethod === 'compile')
    ) {
      const obfDetail = PythonCapabilityExtractor.detectDynamicEvalObfuscation(argsNode, aliases);
      sites.push(
        PythonCapabilityExtractor.createSite(
          'eval',
          callNode,
          filePath,
          true,
          'HIGH',
          obfDetail ?? `Python built-in ${resolvedMethod}() dynamic code evaluation`
        )
      );
      return;
    }

    // Shell capability
    if (PYTHON_SHELL_MODULES.has(resolvedModule) && PYTHON_SHELL_METHODS.has(resolvedMethod)) {
      sites.push(
        PythonCapabilityExtractor.createSite(
          'shell',
          callNode,
          filePath,
          true,
          'HIGH',
          `Python shell execution: ${resolvedModule}.${resolvedMethod}()`
        )
      );
      return;
    }

    // Network capability
    if (PYTHON_NETWORK_MODULES.has(resolvedModule) && PYTHON_NETWORK_METHODS.has(resolvedMethod)) {
      sites.push(
        PythonCapabilityExtractor.createSite(
          'network',
          callNode,
          filePath,
          true,
          'HIGH',
          `Python outbound network request: ${resolvedModule}.${resolvedMethod}()`
        )
      );
      return;
    }

    // Sensitive FS via pathlib.Path(path).read_text() or shutil operations
    if (
      (PYTHON_FS_MODULES.has(resolvedModule) ||
        resolvedModule.endsWith('.Path') ||
        resolvedModule === 'Path') &&
      PYTHON_FS_READ_METHODS.has(resolvedMethod)
    ) {
      sites.push(
        PythonCapabilityExtractor.createSite(
          'fsSensitive',
          callNode,
          filePath,
          true,
          'HIGH',
          `Python filesystem read via pathlib: ${resolvedModule}.${resolvedMethod}()`
        )
      );
    }
  }

  /**
   * Inspects open(...) calls for sensitive path patterns.
   */
  public static checkSensitiveOpenCall(
    callNode: Parser.SyntaxNode,
    argsNode: Parser.SyntaxNode | null,
    filePath: string,
    sites: CapabilitySite[]
  ): void {
    if (!argsNode || argsNode.namedChildCount === 0) return;

    const firstArg = argsNode.namedChild(0)!;
    const pathStr = PythonCapabilityExtractor.tryConstantFoldString(firstArg);

    if (pathStr !== null) {
      const isSensitive = SENSITIVE_PATH_PATTERNS.some((pat) => pat.test(pathStr));
      if (isSensitive) {
        sites.push(
          PythonCapabilityExtractor.createSite(
            'fsSensitive',
            callNode,
            filePath,
            true,
            'HIGH',
            `Python open() targeting sensitive path: ${pathStr}`
          )
        );
      }
    } else {
      // Dynamic path provided to open()
      sites.push(
        PythonCapabilityExtractor.createSite(
          'fsSensitive',
          callNode,
          filePath,
          false,
          'LOW',
          `Python open() with unresolved dynamic path argument: ${firstArg.text}`
        )
      );
    }
  }

  /**
   * Attempts constant-folding for string literals and concatenation in Python.
   */
  public static tryConstantFoldString(node: Parser.SyntaxNode): string | null {
    if (node.type === 'string') {
      return PythonCapabilityExtractor.unquote(node.text);
    }

    if (node.type === 'binary_operator') {
      const left = node.childForFieldName('left');
      const op = node.children.find((c) => c.text === '+');
      const right = node.childForFieldName('right');
      if (left && op && right) {
        const l = PythonCapabilityExtractor.tryConstantFoldString(left);
        const r = PythonCapabilityExtractor.tryConstantFoldString(right);
        if (l !== null && r !== null) return l + r;
      }
    }

    if (node.type === 'call') {
      const fn = node.childForFieldName('function')?.text;
      const args = node.childForFieldName('arguments');
      if (fn === 'os.path.join' && args) {
        const parts: string[] = [];
        for (let i = 0; i < args.namedChildCount; i++) {
          const val = PythonCapabilityExtractor.tryConstantFoldString(args.namedChild(i)!);
          if (val === null) return null;
          parts.push(val);
        }
        return parts.join('/');
      }
      if (fn === 'os.path.expanduser' && args && args.namedChildCount > 0) {
        const first = PythonCapabilityExtractor.tryConstantFoldString(args.namedChild(0)!);
        if (first === '~') return '~';
      }
    }

    return null;
  }

  /**
   * Detects obfuscated dynamic code execution patterns such as:
   * - exec(base64.b64decode(...))
   * - exec(codecs.decode(...))
   * - eval(b64decode(...))
   */
  public static detectDynamicEvalObfuscation(
    argsNode: Parser.SyntaxNode | null,
    aliases: Map<string, { module: string; method?: string }>
  ): string | null {
    if (!argsNode || argsNode.namedChildCount === 0) return null;

    const firstArg = argsNode.namedChild(0)!;
    if (firstArg.type === 'call') {
      const innerFn = firstArg.childForFieldName('function');
      if (innerFn) {
        const innerFnText = innerFn.text;
        // Direct base64 decode calls: base64.b64decode, b64decode, etc.
        if (
          innerFnText === 'base64.b64decode' ||
          innerFnText === 'b64decode' ||
          innerFnText === 'base64.urlsafe_b64decode' ||
          innerFnText === 'base64.decodebytes' ||
          innerFnText.endsWith('.b64decode')
        ) {
          return `Python dynamic eval with base64 obfuscation: ${innerFnText}()`;
        }

        // Direct codecs decode calls: codecs.decode
        if (
          innerFnText === 'codecs.decode' ||
          (innerFn.type === 'attribute' &&
            innerFn.childForFieldName('object')?.text === 'codecs' &&
            innerFn.childForFieldName('attribute')?.text === 'decode')
        ) {
          return `Python dynamic eval with codecs obfuscation: ${innerFnText}()`;
        }

        // Check against collected import aliases
        if (innerFn.type === 'identifier') {
          const alias = aliases.get(innerFn.text);
          if (alias) {
            if (
              alias.module === 'base64' &&
              (alias.method === 'b64decode' ||
                alias.method === 'decodebytes' ||
                alias.method === 'urlsafe_b64decode')
            ) {
              return `Python dynamic eval with aliased base64 obfuscation: ${alias.module}.${alias.method}()`;
            }
            if (alias.module === 'codecs' && alias.method === 'decode') {
              return `Python dynamic eval with aliased codecs obfuscation: ${alias.module}.${alias.method}()`;
            }
          }
        }
      }
    }

    // Heuristic fallback on first argument text representation
    const firstArgText = firstArg.text;
    if (firstArgText.includes('b64decode(') || firstArgText.includes('base64.b64decode')) {
      return 'Python dynamic eval with base64 obfuscation payload';
    }
    if (firstArgText.includes('codecs.decode(')) {
      return 'Python dynamic eval with codecs obfuscation payload';
    }

    return null;
  }

  public static unquote(text: string): string {
    let trimmed = text.trim();
    if (/^[rubfRUBF]+/i.test(trimmed)) {
      trimmed = trimmed.replace(/^[rubfRUBF]+/i, '');
    }
    if (
      (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith('"""') && trimmed.endsWith('"""')) ||
      (trimmed.startsWith("'''") && trimmed.endsWith("'''"))
    ) {
      if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        return trimmed.slice(3, -3);
      }
      return trimmed.slice(1, -1);
    }
    return trimmed;
  }

  public static findEnclosingFunction(node: Parser.SyntaxNode): string | undefined {
    let curr: Parser.SyntaxNode | null = node.parent;
    while (curr) {
      if (curr.type === 'function_definition' || curr.type === 'async_function_definition') {
        const id = curr.childForFieldName('name');
        return id ? id.text : 'anonymous';
      }
      curr = curr.parent;
    }
    return undefined;
  }

  public static createSite(
    capability: CapabilityType,
    node: Parser.SyntaxNode,
    filePath: string,
    resolved: boolean,
    confidence: 'HIGH' | 'MEDIUM' | 'LOW',
    details: string
  ): CapabilitySite {
    const startLine = node.startPosition.row + 1;
    const startCol = node.startPosition.column;
    const endLine = node.endPosition.row + 1;
    const endCol = node.endPosition.column;

    const rawSnippet = node.text.replace(/[\r\n]+/g, ' ').slice(0, 150);
    const enclosing = PythonCapabilityExtractor.findEnclosingFunction(node);

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
}
