export type SourceKind =
  | 'HTTP_PARAM'
  | 'HTTP_QUERY'
  | 'HTTP_BODY'
  | 'HTTP_HEADER'
  | 'CLI_ARG'
  | 'ENVIRONMENT'
  | 'SERVERLESS_EVENT'
  | 'RPC_INPUT'
  | 'FILE_INPUT'
  | 'GENERIC_USER_INPUT';

export type SinkKind =
  | 'SQL_QUERY'
  | 'COMMAND_INJECTION'
  | 'EVAL_CODE'
  | 'PATH_TRAVERSAL'
  | 'SSRF'
  | 'XSS'
  | 'NOSQL_INJECTION'
  | 'TEMPLATE_INJECTION'
  | 'UNSAFE_DESERIALIZATION'
  | 'XXE'
  | 'OPEN_REDIRECT';

export interface SourceRule {
  pattern: RegExp;
  kind: SourceKind;
  description: string;
}

export interface SinkRule {
  pattern: RegExp;
  kind: SinkKind;
  cwe: string;
  description: string;
}

export interface SanitizerRule {
  pattern: RegExp;
  neutralizes: SinkKind[];
  description: string;
}

export class TaintCatalog {
  // Known Sources of untrusted user input across JS/TS, Python, Go, Java, C#
  public static readonly SOURCES: SourceRule[] = [
    // Express, Fastify, Koa, NestJS, Node.js HTTP
    {
      pattern: /\b(?:req|request|ctx)\.query\b/i,
      kind: 'HTTP_QUERY',
      description: 'Express/Node HTTP URL query parameter',
    },
    {
      pattern: /\b(?:req|request|ctx)\.params\b/i,
      kind: 'HTTP_PARAM',
      description: 'Express/Node route parameter',
    },
    {
      pattern: /\b(?:req|request|ctx)\.body\b/i,
      kind: 'HTTP_BODY',
      description: 'Express/Node HTTP request body',
    },
    {
      pattern: /\b(?:req|request|ctx)\.headers\b/i,
      kind: 'HTTP_HEADER',
      description: 'Express/Node HTTP headers',
    },
    {
      pattern: /\b(?:req|request|ctx)\.cookies\b/i,
      kind: 'HTTP_HEADER',
      description: 'Express/Node HTTP cookies',
    },
    {
      pattern: /\bc\.req\.(?:query|param|json)\b/i,
      kind: 'HTTP_QUERY',
      description: 'Hono request parameters',
    },

    // Next.js App Router, Server Actions, Remix, SvelteKit
    {
      pattern: /\bformData\.(?:get|getAll)\b/i,
      kind: 'HTTP_BODY',
      description: 'Web API / Next.js Server Action FormData input',
    },
    {
      pattern: /\bsearchParams\.(?:get|getAll)\b/i,
      kind: 'HTTP_QUERY',
      description: 'URLSearchParams query parameter',
    },
    {
      pattern: /\b(?:req|request)\.(?:json|text|formData)\(\)/i,
      kind: 'HTTP_BODY',
      description: 'Web Request stream body',
    },
    {
      pattern: /\bevent\.(?:url|request)\b/i,
      kind: 'HTTP_PARAM',
      description: 'SvelteKit/Remix request event',
    },

    // Serverless (AWS Lambda, Azure Functions, Cloudflare Workers)
    {
      pattern: /\bevent\.(?:queryStringParameters|multiValueQueryStringParameters)\b/i,
      kind: 'SERVERLESS_EVENT',
      description: 'AWS Lambda query parameters',
    },
    {
      pattern: /\bevent\.(?:body|rawBody)\b/i,
      kind: 'SERVERLESS_EVENT',
      description: 'AWS Lambda event body',
    },

    // Python Flask, Django, FastAPI, Tornado
    {
      pattern: /\brequest\.(?:args|query_params)\b/i,
      kind: 'HTTP_QUERY',
      description: 'Python request query parameters',
    },
    {
      pattern: /\brequest\.(?:form|data|json|POST|body)\b/i,
      kind: 'HTTP_BODY',
      description: 'Python request body data',
    },
    {
      pattern: /\brequest\.GET\b/i,
      kind: 'HTTP_QUERY',
      description: 'Django request.GET parameters',
    },
    {
      pattern: /\brequest\.headers\b/i,
      kind: 'HTTP_HEADER',
      description: 'Python request headers',
    },
    {
      pattern: /\bself\.(?:get_argument|get_query_argument)\b/i,
      kind: 'HTTP_QUERY',
      description: 'Tornado request argument',
    },

    // GraphQL & RPC
    {
      pattern: /(?<!\brequest\.)\bargs\.[a-zA-Z0-9_]+\b/i,
      kind: 'RPC_INPUT',
      description: 'GraphQL resolver argument',
    },

    // Go net/http, Gin, Echo, Fiber, Chi
    {
      pattern: /\br\.URL\.Query\(\)/i,
      kind: 'HTTP_QUERY',
      description: 'Go net/http URL query parameters',
    },
    {
      pattern: /\br\.(?:FormValue|PostFormValue)\b/i,
      kind: 'HTTP_PARAM',
      description: 'Go net/http form value',
    },
    {
      pattern: /\bc\.(?:Query|Param|PostForm|BodyParser)\b/i,
      kind: 'HTTP_PARAM',
      description: 'Gin/Echo/Fiber context parameters',
    },

    // Java Spring, JAX-RS, Servlets
    {
      pattern: /\brequest\.getParameter(?:Values)?\b/i,
      kind: 'HTTP_PARAM',
      description: 'Java Servlet request parameter',
    },
    {
      pattern: /\b@RequestParam\b/i,
      kind: 'HTTP_PARAM',
      description: 'Spring @RequestParam binding',
    },
    {
      pattern: /\b@PathVariable\b/i,
      kind: 'HTTP_PARAM',
      description: 'Spring @PathVariable binding',
    },
    { pattern: /\b@RequestBody\b/i, kind: 'HTTP_BODY', description: 'Spring @RequestBody binding' },

    // C# ASP.NET Core
    {
      pattern: /\bRequest\.(?:Query|Form|Headers|RouteValues)\b/i,
      kind: 'HTTP_QUERY',
      description: 'ASP.NET Request collection',
    },
    {
      pattern: /\b\[FromQuery\]\b/i,
      kind: 'HTTP_QUERY',
      description: 'ASP.NET [FromQuery] binding',
    },
    { pattern: /\b\[FromBody\]\b/i, kind: 'HTTP_BODY', description: 'ASP.NET [FromBody] binding' },
    {
      pattern: /\b\[FromRoute\]\b/i,
      kind: 'HTTP_PARAM',
      description: 'ASP.NET [FromRoute] binding',
    },

    // CLI Arguments & Environment
    {
      pattern: /\bprocess\.argv\b/i,
      kind: 'CLI_ARG',
      description: 'Node.js command line arguments',
    },
    { pattern: /\bsys\.argv\b/i, kind: 'CLI_ARG', description: 'Python command line arguments' },
    { pattern: /\bos\.Args\b/i, kind: 'CLI_ARG', description: 'Go command line arguments' },
    {
      pattern: /\bprocess\.env\b/i,
      kind: 'ENVIRONMENT',
      description: 'Node.js environment variables',
    },
    {
      pattern: /\bos\.environ\b/i,
      kind: 'ENVIRONMENT',
      description: 'Python environment dictionary',
    },
  ];

  // Dangerous Sinks that must not receive untrusted taint without validation
  public static readonly SINKS: SinkRule[] = [
    // SQL Injection (CWE-89)
    {
      pattern:
        /\b(?:db|pool|client|connection|prisma|sequelize|knex|cursor|session)\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\b/i,
      kind: 'SQL_QUERY',
      cwe: 'CWE-89',
      description: 'Direct SQL execution sink',
    },

    // Command Injection / RCE (CWE-78)
    {
      pattern: /\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|fork)\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'Operating system command execution sink',
    },
    {
      pattern: /\b(?:subprocess\.)?(?:Popen|run|call|check_output|check_call)\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'Python subprocess command sink',
    },
    {
      pattern: /\bos\.system\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'OS system command sink',
    },
    {
      pattern: /\bRuntime\.getRuntime\(\)\.exec\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'Java Runtime.exec command sink',
    },
    {
      pattern: /\bProcess\.Start\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'C# Process.Start sink',
    },
    {
      pattern: /\bexec\.Command\b/i,
      kind: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      description: 'Go os/exec Command sink',
    },

    // Dynamic Code Execution / Eval (CWE-95, CWE-94)
    {
      pattern: /\b(?:eval|new\s+Function|vm\.runInContext|vm\.runInNewContext)\b/i,
      kind: 'EVAL_CODE',
      cwe: 'CWE-95',
      description: 'Arbitrary code evaluation sink',
    },

    // Path Traversal (CWE-22)
    {
      pattern:
        /\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|open|unlink)\b/i,
      kind: 'PATH_TRAVERSAL',
      cwe: 'CWE-22',
      description: 'File system access sink',
    },

    // SSRF (CWE-918)
    {
      pattern: /\b(?:axios|fetch|http\.get|https\.get|requests\.get|requests\.post)\b/i,
      kind: 'SSRF',
      cwe: 'CWE-918',
      description: 'Outbound HTTP network request sink',
    },

    // XSS (CWE-79)
    {
      pattern: /\b(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML)\b/i,
      kind: 'XSS',
      cwe: 'CWE-79',
      description: 'DOM raw HTML injection sink',
    },

    // NoSQL Injection (CWE-943)
    {
      pattern: /\b(?:collection|model|User|Account|Doc)\.(?:find|findOne|update|delete|where)\b/i,
      kind: 'NOSQL_INJECTION',
      cwe: 'CWE-943',
      description: 'NoSQL query parameter sink',
    },

    // Template Injection / SSTI (CWE-1336)
    {
      pattern: /\b(?:nunjucks\.renderString|ejs\.render|handlebars\.compile|jinja2\.Template)\b/i,
      kind: 'TEMPLATE_INJECTION',
      cwe: 'CWE-1336',
      description: 'Server-side template evaluation sink',
    },

    // Unsafe Deserialization (CWE-502)
    {
      pattern: /\b(?:pickle\.loads|yaml\.load|serialize-javascript|unserialize)\b/i,
      kind: 'UNSAFE_DESERIALIZATION',
      cwe: 'CWE-502',
      description: 'Unsafe object deserialization sink',
    },

    // Open Redirect (CWE-601)
    {
      pattern: /\b(?:res\.redirect|response\.sendRedirect|redirect)\b/i,
      kind: 'OPEN_REDIRECT',
      cwe: 'CWE-601',
      description: 'HTTP redirection destination sink',
    },
  ];

  // Sanitizers that neutralize taint
  public static readonly SANITIZERS: SanitizerRule[] = [
    {
      pattern: /\b(?:parseInt|parseFloat|Number|int|float|Integer\.parseInt|int\.Parse)\b/i,
      neutralizes: [
        'SQL_QUERY',
        'COMMAND_INJECTION',
        'PATH_TRAVERSAL',
        'SSRF',
        'XSS',
        'EVAL_CODE',
        'NOSQL_INJECTION',
        'OPEN_REDIRECT',
      ],
      description: 'Numeric type cast converts string to safe primitive number',
    },
    {
      pattern: /\b(?:Boolean|bool|bool\.Parse)\b/i,
      neutralizes: [
        'SQL_QUERY',
        'COMMAND_INJECTION',
        'PATH_TRAVERSAL',
        'SSRF',
        'XSS',
        'EVAL_CODE',
        'NOSQL_INJECTION',
        'OPEN_REDIRECT',
      ],
      description: 'Boolean type cast converts to safe primitive boolean',
    },
    {
      pattern:
        /\b(?:encodeURIComponent|encodeURI|escape|validator\.escape|html\.escape|DOMPurify\.sanitize)\b/i,
      neutralizes: ['XSS', 'PATH_TRAVERSAL'],
      description: 'URI/HTML encoding and sanitizer library',
    },
    {
      pattern: /\b(?:path\.basename|filepath\.Base|os\.path\.basename)\b/i,
      neutralizes: ['PATH_TRAVERSAL'],
      description: 'Path basename extraction strips directory traversal sequences',
    },
    {
      pattern: /\b(?:shlex\.quote|shell-quote\.quote)\b/i,
      neutralizes: ['COMMAND_INJECTION'],
      description: 'Shell command argument quoting sanitizer',
    },
    {
      pattern: /\b(?:z\.string|z\.number|zod|\.parse\(|\.safeParse\(|validate\()\b/i,
      neutralizes: [
        'SQL_QUERY',
        'COMMAND_INJECTION',
        'PATH_TRAVERSAL',
        'SSRF',
        'XSS',
        'NOSQL_INJECTION',
      ],
      description: 'Zod or schema validation library sanitizes untrusted input',
    },
  ];

  /**
   * Identifies if an expression is a recognized untrusted source.
   */
  public static matchSource(expr: string): SourceRule | null {
    for (const s of TaintCatalog.SOURCES) {
      if (s.pattern.test(expr)) return s;
    }
    return null;
  }

  /**
   * Identifies if a callee/expression is a recognized dangerous sink.
   */
  public static matchSink(callee: string): SinkRule | null {
    for (const s of TaintCatalog.SINKS) {
      if (s.pattern.test(callee)) return s;
    }
    return null;
  }

  /**
   * Checks if an operation neutralizes taint for the given sink kind (or any sink kind if omitted).
   */
  public static isSanitized(expr: string, sinkKind?: SinkKind): boolean {
    for (const s of TaintCatalog.SANITIZERS) {
      if (!sinkKind || s.neutralizes.includes(sinkKind)) {
        if (s.pattern.test(expr)) {
          return true;
        }
      }
    }
    return false;
  }
}
