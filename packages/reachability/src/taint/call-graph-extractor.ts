import type Parser from 'web-tree-sitter';

export interface FunctionParameter {
  name: string;
  index: number;
}

export interface CallSite {
  calleeName: string;
  calleeExpression: string;
  arguments: Array<{
    text: string;
    index: number;
    node: Parser.SyntaxNode;
    isConstant: boolean;
  }>;
  line: number;
  enclosingFunctionName?: string;
  node: Parser.SyntaxNode;
}

export interface FunctionSummary {
  name: string;
  parameters: FunctionParameter[];
  startLine: number;
  endLine: number;
  isExported: boolean;
  callSites: CallSite[];
  scopeNode: Parser.SyntaxNode;
}

export interface FileAnalysisSummary {
  filePath: string;
  functions: Map<string, FunctionSummary>;
  callSites: CallSite[];
  exportedFunctions: Set<string>;
}

export class CallGraphExtractor {
  /**
   * Analyzes an AST root node across all supported languages and builds a call graph summary.
   * Hardened for Phase B: strictly iterative traversal (no recursion depth limit),
   * Map lookup by node id (eliminating quadratic loop), and comprehensive callee resolution.
   */
  public static extract(rootNode: Parser.SyntaxNode, filePath: string): FileAnalysisSummary {
    const summary: FileAnalysisSummary = {
      filePath,
      functions: new Map(),
      callSites: [],
      exportedFunctions: new Set(),
    };

    // Node id -> FunctionSummary for O(1) lookup during call site traversal
    const functionById = new Map<number, FunctionSummary>();

    // 1. First iterative pass: Collect function declarations and parameters
    interface DeclFrame {
      node: Parser.SyntaxNode;
      isExported: boolean;
    }

    const declStack: DeclFrame[] = [{ node: rootNode, isExported: false }];

    while (declStack.length > 0) {
      const { node, isExported: parentExported } = declStack.pop()!;
      let isExported = parentExported;

      // Handle export wrappers in JS/TS
      if (
        node.type === 'export_statement' ||
        node.type === 'export_default_statement' ||
        node.type === 'export_declaration'
      ) {
        isExported = true;
      }

      // Variable declaration with arrow function or function expression
      if (node.type === 'variable_declarator') {
        const nameNode = node.childForFieldName('name');
        const valNode = node.childForFieldName('value');
        if (
          nameNode &&
          valNode &&
          (valNode.type === 'arrow_function' || valNode.type === 'function_expression')
        ) {
          const fnName = nameNode.text;
          const params = CallGraphExtractor.extractParameters(valNode);
          const fnSummary: FunctionSummary = {
            name: fnName,
            parameters: params,
            startLine: valNode.startPosition.row + 1,
            endLine: valNode.endPosition.row + 1,
            isExported,
            callSites: [],
            scopeNode: valNode,
          };
          summary.functions.set(fnName, fnSummary);
          functionById.set(valNode.id, fnSummary);
          if (isExported) summary.exportedFunctions.add(fnName);
        }
      }

      // Standard function declarations & definitions across languages
      if (
        node.type === 'function_declaration' ||
        node.type === 'function_definition' ||
        node.type === 'method_definition' ||
        node.type === 'method_declaration' ||
        node.type === 'local_function_statement'
      ) {
        const nameNode = node.childForFieldName('name') ?? node.namedChild(0);

        if (
          nameNode &&
          (nameNode.type === 'identifier' ||
            nameNode.type === 'property_identifier' ||
            nameNode.type === 'field_identifier')
        ) {
          const fnName = nameNode.text;
          const params = CallGraphExtractor.extractParameters(node);
          const fnSummary: FunctionSummary = {
            name: fnName,
            parameters: params,
            startLine: node.startPosition.row + 1,
            endLine: node.endPosition.row + 1,
            isExported,
            callSites: [],
            scopeNode: node,
          };
          summary.functions.set(fnName, fnSummary);
          functionById.set(node.id, fnSummary);
          if (isExported) summary.exportedFunctions.add(fnName);
        }
      }

      // Push children in reverse order
      for (let i = node.namedChildCount - 1; i >= 0; i--) {
        declStack.push({ node: node.namedChild(i)!, isExported });
      }
    }

    // 2. Second iterative pass: Collect all call sites and attribute to enclosing function in O(1)
    interface CallFrame {
      node: Parser.SyntaxNode;
      isExit?: boolean;
      fnName?: string;
    }

    const callStack: CallFrame[] = [{ node: rootNode }];
    const activeFnStack: string[] = [];

    while (callStack.length > 0) {
      const frame = callStack.pop()!;

      if (frame.isExit) {
        if (frame.fnName && activeFnStack.length > 0) {
          activeFnStack.pop();
        }
        continue;
      }

      const node = frame.node;

      // Check if entering a function node in O(1)
      const enteredFn = functionById.get(node.id);
      if (enteredFn) {
        activeFnStack.push(enteredFn.name);
        callStack.push({ node, isExit: true, fnName: enteredFn.name });
      }

      const activeFn =
        activeFnStack.length > 0 ? activeFnStack[activeFnStack.length - 1] : undefined;

      if (
        node.type === 'call_expression' ||
        node.type === 'call' ||
        node.type === 'method_invocation' ||
        node.type === 'invocation_expression' ||
        node.type === 'new_expression'
      ) {
        const isNew = node.type === 'new_expression';
        const funcChild = isNew
          ? (node.childForFieldName('constructor') ?? node.namedChild(0))
          : (node.childForFieldName('function') ??
            node.childForFieldName('name') ??
            node.namedChild(0));

        if (funcChild) {
          const calleeText = funcChild.text;
          // Resolve member chains and optional chains (e.g. 'userService?.findUser' -> 'findUser')
          const normalized = calleeText.replace(/\?\./g, '.');
          const parts = normalized.split('.');
          const baseName = parts[parts.length - 1]!.trim();

          const argsNode = isNew
            ? (node.childForFieldName('arguments') ??
              (node.namedChildCount > 1 ? node.namedChild(1) : null))
            : (node.childForFieldName('arguments') ??
              node.childForFieldName('argument_list') ??
              (node.namedChildCount > 1 ? node.namedChild(1) : null));

          const parsedArgs: Array<{
            text: string;
            index: number;
            node: Parser.SyntaxNode;
            isConstant: boolean;
          }> = [];

          if (argsNode) {
            let argIndex = 0;
            for (let i = 0; i < argsNode.namedChildCount; i++) {
              const argChild = argsNode.namedChild(i)!;
              if (argChild.type !== ',' && argChild.type !== '(' && argChild.type !== ')') {
                parsedArgs.push({
                  text: argChild.text,
                  index: argIndex++,
                  node: argChild,
                  isConstant: CallGraphExtractor.isLiteralConstant(argChild),
                });
              }
            }
          }

          const callSite: CallSite = {
            calleeName: baseName,
            calleeExpression: calleeText,
            arguments: parsedArgs,
            line: node.startPosition.row + 1,
            enclosingFunctionName: activeFn,
            node,
          };

          summary.callSites.push(callSite);

          if (activeFn && summary.functions.has(activeFn)) {
            summary.functions.get(activeFn)!.callSites.push(callSite);
          }
        }
      }

      // Push children in reverse order
      for (let i = node.namedChildCount - 1; i >= 0; i--) {
        callStack.push({ node: node.namedChild(i)! });
      }
    }

    return summary;
  }

  /**
   * Extracts function parameter names and indexes across JS/TS, Python, Go, Java, C#.
   */
  private static extractParameters(fnNode: Parser.SyntaxNode): FunctionParameter[] {
    const params: FunctionParameter[] = [];

    const paramsNode =
      fnNode.childForFieldName('parameters') ?? fnNode.childForFieldName('parameter_list');

    if (!paramsNode) {
      // In JS arrow functions, a single identifier can be the parameter: x => ...
      const firstChild = fnNode.namedChild(0);
      if (firstChild && firstChild.type === 'identifier') {
        params.push({ name: firstChild.text, index: 0 });
      }
      return params;
    }

    let index = 0;
    for (let i = 0; i < paramsNode.namedChildCount; i++) {
      const child = paramsNode.namedChild(i)!;

      // JS / TS parameter types
      if (child.type === 'identifier') {
        params.push({ name: child.text, index: index++ });
      } else if (child.type === 'required_parameter' || child.type === 'optional_parameter') {
        const idChild = child.childForFieldName('pattern') ?? child.namedChild(0);
        if (idChild && idChild.type === 'identifier') {
          params.push({ name: idChild.text, index: index++ });
        }
      } else if (child.type === 'assignment_pattern') {
        // Default param: foo = 'default'
        const left = child.childForFieldName('left') ?? child.namedChild(0);
        if (left && left.type === 'identifier') {
          params.push({ name: left.text, index: index++ });
        }
      } else if (child.type === 'typed_parameter' || child.type === 'typed_default_parameter') {
        // Python / TS typed param
        const nameChild = child.childForFieldName('name') ?? child.namedChild(0);
        if (nameChild && nameChild.type === 'identifier') {
          params.push({ name: nameChild.text, index: index++ });
        }
      } else if (child.type === 'parameter_declaration') {
        // Go parameter: a string, b int
        const nameChild = child.childForFieldName('name') ?? child.namedChild(0);
        if (nameChild && nameChild.type === 'identifier') {
          params.push({ name: nameChild.text, index: index++ });
        }
      } else if (child.type === 'formal_parameter' || child.type === 'parameter') {
        // Java / C# parameter
        const nameChild =
          child.childForFieldName('name') ?? child.namedChild(child.namedChildCount - 1);
        if (
          nameChild &&
          (nameChild.type === 'identifier' || nameChild.type === 'variable_declarator_id')
        ) {
          params.push({ name: nameChild.text, index: index++ });
        }
      }
    }

    return params;
  }

  /**
   * Determines if an AST node is a compile-time static literal constant.
   */
  public static isLiteralConstant(node: Parser.SyntaxNode): boolean {
    const text = node.text.trim();
    if (text === 'true' || text === 'false' || text === 'null' || text === 'undefined') {
      return true;
    }

    if (
      node.type === 'string' ||
      node.type === 'string_literal' ||
      node.type === 'number' ||
      node.type === 'integer' ||
      node.type === 'float'
    ) {
      return true;
    }

    // Binary expressions of constants: "SELECT " + "1"
    if (node.type === 'binary_expression') {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      if (left && right) {
        return (
          CallGraphExtractor.isLiteralConstant(left) && CallGraphExtractor.isLiteralConstant(right)
        );
      }
    }

    // Template string with no expressions
    if (node.type === 'template_string') {
      for (let i = 0; i < node.namedChildCount; i++) {
        if (node.namedChild(i)!.type === 'template_substitution') {
          return false;
        }
      }
      return true;
    }

    return false;
  }
}
