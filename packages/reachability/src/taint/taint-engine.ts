import fs from 'node:fs';
import path from 'node:path';
import type Parser from 'web-tree-sitter';
import type { TaintFlowDetail, TaintStep } from '@secureship/contracts';
import { TreeSitterLoader } from '../parsers/tree-sitter-loader.js';
import { TaintCatalog, type SourceKind, type SinkKind } from './taint-catalog.js';
import { CallGraphExtractor, type FunctionParameter } from './call-graph-extractor.js';
import type { ImportGraph } from '../graph/import-graph.js';

export interface TaintAnalysisInput {
  filePath: string;
  fileContent: string;
  findingLine: number;
  findingEndLine?: number;
  ruleId?: string;
  category?: string;
  snippet?: string;
  importGraph?: ImportGraph;
  projectRoot?: string;
  maxHops?: number;
}

export interface TaintAnalysisResult {
  hasTaintFlow: boolean;
  isConstantSink: boolean;
  isSanitized?: boolean;
  taintDetail?: TaintFlowDetail;
  notes?: string;
  hopCount?: number;
}

interface TaintedVarInfo {
  variableName: string;
  sourceExpression: string;
  sourceLine: number;
  kind: SourceKind;
  steps: TaintStep[];
}

export class TaintEngine {
  /**
   * Analyzes a source file for intra-procedural and inter-procedural taint flow
   * from untrusted Sources to dangerous Sinks across function boundaries and files.
   */
  public static analyze(input: TaintAnalysisInput): TaintAnalysisResult {
    const lang = TreeSitterLoader.detectLanguage(input.filePath);
    if (!lang) {
      return { hasTaintFlow: false, isConstantSink: false };
    }

    const parseRes = TreeSitterLoader.parseFile(input.fileContent, lang);
    if (!parseRes.tree || parseRes.hasError) {
      return { hasTaintFlow: false, isConstantSink: false };
    }

    const root = parseRes.tree.rootNode;
    const targetLine = input.findingLine;

    // 1. Find the AST node closest to the finding line
    const findingNode = TaintEngine.findNodeAtLine(root, targetLine);
    if (!findingNode) {
      return { hasTaintFlow: false, isConstantSink: false };
    }

    // 2. Locate enclosing function, method, or program scope
    const scopeNode = TaintEngine.findEnclosingScope(findingNode);

    // 3. Find candidate Sinks at or near the finding line
    const candidateSinks = TaintEngine.findSinksInScope(scopeNode, targetLine);
    if (candidateSinks.length === 0) {
      return { hasTaintFlow: false, isConstantSink: false };
    }

    // 4. Trace local intra-procedural taint propagation in scope
    const taintedVars = TaintEngine.collectTaintedVariablesInScope(scopeNode, input.fileContent);

    // 5. Evaluate candidate sinks
    for (const sink of candidateSinks) {
      // 5.1 Safe Parameterized Query Check (e.g. db.query($1, [req.query.id]))
      if (TaintEngine.isSafeParameterizedQuery(sink)) {
        return {
          hasTaintFlow: false,
          isConstantSink: false,
          isSanitized: true,
          notes: `Sink '${sink.calleeText}' at line ${sink.line} uses safe parameterized query bindings ($1 / ? / :param); parameters are safely bound without SQL concatenation.`,
        };
      }

      // 5.2 Check if sink arguments are purely constant literals
      if (TaintEngine.isAllArgumentsConstant(sink.argumentsNode)) {
        return {
          hasTaintFlow: false,
          isConstantSink: true,
          notes: `Sink '${sink.calleeText}' at line ${sink.line} uses compile-time static constant arguments; no user taint present`,
        };
      }

      // 5.3 Direct or propagated intra-procedural taint flow
      const flow = TaintEngine.checkSinkTaint(sink, taintedVars, input.fileContent);
      if (flow) {
        return {
          hasTaintFlow: true,
          isConstantSink: false,
          taintDetail: flow,
          notes: `Confirmed exploit taint flow: untrusted input from '${flow.sourceExpression}' (line ${flow.sourceLine}) flows into sink '${flow.sinkExpression}' (line ${flow.sinkLine})`,
        };
      }

      // 5.4 Check if any argument in sink was sanitized
      if (sink.argumentsNode && TaintCatalog.isSanitized(sink.argumentsNode.text, sink.sinkKind)) {
        return {
          hasTaintFlow: false,
          isConstantSink: false,
          isSanitized: true,
          notes: `Sink arguments at line ${sink.line} are protected by sanitizer routine (${sink.argumentsNode.text}).`,
        };
      }

      // 6. INTER-PROCEDURAL TAINT TRACKING (Blocker 4 Remediation)
      // If sink argument depends on a parameter of the enclosing function, trace callers backward!
      const feederParams = TaintEngine.findParameterFeeders(scopeNode, sink);
      if (feederParams.length > 0) {
        const fnName = TaintEngine.extractFunctionName(scopeNode);
        if (fnName) {
          const interFlow = TaintEngine.traceInterProceduralTaint({
            functionName: fnName,
            paramIndexes: feederParams.map((p) => p.index),
            currentFilePath: input.filePath,
            currentFileContent: input.fileContent,
            sink,
            importGraph: input.importGraph,
            projectRoot: input.projectRoot,
            maxHops: input.maxHops ?? 5,
            currentHop: 1,
            visited: new Set([`${path.resolve(input.filePath)}:${fnName}`]),
          });

          if (interFlow) {
            return {
              hasTaintFlow: true,
              isConstantSink: false,
              taintDetail: interFlow,
              notes: `Confirmed inter-procedural exploit taint flow (${interFlow.taintSteps.length} steps): untrusted input from '${interFlow.sourceExpression}' flows across function boundaries into sink '${interFlow.sinkExpression}'`,
            };
          }
        }
      }
    }

    return { hasTaintFlow: false, isConstantSink: false };
  }

  /**
   * Scans an entire file for confirmed source-to-sink data flow chains (used by supply chain engine).
   */
  public static findTaintFlowsInFile(filePath: string, fileContent: string): TaintFlowDetail[] {
    const lang = TreeSitterLoader.detectLanguage(filePath);
    if (!lang) return [];

    const parseRes = TreeSitterLoader.parseFile(fileContent, lang);
    if (!parseRes.tree || parseRes.hasError) return [];

    const root = parseRes.tree.rootNode;
    const flows: TaintFlowDetail[] = [];

    // Collect all tainted variables in file scope
    const taintedVars = TaintEngine.collectTaintedVariablesInScope(root, fileContent);
    if (taintedVars.size === 0) return [];

    // Collect all call expressions in file
    function walkCalls(node: Parser.SyntaxNode): void {
      if (
        node.type === 'call_expression' ||
        node.type === 'call' ||
        node.type === 'method_invocation' ||
        node.type === 'invocation_expression'
      ) {
        const funcChild =
          node.childForFieldName('function') ??
          node.childForFieldName('name') ??
          node.namedChild(0);

        if (funcChild) {
          const calleeText = funcChild.text;
          const sinkRule = TaintCatalog.matchSink(calleeText);
          if (sinkRule) {
            const argsNode =
              node.childForFieldName('arguments') ??
              node.childForFieldName('argument_list') ??
              (node.namedChildCount > 1 ? node.namedChild(1) : null);

            if (argsNode) {
              const flow = TaintEngine.checkSinkTaint(
                {
                  node,
                  calleeText,
                  sinkKind: sinkRule.kind,
                  line: node.startPosition.row + 1,
                  argumentsNode: argsNode,
                },
                taintedVars,
                fileContent
              );
              if (flow) {
                flows.push(flow);
              }
            }
          }
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        walkCalls(node.namedChild(i)!);
      }
    }

    walkCalls(root);
    return flows;
  }

  /**
   * Inter-procedural backward taint tracing across functions and files.
   */
  private static traceInterProceduralTaint(ctx: {
    functionName: string;
    paramIndexes: number[];
    currentFilePath: string;
    currentFileContent: string;
    sink: {
      node: Parser.SyntaxNode;
      calleeText: string;
      sinkKind: SinkKind;
      line: number;
    };
    importGraph?: ImportGraph;
    projectRoot?: string;
    maxHops: number;
    currentHop: number;
    visited: Set<string>;
  }): TaintFlowDetail | null {
    if (ctx.currentHop > ctx.maxHops) return null;

    const currentAbsPath = path.resolve(ctx.currentFilePath);
    const lang = TreeSitterLoader.detectLanguage(ctx.currentFilePath);
    if (!lang) return null;

    const parseRes = TreeSitterLoader.parseFile(ctx.currentFileContent, lang);
    if (!parseRes.tree) return null;

    // Extract call graph of current file
    const fileSummary = CallGraphExtractor.extract(parseRes.tree.rootNode, ctx.currentFilePath);

    // Step A: Search for callers in the SAME FILE
    const sameFileCallers = fileSummary.callSites.filter(
      (c) => c.calleeName === ctx.functionName && c.line !== ctx.sink.line
    );

    for (const caller of sameFileCallers) {
      for (const pIdx of ctx.paramIndexes) {
        const arg = caller.arguments.find((a) => a.index === pIdx);
        if (!arg) continue;

        // Check if argument in caller is sanitized
        if (TaintCatalog.isSanitized(arg.text, ctx.sink.sinkKind)) {
          continue;
        }

        // Check if argument is a direct untrusted source
        const directSource = TaintCatalog.matchSource(arg.text);
        if (directSource) {
          const baseRelPath = path.basename(ctx.currentFilePath);
          return {
            sourceType: directSource.kind,
            sourceExpression: arg.text,
            sourceLine: caller.line,
            sinkType: ctx.sink.sinkKind,
            sinkExpression: ctx.sink.node.text,
            sinkLine: ctx.sink.line,
            isExploitable: true,
            taintSteps: [
              {
                variable: arg.text,
                line: caller.line,
                codeSnippet: caller.node.text,
                description: `[Hop ${ctx.currentHop}] Untrusted source '${arg.text}' passed to '${ctx.functionName}()'`,
              },
              {
                variable: ctx.functionName,
                line: ctx.sink.line,
                codeSnippet: ctx.sink.node.text,
                description: `Dangerous sink '${ctx.sink.calleeText}' reached at ${baseRelPath}:${ctx.sink.line}`,
              },
            ],
          };
        }

        // Trace if caller has a local variable that is tainted
        if (caller.enclosingFunctionName) {
          const enclosingFn = fileSummary.functions.get(caller.enclosingFunctionName);
          if (enclosingFn) {
            const taintedInCaller = TaintEngine.collectTaintedVariablesInScope(
              enclosingFn.scopeNode,
              ctx.currentFileContent
            );
            const taintedMatch = Array.from(taintedInCaller.values()).find((t) =>
              new RegExp(`\\b${t.variableName}\\b`).test(arg.text)
            );

            if (taintedMatch) {
              const baseRelPath = path.basename(ctx.currentFilePath);
              return {
                sourceType: taintedMatch.kind,
                sourceExpression: taintedMatch.sourceExpression,
                sourceLine: taintedMatch.sourceLine,
                sinkType: ctx.sink.sinkKind,
                sinkExpression: ctx.sink.node.text,
                sinkLine: ctx.sink.line,
                isExploitable: true,
                taintSteps: [
                  ...taintedMatch.steps,
                  {
                    variable: arg.text,
                    line: caller.line,
                    codeSnippet: caller.node.text,
                    description: `[Hop ${ctx.currentHop}] Propagated taint '${arg.text}' passed to '${ctx.functionName}()'`,
                  },
                  {
                    variable: ctx.functionName,
                    line: ctx.sink.line,
                    codeSnippet: ctx.sink.node.text,
                    description: `Dangerous sink '${ctx.sink.calleeText}' reached at ${baseRelPath}:${ctx.sink.line}`,
                  },
                ],
              };
            }
          }
        }
      }
    }

    // Step B: Search for callers ACROSS FILES (Cross-File Call Graph)
    const importingFiles = TaintEngine.findImportingFiles(
      currentAbsPath,
      ctx.importGraph,
      ctx.projectRoot
    );

    for (const callerFilePath of importingFiles) {
      const visitedKey = `${path.resolve(callerFilePath).toLowerCase().replace(/\\/g, '/')}:${ctx.functionName}`;
      if (ctx.visited.has(visitedKey)) continue;
      ctx.visited.add(visitedKey);

      let callerContent = '';
      try {
        callerContent = fs.readFileSync(callerFilePath, 'utf8');
      } catch {
        continue;
      }

      const callerLang = TreeSitterLoader.detectLanguage(callerFilePath);
      if (!callerLang) continue;

      const callerTree = TreeSitterLoader.parseFile(callerContent, callerLang);
      if (!callerTree.tree) continue;

      const callerSummary = CallGraphExtractor.extract(callerTree.tree.rootNode, callerFilePath);

      // Find call sites calling target function (e.g., 'findUser' or 'userService.findUser')
      const crossCallSites = callerSummary.callSites.filter(
        (c) =>
          c.calleeName === ctx.functionName || c.calleeExpression.endsWith(`.${ctx.functionName}`)
      );

      for (const callSite of crossCallSites) {
        for (const pIdx of ctx.paramIndexes) {
          const arg = callSite.arguments.find((a) => a.index === pIdx);
          if (!arg) continue;

          if (TaintCatalog.isSanitized(arg.text, ctx.sink.sinkKind)) {
            continue;
          }

          const callerRelPath = path.basename(callerFilePath);
          const sinkRelPath = path.basename(ctx.currentFilePath);

          // 1. Check if argument in caller is directly an untrusted source
          const directSource = TaintCatalog.matchSource(arg.text);
          if (directSource) {
            return {
              sourceType: directSource.kind,
              sourceExpression: arg.text,
              sourceLine: callSite.line,
              sinkType: ctx.sink.sinkKind,
              sinkExpression: ctx.sink.node.text,
              sinkLine: ctx.sink.line,
              isExploitable: true,
              taintSteps: [
                {
                  variable: arg.text,
                  line: callSite.line,
                  codeSnippet: callSite.node.text,
                  description: `[Cross-File Hop ${ctx.currentHop}] Untrusted source '${arg.text}' in ${callerRelPath}:${callSite.line} passed to '${ctx.functionName}()'`,
                },
                {
                  variable: ctx.functionName,
                  line: ctx.sink.line,
                  codeSnippet: ctx.sink.node.text,
                  description: `Dangerous sink '${ctx.sink.calleeText}' reached at ${sinkRelPath}:${ctx.sink.line}`,
                },
              ],
            };
          }

          // 2. Check if argument in caller references a local tainted variable
          if (callSite.enclosingFunctionName) {
            const enclosingFn = callerSummary.functions.get(callSite.enclosingFunctionName);
            if (enclosingFn) {
              const taintedInCaller = TaintEngine.collectTaintedVariablesInScope(
                enclosingFn.scopeNode,
                callerContent
              );
              const taintedMatch = Array.from(taintedInCaller.values()).find((t) =>
                new RegExp(`\\b${t.variableName}\\b`).test(arg.text)
              );

              if (taintedMatch) {
                return {
                  sourceType: taintedMatch.kind,
                  sourceExpression: taintedMatch.sourceExpression,
                  sourceLine: taintedMatch.sourceLine,
                  sinkType: ctx.sink.sinkKind,
                  sinkExpression: ctx.sink.node.text,
                  sinkLine: ctx.sink.line,
                  isExploitable: true,
                  taintSteps: [
                    ...taintedMatch.steps.map((s) => ({
                      ...s,
                      description: `[${callerRelPath}] ${s.description}`,
                    })),
                    {
                      variable: arg.text,
                      line: callSite.line,
                      codeSnippet: callSite.node.text,
                      description: `[Cross-File Call at ${callerRelPath}:${callSite.line}] '${arg.text}' passed to '${ctx.functionName}()'`,
                    },
                    {
                      variable: ctx.functionName,
                      line: ctx.sink.line,
                      codeSnippet: ctx.sink.node.text,
                      description: `Dangerous sink '${ctx.sink.calleeText}' reached at ${sinkRelPath}:${ctx.sink.line}`,
                    },
                  ],
                };
              }

              // 3. Recursive backward chaining: If argument in caller is derived from a parameter of caller function!
              const callerFeederParams: FunctionParameter[] = [];
              for (const p of enclosingFn.parameters) {
                const derived = TaintEngine.findDerivedSymbols(
                  enclosingFn.scopeNode,
                  new Set([p.name])
                );
                for (const sym of derived) {
                  if (new RegExp(`\\b${sym}\\b`).test(arg.text)) {
                    callerFeederParams.push(p);
                    break;
                  }
                }
              }

              if (callerFeederParams.length > 0) {
                const upperFlow = TaintEngine.traceInterProceduralTaint({
                  functionName: enclosingFn.name,
                  paramIndexes: callerFeederParams.map((p) => p.index),
                  currentFilePath: callerFilePath,
                  currentFileContent: callerContent,
                  sink: ctx.sink,
                  importGraph: ctx.importGraph,
                  projectRoot: ctx.projectRoot,
                  maxHops: ctx.maxHops,
                  currentHop: ctx.currentHop + 1,
                  visited: ctx.visited,
                });

                if (upperFlow) {
                  return {
                    ...upperFlow,
                    taintSteps: [
                      ...upperFlow.taintSteps,
                      {
                        variable: arg.text,
                        line: callSite.line,
                        codeSnippet: callSite.node.text,
                        description: `[Cross-File Propagation] '${arg.text}' passed to '${ctx.functionName}()'`,
                      },
                    ],
                  };
                }
              }
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Normalizes and compares file paths cross-platform.
   */
  public static pathsEqual(p1: string, p2: string): boolean {
    const norm1 = path.resolve(p1).toLowerCase().replace(/\\/g, '/');
    const norm2 = path.resolve(p2).toLowerCase().replace(/\\/g, '/');
    if (norm1 === norm2) return true;
    const strip1 = norm1.replace(/\.[^/.]+$/, '');
    const strip2 = norm2.replace(/\.[^/.]+$/, '');
    return strip1 === strip2;
  }

  /**
   * Resolves files that import the target file using ImportGraph or filesystem scanning.
   */
  private static findImportingFiles(
    targetAbsPath: string,
    importGraph?: ImportGraph,
    projectRoot?: string
  ): string[] {
    const importers: string[] = [];
    const seen = new Set<string>();

    function addImporter(filePath: string): void {
      const norm = path.resolve(filePath).toLowerCase().replace(/\\/g, '/');
      if (!seen.has(norm)) {
        seen.add(norm);
        importers.push(filePath);
      }
    }

    if (importGraph) {
      for (const [absPath, node] of importGraph.files.entries()) {
        for (const dep of node.localDependencies) {
          if (TaintEngine.pathsEqual(dep, targetAbsPath)) {
            addImporter(absPath);
            break;
          }
        }
      }
      if (importers.length > 0) {
        return importers;
      }
    }

    const searchRoot = projectRoot ?? path.dirname(targetAbsPath);
    if (searchRoot && fs.existsSync(searchRoot)) {
      const targetBase = path.basename(targetAbsPath, path.extname(targetAbsPath));
      // Lightweight search for candidate files importing target basename
      function scanDir(dir: string, depth = 0): void {
        if (depth > 6) return;
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const ent of entries) {
            if (ent.name === 'node_modules' || ent.name === '.git' || ent.name === 'dist') {
              continue;
            }
            const fullPath = path.join(dir, ent.name);
            if (ent.isDirectory()) {
              scanDir(fullPath, depth + 1);
            } else if (
              !TaintEngine.pathsEqual(fullPath, targetAbsPath) &&
              /\.(ts|js|mjs|cjs|py|go|java|cs)$/.test(ent.name)
            ) {
              try {
                const txt = fs.readFileSync(fullPath, 'utf8');
                if (txt.includes(targetBase)) {
                  addImporter(fullPath);
                }
              } catch {
                // Ignore read error
              }
            }
          }
        } catch {
          // Ignore directory read error
        }
      }

      scanDir(path.resolve(searchRoot));
    }

    return importers;
  }

  /**
   * Tracks local variables in scope that are derived from a set of starting symbols.
   */
  private static findDerivedSymbols(
    scopeNode: Parser.SyntaxNode,
    baseSymbols: Set<string>
  ): Set<string> {
    const derived = new Set<string>(baseSymbols);

    function checkMatch(rhsText: string, lhsName: string): void {
      if (TaintCatalog.isSanitized(rhsText)) {
        return;
      }
      for (const sym of derived) {
        if (new RegExp(`\\b${sym}\\b`).test(rhsText)) {
          derived.add(lhsName);
          break;
        }
      }
    }

    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'variable_declarator' || node.type === 'var_spec') {
        const nameNode = node.childForFieldName('name') ?? node.namedChild(0);
        const valNode = node.childForFieldName('value') ?? node.namedChild(1);
        if (
          nameNode &&
          valNode &&
          (nameNode.type === 'identifier' || nameNode.type === 'variable_name')
        ) {
          checkMatch(valNode.text, nameNode.text);
        }
      } else if (
        node.type === 'assignment_expression' ||
        node.type === 'assignment' ||
        node.type === 'augmented_assignment' ||
        node.type === 'short_var_declaration' ||
        node.type === 'assignment_statement'
      ) {
        const leftNode = node.childForFieldName('left') ?? node.namedChild(0);
        const rightNode = node.childForFieldName('right') ?? node.namedChild(1);
        if (
          leftNode &&
          rightNode &&
          (leftNode.type === 'identifier' || leftNode.type === 'variable_name')
        ) {
          checkMatch(rightNode.text, leftNode.text);
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        walk(node.namedChild(i)!);
      }
    }

    walk(scopeNode);
    return derived;
  }

  /**
   * Identifies function parameters that feed into the candidate sink arguments.
   */
  private static findParameterFeeders(
    scopeNode: Parser.SyntaxNode,
    sink: { argumentsNode: Parser.SyntaxNode | null }
  ): FunctionParameter[] {
    if (!sink.argumentsNode) return [];

    const paramsNode =
      scopeNode.childForFieldName('parameters') ?? scopeNode.childForFieldName('parameter_list');

    if (!paramsNode) return [];

    const declaredParams: FunctionParameter[] = [];
    let idx = 0;
    for (let i = 0; i < paramsNode.namedChildCount; i++) {
      const child = paramsNode.namedChild(i)!;
      let pName: string | undefined;

      if (child.type === 'identifier') {
        pName = child.text;
      } else {
        const idChild =
          child.childForFieldName('name') ??
          child.childForFieldName('pattern') ??
          child.namedChild(0);
        if (
          idChild &&
          (idChild.type === 'identifier' || idChild.type === 'variable_declarator_id')
        ) {
          pName = idChild.text;
        }
      }

      if (pName) {
        declaredParams.push({ name: pName, index: idx++ });
      }
    }

    const argsText = sink.argumentsNode.text;
    const feeders: FunctionParameter[] = [];

    for (const p of declaredParams) {
      const derived = TaintEngine.findDerivedSymbols(scopeNode, new Set([p.name]));
      for (const sym of derived) {
        if (new RegExp(`\\b${sym}\\b`).test(argsText)) {
          feeders.push(p);
          break;
        }
      }
    }

    return feeders;
  }

  /**
   * Extracts function name from a scope node.
   */
  private static extractFunctionName(scopeNode: Parser.SyntaxNode): string | null {
    const nameChild = scopeNode.childForFieldName('name') ?? scopeNode.namedChild(0);

    if (
      nameChild &&
      (nameChild.type === 'identifier' ||
        nameChild.type === 'property_identifier' ||
        nameChild.type === 'field_identifier')
    ) {
      return nameChild.text;
    }

    // Check if assigned in parent variable_declarator: const foo = () => ...
    const parent = scopeNode.parent;
    if (parent && parent.type === 'variable_declarator') {
      const varName = parent.childForFieldName('name');
      if (varName && varName.type === 'identifier') {
        return varName.text;
      }
    }

    return null;
  }

  /**
   * Checks if SQL query uses safe parameter placeholders ($1, ?, :param).
   */
  private static isSafeParameterizedQuery(sink: {
    calleeText: string;
    argumentsNode: Parser.SyntaxNode | null;
  }): boolean {
    if (!sink.argumentsNode) return false;
    if (!/\b(?:query|execute|raw|\$queryRaw)\b/i.test(sink.calleeText)) return false;

    const text = sink.argumentsNode.text.trim();
    // Checks for db.query(firstArg, [secondArg])
    const match = text.match(
      /^\s*\((['"`][^'"`]+['"`])\s*,\s*(\[[^\]]+\]|\{[^}]+\}|\([^)]+\))\s*\)/s
    );
    if (match) {
      const queryStr = match[1]!;
      // Parameter placeholders in query string
      if (/\$[0-9]+|\?|:[a-zA-Z0-9_]+|@[a-zA-Z0-9_]+|%s/.test(queryStr)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Finds the deepest AST node spanning the specified line number.
   */
  private static findNodeAtLine(
    root: Parser.SyntaxNode,
    targetLine: number
  ): Parser.SyntaxNode | null {
    let closest: Parser.SyntaxNode | null = null;

    function walk(node: Parser.SyntaxNode): void {
      const startLine = node.startPosition.row + 1;
      const endLine = node.endPosition.row + 1;

      if (targetLine >= startLine && targetLine <= endLine) {
        closest = node;
        for (let i = 0; i < node.namedChildCount; i++) {
          walk(node.namedChild(i)!);
        }
      }
    }

    walk(root);
    return closest;
  }

  /**
   * Ascends AST to find the enclosing function/method/block or root program.
   */
  private static findEnclosingScope(node: Parser.SyntaxNode): Parser.SyntaxNode {
    const scopeTypes = new Set([
      'function_declaration',
      'function_definition',
      'arrow_function',
      'function_expression',
      'method_definition',
      'method_declaration',
      'local_function_statement',
      'program',
      'source_file',
      'compilation_unit',
      'module',
    ]);

    let curr: Parser.SyntaxNode | null = node;
    while (curr) {
      if (scopeTypes.has(curr.type)) {
        return curr;
      }
      curr = curr.parent;
    }

    return node;
  }

  /**
   * Discovers dangerous sink calls within scope around the target line.
   */
  private static findSinksInScope(
    scope: Parser.SyntaxNode,
    targetLine: number
  ): Array<{
    node: Parser.SyntaxNode;
    calleeText: string;
    sinkKind: SinkKind;
    line: number;
    argumentsNode: Parser.SyntaxNode | null;
  }> {
    const sinks: Array<{
      node: Parser.SyntaxNode;
      calleeText: string;
      sinkKind: SinkKind;
      line: number;
      argumentsNode: Parser.SyntaxNode | null;
    }> = [];

    function checkCall(node: Parser.SyntaxNode): void {
      if (
        node.type === 'call_expression' ||
        node.type === 'call' ||
        node.type === 'method_invocation' ||
        node.type === 'invocation_expression'
      ) {
        const line = node.startPosition.row + 1;
        if (Math.abs(line - targetLine) <= 5) {
          const funcChild =
            node.childForFieldName('function') ??
            node.childForFieldName('name') ??
            node.namedChild(0);

          if (funcChild) {
            const calleeText = funcChild.text;
            const sinkRule = TaintCatalog.matchSink(calleeText);
            if (sinkRule) {
              const argsNode =
                node.childForFieldName('arguments') ??
                node.childForFieldName('argument_list') ??
                (node.namedChildCount > 1 ? node.namedChild(1) : null);

              sinks.push({
                node,
                calleeText,
                sinkKind: sinkRule.kind,
                line,
                argumentsNode: argsNode,
              });
            }
          }
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        checkCall(node.namedChild(i)!);
      }
    }

    checkCall(scope);
    return sinks;
  }

  /**
   * Evaluates if argument list contains only compile-time literals without variable identifiers.
   */
  private static isAllArgumentsConstant(argsNode: Parser.SyntaxNode | null): boolean {
    if (!argsNode) return false;
    const text = argsNode.text.trim();
    if (text === '()' || text === '') return true;

    let hasIdentifier = false;
    let hasStringOrNumber = false;

    function walk(node: Parser.SyntaxNode): void {
      if (
        node.type === 'identifier' ||
        node.type === 'variable_name' ||
        node.type === 'property_identifier'
      ) {
        hasIdentifier = true;
      }
      if (
        node.type === 'string' ||
        node.type === 'string_literal' ||
        node.type === 'number' ||
        node.type === 'integer' ||
        node.type === 'true' ||
        node.type === 'false'
      ) {
        hasStringOrNumber = true;
      }
      for (let i = 0; i < node.namedChildCount; i++) {
        walk(node.namedChild(i)!);
      }
    }

    walk(argsNode);
    return hasStringOrNumber && !hasIdentifier;
  }

  /**
   * Tracks variable assignments in scope and propagates taint tags.
   */
  private static collectTaintedVariablesInScope(
    scope: Parser.SyntaxNode,
    _content: string
  ): Map<string, TaintedVarInfo> {
    const tainted = new Map<string, TaintedVarInfo>();

    function inspectAssignment(targetName: string, exprNode: Parser.SyntaxNode): void {
      const exprText = exprNode.text;
      const line = exprNode.startPosition.row + 1;

      // Check if expression is sanitized first (e.g. parseInt(req.query.id))
      if (TaintCatalog.isSanitized(exprText, 'SQL_QUERY')) {
        return;
      }

      // 1. Direct Source Match (e.g. const x = req.query.id)
      const sourceMatch = TaintCatalog.matchSource(exprText);
      if (sourceMatch) {
        tainted.set(targetName, {
          variableName: targetName,
          sourceExpression: exprText,
          sourceLine: line,
          kind: sourceMatch.kind,
          steps: [
            {
              variable: targetName,
              line,
              codeSnippet: `${targetName} = ${exprText}`,
              description: `Taint origin: ${sourceMatch.description}`,
            },
          ],
        });
        return;
      }

      // 2. Taint Propagation from existing tainted variable
      for (const [taintedName, info] of tainted.entries()) {
        const idRegex = new RegExp(`\\b${taintedName}\\b`);
        if (idRegex.test(exprText)) {
          if (TaintCatalog.isSanitized(exprText, 'SQL_QUERY')) {
            continue;
          }

          const newSteps = [
            ...info.steps,
            {
              variable: targetName,
              line,
              codeSnippet: `${targetName} = ${exprText}`,
              description: `Taint propagated via assignment referencing '${taintedName}'`,
            },
          ];

          tainted.set(targetName, {
            variableName: targetName,
            sourceExpression: info.sourceExpression,
            sourceLine: info.sourceLine,
            kind: info.kind,
            steps: newSteps,
          });
          break;
        }
      }
    }

    function walk(node: Parser.SyntaxNode): void {
      if (node.type === 'variable_declarator') {
        const nameNode = node.childForFieldName('name');
        const valNode = node.childForFieldName('value');
        if (nameNode && valNode) {
          if (nameNode.type === 'identifier') {
            inspectAssignment(nameNode.text, valNode);
          } else if (nameNode.type === 'object_pattern') {
            for (let i = 0; i < nameNode.namedChildCount; i++) {
              const prop = nameNode.namedChild(i);
              if (prop && prop.type === 'shorthand_property_identifier_pattern') {
                inspectAssignment(prop.text, valNode);
              }
            }
          }
        }
      }

      if (
        node.type === 'assignment' ||
        node.type === 'assignment_expression' ||
        node.type === 'short_var_declaration'
      ) {
        const leftNode = node.childForFieldName('left') ?? node.namedChild(0);
        const rightNode = node.childForFieldName('right') ?? node.namedChild(1);
        if (leftNode && rightNode) {
          inspectAssignment(leftNode.text, rightNode);
        }
      }

      for (let i = 0; i < node.namedChildCount; i++) {
        walk(node.namedChild(i)!);
      }
    }

    walk(scope);
    return tainted;
  }

  /**
   * Checks if candidate sink receives an untrusted source directly or via propagated variable.
   */
  private static checkSinkTaint(
    sink: {
      node: Parser.SyntaxNode;
      calleeText: string;
      sinkKind: SinkKind;
      line: number;
      argumentsNode: Parser.SyntaxNode | null;
    },
    taintedVars: Map<string, TaintedVarInfo>,
    _content: string
  ): TaintFlowDetail | null {
    if (!sink.argumentsNode) return null;
    const argsText = sink.argumentsNode.text;

    // 1. Direct Source passed directly to sink (e.g. exec(req.query.cmd))
    const directSource = TaintCatalog.matchSource(argsText);
    if (directSource) {
      return {
        sourceType: directSource.kind,
        sourceExpression: argsText,
        sourceLine: sink.line,
        sinkType: sink.sinkKind,
        sinkExpression: sink.node.text,
        sinkLine: sink.line,
        taintSteps: [
          {
            variable: argsText,
            line: sink.line,
            codeSnippet: sink.node.text,
            description: `Direct source argument '${argsText}' passed to sink '${sink.calleeText}'`,
          },
        ],
        isExploitable: true,
      };
    }

    // 2. Propagated Tainted Variable passed to sink
    for (const [varName, info] of taintedVars.entries()) {
      const varRegex = new RegExp(`\\b${varName}\\b`);
      if (varRegex.test(argsText)) {
        if (TaintCatalog.isSanitized(argsText, sink.sinkKind)) {
          continue;
        }

        const steps = [
          ...info.steps,
          {
            variable: varName,
            line: sink.line,
            codeSnippet: sink.node.text,
            description: `Tainted variable '${varName}' passed to dangerous sink '${sink.calleeText}'`,
          },
        ];

        return {
          sourceType: info.kind,
          sourceExpression: info.sourceExpression,
          sourceLine: info.sourceLine,
          sinkType: sink.sinkKind,
          sinkExpression: sink.node.text,
          sinkLine: sink.line,
          taintSteps: steps,
          isExploitable: true,
        };
      }
    }

    return null;
  }
}
