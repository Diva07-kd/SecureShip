import fs from 'node:fs';
import path from 'node:path';
import type { NormalizedFinding, ReachabilityDetail } from '@secureship/contracts';
import type { ImportGraph } from '../graph/import-graph.js';
import { TaintEngine } from '../taint/taint-engine.js';

export class SastReachabilityAnalyzer {
  /**
   * Evaluates reachability for a SAST finding at the file level and AST source-to-sink taint level.
   */
  public static analyze(
    finding: NormalizedFinding,
    graph: ImportGraph,
    projectRoot: string
  ): ReachabilityDetail {
    const rawFilePath = finding.location.filePath;
    const absPath = path.isAbsolute(rawFilePath)
      ? path.resolve(rawFilePath)
      : path.resolve(projectRoot, rawFilePath);

    // Gate 1 Preservation: Gate 1 TEST_OR_MOCK verdict (UNREACHABLE) from Phase 1 is never overwritten by weaker Gate 2
    if (finding.scopeTag === 'TEST_OR_MOCK' || finding.scopeTag === 'EXAMPLE') {
      return {
        verdict: 'UNREACHABLE',
        analysisConfidence: 'HIGH',
        evidence: {
          kind: 'DEV_ONLY',
          chain: [rawFilePath],
          notes: `Preserved Gate 1 scope classification: ${finding.scopeTag}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    const fileNode = graph.files.get(absPath);

    if (!fileNode) {
      // Check if it's an unsupported language or external file
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'UNSUPPORTED_LANGUAGE',
          notes: `File '${rawFilePath}' was not indexed in the production import graph`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    if (fileNode.hasParseError) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'PARSE_FAILURE',
          notes: fileNode.parseErrorReason ?? 'File failed syntax parsing',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    if (graph.entrypoints.length === 0) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'NO_ENTRYPOINT',
          notes: 'No production entrypoint could be detected; cannot assert unreachability',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    if (fileNode.isReachable) {
      // Perform AST Source-to-Sink Taint Analysis on finding location
      let fileContent = '';
      try {
        if (fs.existsSync(absPath)) {
          fileContent = fs.readFileSync(absPath, 'utf8');
        }
      } catch {
        // Fallback to import-level if file unreadable
      }

      if (fileContent) {
        const taintResult = TaintEngine.analyze({
          filePath: absPath,
          fileContent,
          findingLine: finding.location.startLine,
          findingEndLine: finding.location.endLine,
          ruleId: finding.ruleId,
          category: finding.category,
          importGraph: graph,
          projectRoot,
        });

        // 1. Confirmed Taint Flow (Exploitable Source reaches Sink)
        if (taintResult.hasTaintFlow && taintResult.taintDetail) {
          const taintStepsChain = [
            ...fileNode.reachabilityChain,
            `${fileNode.relativePath}:${taintResult.taintDetail.sourceLine} (source)`,
            `${fileNode.relativePath}:${taintResult.taintDetail.sinkLine} (sink)`,
          ].slice(0, 10);

          return {
            verdict: 'REACHABLE_CALL_PATH',
            analysisConfidence: 'HIGH',
            evidence: {
              kind: 'TAINT_FLOW',
              chain: taintStepsChain,
              notes:
                taintResult.notes ??
                `Confirmed exploit taint flow: untrusted source reaches dangerous sink at line ${taintResult.taintDetail.sinkLine}`,
              taintFlow: taintResult.taintDetail,
            },
            limitations: [
              'Source-to-sink AST data-flow analysis confirmed. Validated untrusted user input reaches dangerous sink.',
            ],
          };
        }

        // 2. Constant Sink or Sanitized Sink (Safe, no user taint)
        if (taintResult.isConstantSink || taintResult.isSanitized) {
          return {
            verdict: 'REACHABLE_IMPORT',
            analysisConfidence: 'HIGH',
            evidence: {
              kind: 'IMPORT_CHAIN',
              chain: fileNode.reachabilityChain,
              notes:
                taintResult.notes ??
                'Sink call receives compile-time static constant or sanitized arguments; no user taint detected.',
            },
            limitations: [
              'Import-level analysis and AST data-flow inspection confirmed sink uses safe / sanitized arguments.',
            ],
          };
        }
      }

      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'HIGH',
        evidence: {
          kind: 'IMPORT_CHAIN',
          chain: fileNode.reachabilityChain,
          notes: `Reachable from production entrypoint: ${fileNode.reachabilityChain.join(' -> ')}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Dead file: Not reachable from entrypoint.
    // Confidence is capped at LOW per specifications (frameworks load files implicitly),
    // so dead files are NEVER auto-suppressed in Gate 2.
    return {
      verdict: 'UNREACHABLE',
      analysisConfidence: 'LOW',
      evidence: {
        kind: 'DEAD_FILE',
        chain: [fileNode.relativePath],
        notes:
          'File is not in the transitive import graph from any discovered production entrypoint',
      },
      limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
    };
  }
}
