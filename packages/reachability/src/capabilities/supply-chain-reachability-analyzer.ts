import path from 'node:path';
import type { NormalizedFinding, ReachabilityDetail, ScReachability } from '@secureship/contracts';
import type { ImportGraph } from '../graph/import-graph.js';
import type { LockfileGraph } from '../lockfile/lockfile-tree-parser.js';

const NON_REACHABILITY_GATED_PREFIXES = ['SC-INSTALL-', 'SC-UNI-', 'SC-META-003', 'SC-GOV-'];

export interface SupplyChainReachabilityResult {
  detail: ReachabilityDetail;
  scReachability: ScReachability;
  isP1Candidate: boolean;
}

export class SupplyChainReachabilityAnalyzer {
  /**
   * Evaluates reachability for a supply-chain finding.
   * Gated: SC-CAP-*.
   * Non-gated exceptions: SC-INSTALL-*, SC-UNI-*, SC-META-003, SC-GOV-*.
   */
  public static analyze(
    finding: NormalizedFinding,
    graph: ImportGraph,
    lockfileGraph: LockfileGraph | null,
    projectRoot: string
  ): SupplyChainReachabilityResult {
    const ruleId = finding.ruleId;

    // Check if non-reachability gated rule (Exception)
    const isNonGated = NON_REACHABILITY_GATED_PREFIXES.some((prefix) => ruleId.startsWith(prefix));

    if (isNonGated) {
      return {
        scReachability: 'NOT_APPLICABLE',
        isP1Candidate: false,
        detail: {
          verdict: 'UNKNOWN',
          analysisConfidence: 'LOW',
          evidence: {
            kind: 'NOT_APPLICABLE',
            notes: `${ruleId} executes pre-runtime or is un-gated; reachability analysis is not applicable`,
          },
          limitations: [
            'Supply-chain finding is install-time, governance, or file-level unicode; never downgraded by reachability.',
          ],
        },
      };
    }

    const packageName = finding.package?.name?.trim();
    if (!packageName) {
      return {
        scReachability: 'UNKNOWN',
        isP1Candidate: false,
        detail: {
          verdict: 'UNKNOWN',
          analysisConfidence: 'LOW',
          evidence: {
            kind: 'UNMAPPED_PACKAGE',
            notes: 'Finding does not specify a package name',
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        },
      };
    }

    const normPkg = packageName.toLowerCase();

    // 1. Direct Dependency Import Check
    const isDirectlyImported =
      graph.importedPackages.has(packageName) || graph.importedPackages.has(normPkg);

    if (isDirectlyImported) {
      const importingFiles =
        graph.importedPackages.get(packageName) ?? graph.importedPackages.get(normPkg);
      const firstFile = importingFiles ? Array.from(importingFiles)[0] : undefined;
      const relImportFile = firstFile
        ? path.relative(projectRoot, firstFile).replace(/\\/g, '/')
        : 'entrypoint';

      // Dangerous capability combination or critical capability reachable from entrypoint
      const isDangerousCombo =
        ruleId === 'SC-CAP-100' ||
        ruleId === 'SC-CAP-101' ||
        ruleId === 'SC-CAP-102' ||
        ruleId === 'SC-CAP-103' ||
        ruleId === 'SC-CAP-104' ||
        finding.severity === 'CRITICAL';

      return {
        scReachability: 'REACHABLE',
        isP1Candidate: isDangerousCombo,
        detail: {
          verdict: 'REACHABLE_IMPORT',
          analysisConfidence: 'HIGH',
          evidence: {
            kind: 'PACKAGE_IMPORTED',
            chain: [relImportFile, packageName],
            via: [packageName],
            notes: `Directly imported in production scope by ${relImportFile}`,
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        },
      };
    }

    // 2. Transitive Dependency Trace via Lockfile Graph
    if (lockfileGraph) {
      const prodImportedSet = new Set<string>();
      for (const [pkg, fileSet] of graph.importedPackages.entries()) {
        if (fileSet.size > 0) {
          prodImportedSet.add(pkg.toLowerCase());
        }
      }

      // Check if reachable via any production-imported package
      const node = lockfileGraph.nodes.get(normPkg) ?? lockfileGraph.nodes.get(packageName);
      if (node) {
        // Trace upstream to see if reachable
        for (const rootPkg of prodImportedSet) {
          if (rootPkg === normPkg) continue;
          const rootNode = lockfileGraph.nodes.get(rootPkg);
          if (rootNode?.dependencies?.includes(normPkg)) {
            const isDangerousCombo =
              ruleId === 'SC-CAP-100' ||
              ruleId === 'SC-CAP-101' ||
              ruleId === 'SC-CAP-102' ||
              ruleId === 'SC-CAP-103' ||
              ruleId === 'SC-CAP-104' ||
              finding.severity === 'CRITICAL';

            return {
              scReachability: 'REACHABLE',
              isP1Candidate: isDangerousCombo,
              detail: {
                verdict: 'REACHABLE_IMPORT',
                analysisConfidence: 'MEDIUM',
                evidence: {
                  kind: 'TRANSITIVE_VIA',
                  via: [rootPkg, packageName],
                  notes: `Transitive dependency pulled into production scope via ${rootPkg}`,
                },
                limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
              },
            };
          }
        }
      }

      // Present in dependency tree but not imported in production
      return {
        scReachability: 'DEP_REACHABLE_ONLY',
        isP1Candidate: false,
        detail: {
          verdict: 'UNREACHABLE',
          analysisConfidence: 'HIGH',
          evidence: {
            kind: 'NOT_IMPORTED',
            notes: `Package '${packageName}' is present in dependency tree but not imported or called from production entrypoints`,
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        },
      };
    }

    // 3. Fallback when lockfileGraph is unavailable
    if (graph.entrypoints.length === 0) {
      return {
        scReachability: 'UNKNOWN',
        isP1Candidate: false,
        detail: {
          verdict: 'UNKNOWN',
          analysisConfidence: 'LOW',
          evidence: {
            kind: 'NO_ENTRYPOINT',
            notes: 'No production entrypoint could be detected to evaluate reachability',
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        },
      };
    }

    return {
      scReachability: 'UNKNOWN',
      isP1Candidate: false,
      detail: {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'NO_LOCKFILE_TREE',
          notes: 'Dependency lockfile tree unavailable to trace reachability',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      },
    };
  }
}
