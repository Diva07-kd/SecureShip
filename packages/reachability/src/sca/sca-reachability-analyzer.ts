import fs from 'node:fs';
import path from 'node:path';
import type { NormalizedFinding, ReachabilityDetail, Confidence } from '@secureship/contracts';
import type { ImportGraph } from '../graph/import-graph.js';
import { LockfileTreeParser, type LockfileGraph } from '../lockfile/lockfile-tree-parser.js';
import { ReferenceScanner } from '../reference/reference-scanner.js';
import { PythonPackageMap } from '../python/package-map.js';
import { extractVulnerableSymbols } from '../symbols/candidate-extractor.js';
import { SymbolDatasetLoader } from '../symbols/dataset-loader.js';
import type { VulnerableSymbolDataset } from '../symbols/vulnerable-symbol.schema.js';
import { CallPathProver } from '../symbol-usage/call-path-prover.js';
import { EntrypointDetector } from '../entrypoints/entrypoint-detector.js';
import type { SymbolUsageFact, EscapeFact } from '../symbol-usage/symbol-usage.types.js';

export interface ScaReachabilityOptions {
  functionLevel?: boolean;
  symbolDataset?: VulnerableSymbolDataset | null;
  datasetIntegrityVerified?: boolean;
}

export class ScaReachabilityAnalyzer {
  /**
   * Evaluates reachability for an SCA finding against the whole-repository import graph and lockfile tree.
   */
  public static analyze(
    finding: NormalizedFinding,
    graph: ImportGraph,
    lockfileGraph: LockfileGraph | null,
    projectRoot: string,
    options?: ScaReachabilityOptions
  ): ReachabilityDetail {
    const rawPackageName = finding.package?.name;
    if (!rawPackageName) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'UNMAPPED_PACKAGE',
          notes: 'Finding does not specify a package name',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    const packageName = rawPackageName.trim();
    const normPkg = packageName.toLowerCase();
    const stats = graph.computeStats();

    // Collect module names to search for this package
    const candidateModuleNames: string[] = [packageName, normPkg];
    const pyMapped = PythonPackageMap.getImportableModuleNames(packageName, projectRoot);
    if (pyMapped.modules.length > 0) {
      candidateModuleNames.push(...pyMapped.modules);
    }

    // 1. Direct Dependency Production Import Check
    const isDirectlyImportedInProd = candidateModuleNames.some(
      (m) => graph.importedPackages.has(m) || graph.importedPackages.has(m.toLowerCase())
    );

    if (isDirectlyImportedInProd) {
      // Find sample importing file for evidence
      let importingFile: string | undefined;
      for (const m of candidateModuleNames) {
        const files = graph.importedPackages.get(m) ?? graph.importedPackages.get(m.toLowerCase());
        if (files && files.size > 0) {
          importingFile = Array.from(files)[0];
          break;
        }
      }

      // Check if it was imported strictly as type-only (Amendment A4)
      const isOnlyTypeOnly =
        graph.typeOnlyPackages.has(normPkg) &&
        !Array.from(graph.files.values()).some(
          (f) =>
            f.isReachable &&
            f.packageDependencies.has(normPkg) &&
            !f.packageDependencies.get(normPkg)!.isTypeOnly
        );

      if (isOnlyTypeOnly) {
        return {
          verdict: 'UNREACHABLE',
          analysisConfidence: 'MEDIUM', // Amendment A4: type-only never HIGH
          evidence: {
            kind: 'DEV_ONLY',
            chain: importingFile ? [importingFile, packageName] : [packageName],
            notes:
              'Package is imported strictly via TypeScript type-only imports and omitted from runtime bundle',
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        };
      }

      const chain = importingFile
        ? [graph.files.get(importingFile)?.relativePath ?? importingFile, packageName]
        : [packageName];

      const eco = finding.package?.ecosystem?.toLowerCase();
      const isEligibleEco = eco === 'npm' || eco === 'pypi' || eco === 'pip';
      const isFunctionLevelEnabled = options?.functionLevel !== false;

      if (isEligibleEco && isFunctionLevelEnabled) {
        return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
          finding,
          packageName,
          normPkg,
          candidateModuleNames,
          chain,
          graph,
          lockfileGraph,
          projectRoot,
          options
        );
      }

      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'HIGH',
        evidence: {
          kind: 'PACKAGE_IMPORTED',
          chain,
          via: [packageName],
          notes: `Directly imported in production scope by ${chain[0]}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Python packages without verified static mapping or .venv metadata degrade to UNKNOWN
    const isPythonEco =
      finding.package?.ecosystem?.toLowerCase() === 'pypi' ||
      finding.package?.ecosystem?.toLowerCase() === 'pip';
    if (isPythonEco && pyMapped.source !== 'STATIC' && pyMapped.source !== 'VENV') {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'UNMAPPED_PACKAGE',
          notes: `Python package '${packageName}' has no known top-level module mapping or .venv metadata`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // 2. Transitive Dependency Analysis via Lockfile Tree (Amendment A1)
    if (!lockfileGraph) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'NO_LOCKFILE_TREE',
          notes:
            'No supported dependency tree lockfile (package-lock.json v2/v3, pnpm-lock.yaml v6/v9, poetry.lock, Pipfile.lock) found to evaluate transitive reachability',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Trace if it is a transitive dependency of ANY production-reachable package
    const prodImportedSet = new Set<string>();
    for (const [pkg, fileSet] of graph.importedPackages.entries()) {
      if (fileSet.size > 0) {
        prodImportedSet.add(pkg.toLowerCase());
      }
    }

    const transitiveRes = LockfileTreeParser.traceTransitiveVia(
      lockfileGraph,
      packageName,
      prodImportedSet
    );

    if (transitiveRes.isTransitiveVia) {
      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'MEDIUM',
        evidence: {
          kind: 'TRANSITIVE_VIA',
          via: transitiveRes.viaChain,
          notes: `Transitive dependency pulled into production runtime via: ${transitiveRes.viaChain.join(' -> ')}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // 3. Dev-Only Dependency Check (Amendment A4)
    const lockNode = lockfileGraph.nodes.get(normPkg) ?? lockfileGraph.nodes.get(packageName);
    const isDeclaredInDev =
      lockfileGraph.directDevDependencies.has(normPkg) ||
      lockfileGraph.directDevDependencies.has(packageName) ||
      lockNode?.isDev === true;

    if (isDeclaredInDev && !lockfileGraph.directProdDependencies.has(normPkg)) {
      // Check if referenced by scripts, configs, or CI per A4
      const refCheck = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames);
      if (refCheck.incompleteScan) {
        return {
          verdict: 'UNKNOWN',
          analysisConfidence: 'LOW',
          evidence: {
            kind: 'CONFIG_REFERENCE',
            notes: `Reference scan incomplete (${refCheck.incompleteReason}); degrading fail-closed to UNKNOWN`,
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        };
      }
      if (refCheck.isReferenced) {
        return {
          verdict: 'UNKNOWN',
          analysisConfidence: 'MEDIUM',
          evidence: {
            kind: 'CONFIG_REFERENCE',
            notes: `DevDependency referenced in repository configuration or scripts at ${refCheck.matchedFile}:${refCheck.matchedLine}`,
          },
          limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
        };
      }

      return {
        verdict: 'UNREACHABLE',
        analysisConfidence: 'MEDIUM', // Amendment A4: dev-only never HIGH
        evidence: {
          kind: 'DEV_ONLY',
          via: [packageName],
          notes: 'Declared strictly in devDependencies and not reachable from production code',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // 4. NOT_IMPORTED Precondition Verification (Amendments A1, A5, A6)
    // All 7 positive evidence conditions must hold for UNREACHABLE with HIGH confidence:

    // Precondition 1: Entrypoints found
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

    // Precondition 2: No parse errors in production scope (Amendment A6)
    if (stats.hasAnyParseErrorInProduction) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'PARSE_FAILURE',
          notes:
            'One or more source files in production scope failed syntax parsing (rootNode.hasError is true)',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Precondition 3: Zero unresolved local imports in production scope (Amendment A6)
    if (stats.hasAnyUnresolvedLocalImportsInProduction) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'DYNAMIC_UNKNOWN',
          notes: 'Production scope contains unresolved local imports or path aliases',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Precondition 4: No dynamic imports in production scope
    if (stats.hasAnyDynamicInProduction) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'DYNAMIC_UNKNOWN',
          notes: `Production scope contains dynamic require/import, eval, or Function invocation (${stats.dynamicFiles.slice(0, 3).join(', ')})`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Precondition 5: Transitive hole check (Amendment A1)
    // Must be declared directly in manifest AND no other installed package depends on it
    const isLeafDirect = LockfileTreeParser.isLeafDirectPackage(lockfileGraph, packageName);
    if (!isLeafDirect) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'NO_LOCKFILE_TREE',
          notes: `Package '${packageName}' is not a direct leaf package or is depended upon by other installed packages`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Precondition 6: If package is imported anywhere in non-production files (e.g. tests), it is NOT "NOT_IMPORTED"
    const importedNonProdFile = Array.from(graph.files.values()).find(
      (f) =>
        !f.isReachable &&
        candidateModuleNames.some(
          (m) => f.packageDependencies.has(m) || f.packageDependencies.has(m.toLowerCase())
        )
    );
    if (importedNonProdFile) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'TEST_ONLY_IMPORT',
          notes: `Package is imported in non-production scope (${importedNonProdFile.relativePath}) but declared in production dependencies`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // Precondition 7: Reference scan across scripts, configs, and string literals (Amendment A5 & Fix C6)
    const refMatch = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames);
    if (refMatch.incompleteScan) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'CONFIG_REFERENCE',
          notes: `Reference scan incomplete (${refMatch.incompleteReason}); cannot prove absence of references`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }
    if (refMatch.isReferenced) {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'MEDIUM',
        evidence: {
          kind: 'CONFIG_REFERENCE',
          notes: `Package name referenced in configuration, script, or string literal at ${refMatch.matchedFile}:${refMatch.matchedLine}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // ALL POSITIVE EVIDENCE CRITERIA MET!
    // Rule C1: In Phase 3, Python SCA findings are NEVER assigned UNREACHABLE with HIGH confidence
    const finalConfidence: Confidence = isPythonEco ? 'MEDIUM' : 'HIGH';

    return {
      verdict: 'UNREACHABLE',
      analysisConfidence: finalConfidence,
      evidence: {
        kind: 'NOT_IMPORTED',
        notes: `Verified positive evidence: declared directly, 0 dependents in lockfile tree, 0 imports across ${stats.reachableFiles} production files, 0 references in configs/scripts`,
      },
      limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
    };
  }

  /**
   * Evaluates function-level reachability refinement for directly imported production dependencies (Rules R1-R5).
   */
  private static analyzeFunctionLevelDirectImport(
    finding: NormalizedFinding,
    packageName: string,
    normPkg: string,
    candidateModuleNames: string[],
    chain: string[],
    graph: ImportGraph,
    lockfileGraph: LockfileGraph | null,
    projectRoot: string,
    options?: ScaReachabilityOptions
  ): ReachabilityDetail {
    // R1. Candidates = extractVulnerableSymbols(finding). None => return existing result with note SYMBOL_DATA_UNAVAILABLE
    const candidates = extractVulnerableSymbols(finding, options?.symbolDataset);
    if (candidates.length === 0) {
      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'HIGH',
        evidence: {
          kind: 'PACKAGE_IMPORTED',
          chain,
          via: [packageName],
          notes: `Directly imported in production scope by ${chain[0]}; symbol data unavailable`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    const bestCandidate = candidates[0]!;
    const bestSource = bestCandidate.source;
    const datasetEntry = candidates.find((c) => c.entry)?.entry;

    // R2. Aggregate usage over all non-test source files. If any file is usageIncomplete => no pruning
    const nonTestFiles = Array.from(graph.files.values()).filter(
      (f) => !EntrypointDetector.isTestOrMockFile(f.relativePath)
    );

    const incompleteFile = nonTestFiles.find(
      (f) => f.symbolUsage?.usageIncomplete === true && !f.hasParseError
    );
    if (incompleteFile) {
      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'HIGH',
        evidence: {
          kind: 'PACKAGE_IMPORTED',
          chain,
          via: [packageName],
          blockedBy: 'USAGE_INCOMPLETE',
          notes: `Directly imported in production scope by ${chain[0]}; symbol usage extraction incomplete in ${incompleteFile.relativePath}`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // R3. Any candidate (or dataset entry point whose via chain applies) referenced => REACHABLE
    const candidateSymbolNames = new Set(candidates.map((c) => c.symbol.toLowerCase()));
    if (datasetEntry?.entryPoints) {
      for (const ep of datasetEntry.entryPoints) {
        candidateSymbolNames.add(ep.export.toLowerCase());
      }
    }

    const matchedUsageFacts: SymbolUsageFact[] = [];
    for (const f of nonTestFiles) {
      if (!f.symbolUsage) continue;
      for (const fact of f.symbolUsage.usageFacts) {
        const factPkg = fact.packageRoot.toLowerCase();
        if (factPkg === normPkg || candidateModuleNames.some((m) => m.toLowerCase() === factPkg)) {
          if (candidateSymbolNames.has(fact.symbol.toLowerCase())) {
            matchedUsageFacts.push(fact);
          }
        }
      }
    }

    if (matchedUsageFacts.length > 0) {
      let provenChain: string[] | null = null;
      for (const fact of matchedUsageFacts) {
        const proof = CallPathProver.proveCallPath(graph, {
          file: fact.file,
          line: fact.line,
          enclosingFunction: fact.enclosingFunction,
          symbol: fact.symbol,
        });
        if (proof.proven && proof.chain) {
          provenChain = proof.chain;
          break;
        }
      }

      const isCallPathProven = provenChain !== null;
      const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'REACHABLE_IMPORT';
      const evidenceKind = isCallPathProven ? 'SYMBOL_CALL_PATH' : 'SYMBOL_REFERENCED';
      const confidence = bestSource === 'HEURISTIC_TEXT' ? 'MEDIUM' : 'HIGH';

      return {
        verdict,
        analysisConfidence: confidence,
        evidence: {
          kind: evidenceKind,
          chain: provenChain ?? chain,
          via: [packageName],
          symbols: Array.from(new Set(matchedUsageFacts.map((f) => f.symbol))),
          symbolSource: bestSource,
          usageSites: matchedUsageFacts.slice(0, 5).map((f) => ({
            file: f.file,
            line: f.line,
            form: f.form,
          })),
          dataset: datasetEntry
            ? { id: datasetEntry.id, sourceUrls: datasetEntry.sourceUrls }
            : undefined,
          notes: isCallPathProven
            ? `Call path proven from entrypoint to vulnerable symbol '${matchedUsageFacts[0]!.symbol}'`
            : `Vulnerable symbol '${matchedUsageFacts[0]!.symbol}' referenced in ${matchedUsageFacts[0]!.file}:${matchedUsageFacts[0]!.line}`,
        },
        limitations: ['Static first-party analysis only; not proof of exploitability or safety.'],
      };
    }

    // R4. Any escape, unknown binding, unknown subpath mapping, import *, computed access or createRequire
    const matchedEscapes: EscapeFact[] = [];
    let hasGlobalCreateRequire = false;
    for (const f of nonTestFiles) {
      if (!f.symbolUsage) continue;
      if (f.symbolUsage.hasCreateRequire) hasGlobalCreateRequire = true;
      for (const esc of f.symbolUsage.escapes) {
        const escPkg = esc.packageRoot.toLowerCase();
        if (escPkg === normPkg || candidateModuleNames.some((m) => m.toLowerCase() === escPkg)) {
          matchedEscapes.push(esc);
        }
      }
    }

    if (matchedEscapes.length > 0 || hasGlobalCreateRequire) {
      return {
        verdict: 'REACHABLE_IMPORT',
        analysisConfidence: 'MEDIUM',
        evidence: {
          kind: 'NAMESPACE_ESCAPES',
          chain,
          via: [packageName],
          symbols: candidates.map((c) => c.symbol),
          symbolSource: bestSource,
          dataset: datasetEntry
            ? { id: datasetEntry.id, sourceUrls: datasetEntry.sourceUrls }
            : undefined,
          notes: hasGlobalCreateRequire
            ? 'Package namespace may escape via createRequire or module.require in repository'
            : `Package namespace escape detected (${matchedEscapes[0]!.reason}) at ${matchedEscapes[0]!.file}:${matchedEscapes[0]!.line}`,
        },
        limitations: ['Static first-party analysis only; not proof of exploitability or safety.'],
      };
    }

    // R5. Evaluate ALL preconditions P1–P10
    const stats = graph.computeStats();

    // P1: Entrypoints found and resolved
    if (
      graph.entrypoints.length === 0 ||
      graph.unresolvedImports.some((u) => u.fromFile === 'entrypoints')
    ) {
      return ScaReachabilityAnalyzer.blockedResult(
        'NO_ENTRYPOINT',
        'No production entrypoint could be detected or resolved',
        chain,
        packageName
      );
    }

    // P2: Zero parse errors in all non-test source files
    if (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError)) {
      return ScaReachabilityAnalyzer.blockedResult(
        'PARSE_ERROR',
        'One or more non-test source files failed syntax parsing',
        chain,
        packageName
      );
    }

    // P3: Zero unresolved local imports and zero dynamic-import/eval markers outside tests
    if (stats.hasAnyUnresolvedLocalImportsInProduction) {
      return ScaReachabilityAnalyzer.blockedResult(
        'UNRESOLVED_IMPORT',
        'Production scope contains unresolved local imports or path aliases',
        chain,
        packageName
      );
    }
    if (stats.hasAnyDynamicInProduction) {
      return ScaReachabilityAnalyzer.blockedResult(
        'DYNAMIC_IMPORT',
        'Production scope contains dynamic require/import, eval, or Function invocation',
        chain,
        packageName
      );
    }

    // P4: Reference scan clean over config/script/CI/Dockerfile/Makefile files AND unparsed files
    const excludeFiles = ScaReachabilityAnalyzer.computeReferenceScanExclusions(nonTestFiles);

    const refCheck = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames, {
      excludeFiles,
    });
    if (refCheck.incompleteScan) {
      return ScaReachabilityAnalyzer.blockedResult(
        'CONFIG_REFERENCE',
        `Reference scan incomplete (${refCheck.incompleteReason})`,
        chain,
        packageName
      );
    }
    if (refCheck.isReferenced) {
      return ScaReachabilityAnalyzer.blockedResult(
        'CONFIG_REFERENCE',
        `Package or module referenced in config/script at ${refCheck.matchedFile}:${refCheck.matchedLine ?? 1}`,
        chain,
        packageName
      );
    }

    // P5: Lockfile dependency tree present and the package is a leaf direct dependency
    if (!lockfileGraph) {
      return ScaReachabilityAnalyzer.blockedResult(
        'NO_LOCKFILE_TREE',
        'No lockfile dependency tree found to verify absence of dependents',
        chain,
        packageName
      );
    }

    const isLeafDirect = LockfileTreeParser.isLeafDirectPackage(lockfileGraph, packageName);
    if (!isLeafDirect) {
      return ScaReachabilityAnalyzer.blockedResult(
        'NOT_LEAF_PACKAGE',
        `Package '${packageName}' is depended upon by other installed dependencies in the lockfile tree`,
        chain,
        packageName
      );
    }

    // P7: Dataset integrity verified
    const isIntegrityOk =
      options?.datasetIntegrityVerified !== undefined
        ? options.datasetIntegrityVerified
        : SymbolDatasetLoader.loadBundledDataset().ok;
    if (!isIntegrityOk) {
      return ScaReachabilityAnalyzer.blockedResult(
        'INTEGRITY_FAILED',
        'Vulnerable symbol dataset manifest failed cryptographic integrity verification',
        chain,
        packageName
      );
    }

    // P8: Trigger condition and entry points completeness
    if (datasetEntry) {
      if (datasetEntry.triggeredOn !== 'CALL') {
        return ScaReachabilityAnalyzer.blockedResult(
          'TRIGGER_NOT_CALL',
          `Vulnerability triggers on ${datasetEntry.triggeredOn}; not eligible for function call pruning`,
          chain,
          packageName
        );
      }
      if (!datasetEntry.entryPointsComplete) {
        return ScaReachabilityAnalyzer.blockedResult(
          'ENTRYPOINTS_INCOMPLETE',
          'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
          chain,
          packageName
        );
      }
      for (const ep of datasetEntry.entryPoints) {
        if (ep.kind === 'METHOD' && (!ep.via || ep.via.length === 0)) {
          return ScaReachabilityAnalyzer.blockedResult(
            'ENTRYPOINTS_INCOMPLETE',
            `Method entry point '${ep.export}' missing via instance creation exports`,
            chain,
            packageName
          );
        }
      }
    }

    // P10: Package not referenced under an npm alias or another specifier form
    const isAliased = ScaReachabilityAnalyzer.isPackageAliased(projectRoot, packageName);
    if (isAliased) {
      return ScaReachabilityAnalyzer.blockedResult(
        'ALIASED_PACKAGE',
        `Package '${packageName}' is declared or imported under an npm alias`,
        chain,
        packageName
      );
    }

    // P6, P8, P9 determine Confidence
    const isPythonEco =
      finding.package?.ecosystem?.toLowerCase() === 'pypi' ||
      finding.package?.ecosystem?.toLowerCase() === 'pip';

    // P6: Bin exposure check
    const isBinSafe = ScaReachabilityAnalyzer.isPackageBinSafe(
      projectRoot,
      packageName,
      lockfileGraph
    );

    let finalConfidence: Confidence;
    if (bestSource === 'HEURISTIC_TEXT') {
      finalConfidence = 'LOW';
    } else if (
      datasetEntry &&
      (datasetEntry.triggeredOn !== 'CALL' || !datasetEntry.entryPointsComplete)
    ) {
      finalConfidence = 'LOW';
    } else if (isPythonEco || !isBinSafe) {
      finalConfidence = 'MEDIUM';
    } else {
      finalConfidence = 'HIGH';
    }

    return {
      verdict: 'UNREACHABLE',
      analysisConfidence: finalConfidence,
      evidence: {
        kind: 'UNINVOKED_SYMBOL',
        chain,
        via: [packageName],
        symbols: candidates.map((c) => c.symbol),
        symbolSource: bestSource,
        dataset: datasetEntry
          ? { id: datasetEntry.id, sourceUrls: datasetEntry.sourceUrls }
          : undefined,
        notes: `No references to vulnerable symbols (${candidates.map((c) => c.symbol).join(', ')}) detected in first-party code`,
      },
      limitations: [
        'static first-party analysis only; dependency code that may call the vulnerable function is not analyzed unless no dependents exist; vulnerable-symbol data may be incomplete',
      ],
    };
  }

  private static blockedResult(
    reasonCode: string,
    notes: string,
    chain: string[],
    packageName: string
  ): ReachabilityDetail {
    return {
      verdict: 'REACHABLE_IMPORT',
      analysisConfidence: 'HIGH',
      evidence: {
        kind: 'PACKAGE_IMPORTED',
        chain,
        via: [packageName],
        blockedBy: reasonCode,
        notes,
      },
      limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
    };
  }

  private static isPackageAliased(projectRoot: string, packageName: string): boolean {
    const pkgJsonPath = path.join(projectRoot, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return false;

    try {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      const depSections = [
        pkg.dependencies,
        pkg.devDependencies,
        pkg.peerDependencies,
        pkg.optionalDependencies,
      ];

      for (const section of depSections) {
        if (!section || typeof section !== 'object') continue;
        for (const [depName, versionSpec] of Object.entries(section)) {
          if (typeof versionSpec === 'string' && versionSpec.startsWith('npm:')) {
            const target = versionSpec.slice(4).split('@')[0]!;
            if (
              target.toLowerCase() === packageName.toLowerCase() ||
              depName.toLowerCase() === packageName.toLowerCase()
            ) {
              return true;
            }
          }
        }
      }
    } catch {
      // Ignored
    }

    return false;
  }

  public static computeReferenceScanExclusions(
    files: Array<{ filePath: string; relativePath: string; hasParseError: boolean }>
  ): Set<string> {
    const excludeFiles = new Set<string>();
    for (const f of files) {
      if (!f.hasParseError) {
        excludeFiles.add(f.filePath);
        excludeFiles.add(f.relativePath);
      }
    }
    return excludeFiles;
  }

  public static isPackageBinSafe(
    projectRoot: string,
    packageName: string,
    _lockfileGraph: LockfileGraph | null
  ): boolean {
    // 1. Check installed node_modules/<packageName>/package.json
    const pkgJsonPath = path.join(projectRoot, 'node_modules', packageName, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        if (pkg.bin) {
          // Bin exposure present
          return false;
        }
        return true;
      } catch {
        return false;
      }
    }

    // 2. Check package-lock.json packages entry
    const lockPath = path.join(projectRoot, 'package-lock.json');
    if (fs.existsSync(lockPath)) {
      try {
        const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        const pkgEntry =
          lock.packages?.[`node_modules/${packageName}`] ?? lock.packages?.[packageName];
        if (pkgEntry) {
          if (pkgEntry.bin) {
            // Bin exposure present
            return false;
          }
          // Lockfile explicitly describes the package and has no bin
          return true;
        }
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.
   */
  public static filterByReachability(
    findings: NormalizedFinding[],
    filter: 'reachable' | 'no-info' | 'not-applicable' | 'all'
  ): NormalizedFinding[] {
    if (!filter || filter === 'all') {
      return findings;
    }

    return findings.filter((f) => {
      if (filter === 'reachable') {
        return f.reachability === 'REACHABLE_CALL_PATH' || f.reachability === 'REACHABLE_IMPORT';
      }

      if (filter === 'no-info') {
        return f.reachability === 'UNKNOWN';
      }

      if (filter === 'not-applicable') {
        return f.reachabilityDetail?.evidence?.kind === 'NOT_APPLICABLE';
      }

      return true;
    });
  }
}
