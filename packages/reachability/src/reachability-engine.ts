import type { NormalizedFinding, ReachabilityDetail } from '@secureship/contracts';
import { ImportGraph } from './graph/import-graph.js';
import { LockfileTreeParser, type LockfileGraph } from './lockfile/lockfile-tree-parser.js';
import { ScaReachabilityAnalyzer } from './sca/sca-reachability-analyzer.js';
import { SastReachabilityAnalyzer } from './sast/sast-reachability-analyzer.js';
import { SupplyChainReachabilityAnalyzer } from './capabilities/supply-chain-reachability-analyzer.js';
import type { VulnerableSymbolDataset } from './symbols/vulnerable-symbol.schema.js';

export interface ReachabilityEngineOptions {
  userConfigEntrypoints?: string[];
  noCache?: boolean;
  parseTimeoutMs?: number;
  maxFileBytes?: number;
  functionLevel?: boolean;
  symbolDataset?: VulnerableSymbolDataset | null;
  datasetIntegrityVerified?: boolean;
}

export class ReachabilityEngine {
  private readonly projectRoot: string;
  private readonly options: ReachabilityEngineOptions;
  private graph: ImportGraph | null = null;
  private lockfileGraph: LockfileGraph | null = null;

  constructor(projectRoot: string, options: ReachabilityEngineOptions = {}) {
    this.projectRoot = projectRoot;
    this.options = options;
  }

  /**
   * Initializes the engine by constructing the whole-repository import graph and parsing lockfiles.
   */
  public async init(): Promise<void> {
    // 1. Build whole-repository import graph
    this.graph = await ImportGraph.build(this.projectRoot, {
      userConfigEntrypoints: this.options.userConfigEntrypoints,
      noCache: this.options.noCache,
      parseOptions: {
        parseTimeoutMs: this.options.parseTimeoutMs,
        maxFileBytes: this.options.maxFileBytes,
      },
    });

    // 2. Parse lockfile tree
    const lockfileRes = LockfileTreeParser.parse(this.projectRoot);
    if (lockfileRes.success) {
      this.lockfileGraph = lockfileRes.graph;
    }
  }

  public getGraph(): ImportGraph {
    if (!this.graph) {
      throw new Error('ReachabilityEngine.init() must be awaited before accessing graph.');
    }
    return this.graph;
  }

  public getLockfileGraph(): LockfileGraph | null {
    return this.lockfileGraph;
  }

  /**
   * Evaluates reachability for a normalized finding according to Phase 3 principles.
   */
  public evaluate(finding: NormalizedFinding): ReachabilityDetail {
    if (!this.graph) {
      throw new Error('ReachabilityEngine.init() must be awaited before evaluating findings.');
    }

    // Principle G8: SECRET and IAC findings are never gated by reachability
    if (finding.category === 'SECRET' || finding.category === 'IAC') {
      return {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: {
          kind: 'NOT_APPLICABLE',
          notes: `${finding.category} findings are never gated by reachability analysis`,
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
    }

    // SAST: file-level reachability
    if (finding.category === 'SAST') {
      return SastReachabilityAnalyzer.analyze(finding, this.graph, this.projectRoot);
    }

    // SCA: package-level and symbol-level reachability
    if (finding.category === 'SCA') {
      return ScaReachabilityAnalyzer.analyze(
        finding,
        this.graph,
        this.lockfileGraph,
        this.projectRoot,
        {
          functionLevel: this.options.functionLevel,
          symbolDataset: this.options.symbolDataset,
          datasetIntegrityVerified: this.options.datasetIntegrityVerified,
        }
      );
    }

    // Supply-Chain: capability & package reachability correlation
    if (finding.category === 'SUPPLY_CHAIN') {
      const res = SupplyChainReachabilityAnalyzer.analyze(
        finding,
        this.graph,
        this.lockfileGraph,
        this.projectRoot
      );
      return res.detail;
    }

    // Default fallback
    return {
      verdict: 'UNKNOWN',
      analysisConfidence: 'LOW',
      evidence: {
        kind: 'NOT_APPLICABLE',
        notes: `Unsupported finding category: ${finding.category}`,
      },
      limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
    };
  }
}
