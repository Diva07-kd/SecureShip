import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type {
  NormalizedFinding,
  Severity,
  SupplyChainDiagnostic,
  SupplyChainPolicy,
  SupplyChainScanResult,
} from '@secureship/contracts';
import type { DetectorContext, RuleHit } from './internal/types.js';
import { normalizeRuleHit } from './normalize.js';
import { detectInstallScripts } from './detectors/install-script.detector.js';
import { detectBinConfusion } from './detectors/bin-confusion.detector.js';
import { detectTyposquats, PopularListIndex } from './detectors/typosquat.detector.js';
import { detectUnicodeAttacks } from './detectors/unicode.detector.js';
import { detectHighEntropy } from './detectors/entropy.detector.js';
import { detectEmptyPackage } from './detectors/pkg-empty.detector.js';
import { detectMetadataAnomalies } from './detectors/metadata.detector.js';
import { detectGovernanceRisk } from './detectors/governance.detector.js';
import type { MetadataProvider } from './providers/provider.interface.js';
import { NullProvider } from './providers/null.provider.js';
import popularNpmData from './data/popular-npm.json' with { type: 'json' };
import popularPypiData from './data/popular-pypi.json' with { type: 'json' };
import {
  AstCapabilityAnalyzer,
  CapabilityMatrix,
  type CapabilitySite,
} from '@secureship/reachability';

export interface SupplyChainAnalyzerOptions {
  rootDir: string;
  policy: SupplyChainPolicy;
  provider?: MetadataProvider;
  now?: () => Date;
  signal?: AbortSignal;
  concurrency?: number;
}

export interface PackageTarget {
  name: string;
  version: string;
  ecosystem: 'npm' | 'pypi';
  dir: string;
  packageJson: Record<string, unknown>;
}
export type DiscoveredPackage = PackageTarget;

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function addDuration(durations: Record<string, number>, key: string, delta: number): void {
  durations[key] = (durations[key] ?? 0) + delta;
}

let cachedPopularNpmIndex: PopularListIndex | null = null;
let cachedPopularPypiIndex: PopularListIndex | null = null;

function getPopularIndex(ecosystem: 'npm' | 'pypi' = 'npm'): PopularListIndex {
  if (ecosystem === 'pypi') {
    if (!cachedPopularPypiIndex) {
      cachedPopularPypiIndex = new PopularListIndex(popularPypiData as { name: string }[]);
    }
    return cachedPopularPypiIndex;
  }
  if (!cachedPopularNpmIndex) {
    cachedPopularNpmIndex = new PopularListIndex(popularNpmData as { name: string }[]);
  }
  return cachedPopularNpmIndex;
}

const SCANNABLE_EXTS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.mts',
  '.cts',
  '.jsx',
  '.tsx',
  '.py',
  '.pyw',
  '.json',
]);

export function discoverPackages(
  rootDir: string,
  diagnostics: SupplyChainDiagnostic[] = []
): PackageTarget[] {
  const targets: PackageTarget[] = [];
  const visitedDirs = new Set<string>();

  const checkAndAdd = (pkgDir: string) => {
    const pkgJsonPath = path.join(pkgDir, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) return;

    try {
      const stat = fs.lstatSync(pkgDir);
      if (stat.isSymbolicLink()) {
        diagnostics.push({
          level: 'INFO',
          file: pkgDir,
          message: `Symlinked package directory skipped to prevent recursion: ${pkgDir}`,
        });
        return;
      }

      const real = fs.realpathSync(pkgDir);
      if (visitedDirs.has(real)) return;
      visitedDirs.add(real);

      const content = fs.readFileSync(pkgJsonPath, 'utf-8');
      const parsed = JSON.parse(content) as Record<string, unknown>;
      const name = typeof parsed.name === 'string' ? parsed.name : path.basename(pkgDir);
      const version = typeof parsed.version === 'string' ? parsed.version : '0.0.0';

      targets.push({
        name,
        version,
        ecosystem: 'npm',
        dir: pkgDir,
        packageJson: parsed,
      });
    } catch (err) {
      diagnostics.push({
        level: 'WARN',
        file: pkgJsonPath,
        message: `Failed to read package.json in ${pkgDir}: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  };

  const nodeModulesDir = path.join(rootDir, 'node_modules');
  if (fs.existsSync(nodeModulesDir)) {
    try {
      const entries = fs.readdirSync(nodeModulesDir, { withFileTypes: true });
      for (const ent of entries) {
        if (ent.name.startsWith('.') || ent.name === '.bin' || ent.name === '.pnpm') {
          continue;
        }

        const fullPath = path.join(nodeModulesDir, ent.name);
        if (ent.name.startsWith('@') && ent.isDirectory()) {
          // Scoped packages
          try {
            const scopedEntries = fs.readdirSync(fullPath, { withFileTypes: true });
            for (const scopedEnt of scopedEntries) {
              if (!scopedEnt.name.startsWith('.')) {
                checkAndAdd(path.join(fullPath, scopedEnt.name));
              }
            }
          } catch {
            // Ignore readdir error
          }
        } else if (ent.isDirectory()) {
          checkAndAdd(fullPath);
        }
      }
    } catch {
      // Ignore node_modules read error
    }
  }

  // Also inspect rootDir if it is a standalone package
  checkAndAdd(rootDir);

  // Discovery of Python / PyPI packages in virtual environments (.venv, venv, env, .env)
  const venvNames = ['.venv', 'venv', 'env', '.env'];
  for (const venvName of venvNames) {
    const venvDir = path.join(rootDir, venvName);
    if (!fs.existsSync(venvDir)) continue;

    const sitePackagesCandidates: string[] = [
      path.join(venvDir, 'Lib', 'site-packages'),
      path.join(venvDir, 'lib', 'site-packages'),
    ];

    const libDir = path.join(venvDir, 'lib');
    if (fs.existsSync(libDir)) {
      try {
        const subdirs = fs.readdirSync(libDir);
        for (const s of subdirs) {
          if (s.startsWith('python')) {
            sitePackagesCandidates.push(path.join(libDir, s, 'site-packages'));
          }
        }
      } catch {
        // Ignore read errors
      }
    }

    for (const sp of sitePackagesCandidates) {
      if (!fs.existsSync(sp)) continue;
      try {
        const entries = fs.readdirSync(sp, { withFileTypes: true });
        for (const ent of entries) {
          if (ent.name.startsWith('.') || ent.name === '__pycache__') continue;
          if (ent.isDirectory()) {
            const fullPath = path.join(sp, ent.name);
            const real = fs.realpathSync(fullPath);
            if (visitedDirs.has(real)) continue;

            if (ent.name.endsWith('.dist-info')) {
              const baseName = ent.name.slice(0, -10);
              const match = baseName.match(/^([A-Za-z0-9_.-]+?)(?:-([0-9][A-Za-z0-9_.]*))?$/);
              const pkgName = match?.[1] ?? baseName;
              const pkgVersion = match?.[2] ?? '0.0.0';

              visitedDirs.add(real);
              targets.push({
                name: pkgName,
                version: pkgVersion,
                ecosystem: 'pypi',
                dir: fullPath,
                packageJson: { name: pkgName, version: pkgVersion },
              });
            } else if (!ent.name.endsWith('.egg-info')) {
              const initPy = path.join(fullPath, '__init__.py');
              if (fs.existsSync(initPy)) {
                visitedDirs.add(real);
                targets.push({
                  name: ent.name,
                  version: '0.0.0',
                  ecosystem: 'pypi',
                  dir: fullPath,
                  packageJson: { name: ent.name, version: '0.0.0' },
                });
              }
            }
          }
        }
      } catch {
        // Ignore site-packages read error
      }
    }
  }

  // Also inspect rootDir if it is a standalone Python package
  if (!targets.some((t) => t.dir === rootDir)) {
    const pyprojectPath = path.join(rootDir, 'pyproject.toml');
    const setupPyPath = path.join(rootDir, 'setup.py');
    const requirementsPath = path.join(rootDir, 'requirements.txt');

    if (
      fs.existsSync(pyprojectPath) ||
      fs.existsSync(setupPyPath) ||
      fs.existsSync(requirementsPath)
    ) {
      let pyName = path.basename(rootDir);
      let pyVersion = '0.0.0';

      if (fs.existsSync(pyprojectPath)) {
        try {
          const content = fs.readFileSync(pyprojectPath, 'utf-8');
          const nameMatch = content.match(/name\s*=\s*["']([^"']+)["']/);
          const verMatch = content.match(/version\s*=\s*["']([^"']+)["']/);
          if (nameMatch?.[1]) pyName = nameMatch[1];
          if (verMatch?.[1]) pyVersion = verMatch[1];
        } catch {
          // Ignore
        }
      }

      targets.push({
        name: pyName,
        version: pyVersion,
        ecosystem: 'pypi',
        dir: rootDir,
        packageJson: { name: pyName, version: pyVersion },
      });
    }
  }

  return targets;
}

export async function analyzeSupplyChain(
  options: SupplyChainAnalyzerOptions
): Promise<SupplyChainScanResult> {
  const startTime = Date.now();
  const nowFn = options.now ?? (() => new Date());
  const provider = options.provider ?? new NullProvider();
  const policy = options.policy;

  if (policy.enabled === false) {
    const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');

    return {
      findings: [],
      diagnostics: [],
      stats: {
        packagesAnalyzed: 0,
        packagesSkipped: 0,
        filesScanned: 0,
        bytesScanned: 0,
        durationMs: Date.now() - startTime,
        detectorDurations: {
          InstallScript: 0,
          BinConfusion: 0,
          Typosquat: 0,
          EmptyPackage: 0,
          Unicode: 0,
          Entropy: 0,
          Metadata: 0,
          Governance: 0,
          AstCapabilities: 0,
        },
      },
      policyHash,
      engineVersion: '0.1.0',
    };
  }

  const diagnostics: SupplyChainDiagnostic[] = [];

  const packages = discoverPackages(options.rootDir, diagnostics);

  const concurrency = Math.max(
    1,
    Math.min(options.concurrency ?? policy.concurrency ?? 8, os.cpus().length || 4)
  );

  const allHits: RuleHit[] = [];
  const detectorDurations: Record<string, number> = {
    InstallScript: 0,
    BinConfusion: 0,
    Typosquat: 0,
    EmptyPackage: 0,
    Unicode: 0,
    Entropy: 0,
    Metadata: 0,
    Governance: 0,
    AstCapabilities: 0,
  };

  let filesScanned = 0;
  let bytesScanned = 0;

  // Concurrency-limited execution over discovered packages
  let pkgIdx = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (pkgIdx < packages.length) {
      if (options.signal?.aborted) break;

      const currentPkg = packages[pkgIdx++];
      if (!currentPkg) break;

      const ctx: DetectorContext = {
        packageName: currentPkg.name,
        version: currentPkg.version,
        ecosystem: currentPkg.ecosystem,
        packageDir: currentPkg.dir,
        now: nowFn,
        signal: options.signal,
      };

      try {
        // Run Detectors for this package
        const t0 = Date.now();
        const installHits = detectInstallScripts(
          currentPkg.packageJson,
          currentPkg.dir,
          policy,
          ctx
        );
        addDuration(detectorDurations, 'InstallScript', Date.now() - t0);
        allHits.push(...installHits);

        const t1 = Date.now();
        const binHits = detectBinConfusion(currentPkg.packageJson, policy, ctx);
        addDuration(detectorDurations, 'BinConfusion', Date.now() - t1);
        allHits.push(...binHits);

        const t2 = Date.now();
        const typoHits = await detectTyposquats(
          currentPkg.name,
          currentPkg.ecosystem,
          getPopularIndex(currentPkg.ecosystem),
          policy,
          provider,
          ctx
        );
        addDuration(detectorDurations, 'Typosquat', Date.now() - t2);
        allHits.push(...typoHits);

        const t3 = Date.now();
        const emptyHits = detectEmptyPackage(currentPkg.dir, currentPkg.packageJson, ctx);
        addDuration(detectorDurations, 'EmptyPackage', Date.now() - t3);
        allHits.push(...emptyHits);

        const t4 = Date.now();
        const metaHits = await detectMetadataAnomalies(
          currentPkg.name,
          currentPkg.version,
          currentPkg.packageJson,
          provider,
          policy,
          ctx
        );
        addDuration(detectorDurations, 'Metadata', Date.now() - t4);
        allHits.push(...metaHits);

        const t5 = Date.now();
        const govHits = await detectGovernanceRisk(
          currentPkg.name,
          currentPkg.version,
          currentPkg.packageJson,
          provider,
          policy,
          ctx
        );
        addDuration(detectorDurations, 'Governance', Date.now() - t5);
        allHits.push(...govHits);

        const pkgSites: CapabilitySite[] = [];
        const pkgCapabilities = {
          hasShell: false,
          hasNetwork: false,
          hasEnvAccess: false,
          hasFsSensitive: false,
          hasEval: false,
          hasDynamicRequire: false,
          hasInstallScript: installHits.length > 0,
          hasDebugInternals: false,
        };

        // File scanning inside packageDir (bounded by maxFileSizeBytes & maxFileCount)
        const maxFileBytes = policy.maxFileSizeBytes ?? 2_097_152;
        const scanFiles = async (dir: string, depth = 0): Promise<void> => {
          if (depth > 4 || filesScanned >= (policy.maxFileCount ?? 20_000)) return;
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const ent of entries) {
              if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
              const fullPath = path.join(dir, ent.name);
              if (ent.isDirectory()) {
                await scanFiles(fullPath, depth + 1);
              } else if (ent.isFile()) {
                const ext = path.extname(ent.name).toLowerCase();
                if (SCANNABLE_EXTS.has(ext)) {
                  try {
                    const st = fs.statSync(fullPath);
                    if (st.size <= maxFileBytes) {
                      filesScanned++;
                      bytesScanned += st.size;
                      const content = fs.readFileSync(fullPath, 'utf-8');

                      const tu = Date.now();
                      const uniHits = detectUnicodeAttacks(content, fullPath, policy, ctx);
                      addDuration(detectorDurations, 'Unicode', Date.now() - tu);
                      allHits.push(...uniHits);

                      const te = Date.now();
                      const entHits = detectHighEntropy(content, fullPath, policy, ctx);
                      addDuration(detectorDurations, 'Entropy', Date.now() - te);
                      allHits.push(...entHits);

                      // AST Capability Extraction
                      if (
                        [
                          '.js',
                          '.mjs',
                          '.cjs',
                          '.ts',
                          '.mts',
                          '.cts',
                          '.jsx',
                          '.tsx',
                          '.py',
                          '.pyw',
                        ].includes(ext)
                      ) {
                        const tc = Date.now();
                        const capRes = await AstCapabilityAnalyzer.analyzeFile(content, fullPath, {
                          maxFileBytes,
                        });
                        addDuration(detectorDurations, 'AstCapabilities', Date.now() - tc);
                        if (capRes.sites.length > 0) {
                          pkgSites.push(...capRes.sites);
                          if (capRes.capabilities.hasShell) pkgCapabilities.hasShell = true;
                          if (capRes.capabilities.hasNetwork) pkgCapabilities.hasNetwork = true;
                          if (capRes.capabilities.hasEnvAccess) pkgCapabilities.hasEnvAccess = true;
                          if (capRes.capabilities.hasFsSensitive)
                            pkgCapabilities.hasFsSensitive = true;
                          if (capRes.capabilities.hasEval) pkgCapabilities.hasEval = true;
                          if (capRes.capabilities.hasDynamicRequire)
                            pkgCapabilities.hasDynamicRequire = true;
                          if (capRes.capabilities.hasDebugInternals)
                            pkgCapabilities.hasDebugInternals = true;
                        }
                      }
                    }
                  } catch {
                    // Ignore file read error
                  }
                }
              }
            }
          } catch {
            // Ignore dir read error
          }
        };

        await scanFiles(currentPkg.dir);

        // Capability combinations and matrix evaluation
        const hasObf = allHits.some(
          (h) =>
            h.packageName === currentPkg.name &&
            (h.ruleId === 'SC-OBF-001' || h.ruleId === 'SC-OBF-002')
        );
        const comboHits = CapabilityMatrix.evaluateCombinations(pkgCapabilities, pkgSites, {
          packageName: currentPkg.name,
          version: currentPkg.version,
          hasInstallScript: installHits.length > 0,
          hasHighEntropyOrObfuscation: hasObf,
        });

        for (const ch of comboHits) {
          allHits.push({
            ruleId: ch.ruleId,
            packageName: currentPkg.name,
            version: currentPkg.version,
            ecosystem: currentPkg.ecosystem,
            purl: `pkg:${currentPkg.ecosystem}/${currentPkg.name}@${currentPkg.version}`,
            severity: ch.severity,
            confidence: 'HIGH',
            evidence: ch.evidenceSites.slice(0, 20).map((s) => ({
              file: s.file,
              startLine: s.startLine,
              startCol: s.startCol,
              endLine: s.endLine,
              endCol: s.endCol,
              snippetSha256: crypto.createHash('sha256').update(s.snippet).digest('hex'),
              redactedSnippet: s.snippet.slice(0, 150),
              note: s.details,
            })),
            metadataUnavailable: false,
            blocking: ch.blocking,
            title: ch.title,
            description: ch.description,
            reachabilityGated: ch.reachabilityGated,
            remediationText: ch.remediation,
            capabilities: pkgCapabilities,
          });
        }

        if (comboHits.length === 0 && pkgSites.length > 0) {
          const singleHits = CapabilityMatrix.evaluateSingleCapabilities(pkgCapabilities, pkgSites);
          for (const sh of singleHits) {
            allHits.push({
              ruleId: sh.ruleId,
              packageName: currentPkg.name,
              version: currentPkg.version,
              ecosystem: currentPkg.ecosystem,
              purl: `pkg:${currentPkg.ecosystem}/${currentPkg.name}@${currentPkg.version}`,
              severity: sh.severity,
              confidence: 'MEDIUM',
              evidence: sh.evidenceSites.slice(0, 20).map((s) => ({
                file: s.file,
                startLine: s.startLine,
                startCol: s.startCol,
                endLine: s.endLine,
                endCol: s.endCol,
                snippetSha256: crypto.createHash('sha256').update(s.snippet).digest('hex'),
                redactedSnippet: s.snippet.slice(0, 150),
                note: s.details,
              })),
              metadataUnavailable: false,
              blocking: false,
              title: sh.title,
              description: sh.description,
              reachabilityGated: sh.reachabilityGated,
              remediationText: sh.remediation,
              capabilities: pkgCapabilities,
            });
          }
        }
      } catch (err) {
        diagnostics.push({
          level: 'WARN',
          packageName: currentPkg.name,
          message: `Package scan encountered an unexpected error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  });

  await Promise.all(workers);

  // Apply policy ruleOverrides
  const effectiveHits: RuleHit[] = [];
  for (const hit of allHits) {
    const override = policy.ruleOverrides?.[hit.ruleId];
    if (override?.enabled === false) {
      continue;
    }
    if (override?.severity) {
      hit.severity = override.severity;
    }
    if (override?.blocking !== undefined) {
      hit.blocking = override.blocking;
    }
    effectiveHits.push(hit);
  }

  // Convert RuleHit to NormalizedFinding
  const nowIso = nowFn().toISOString();
  const rawFindings: NormalizedFinding[] = effectiveHits.map((hit) =>
    normalizeRuleHit(hit, nowIso)
  );

  // Deduplicate findings by fingerprint
  const dedupeMap = new Map<string, NormalizedFinding>();
  for (const f of rawFindings) {
    if (!dedupeMap.has(f.fingerprint)) {
      dedupeMap.set(f.fingerprint, f);
    }
  }

  const findings = Array.from(dedupeMap.values());

  // Deterministic sort: Severity desc -> RuleId asc -> Purl asc -> File asc -> Line asc -> Fingerprint asc
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_WEIGHT[a.severity] - SEVERITY_WEIGHT[b.severity];
    if (sevDiff !== 0) return sevDiff;

    const ruleDiff = a.ruleId.localeCompare(b.ruleId);
    if (ruleDiff !== 0) return ruleDiff;

    const purlA = String(a.evidence[0]?.metadata?.['purl'] || '');
    const purlB = String(b.evidence[0]?.metadata?.['purl'] || '');
    const purlDiff = purlA.localeCompare(purlB);
    if (purlDiff !== 0) return purlDiff;

    const fileDiff = a.location.filePath.localeCompare(b.location.filePath);
    if (fileDiff !== 0) return fileDiff;

    const lineDiff = (a.location.startLine || 0) - (b.location.startLine || 0);
    if (lineDiff !== 0) return lineDiff;

    return a.fingerprint.localeCompare(b.fingerprint);
  });

  const durationMs = Date.now() - startTime;
  const policyHash = crypto.createHash('sha256').update(JSON.stringify(policy)).digest('hex');

  return {
    findings,
    diagnostics,
    stats: {
      packagesAnalyzed: packages.length,
      packagesSkipped: 0,
      filesScanned,
      bytesScanned,
      durationMs,
      detectorDurations,
    },
    policyHash,
    engineVersion: '0.1.0',
  };
}
