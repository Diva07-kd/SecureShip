import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  CycloneDxBomSchema,
  SpdxBomSchema,
  type NormalizedFinding,
  type ScanReport,
} from '@secureship/contracts';
import {
  computePackageHash,
  generateCycloneDXSbom,
  generatePurl,
  generateSpdxSbom,
} from '../../src/sbom/sbom-generator.js';
import type { PackageTarget } from '../../src/supply-chain/supply-chain-analyzer.js';

describe('SbomGenerator Engine Suite (Phase 4)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sbom-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('generatePurl', () => {
    it('generates compliant purl for unscoped npm package', () => {
      const pkg: PackageTarget = {
        name: 'express',
        version: '4.18.2',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: 'express', version: '4.18.2' },
      };
      expect(generatePurl(pkg)).toBe('pkg:npm/express@4.18.2');
    });

    it('generates compliant purl with percent-encoded scope for scoped npm package', () => {
      const pkg: PackageTarget = {
        name: '@secureship/core-engine',
        version: '1.0.0-beta.1',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: '@secureship/core-engine', version: '1.0.0-beta.1' },
      };
      expect(generatePurl(pkg)).toBe('pkg:npm/%40secureship/core-engine@1.0.0-beta.1');
    });

    it('generates compliant purl for PyPI packages', () => {
      const pkg: PackageTarget = {
        name: 'Urllib3',
        version: '2.0.7',
        ecosystem: 'pypi',
        dir: tempDir,
        packageJson: { name: 'Urllib3', version: '2.0.7' },
      };
      expect(generatePurl(pkg)).toBe('pkg:pypi/urllib3@2.0.7');
    });
  });

  describe('computePackageHash', () => {
    it('computes deterministic SHA-256 hash based on package.json content', () => {
      const pkgJsonPath = path.join(tempDir, 'package.json');
      fs.writeFileSync(pkgJsonPath, JSON.stringify({ name: 'test', version: '1.0.0' }), 'utf-8');

      const hash1 = computePackageHash(tempDir);
      const hash2 = computePackageHash(tempDir);

      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
      expect(hash1).toBe(hash2);
    });

    it('gracefully handles non-existent directories without throwing', () => {
      const fakeDir = path.join(tempDir, 'does-not-exist');
      const hash = computePackageHash(fakeDir);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('generateCycloneDXSbom', () => {
    it('generates a valid, schema-compliant CycloneDX 1.5 document', () => {
      const rootPkgJson = path.join(tempDir, 'package.json');
      fs.writeFileSync(
        rootPkgJson,
        JSON.stringify({ name: 'sample-app', version: '2.0.0', description: 'Sample Root App' }),
        'utf-8'
      );

      const packages: PackageTarget[] = [
        {
          name: 'lodash',
          version: '4.17.21',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'lodash', version: '4.17.21', license: 'MIT' },
        },
        {
          name: '@types/node',
          version: '20.10.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: '@types/node', version: '20.10.0', license: 'MIT' },
        },
      ];

      const sbom = generateCycloneDXSbom({
        rootDir: tempDir,
        packages,
        cliVersion: '1.0.0-beta.1',
      });

      // Assert schema validity
      const parsed = CycloneDxBomSchema.parse(sbom);
      expect(parsed.bomFormat).toBe('CycloneDX');
      expect(parsed.specVersion).toBe('1.5');
      expect(parsed.serialNumber).toMatch(/^urn:uuid:/);
      const tool0 = parsed.metadata.tools[0];
      expect(tool0).toBeDefined();
      expect(tool0?.name).toBe('SecureShip CLI');
      expect(tool0?.version).toBe('1.0.0-beta.1');
      expect(parsed.metadata.component?.name).toBe(path.basename(tempDir));
      expect(parsed.components).toHaveLength(2);
      const comp0 = parsed.components[0];
      const comp1 = parsed.components[1];
      expect(comp0).toBeDefined();
      expect(comp1).toBeDefined();
      expect(comp0?.purl).toBe('pkg:npm/lodash@4.17.21');
      expect(comp1?.purl).toBe('pkg:npm/%40types/node@20.10.0');
      expect(parsed.dependencies).toBeDefined();
    });

    it('enriches components with vulnerability ratings when scanReport is provided', () => {
      const packages: PackageTarget[] = [
        {
          name: 'vulnerable-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: path.join(tempDir, 'node_modules', 'vulnerable-pkg'),
          packageJson: { name: 'vulnerable-pkg', version: '1.0.0', license: 'Apache-2.0' },
        },
      ];

      const dummyFinding: NormalizedFinding = {
        id: 'finding-1',
        ruleId: 'SC-TYPO-001',
        fingerprint: 'a'.repeat(64),
        scannerName: 'generic',
        category: 'SUPPLY_CHAIN',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'High risk typosquatting package detected',
        description: 'High risk typosquatting package detected',
        cweIds: [],
        location: {
          filePath: path.join(tempDir, 'node_modules', 'vulnerable-pkg', 'package.json'),
          startLine: 1,
          endLine: 1,
        },
        package: {
          name: 'vulnerable-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
        },
        evidence: [
          {
            scannerName: 'generic',
            scannerRuleId: 'SC-TYPO-001',
            message: 'High risk typosquatting package detected',
          },
        ],
        createdAt: new Date().toISOString(),
      };

      const scanReport: ScanReport = {
        schemaVersion: '1.2',
        tool: { name: 'secureship', version: '1.0.0-beta.1' },
        target: tempDir,
        mode: 'FULL',
        startedAt: new Date().toISOString(),
        durationMs: 100,
        scanners: [
          {
            name: 'generic',
            status: 'SUCCESS',
            durationMs: 100,
            rawFindingCount: 1,
          },
        ],
        summary: {
          totalRaw: 1,
          totalReported: 1,
          totalSuppressed: 0,
          totalOutOfScope: 0,
          bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          byCategory: { SUPPLY_CHAIN: 1, SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
          suppressedByReason: {
            GATE1_TEST_OR_MOCK: 0,
            GATE1_EXAMPLE: 0,
            GATE1_DOCUMENTATION: 0,
            USER_IGNORE_RULE: 0,
            BASELINE_KNOWN: 0,
            GATE2_UNREACHABLE: 0,
            GATE3_LIKELY_FALSE_POSITIVE: 0,
            SUPPLY_CHAIN_ALLOWLISTED: 0,
          },
        },
        findings: [dummyFinding],
        suppressed: [],
        warnings: [],
      };

      const sbom = generateCycloneDXSbom({
        rootDir: tempDir,
        packages,
        scanReport,
        cliVersion: '1.0.0-beta.1',
      });

      const comp0 = sbom.components[0];
      expect(comp0).toBeDefined();
      expect(comp0?.vulnerabilities).toBeDefined();
      expect(comp0?.vulnerabilities).toHaveLength(1);
      const vuln0 = comp0?.vulnerabilities?.[0];
      expect(vuln0).toBeDefined();
      expect(vuln0?.id).toBe('SC-TYPO-001');
      expect(vuln0?.ratings?.[0]?.severity).toBe('critical');
      expect(sbom.vulnerabilities).toHaveLength(1);
    });

    it('correlates vulnerabilities by exact package name and scoped node_modules path without false substring matches', () => {
      const packages: PackageTarget[] = [
        {
          name: 'lo',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: path.join(tempDir, 'node_modules', 'lo'),
          packageJson: { name: 'lo', version: '1.0.0', license: 'MIT' },
        },
        {
          name: 'lodash',
          version: '4.17.21',
          ecosystem: 'npm',
          dir: path.join(tempDir, 'node_modules', 'lodash'),
          packageJson: { name: 'lodash', version: '4.17.21', license: 'MIT' },
        },
        {
          name: '@babel/core',
          version: '7.24.0',
          ecosystem: 'npm',
          dir: path.join(tempDir, 'node_modules', '@babel', 'core'),
          packageJson: { name: '@babel/core', version: '7.24.0', license: 'MIT' },
        },
      ];

      const findings: NormalizedFinding[] = [
        {
          id: 'vuln-lodash',
          ruleId: 'SC-LODASH-001',
          fingerprint: 'b'.repeat(64),
          scannerName: 'generic',
          category: 'SUPPLY_CHAIN',
          severity: 'HIGH',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'Prototype pollution in lodash',
          description: 'Prototype pollution in lodash',
          cweIds: [],
          evidence: [
            {
              scannerName: 'generic',
              scannerRuleId: 'SC-LODASH-001',
              message: 'Prototype pollution in lodash',
            },
          ],
          location: {
            filePath: path.join(tempDir, 'node_modules', 'lodash', 'lodash.js'),
            startLine: 1,
            endLine: 1,
          },
          package: { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
          createdAt: new Date().toISOString(),
        },
        {
          id: 'vuln-babel',
          ruleId: 'SC-BABEL-001',
          fingerprint: 'c'.repeat(64),
          scannerName: 'generic',
          category: 'SUPPLY_CHAIN',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          scopeTag: 'PRODUCTION',
          title: 'Vulnerability in @babel/core',
          description: 'Vulnerability in @babel/core',
          cweIds: [],
          evidence: [
            {
              scannerName: 'generic',
              scannerRuleId: 'SC-BABEL-001',
              message: 'Vulnerability in @babel/core',
            },
          ],
          location: {
            filePath: 'node_modules/@babel/core/lib/index.js',
            startLine: 1,
            endLine: 1,
          },
          createdAt: new Date().toISOString(),
        },
      ];

      const scanReport: ScanReport = {
        schemaVersion: '1.2',
        tool: { name: 'secureship', version: '1.0.0-beta.1' },
        target: tempDir,
        mode: 'FULL',
        startedAt: new Date().toISOString(),
        durationMs: 50,
        scanners: [{ name: 'generic', status: 'SUCCESS', durationMs: 50, rawFindingCount: 2 }],
        summary: {
          totalRaw: 2,
          totalReported: 2,
          totalSuppressed: 0,
          totalOutOfScope: 0,
          bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
          byCategory: { SUPPLY_CHAIN: 2, SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
          suppressedByReason: {},
        },
        findings,
        suppressed: [],
        warnings: [],
      };

      const sbom = generateCycloneDXSbom({
        rootDir: tempDir,
        packages,
        scanReport,
        cliVersion: '1.0.0-beta.1',
      });

      const compLo = sbom.components.find((c) => c.name === 'lo');
      const compLodash = sbom.components.find((c) => c.name === 'lodash');
      const compBabel = sbom.components.find((c) => c.name === '@babel/core');

      expect(compLo?.vulnerabilities).toBeUndefined();
      expect(compLodash?.vulnerabilities).toHaveLength(1);
      expect(compLodash?.vulnerabilities?.[0]?.id).toBe('SC-LODASH-001');
      expect(compBabel?.vulnerabilities).toHaveLength(1);
      expect(compBabel?.vulnerabilities?.[0]?.id).toBe('SC-BABEL-001');
    });
  });

  describe('generateSpdxSbom', () => {
    it('generates a valid, schema-compliant SPDX 2.3 JSON document', () => {
      const packages: PackageTarget[] = [
        {
          name: 'react',
          version: '18.2.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'react', version: '18.2.0', license: 'MIT' },
        },
      ];

      const spdx = generateSpdxSbom({
        rootDir: tempDir,
        packages,
        cliVersion: '1.0.0-beta.1',
      });

      const parsed = SpdxBomSchema.parse(spdx);
      expect(parsed.spdxVersion).toBe('SPDX-2.3');
      expect(parsed.dataLicense).toBe('CC0-1.0');
      expect(parsed.SPDXID).toBe('SPDXRef-DOCUMENT');
      expect(parsed.documentNamespace).toMatch(/^https:\/\/secureship\.dev\/spdx\//);
      const creator0 = parsed.creationInfo.creators[0];
      expect(creator0).toBeDefined();
      expect(creator0).toContain('SecureShip-1.0.0-beta.1');
      expect(parsed.packages).toHaveLength(1);
      const pkg0 = parsed.packages[0];
      expect(pkg0).toBeDefined();
      expect(pkg0?.name).toBe('react');
      expect(pkg0?.licenseConcluded).toBe('MIT');
      expect(pkg0?.checksums?.[0]?.algorithm).toBe('SHA256');
      const rel0 = parsed.relationships[0];
      expect(rel0).toBeDefined();
      expect(rel0?.relationshipType).toBe('DESCRIBES');
    });
  });
});
