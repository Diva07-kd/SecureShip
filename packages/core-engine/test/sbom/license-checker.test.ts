import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  evaluateLicenseCompliance,
  extractPackageLicenses,
  normalizeLicense,
  parseLicenseExpression,
} from '../../src/sbom/license-checker.js';
import type { PackageTarget } from '../../src/supply-chain/supply-chain-analyzer.js';

describe('LicenseChecker Engine Suite (Phase 4)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-lic-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('normalizeLicense', () => {
    it('normalizes known variant spellings to standard SPDX identifiers', () => {
      expect(normalizeLicense('apache 2.0')).toBe('Apache-2.0');
      expect(normalizeLicense('apache-2.0')).toBe('Apache-2.0');
      expect(normalizeLicense('mit')).toBe('MIT');
      expect(normalizeLicense('mit license')).toBe('MIT');
      expect(normalizeLicense('bsd')).toBe('BSD-3-Clause');
      expect(normalizeLicense('bsd-2-clause')).toBe('BSD-2-Clause');
      expect(normalizeLicense('public domain')).toBe('CC0-1.0');
      expect(normalizeLicense('gplv3')).toBe('GPL-3.0-only');
      expect(normalizeLicense('agpl-3.0')).toBe('AGPL-3.0-only');
    });

    it('preserves unknown custom licenses verbatim without mangling', () => {
      expect(normalizeLicense('Commercial-Proprietary-v1')).toBe('Commercial-Proprietary-v1');
      expect(normalizeLicense('Custom-Org-License')).toBe('Custom-Org-License');
    });
  });

  describe('parseLicenseExpression', () => {
    it('splits compound OR expressions into constituent licenses', () => {
      const parsed = parseLicenseExpression('(MIT OR Apache-2.0)');
      expect(parsed).toEqual(['MIT', 'Apache-2.0']);
    });

    it('splits compound AND expressions into constituent licenses', () => {
      const parsed = parseLicenseExpression('(MIT AND BSD-3-Clause)');
      expect(parsed).toEqual(['MIT', 'BSD-3-Clause']);
    });

    it('handles single license expressions cleanly', () => {
      const parsed = parseLicenseExpression('ISC');
      expect(parsed).toEqual(['ISC']);
    });
  });

  describe('extractPackageLicenses', () => {
    it('extracts license declared as a string in package.json', () => {
      const pkg: PackageTarget = {
        name: 'pkg-string-lic',
        version: '1.2.3',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: 'pkg-string-lic', version: '1.2.3', license: 'MIT' },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('MIT');
      expect(licenses.length).toBe(1);
    });

    it('extracts legacy object license { type: "Apache-2.0" }', () => {
      const pkg: PackageTarget = {
        name: 'pkg-obj-lic',
        version: '2.0.0',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: {
          name: 'pkg-obj-lic',
          version: '2.0.0',
          license: { type: 'Apache-2.0', url: 'https://example.com/license' },
        },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('Apache-2.0');
      expect(licenses.length).toBe(1);
    });

    it('extracts legacy licenses array in package.json', () => {
      const pkg: PackageTarget = {
        name: 'pkg-array-lic',
        version: '3.0.0',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: {
          name: 'pkg-array-lic',
          version: '3.0.0',
          licenses: [{ type: 'MIT' }, { type: 'BSD-3-Clause' }],
        },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('MIT');
      expect(licenses).toContain('BSD-3-Clause');
      expect(licenses.length).toBe(2);
    });

    it('extracts Python METADATA declared licenses and classifiers', () => {
      const metadataContent = [
        'Metadata-Version: 2.1',
        'Name: requests',
        'Version: 2.31.0',
        'License: Apache 2.0',
        'Classifier: License :: OSI Approved :: Apache Software License',
        'Classifier: Programming Language :: Python :: 3',
      ].join('\n');

      fs.writeFileSync(path.join(tempDir, 'METADATA'), metadataContent, 'utf-8');

      const pkg: PackageTarget = {
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'pypi',
        dir: tempDir,
        packageJson: { name: 'requests', version: '2.31.0' },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('Apache-2.0');
      expect(licenses.length).toBeGreaterThanOrEqual(1);
    });

    it('infers license from LICENSE file text when manifest has no license field', () => {
      const mitLicenseText = [
        'MIT License',
        'Copyright (c) 2026 Test Author',
        'Permission is hereby granted, free of charge, to any person obtaining a copy...',
      ].join('\n');
      fs.writeFileSync(path.join(tempDir, 'LICENSE'), mitLicenseText, 'utf-8');

      const pkg: PackageTarget = {
        name: 'pkg-license-file',
        version: '1.0.0',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: 'pkg-license-file', version: '1.0.0' },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('MIT');
    });

    it('infers GPL-3.0 from LICENSE file text containing GNU GPL version 3', () => {
      const gplText = 'GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n...';
      fs.writeFileSync(path.join(tempDir, 'LICENSE.txt'), gplText, 'utf-8');

      const pkg: PackageTarget = {
        name: 'pkg-gpl',
        version: '1.0.0',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: 'pkg-gpl', version: '1.0.0' },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toContain('GPL-3.0-only');
    });

    it('returns NOASSERTION when no license information can be found anywhere', () => {
      const pkg: PackageTarget = {
        name: 'pkg-no-lic',
        version: '0.0.1',
        ecosystem: 'npm',
        dir: tempDir,
        packageJson: { name: 'pkg-no-lic', version: '0.0.1' },
      };

      const licenses = extractPackageLicenses(pkg);
      expect(licenses).toEqual(['NOASSERTION']);
    });
  });

  describe('evaluateLicenseCompliance', () => {
    it('approves packages when all licenses match allowed policy', () => {
      const packages: PackageTarget[] = [
        {
          name: 'lib-mit',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'lib-mit', version: '1.0.0', license: 'MIT' },
        },
        {
          name: 'lib-apache',
          version: '2.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'lib-apache', version: '2.0.0', license: 'Apache-2.0' },
        },
      ];

      const result = evaluateLicenseCompliance(packages, { allow: ['MIT', 'Apache-2.0'] });
      expect(result.status).toBe('COMPLIANT');
      expect(result.totalPackages).toBe(2);
      expect(result.compliantCount).toBe(2);
      expect(result.violationCount).toBe(0);
      expect(result.violations).toHaveLength(0);
    });

    it('flags violations when package license is not in allow list', () => {
      const packages: PackageTarget[] = [
        {
          name: 'lib-gpl',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'lib-gpl', version: '1.0.0', license: 'GPL-3.0' },
        },
      ];

      const result = evaluateLicenseCompliance(packages, { allow: ['MIT', 'Apache-2.0'] });
      expect(result.status).toBe('NON_COMPLIANT');
      expect(result.violationCount).toBe(1);
      const v0 = result.violations[0];
      expect(v0).toBeDefined();
      expect(v0?.packageName).toBe('lib-gpl');
      expect(v0?.severity).toBe('HIGH');
      expect(v0?.reason).toContain('not included in the allowed license policy');
    });

    it('flags critical violation when package matches deny list even if in allow list', () => {
      const packages: PackageTarget[] = [
        {
          name: 'lib-agpl',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'lib-agpl', version: '1.0.0', license: 'AGPL-3.0' },
        },
      ];

      const result = evaluateLicenseCompliance(packages, {
        allow: ['MIT', 'AGPL-3.0'],
        deny: ['AGPL-3.0'],
      });
      expect(result.status).toBe('NON_COMPLIANT');
      expect(result.violationCount).toBe(1);
      const v0 = result.violations[0];
      expect(v0).toBeDefined();
      expect(v0?.packageName).toBe('lib-agpl');
      expect(v0?.severity).toBe('CRITICAL');
      expect(v0?.reason).toContain('explicitly prohibited by policy deny list');
    });

    it('evaluates dual-licensed (MIT OR GPL-3.0) package as compliant under permissive allow list', () => {
      const packages: PackageTarget[] = [
        {
          name: 'dual-licensed',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'dual-licensed', version: '1.0.0', license: '(MIT OR GPL-3.0)' },
        },
      ];

      const result = evaluateLicenseCompliance(packages, { allow: ['MIT'] });
      expect(result.status).toBe('COMPLIANT');
      expect(result.violationCount).toBe(0);
    });

    it('flags default strong copyleft licenses as MEDIUM violations when no policy is configured', () => {
      const packages: PackageTarget[] = [
        {
          name: 'copyleft-pkg',
          version: '1.0.0',
          ecosystem: 'npm',
          dir: tempDir,
          packageJson: { name: 'copyleft-pkg', version: '1.0.0', license: 'GPL-3.0' },
        },
      ];

      const result = evaluateLicenseCompliance(packages);
      expect(result.status).toBe('NON_COMPLIANT');
      expect(result.violationCount).toBe(1);
      const v0 = result.violations[0];
      expect(v0).toBeDefined();
      expect(v0?.packageName).toBe('copyleft-pkg');
      expect(v0?.severity).toBe('MEDIUM');
      expect(v0?.reason).toContain('Strong copyleft license');
    });
  });
});
