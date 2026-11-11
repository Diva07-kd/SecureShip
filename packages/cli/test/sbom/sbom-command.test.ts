import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type LicenseComplianceResult, TIER_CAPABILITY_DEFAULTS } from '@secureship/contracts';
import {
  discoverPackages,
  evaluateLicenseCompliance,
  resolveTierCapabilities,
  type PackageTarget,
  type ResolvedTierState,
} from '@secureship/core-engine';
import { SbomCommand } from '../../src/commands/sbom.js';

vi.mock('@secureship/core-engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@secureship/core-engine')>();
  return {
    ...actual,
    discoverPackages: vi.fn(),
    resolveTierCapabilities: vi.fn(),
    evaluateLicenseCompliance: vi.fn(),
  };
});

describe('SbomCommand Integration Suite (Phase 4)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let stdoutCaptured: string;
  let stderrCaptured: string;

  beforeEach(() => {
    vi.clearAllMocks();
    stdoutCaptured = '';
    stderrCaptured = '';

    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdoutCaptured +=
        args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\n';
    });

    errorSpy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderrCaptured +=
        args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ') + '\n';
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('sbom generates valid CycloneDX 1.5 JSON structure for discovered packages', async () => {
    const mockPackages: PackageTarget[] = [
      {
        name: 'pkg-alpha',
        version: '1.0.0',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-alpha'),
        packageJson: { name: 'pkg-alpha', version: '1.0.0', license: 'MIT' },
      },
      {
        name: 'pkg-beta',
        version: '2.3.1',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-beta'),
        packageJson: { name: 'pkg-beta', version: '2.3.1', license: 'Apache-2.0' },
      },
      {
        name: 'pkg-gamma',
        version: '0.9.0',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-gamma'),
        packageJson: { name: 'pkg-gamma', version: '0.9.0', license: 'BSD-3-Clause' },
      },
    ];

    vi.mocked(discoverPackages).mockReturnValue(mockPackages);

    const exitCode = await SbomCommand.run('.', { format: 'cyclonedx', json: true });

    expect(exitCode).toBe(0);
    expect(stdoutCaptured.trim().length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdoutCaptured) as {
      bomFormat: string;
      specVersion: string;
      components: { name: string; version: string; purl: string }[];
    };

    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.5');
    expect(parsed.components).toHaveLength(3);

    for (const comp of parsed.components) {
      expect(comp.purl).toMatch(/^pkg:npm\//);
    }

    expect(parsed.components[0]?.name).toBe('pkg-alpha');
    expect(parsed.components[0]?.purl).toBe('pkg:npm/pkg-alpha@1.0.0');
    expect(parsed.components[1]?.name).toBe('pkg-beta');
    expect(parsed.components[1]?.purl).toBe('pkg:npm/pkg-beta@2.3.1');
    expect(parsed.components[2]?.name).toBe('pkg-gamma');
    expect(parsed.components[2]?.purl).toBe('pkg:npm/pkg-gamma@0.9.0');
  });

  it('sbom generates valid SPDX 2.3 JSON structure', async () => {
    const mockPackages: PackageTarget[] = [
      {
        name: 'pkg-alpha',
        version: '1.0.0',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-alpha'),
        packageJson: { name: 'pkg-alpha', version: '1.0.0', license: 'MIT' },
      },
      {
        name: 'pkg-beta',
        version: '2.3.1',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-beta'),
        packageJson: { name: 'pkg-beta', version: '2.3.1', license: 'Apache-2.0' },
      },
      {
        name: 'pkg-gamma',
        version: '0.9.0',
        ecosystem: 'npm',
        dir: path.resolve('node_modules/pkg-gamma'),
        packageJson: { name: 'pkg-gamma', version: '0.9.0', license: 'BSD-3-Clause' },
      },
    ];

    vi.mocked(discoverPackages).mockReturnValue(mockPackages);

    const exitCode = await SbomCommand.run('.', { format: 'spdx', json: true });

    expect(exitCode).toBe(0);
    expect(stdoutCaptured.trim().length).toBeGreaterThan(0);

    const parsed = JSON.parse(stdoutCaptured) as {
      spdxVersion: string;
      packages: { name: string; versionInfo: string }[];
    };

    expect(parsed.spdxVersion).toBe('SPDX-2.3');
    expect(Array.isArray(parsed.packages)).toBe(true);
    expect(parsed.packages).toHaveLength(3);
    expect(parsed.packages[0]?.name).toBe('pkg-alpha');
    expect(parsed.packages[1]?.name).toBe('pkg-beta');
    expect(parsed.packages[2]?.name).toBe('pkg-gamma');
  });

  it('sbom --signed rejects on FREE tier with exit code 1', async () => {
    const freeTierState: ResolvedTierState = {
      tier: 'FREE_BYOK',
      status: 'UNLICENSED_FREE',
      source: 'default',
      licensePath: '',
      capabilities: TIER_CAPABILITY_DEFAULTS.FREE_BYOK,
    };

    vi.mocked(resolveTierCapabilities).mockResolvedValue(freeTierState);

    const exitCode = await SbomCommand.run('.', { signed: true });

    expect(exitCode).toBe(1);
    expect(stderrCaptured).toContain('PRO_TEAM or ENTERPRISE');
    expect(stderrCaptured).toContain('https://secureship.dev/pricing');
    expect(stderrCaptured).toContain(
      "Run 'secureship license upgrade' to unlock signed compliance exports."
    );
  });

  it('sbom --check-licenses with deny=GPL-3.0 returns exit code 1 when violation found', async () => {
    const gplPackage: PackageTarget = {
      name: 'gpl-dep',
      version: '1.2.3',
      ecosystem: 'npm',
      dir: path.resolve('node_modules/gpl-dep'),
      packageJson: { name: 'gpl-dep', version: '1.2.3', license: 'GPL-3.0-or-later' },
    };

    const mockViolationResult: LicenseComplianceResult = {
      status: 'NON_COMPLIANT',
      totalPackages: 1,
      compliantCount: 0,
      violationCount: 1,
      allowedList: [],
      deniedList: ['GPL-3.0'],
      violations: [
        {
          packageName: 'gpl-dep',
          version: '1.2.3',
          license: 'GPL-3.0-or-later',
          reason: "License 'GPL-3.0-or-later' matches denied policy 'GPL-3.0'.",
          severity: 'HIGH',
        },
      ],
    };

    vi.mocked(discoverPackages).mockReturnValue([gplPackage]);
    vi.mocked(evaluateLicenseCompliance).mockReturnValue(mockViolationResult);

    const exitCode = await SbomCommand.run('.', {
      checkLicenses: true,
      deny: ['GPL-3.0'],
    });

    expect(exitCode).toBe(1);
    expect(vi.mocked(evaluateLicenseCompliance)).toHaveBeenCalledWith([gplPackage], {
      allow: undefined,
      deny: ['GPL-3.0'],
    });
  });

  it('sbom gracefully returns 1 when target directory does not exist', async () => {
    const nonExistentDir = path.resolve('missing-target-dir-non-existent-12345');

    const exitCode = await SbomCommand.run(nonExistentDir);

    expect(exitCode).toBe(1);
    expect(stderrCaptured).toContain(nonExistentDir);
    expect(stderrCaptured).toContain('Target directory does not exist');
  });
});
