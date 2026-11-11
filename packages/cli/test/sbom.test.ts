import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SbomCommand, SbomOptionsSchema } from '../src/commands/sbom.js';

describe('SbomCommand — Production CLI Suite (Phase 4)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sbom-cli-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('validates SbomOptionsSchema defaults accurately', () => {
    const parsed = SbomOptionsSchema.parse({});
    expect(parsed.format).toBe('cyclonedx');
    expect(parsed.dir).toBe('.');
    expect(parsed.withVulns).toBe(false);
    expect(parsed.checkLicenses).toBe(false);
    expect(parsed.json).toBe(false);
  });

  it('returns exit code 1 when target directory does not exist', async () => {
    const nonExistent = path.join(tempDir, 'missing-dir-12345');
    const exitCode = await SbomCommand.run(nonExistent);
    expect(exitCode).toBe(1);
  });

  it('generates CycloneDX SBOM and writes to output file', async () => {
    // Setup dummy package in tempDir
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'dummy-pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeModulesDir, 'package.json'),
      JSON.stringify({ name: 'dummy-pkg', version: '1.0.0', license: 'MIT' }),
      'utf-8'
    );

    const outputFile = path.join(tempDir, 'cyclonedx.json');
    const exitCode = await SbomCommand.run(tempDir, {
      format: 'cyclonedx',
      output: outputFile,
    });

    expect(exitCode).toBe(0);
    expect(fs.existsSync(outputFile)).toBe(true);

    const content = JSON.parse(fs.readFileSync(outputFile, 'utf-8')) as {
      bomFormat: string;
      specVersion: string;
      components: { name: string; version: string; purl: string }[];
    };
    expect(content.bomFormat).toBe('CycloneDX');
    expect(content.specVersion).toBe('1.5');
    expect(content.components.some((c) => c.name === 'dummy-pkg')).toBe(true);
  });

  it('generates SPDX SBOM when --format spdx is requested', async () => {
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'spdx-pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeModulesDir, 'package.json'),
      JSON.stringify({ name: 'spdx-pkg', version: '2.1.0', license: 'Apache-2.0' }),
      'utf-8'
    );

    const outputFile = path.join(tempDir, 'spdx.json');
    const exitCode = await SbomCommand.run(tempDir, {
      format: 'spdx',
      output: outputFile,
    });

    expect(exitCode).toBe(0);
    expect(fs.existsSync(outputFile)).toBe(true);

    const content = JSON.parse(fs.readFileSync(outputFile, 'utf-8')) as {
      spdxVersion: string;
      packages: { name: string; versionInfo: string; licenseConcluded: string }[];
    };
    expect(content.spdxVersion).toBe('SPDX-2.3');
    expect(content.packages.some((p) => p.name === 'spdx-pkg')).toBe(true);
  });

  it('evaluates license compliance and returns 0 when compliant', async () => {
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'compliant-pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeModulesDir, 'package.json'),
      JSON.stringify({ name: 'compliant-pkg', version: '1.0.0', license: 'MIT' }),
      'utf-8'
    );

    const exitCode = await SbomCommand.run(tempDir, {
      checkLicenses: true,
      allow: ['MIT', 'Apache-2.0'],
    });

    expect(exitCode).toBe(0);
  });

  it('evaluates license compliance and returns exit code 1 when violation detected', async () => {
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'forbidden-pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeModulesDir, 'package.json'),
      JSON.stringify({ name: 'forbidden-pkg', version: '1.0.0', license: 'GPL-3.0' }),
      'utf-8'
    );

    const exitCode = await SbomCommand.run(tempDir, {
      checkLicenses: true,
      allow: ['MIT', 'Apache-2.0'],
    });

    expect(exitCode).toBe(1);
  });

  it('enriches components with vulnerabilities when --with-vulns is specified with explicit report', async () => {
    const nodeModulesDir = path.join(tempDir, 'node_modules', 'target-pkg');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    const targetPkgJson = path.join(nodeModulesDir, 'package.json');
    fs.writeFileSync(
      targetPkgJson,
      JSON.stringify({ name: 'target-pkg', version: '1.0.0', license: 'MIT' }),
      'utf-8'
    );

    const reportFile = path.join(tempDir, 'report.json');
    const dummyReport = {
      runId: 'rep-1',
      timestamp: new Date().toISOString(),
      targetDirectory: tempDir,
      status: 'COMPLETED',
      durationMs: 10,
      scannersExecuted: ['supply-chain'],
      summary: { total: 1, bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } },
      findings: [
        {
          id: 'vuln-1',
          findingId: 'vuln-1',
          ruleId: 'SC-EVIL-001',
          severity: 'CRITICAL',
          category: 'SUPPLY_CHAIN',
          scanner: 'supply-chain',
          location: { filePath: targetPkgJson, startLine: 1, endLine: 1 },
          message: 'Malicious payload in target-pkg',
          package: { name: 'target-pkg', version: '1.0.0', ecosystem: 'npm' },
          evidence: [
            { scannerName: 'generic', scannerRuleId: 'SC-EVIL-001', message: 'Malicious' },
          ],
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          fingerprint: 'fp-target-1',
        },
      ],
      suppressed: [],
    };
    fs.writeFileSync(reportFile, JSON.stringify(dummyReport), 'utf-8');

    const outputFile = path.join(tempDir, 'sbom-with-vulns.json');
    const exitCode = await SbomCommand.run(tempDir, {
      withVulns: true,
      report: reportFile,
      output: outputFile,
    });

    expect(exitCode).toBe(0);
    const content = JSON.parse(fs.readFileSync(outputFile, 'utf-8')) as {
      components: { name: string; vulnerabilities?: { id: string }[] }[];
    };
    const targetComp = content.components.find((c) => c.name === 'target-pkg');
    expect(targetComp).toBeDefined();
    expect(targetComp?.vulnerabilities).toBeDefined();
    expect(targetComp?.vulnerabilities?.[0]?.id).toBe('SC-EVIL-001');
  });

  it('outputs valid JSON structure in --json mode without error', async () => {
    const exitCode = await SbomCommand.run(tempDir, {
      json: true,
      checkLicenses: true,
      allow: ['MIT', 'Apache-2.0', 'NOASSERTION'],
    });

    expect(exitCode).toBe(0);
  });
});
