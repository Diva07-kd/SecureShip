import { describe, it, expect, vi } from 'vitest';
import path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  getInstallHint,
  compareSemver,
  isVersionSupported,
  GitleaksAdapter,
  OpengrepAdapter,
  TrivyAdapter,
  OsvScannerAdapter,
  CheckovAdapter,
} from '../src/index.js';
import { SafeProcessRunner } from '@secureship/core-engine';
import type { ProjectProfile } from '@secureship/contracts';

describe('Scanner Adapters & Supported Versions Deep Coverage Suite', () => {
  it('supported-versions.ts: extracts install hints across win32, darwin, and linux', () => {
    // Win32 with winget note
    const gitleaksWin = getInstallHint('gitleaks', 'win32');
    expect(gitleaksWin).toContain('winget install Gitleaks.Gitleaks');
    expect(gitleaksWin).toContain('refresh PATH');

    // Opengrep win32
    const opengrepWin = getInstallHint('opengrep', 'win32');
    expect(opengrepWin).toContain('install.ps1');

    // Darwin (brew)
    const gitleaksMac = getInstallHint('gitleaks', 'darwin');
    expect(gitleaksMac).toContain('brew install');

    // Linux
    const trivyLinux = getInstallHint('trivy', 'linux');
    expect(trivyLinux).toContain('apt-get');

    // Unknown scanner
    const unknownHint = getInstallHint('nonexistent_tool');
    expect(unknownHint).toContain('Install nonexistent_tool and ensure it is available');
  });

  it('supported-versions.ts: compares semver strings and validates thresholds', () => {
    expect(compareSemver('8.30.1', '8.0.0')).toBeGreaterThan(0);
    expect(compareSemver('8.0.0', '8.30.1')).toBeLessThan(0);
    expect(compareSemver('1.2.3', '1.2.3')).toBe(0);
    expect(compareSemver('2.0.0', '1.99.99')).toBeGreaterThan(0);
    expect(compareSemver('1.5.0', '1.4.9')).toBeGreaterThan(0);
    expect(compareSemver('1.5.0', '1.5.1')).toBeLessThan(0);
    expect(compareSemver('invalid_str', '1.0.0')).toBeLessThan(0);

    expect(isVersionSupported('8.30.1', '8.18.0')).toBe(true);
    expect(isVersionSupported('1.0.0', '2.0.0')).toBe(false);
  });

  it('supportsProject checks project profile matching across all 5 adapters', () => {
    const gitleaks = new GitleaksAdapter();
    const opengrep = new OpengrepAdapter();
    const trivy = new TrivyAdapter();
    const osv = new OsvScannerAdapter();
    const checkov = new CheckovAdapter();

    const emptyProfile: ProjectProfile = {
      workspaceRoot: 'c:/test',
      languages: [],
      frameworks: [],
      packageManagers: [],
      lockfiles: [],
      iacManifests: [],
      testDirectories: [],
      recommendedScanners: [],
      totalFilesScanned: 0,
      hasGit: false,
    };

    // Gitleaks supports everything
    expect(gitleaks.supportsProject(emptyProfile)).toBe(true);

    // Opengrep checks languages or recommendation
    expect(opengrep.supportsProject(emptyProfile)).toBe(false);
    expect(opengrep.supportsProject({ ...emptyProfile, languages: ['JavaScript'] })).toBe(true);
    expect(opengrep.supportsProject({ ...emptyProfile, recommendedScanners: ['opengrep'] })).toBe(
      true
    );

    // Trivy checks lockfiles, packageManagers, iac, or recommendation
    expect(trivy.supportsProject(emptyProfile)).toBe(false);
    expect(trivy.supportsProject({ ...emptyProfile, lockfiles: ['package-lock.json'] })).toBe(true);
    expect(trivy.supportsProject({ ...emptyProfile, packageManagers: ['npm'] })).toBe(true);
    expect(trivy.supportsProject({ ...emptyProfile, iacManifests: ['Dockerfile'] })).toBe(true);

    // OSV-Scanner checks lockfiles or recommendation
    expect(osv.supportsProject(emptyProfile)).toBe(false);
    expect(osv.supportsProject({ ...emptyProfile, lockfiles: ['pnpm-lock.yaml'] })).toBe(true);
    expect(osv.supportsProject({ ...emptyProfile, recommendedScanners: ['osv-scanner'] })).toBe(
      true
    );

    // Checkov checks iacManifests or recommendation
    expect(checkov.supportsProject(emptyProfile)).toBe(false);
    expect(checkov.supportsProject({ ...emptyProfile, iacManifests: ['main.tf'] })).toBe(true);
    expect(checkov.supportsProject({ ...emptyProfile, recommendedScanners: ['checkov'] })).toBe(
      true
    );
  });

  it('handles timeout path on all adapters cleanly', async () => {
    // Mock SafeProcessRunner to simulate a timeout
    const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: '',
      stderr: 'Process exceeded time limit',
      exitCode: 124,
      signal: null,
      timedOut: true,
      truncated: false,
      durationMs: 5000,
    });

    try {
      const gitleaks = new GitleaksAdapter();
      const resG = await gitleaks.scan(process.cwd(), { timeoutMs: 5000 });
      expect(resG.status).toBe('TIMEOUT');
      expect(resG.timedOut).toBe(true);

      const opengrep = new OpengrepAdapter();
      const resO = await opengrep.scan(process.cwd(), { timeoutMs: 5000 });
      expect(resO.status).toBe('TIMEOUT');
      expect(resO.timedOut).toBe(true);

      const trivy = new TrivyAdapter();
      const resT = await trivy.scan(process.cwd(), { timeoutMs: 5000 });
      expect(resT.status).toBe('TIMEOUT');
      expect(resT.timedOut).toBe(true);

      const osv = new OsvScannerAdapter();
      const resOsv = await osv.scan(process.cwd(), { timeoutMs: 5000 });
      expect(resOsv.status).toBe('TIMEOUT');
      expect(resOsv.timedOut).toBe(true);

      const checkov = new CheckovAdapter();
      const resC = await checkov.scan(process.cwd(), { timeoutMs: 5000 });
      expect(resC.status).toBe('TIMEOUT');
      expect(resC.timedOut).toBe(true);
    } finally {
      runSpy.mockRestore();
    }
  });

  it('handles process throwing unexpected exception on all adapters', async () => {
    const runSpy = vi
      .spyOn(SafeProcessRunner, 'run')
      .mockRejectedValue(new Error('Spawn ENOENT / OS failure'));

    try {
      const gitleaks = new GitleaksAdapter();
      const resG = await gitleaks.scan(process.cwd());
      expect(resG.status).toBe('ERROR');
      expect(resG.errorMessage).toContain('Spawn ENOENT');

      const opengrep = new OpengrepAdapter();
      const resO = await opengrep.scan(process.cwd());
      expect(resO.status).toBe('ERROR');
      expect(resO.errorMessage).toContain('Spawn ENOENT');

      const trivy = new TrivyAdapter();
      const resT = await trivy.scan(process.cwd());
      expect(resT.status).toBe('ERROR');
      expect(resT.errorMessage).toContain('Spawn ENOENT');

      const osv = new OsvScannerAdapter();
      const resOsv = await osv.scan(process.cwd());
      expect(resOsv.status).toBe('ERROR');
      expect(resOsv.errorMessage).toContain('Spawn ENOENT');

      const checkov = new CheckovAdapter();
      const resC = await checkov.scan(process.cwd());
      expect(resC.status).toBe('ERROR');
      expect(resC.errorMessage).toContain('Spawn ENOENT');
    } finally {
      runSpy.mockRestore();
    }
  });

  it('handles version() error and non-zero exit codes gracefully', async () => {
    const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: '',
      stderr: 'Version query failed',
      exitCode: 1,
      signal: null,
      timedOut: false,
      truncated: false,
      durationMs: 100,
    });

    try {
      const gitleaks = new GitleaksAdapter();
      expect(await gitleaks.version()).toBe('Unknown');

      const opengrep = new OpengrepAdapter();
      expect(await opengrep.version()).toBe('Unknown');

      const trivy = new TrivyAdapter();
      expect(await trivy.version()).toBe('Unknown');

      const osv = new OsvScannerAdapter();
      expect(await osv.version()).toBe('Unknown');

      const checkov = new CheckovAdapter();
      expect(await checkov.version()).toBe('Unknown');
    } finally {
      runSpy.mockRestore();
    }
  });

  it('handles exit code 0 without SARIF output returning SUCCESS with 0 findings across all adapters', async () => {
    // Process exits 0 without writing SARIF file
    const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
      stdout: 'Clean scan completed',
      stderr: '',
      exitCode: 0,
      signal: null,
      timedOut: false,
      truncated: false,
      durationMs: 150,
    });

    try {
      const gitleaks = new GitleaksAdapter();
      const resG = await gitleaks.scan(process.cwd());
      expect(resG.status).toBe('SUCCESS');
      expect(resG.findings).toHaveLength(0);

      const opengrep = new OpengrepAdapter();
      const resO = await opengrep.scan(process.cwd(), {
        changedFiles: ['src/app.ts', 'src/util.ts'],
      });
      expect(resO.status).toBe('SUCCESS');
      expect(resO.findings).toHaveLength(0);

      const trivy = new TrivyAdapter();
      const resT = await trivy.scan(process.cwd());
      expect(resT.status).toBe('SUCCESS');
      expect(resT.findings).toHaveLength(0);

      const osv = new OsvScannerAdapter();
      const resOsv = await osv.scan(process.cwd());
      expect(resOsv.status).toBe('SUCCESS');
      expect(resOsv.findings).toHaveLength(0);

      const checkov = new CheckovAdapter();
      const resC = await checkov.scan(process.cwd());
      expect(resC.status).toBe('SUCCESS');
      expect(resC.findings).toHaveLength(0);
    } finally {
      runSpy.mockRestore();
    }
  });

  it('handles TOOL_MISSING on all adapters when binary cannot be resolved', async () => {
    const invalidPath = path.resolve('c:/nonexistent/fake-tool');

    const gitleaks = new GitleaksAdapter({ binaryOverride: invalidPath });
    expect(await gitleaks.isAvailable()).toBe(false);
    const resG = await gitleaks.scan(process.cwd());
    expect(resG.status).toBe('TOOL_MISSING');

    const opengrep = new OpengrepAdapter({ binaryOverride: invalidPath });
    expect(await opengrep.isAvailable()).toBe(false);
    const resO = await opengrep.scan(process.cwd());
    expect(resO.status).toBe('TOOL_MISSING');

    const trivy = new TrivyAdapter({ binaryOverride: invalidPath });
    expect(await trivy.isAvailable()).toBe(false);
    const resT = await trivy.scan(process.cwd());
    expect(resT.status).toBe('TOOL_MISSING');

    const osv = new OsvScannerAdapter({ binaryOverride: invalidPath });
    expect(await osv.isAvailable()).toBe(false);
    const resOsv = await osv.scan(process.cwd());
    expect(resOsv.status).toBe('TOOL_MISSING');

    const checkov = new CheckovAdapter({ binaryOverride: invalidPath });
    expect(await checkov.isAvailable()).toBe(false);
    const resC = await checkov.scan(process.cwd());
    expect(resC.status).toBe('TOOL_MISSING');
  });

  it('checkov.adapter: tests .cmd shim resolution, python fallback, and offline execution', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'checkov-cov-'));
    const cmdShim = path.join(tempDir, 'checkov.cmd');
    writeFileSync(cmdShim, '@echo off\npython -m checkov %*');

    try {
      const checkovCmd = new CheckovAdapter({ binaryOverride: cmdShim, offline: true });
      const exec = checkovCmd.resolveExecution();
      expect(exec).not.toBeNull();
      expect(exec!.argsPrefix).toContain('checkov.main');

      const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
        stdout: 'Checkov offline scan output',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        truncated: false,
        durationMs: 200,
      });

      try {
        const scanRes = await checkovCmd.scan(process.cwd());
        expect(scanRes.status).toBe('SUCCESS');
        const firstCall = runSpy.mock.calls[0];
        expect(firstCall).toBeDefined();
        const calledArgs = firstCall?.[1] as string[] | undefined;
        expect(calledArgs).toContain('--skip-download');
      } finally {
        runSpy.mockRestore();
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('checkov.adapter: tests isAvailable, version, and execution branches', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'checkov-cov2-'));
    const mockBin = path.join(tempDir, 'checkov-mock');
    writeFileSync(mockBin, '#!/bin/sh\necho "3.2.0"');

    try {
      const directAdapter = new CheckovAdapter({ binaryOverride: mockBin });
      expect(directAdapter.resolveExecution()?.executable).toBe(path.resolve(mockBin));
      expect(await directAdapter.isAvailable()).toBe(true);

      const runSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
        stdout: '3.2.350',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        truncated: false,
        durationMs: 50,
      });

      try {
        expect(await directAdapter.version()).toBe('3.2.350');
      } finally {
        runSpy.mockRestore();
      }

      const cmdShim = path.join(tempDir, 'checkov.cmd');
      writeFileSync(cmdShim, '@echo off\npython -m checkov %*');
      const pyAdapter = new CheckovAdapter({ binaryOverride: cmdShim });

      const successSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
        stdout: 'Checkov 3.2.1',
        stderr: '',
        exitCode: 0,
        signal: null,
        timedOut: false,
        truncated: false,
        durationMs: 50,
      });
      try {
        expect(await pyAdapter.isAvailable()).toBe(true);
      } finally {
        successSpy.mockRestore();
      }

      const failSpy = vi.spyOn(SafeProcessRunner, 'run').mockResolvedValue({
        stdout: '',
        stderr: 'No module named checkov',
        exitCode: 1,
        signal: null,
        timedOut: false,
        truncated: false,
        durationMs: 50,
      });
      try {
        expect(await pyAdapter.isAvailable()).toBe(false);
      } finally {
        failSpy.mockRestore();
      }

      const throwSpy = vi
        .spyOn(SafeProcessRunner, 'run')
        .mockRejectedValue(new Error('Spawn failed'));
      try {
        expect(await pyAdapter.isAvailable()).toBe(false);
      } finally {
        throwSpy.mockRestore();
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
