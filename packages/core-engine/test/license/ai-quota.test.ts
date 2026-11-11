import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TIER_CAPABILITY_DEFAULTS } from '@secureship/contracts';
import {
  ScanOrchestrator,
  type OrchestratorRunOptions,
} from '../../src/orchestrator/scan-orchestrator.js';
import * as licenseResolver from '../../src/license/tier-resolver.js';
import * as aiUsageLedger from '../../src/license/ai-usage-ledger.js';

describe('AI Usage Quota Enforcement in Scan Orchestrator (Task 3)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-ai-quota-test-'));
    vi.restoreAllMocks();
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
    vi.restoreAllMocks();
  });

  it('AI triage disabled when fixesUsed >= maxMonthlyAiFixes for FREE_BYOK', async () => {
    vi.spyOn(licenseResolver, 'resolveTierCapabilities').mockResolvedValue({
      tier: 'FREE_BYOK',
      capabilities: {
        ...TIER_CAPABILITY_DEFAULTS['FREE_BYOK'],
        maxMonthlyAiFixes: 15,
      },
      status: 'UNLICENSED_FREE',
      licensePath: path.join(tempDir, 'license.jwt'),
      source: 'default',
    });

    vi.spyOn(aiUsageLedger, 'getMonthlyAiUsage').mockReturnValue({
      month: '2026-10',
      fixesUsed: 15,
      lastUpdated: new Date().toISOString(),
    });

    const options: OrchestratorRunOptions = {
      adapters: [],
      ai: true,
      targetDir: tempDir,
    };

    await ScanOrchestrator.scan(options);

    expect(options.ai).toBe(false);
  });

  it('AI triage NOT disabled for PRO_TEAM (maxMonthlyAiFixes: 100)', async () => {
    vi.spyOn(licenseResolver, 'resolveTierCapabilities').mockResolvedValue({
      tier: 'PRO_TEAM',
      capabilities: {
        ...TIER_CAPABILITY_DEFAULTS['PRO_TEAM'],
        maxMonthlyAiFixes: 100,
      },
      status: 'ACTIVE',
      licensePath: path.join(tempDir, 'license.jwt'),
      source: 'jwt',
    });

    vi.spyOn(aiUsageLedger, 'getMonthlyAiUsage').mockReturnValue({
      month: '2026-10',
      fixesUsed: 50,
      lastUpdated: new Date().toISOString(),
    });

    const options: OrchestratorRunOptions = {
      adapters: [],
      ai: true,
      aiDryRun: true,
      targetDir: tempDir,
    };

    await ScanOrchestrator.scan(options);

    expect(options.ai).toBe(true);
  });

  it('AI triage NOT disabled for ENTERPRISE (maxMonthlyAiFixes: null = unlimited)', async () => {
    vi.spyOn(licenseResolver, 'resolveTierCapabilities').mockResolvedValue({
      tier: 'ENTERPRISE',
      capabilities: {
        ...TIER_CAPABILITY_DEFAULTS['ENTERPRISE'],
        maxMonthlyAiFixes: null,
      },
      status: 'ACTIVE',
      licensePath: path.join(tempDir, 'license.jwt'),
      source: 'jwt',
    });

    vi.spyOn(aiUsageLedger, 'getMonthlyAiUsage').mockReturnValue({
      month: '2026-10',
      fixesUsed: 9999,
      lastUpdated: new Date().toISOString(),
    });

    const options: OrchestratorRunOptions = {
      adapters: [],
      ai: true,
      aiDryRun: true,
      targetDir: tempDir,
    };

    await ScanOrchestrator.scan(options);

    expect(options.ai).toBe(true);
  });
});
