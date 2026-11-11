import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { AiUsageLedgerSchema, type AiUsageLedger } from '@secureship/contracts';
import { resolveSecureshipHome } from '../paths/index.js';

/**
 * Returns default path for the AI usage ledger.
 */
export function getDefaultAiUsagePath(): string {
  if (process.env.SECURESHIP_AI_USAGE_PATH) {
    return path.resolve(process.env.SECURESHIP_AI_USAGE_PATH);
  }
  if (process.env.VITEST === 'true') {
    return path.join(os.tmpdir(), '.secureship-test', 'ai-usage.json');
  }
  return path.join(resolveSecureshipHome(), 'ai-usage.json');
}

/**
 * Returns current calendar month key in YYYY-MM format.
 */
export function getCurrentMonthKey(date: Date = new Date()): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

/**
 * Reads the current monthly AI usage ledger.
 * Automatically resets count to 0 if a new month has started.
 */
export function getMonthlyAiUsage(
  ledgerPath: string = getDefaultAiUsagePath(),
  now: Date = new Date()
): AiUsageLedger {
  const currentMonth = getCurrentMonthKey(now);

  try {
    if (fs.existsSync(ledgerPath)) {
      const raw = JSON.parse(fs.readFileSync(ledgerPath, 'utf-8'));
      const parsed = AiUsageLedgerSchema.safeParse(raw);
      if (parsed.success) {
        if (parsed.data.month === currentMonth) {
          return parsed.data;
        }
        // Month boundary crossed — auto reset
        const resetData: AiUsageLedger = {
          month: currentMonth,
          fixesUsed: 0,
          lastUpdated: now.toISOString(),
        };
        saveMonthlyAiUsage(resetData, ledgerPath);
        return resetData;
      }
    }
  } catch {
    // Corrupted file -> fallback to fresh month ledger
  }

  return {
    month: currentMonth,
    fixesUsed: 0,
    lastUpdated: now.toISOString(),
  };
}

/**
 * Saves usage data atomically to disk.
 */
export function saveMonthlyAiUsage(
  data: AiUsageLedger,
  ledgerPath: string = getDefaultAiUsagePath()
): void {
  const targetDir = path.dirname(ledgerPath);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  }

  const tempPath = `${ledgerPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), { encoding: 'utf-8', mode: 0o600 });
  fs.renameSync(tempPath, ledgerPath);
}

/**
 * Records an executed AI fix by incrementing the monthly count.
 */
export function recordAiFixExecution(
  ledgerPath: string = getDefaultAiUsagePath(),
  now: Date = new Date()
): AiUsageLedger {
  const current = getMonthlyAiUsage(ledgerPath, now);
  const updated: AiUsageLedger = {
    month: current.month,
    fixesUsed: current.fixesUsed + 1,
    lastUpdated: now.toISOString(),
  };
  saveMonthlyAiUsage(updated, ledgerPath);
  return updated;
}

/**
 * Evaluates whether an AI fix is permitted under the given quota limit.
 */
export function canPerformAiFix(
  maxMonthlyAiFixes: number | null,
  ledgerPath: string = getDefaultAiUsagePath(),
  now: Date = new Date()
): { allowed: boolean; fixesUsed: number; limit: number | null; remaining: number | null } {
  // Unlimited tier (Enterprise)
  if (maxMonthlyAiFixes === null) {
    const usage = getMonthlyAiUsage(ledgerPath, now);
    return {
      allowed: true,
      fixesUsed: usage.fixesUsed,
      limit: null,
      remaining: null,
    };
  }

  const usage = getMonthlyAiUsage(ledgerPath, now);
  const remaining = Math.max(0, maxMonthlyAiFixes - usage.fixesUsed);
  const allowed = usage.fixesUsed < maxMonthlyAiFixes;

  return {
    allowed,
    fixesUsed: usage.fixesUsed,
    limit: maxMonthlyAiFixes,
    remaining,
  };
}
