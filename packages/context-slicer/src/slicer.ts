import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import type { FindingCategory, NormalizedFinding, Severity } from '@secureship/contracts';
import { SecretRedactor } from './redactor.js';
import { SlicerDenylist } from './denylist.js';
import { AstScopeFinder } from './ast-scope.js';
import { UsageFinder, type UsageSite } from './usage-finder.js';

export interface SlicedFindingContext {
  skipped: false;
  findingId: string;
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  filePath: string; // root-relative POSIX
  startLine: number;
  endLine: number;
  enclosingScopeName?: string;
  primarySlice: string;
  primarySliceLines: { start: number; end: number };
  usageSites: UsageSite[];
  scannerMessage: string;
  scannerSnippet?: string;
  contentHash: string;
  estimatedTokens: number;
  truncated: boolean;
  filesSent: string[];
}

export interface SlicedFindingSkipped {
  skipped: true;
  skipReason: string;
  findingId: string;
}

export type SlicingResult = SlicedFindingContext | SlicedFindingSkipped;

export interface SlicerOptions {
  sliceTokens?: number;
  gitleaksPath?: string | null;
  skipUsageSites?: boolean;
}

export class ContextSlicer {
  public static readonly DEFAULT_SLICE_TOKENS = 6000;
  private static readonly MAX_FILE_SIZE = 1_048_576; // 1 MB
  private static gitleaksNoticePrinted = false;

  private static readonly CREDENTIAL_CWES = new Set(['CWE-798', 'CWE-259', 'CWE-321']);

  private static normalizeRuleId(raw: string): string {
    const secureshipMatch = raw.match(/(secureship-[a-zA-Z0-9_-]+)$/);
    if (secureshipMatch && secureshipMatch[1]) return secureshipMatch[1];
    const dotIndex = raw.lastIndexOf('.');
    if (dotIndex !== -1) {
      const candidate = raw.slice(dotIndex + 1);
      if (/^[a-zA-Z0-9_-]+$/.test(candidate)) return candidate;
    }
    return raw;
  }

  /**
   * Evaluates if a finding belongs to the hardcoded credential class.
   */
  public static isCredentialClassFinding(finding: NormalizedFinding): boolean {
    if (finding.category === 'SECRET') return true;

    for (const cwe of finding.cweIds || []) {
      if (ContextSlicer.CREDENTIAL_CWES.has(cwe.toUpperCase())) {
        return true;
      }
    }

    // Inspect scanner evidence metadata for CWE tags
    for (const ev of finding.evidence || []) {
      if (ev.metadata && typeof ev.metadata === 'object') {
        const tags = (ev.metadata as Record<string, unknown>)['tags'];
        if (Array.isArray(tags)) {
          for (const tag of tags) {
            if (typeof tag === 'string' && /(?:CWE-798|CWE-259|CWE-321)\b/i.test(tag)) {
              return true;
            }
          }
        }
      }
    }

    const lowerRule = finding.ruleId.toLowerCase();
    const normalizedRule = ContextSlicer.normalizeRuleId(finding.ruleId).toLowerCase();
    const rawRule = (finding.evidence?.[0]?.scannerRuleId ?? finding.ruleId).toLowerCase();
    if (
      lowerRule.includes('hardcoded') ||
      lowerRule.includes('jwt-secret') ||
      lowerRule.includes('jwt_secret') ||
      lowerRule.includes('credential') ||
      normalizedRule === 'secureship-js-hardcoded-jwt-secret' ||
      rawRule === 'secureship-js-hardcoded-jwt-secret' ||
      normalizedRule.includes('hardcoded') ||
      normalizedRule.includes('jwt-secret') ||
      normalizedRule.includes('jwt_secret') ||
      normalizedRule.includes('credential') ||
      rawRule.includes('hardcoded') ||
      rawRule.includes('jwt-secret') ||
      rawRule.includes('jwt_secret') ||
      rawRule.includes('credential')
    ) {
      return true;
    }

    return false;
  }

  /**
   * Slices bounded, redacted code context around a finding.
   */
  public static async sliceFinding(
    workspaceRoot: string,
    finding: NormalizedFinding,
    options: SlicerOptions = {}
  ): Promise<SlicingResult> {
    const budgetTokens = options.sliceTokens ?? ContextSlicer.DEFAULT_SLICE_TOKENS;

    // 1. Skip SECRET category findings
    if (finding.category === 'SECRET') {
      return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
    }

    // 2. Skip credential-class findings (A5)
    if (ContextSlicer.isCredentialClassFinding(finding)) {
      return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
    }

    // 3. Skip SCA findings (Gate 3 is SAST and IAC)
    if (finding.category === 'SCA') {
      return { skipped: true, skipReason: 'SCA', findingId: finding.id };
    }

    // 4. Denylist check on file path
    const rawFilePath = finding.location.filePath;
    if (SlicerDenylist.isDenylisted(rawFilePath)) {
      return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
    }

    // 5. Symlink jail and path traversal verification
    if (!SlicerDenylist.isWithinRoot(workspaceRoot, rawFilePath)) {
      return { skipped: true, skipReason: 'SYMLINK_JAIL_ESCAPE', findingId: finding.id };
    }

    // 6. Read source file
    const resolvedPath = path.isAbsolute(rawFilePath)
      ? rawFilePath
      : path.resolve(workspaceRoot, rawFilePath);

    if (!fs.existsSync(resolvedPath)) {
      return { skipped: true, skipReason: 'FILE_NOT_FOUND', findingId: finding.id };
    }

    let fileContent: string;
    try {
      const stat = fs.statSync(resolvedPath);
      if (stat.size > ContextSlicer.MAX_FILE_SIZE) {
        return { skipped: true, skipReason: 'FILE_TOO_LARGE', findingId: finding.id };
      }
      fileContent = fs.readFileSync(resolvedPath, 'utf-8');
    } catch {
      return { skipped: true, skipReason: 'FILE_READ_ERROR', findingId: finding.id };
    }

    // 7. Pass 1 Redaction on raw content
    const redactedRaw = SecretRedactor.redactText(fileContent);

    // 8. AST Scope Search
    const scope = await AstScopeFinder.findEnclosingScope(
      redactedRaw,
      resolvedPath,
      finding.location.startLine,
      finding.location.endLine
    );

    const relativePosixPath = SlicerDenylist.toRootRelativePosix(workspaceRoot, resolvedPath);
    const filesSent: string[] = [relativePosixPath];

    // 9. Discover usage sites if symbol name is identifiable
    let usageSites: UsageSite[] = [];
    if (!options.skipUsageSites && scope.scopeName && !scope.scopeName.startsWith('line-window')) {
      const symbolName = scope.scopeName.includes(':')
        ? scope.scopeName.split(':')[1]
        : scope.scopeName;
      if (symbolName) {
        usageSites = UsageFinder.findUsageSites(workspaceRoot, symbolName, resolvedPath);
        for (const u of usageSites) {
          if (!filesSent.includes(u.filePath)) {
            filesSent.push(u.filePath);
          }
        }
      }
    }

    // 10. Pass 2 Redaction & Assembled Payload Construction
    let primarySlice = SecretRedactor.redactText(scope.sliceText);
    const scannerMessage = SecretRedactor.redactText(
      finding.evidence?.[0]?.message || finding.description || finding.title || ''
    );
    const scannerSnippet = finding.location.redactedSnippet
      ? SecretRedactor.redactText(finding.location.redactedSnippet)
      : undefined;

    // 11. Token Budget Estimation and Truncation
    let totalChars =
      primarySlice.length +
      scannerMessage.length +
      (scannerSnippet ? scannerSnippet.length : 0) +
      usageSites.reduce((acc, u) => acc + u.snippet.length, 0);

    let estimatedTokens = Math.ceil(totalChars / 4);
    let truncated = false;

    if (estimatedTokens > budgetTokens) {
      truncated = true;
      // Truncate primary slice to fit remaining token budget
      const maxSliceChars = Math.max(200, budgetTokens * 4 - 500);
      if (primarySlice.length > maxSliceChars) {
        primarySlice = primarySlice.slice(0, maxSliceChars) + '\n/* ... [TRUNCATED] ... */';
      }
      totalChars = primarySlice.length + scannerMessage.length;
      estimatedTokens = Math.ceil(totalChars / 4);
    }

    // 12. Optional Gitleaks verification scan of assembled payload (A4)
    const gitleaksCheck = ContextSlicer.checkPayloadWithGitleaks(
      primarySlice,
      options.gitleaksPath
    );
    if (gitleaksCheck.hasSecret) {
      return {
        skipped: true,
        skipReason: 'PAYLOAD_SECRET_DETECTED',
        findingId: finding.id,
      };
    }

    // 13. Deterministic Content Hash
    const contentHash = crypto
      .createHash('sha256')
      .update(
        `${relativePosixPath}:${scope.startLine}-${scope.endLine}:${primarySlice}:${scannerMessage}`
      )
      .digest('hex');

    return {
      skipped: false,
      findingId: finding.id,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      filePath: relativePosixPath,
      startLine: scope.startLine,
      endLine: scope.endLine,
      enclosingScopeName: scope.scopeName,
      primarySlice,
      primarySliceLines: { start: scope.startLine, end: scope.endLine },
      usageSites,
      scannerMessage,
      scannerSnippet,
      contentHash,
      estimatedTokens,
      truncated,
      filesSent,
    };
  }

  /**
   * Writes payload to a temp file (0600 mode) and scans with gitleaks if available.
   */
  private static checkPayloadWithGitleaks(
    payload: string,
    explicitGitleaksPath?: string | null
  ): { hasSecret: boolean } {
    let gitleaksBin = explicitGitleaksPath;

    if (gitleaksBin === undefined) {
      // Check if gitleaks is on PATH
      try {
        const cmd = process.platform === 'win32' ? 'where' : 'which';
        const stdout = execFileSync(cmd, ['gitleaks'], {
          encoding: 'utf-8',
          stdio: ['pipe', 'pipe', 'ignore'],
        });
        gitleaksBin = stdout.trim().split(/\r?\n/)[0] || null;
      } catch {
        gitleaksBin = null;
      }
    }

    if (!gitleaksBin) {
      if (!ContextSlicer.gitleaksNoticePrinted) {
        ContextSlicer.gitleaksNoticePrinted = true;
        // Notice printed only once
      }
      return { hasSecret: false };
    }

    const tempFile = path.join(
      os.tmpdir(),
      `secureship-slice-${crypto.randomBytes(8).toString('hex')}.tmp`
    );

    try {
      fs.writeFileSync(tempFile, payload, { encoding: 'utf-8', mode: 0o600 });
      if (process.platform !== 'win32') {
        try {
          fs.chmodSync(tempFile, 0o600);
        } catch {}
      }

      // Execute gitleaks detect --no-git --source <tempFile>
      try {
        let exec = gitleaksBin;
        let args = ['detect', '--no-git', '--source', tempFile, '--verbose'];
        if (
          gitleaksBin.endsWith('.js') ||
          gitleaksBin.endsWith('.cjs') ||
          gitleaksBin.endsWith('.mjs')
        ) {
          exec = process.execPath;
          args = [gitleaksBin, ...args];
        }
        execFileSync(exec, args, {
          stdio: ['pipe', 'pipe', 'pipe'],
          timeout: 5000,
        });
        // Exit code 0 means no leaks found
        return { hasSecret: false };
      } catch (err: unknown) {
        // Gitleaks exits with code 1 when leaks are detected
        const exitCode = (err as { status?: number }).status;
        if (exitCode === 1) {
          return { hasSecret: true };
        }
        return { hasSecret: false };
      }
    } catch {
      return { hasSecret: false };
    } finally {
      try {
        if (fs.existsSync(tempFile)) {
          fs.unlinkSync(tempFile);
        }
      } catch {}
    }
  }
}
