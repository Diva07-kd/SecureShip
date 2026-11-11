import fs from 'node:fs';
import path from 'node:path';
import { SecretRedactor } from './redactor.js';
import { SlicerDenylist } from './denylist.js';

export interface UsageSite {
  filePath: string; // root-relative POSIX
  startLine: number;
  endLine: number;
  snippet: string;
}

export class UsageFinder {
  private static readonly MAX_USAGE_SITES = 3;
  private static readonly MAX_FILE_SIZE = 1_048_576; // 1 MB
  private static readonly MAX_FILES_TO_SCAN = 100;

  private static readonly BINARY_EXTENSIONS = new Set([
    '.wasm',
    '.exe',
    '.bin',
    '.dll',
    '.so',
    '.dylib',
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.pdf',
    '.zip',
    '.tar',
    '.gz',
    '.tgz',
    '.7z',
    '.pyc',
    '.class',
    '.ico',
  ]);

  /**
   * Discovers up to K=3 reference/usage sites of a symbol across the workspace.
   */
  public static findUsageSites(
    workspaceRoot: string,
    symbolName: string,
    sourceFilePath: string
  ): UsageSite[] {
    if (!symbolName || symbolName.length < 3 || /^[0-9]+$/.test(symbolName)) {
      return [];
    }

    const usageSites: UsageSite[] = [];
    const sourcePosix = SlicerDenylist.toRootRelativePosix(workspaceRoot, sourceFilePath);

    const regex = new RegExp(`\\b${UsageFinder.escapeRegex(symbolName)}\\b`);
    const candidateFiles = UsageFinder.collectFiles(workspaceRoot);

    for (const file of candidateFiles) {
      if (usageSites.length >= UsageFinder.MAX_USAGE_SITES) break;

      const filePosix = SlicerDenylist.toRootRelativePosix(workspaceRoot, file);
      if (filePosix === sourcePosix) continue;

      if (SlicerDenylist.isDenylisted(filePosix)) continue;

      try {
        const stat = fs.statSync(file);
        if (stat.size > UsageFinder.MAX_FILE_SIZE) continue;

        const buf = fs.readFileSync(file);
        if (UsageFinder.isBinaryBuffer(buf)) continue;

        const content = buf.toString('utf-8');
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i] ?? '';
          if (regex.test(line)) {
            const startLine = Math.max(1, i - 1);
            const endLine = Math.min(lines.length, i + 3);
            const rawSnippet = lines.slice(startLine - 1, endLine).join('\n');
            const redactedSnippet = SecretRedactor.redactText(rawSnippet);

            usageSites.push({
              filePath: filePosix,
              startLine,
              endLine,
              snippet: redactedSnippet,
            });

            if (usageSites.length >= UsageFinder.MAX_USAGE_SITES) break;
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    return usageSites;
  }

  private static collectFiles(dir: string, fileList: string[] = []): string[] {
    if (fileList.length >= UsageFinder.MAX_FILES_TO_SCAN) return fileList;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (fileList.length >= UsageFinder.MAX_FILES_TO_SCAN) break;

        const fullPath = path.join(dir, entry.name);
        const name = entry.name;

        if (name === 'node_modules' || name === '.git' || name === 'dist' || name === 'build') {
          continue;
        }

        if (entry.isDirectory()) {
          UsageFinder.collectFiles(fullPath, fileList);
        } else if (entry.isFile()) {
          const ext = path.extname(name).toLowerCase();
          if (!UsageFinder.BINARY_EXTENSIONS.has(ext)) {
            fileList.push(fullPath);
          }
        }
      }
    } catch {
      // Ignore directory read errors
    }

    return fileList;
  }

  private static isBinaryBuffer(buf: Buffer): boolean {
    const checkLength = Math.min(buf.length, 1024);
    for (let i = 0; i < checkLength; i++) {
      if (buf[i] === 0) return true;
    }
    return false;
  }

  private static escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
