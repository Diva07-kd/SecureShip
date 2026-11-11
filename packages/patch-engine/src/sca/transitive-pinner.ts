import fs from 'node:fs';
import path from 'node:path';
import type { LockfileGraph } from '@secureship/reachability';
import type { ScaPatchProposal } from '@secureship/contracts';
import { DepGraphBuilder } from './dep-graph-builder.js';

export type PinResult =
  | { kind: 'DIRECT_UPGRADE'; manifestEdits: ManifestEdit[]; unifiedDiff?: string }
  | { kind: 'TRANSITIVE_PIN'; manifestEdits: ManifestEdit[]; unifiedDiff?: string }
  | { kind: 'OVERRIDES_INJECTION'; manifestEdits: ManifestEdit[]; unifiedDiff?: string }
  | { kind: 'UNSUPPORTED'; reason: string };

export interface ManifestEdit {
  filePath: string; // relative to projectRoot
  editType: 'SET_VERSION' | 'ADD_OVERRIDES' | 'ADD_PIN_COMMENT' | 'ADD_CONSTRAINT';
  packageName: string;
  newVersion: string;
  currentValue?: string;
  annotation?: string;
}

export class TransitivePinner {
  private readonly graphBuilder: DepGraphBuilder;

  constructor(
    private readonly graph: LockfileGraph,
    private readonly projectRoot: string
  ) {
    this.graphBuilder = new DepGraphBuilder(graph);
  }

  /**
   * Main decision function: calculates manifest edits and target strategy.
   */
  public computeFix(proposal: ScaPatchProposal): PinResult {
    const pkg = proposal.targetPackage;
    const isDirect = this.graphBuilder.isDirect(pkg);
    const chains = this.graphBuilder.getTransitiveChains(pkg);
    const shortestChain =
      chains.length > 0
        ? chains.reduce((min, c) => (c.length < min.length ? c : min), chains[0]!)
        : [];

    let kind: 'DIRECT_UPGRADE' | 'TRANSITIVE_PIN' | 'OVERRIDES_INJECTION';
    // shortestChain format: ['root', ...intermediates, vulnerablePkg]
    // 2-hop chain has 3 elements (root -> middle -> vuln) -> TRANSITIVE_PIN
    // 3+ hops has > 3 elements (root -> A -> B -> vuln) -> OVERRIDES_INJECTION
    if (isDirect) {
      kind = 'DIRECT_UPGRADE';
    } else if (shortestChain.length <= 3) {
      kind = 'TRANSITIVE_PIN';
    } else {
      kind = 'OVERRIDES_INJECTION';
    }

    const manifestEdits: ManifestEdit[] = [];
    const pm = proposal.packageManager;
    const manifestPath = proposal.manifestPath;
    const newVersion = proposal.targetVersion;

    if (pm === 'npm' || pm === 'pnpm' || pm === 'yarn') {
      if (kind === 'DIRECT_UPGRADE') {
        manifestEdits.push({
          filePath: manifestPath,
          editType: 'SET_VERSION',
          packageName: pkg,
          newVersion,
          currentValue: proposal.currentVersion,
        });
      } else {
        manifestEdits.push({
          filePath: manifestPath,
          editType: 'ADD_OVERRIDES',
          packageName: pkg,
          newVersion,
          currentValue: proposal.currentVersion,
          annotation: `pinned by SecureShip to fix vulnerability`,
        });
      }
    } else if (pm === 'pip') {
      if (kind === 'DIRECT_UPGRADE') {
        manifestEdits.push({
          filePath: manifestPath,
          editType: 'SET_VERSION',
          packageName: pkg,
          newVersion,
          currentValue: proposal.currentVersion,
        });
      } else {
        manifestEdits.push({
          filePath: manifestPath,
          editType: 'ADD_PIN_COMMENT',
          packageName: pkg,
          newVersion,
          currentValue: proposal.currentVersion,
          annotation: '# not directly required, pinned by SecureShip to avoid vulnerability',
        });
      }
    } else if (pm === 'poetry') {
      manifestEdits.push({
        filePath: manifestPath,
        editType: 'ADD_CONSTRAINT',
        packageName: pkg,
        newVersion,
        currentValue: proposal.currentVersion,
      });
    } else {
      return {
        kind: 'UNSUPPORTED',
        reason: `Unsupported package manager for SCA fix: ${pm}`,
      };
    }

    // Try generating a clean unified diff if files exist
    let unifiedDiff: string | undefined;
    try {
      const editMap = this.applyEdits(manifestEdits);
      for (const [relPath, newContent] of editMap.entries()) {
        const fullPath = path.resolve(this.projectRoot, relPath);
        if (fs.existsSync(fullPath)) {
          const original = fs.readFileSync(fullPath, 'utf8');
          unifiedDiff = TransitivePinner.createUnifiedDiff(relPath, original, newContent);
          break; // First manifest file diff
        }
      }
    } catch {
      // Ignore diff generation failure during dry planning
    }

    return {
      kind,
      manifestEdits,
      unifiedDiff,
    };
  }

  /**
   * Applies ManifestEdits to manifest files.
   * Returns a Map<filePath, newContent>.
   * Pure string manipulation: NEVER executes subprocesses or package managers!
   */
  public applyEdits(
    edits: ManifestEdit[],
    customFileContents?: Map<string, string>
  ): Map<string, string> {
    const results = new Map<string, string>();
    const editsByFile = new Map<string, ManifestEdit[]>();

    for (const edit of edits) {
      const list = editsByFile.get(edit.filePath) ?? [];
      list.push(edit);
      editsByFile.set(edit.filePath, list);
    }

    for (const [relPath, fileEdits] of editsByFile.entries()) {
      let content = customFileContents?.get(relPath);
      if (content === undefined) {
        const fullPath = path.resolve(this.projectRoot, relPath);
        if (fs.existsSync(fullPath)) {
          content = fs.readFileSync(fullPath, 'utf8');
        } else {
          continue;
        }
      }

      const basename = path.basename(relPath).toLowerCase();
      let updatedContent = content;

      if (basename === 'package.json') {
        updatedContent = TransitivePinner.patchPackageJson(content, fileEdits);
      } else if (basename.startsWith('requirements') && basename.endsWith('.txt')) {
        updatedContent = TransitivePinner.patchRequirementsTxt(content, fileEdits);
      } else if (basename === 'pyproject.toml') {
        updatedContent = TransitivePinner.patchPyprojectToml(content, fileEdits);
      }

      results.set(relPath, updatedContent);
    }

    return results;
  }

  /**
   * Patches package.json preserving indentation (2, 4, tab).
   */
  public static patchPackageJson(content: string, edits: ManifestEdit[]): string {
    const indent = TransitivePinner.detectJsonIndent(content);
    let pkg: Record<string, unknown> = {};
    try {
      pkg = JSON.parse(content);
    } catch {
      return content;
    }

    for (const edit of edits) {
      const pkgName = edit.packageName;
      const newVer = edit.newVersion;

      if (edit.editType === 'SET_VERSION') {
        let set = false;
        if (
          pkg.dependencies &&
          typeof pkg.dependencies === 'object' &&
          pkgName in (pkg.dependencies as Record<string, string>)
        ) {
          (pkg.dependencies as Record<string, string>)[pkgName] = newVer;
          set = true;
        }
        if (
          pkg.devDependencies &&
          typeof pkg.devDependencies === 'object' &&
          pkgName in (pkg.devDependencies as Record<string, string>)
        ) {
          (pkg.devDependencies as Record<string, string>)[pkgName] = newVer;
          set = true;
        }
        if (!set) {
          if (!pkg.dependencies) pkg.dependencies = {};
          (pkg.dependencies as Record<string, string>)[pkgName] = newVer;
        }
      } else if (edit.editType === 'ADD_OVERRIDES') {
        // npm v8.3+ 'overrides', pnpm 'pnpm.overrides', yarn 'resolutions'
        if (!pkg.overrides || typeof pkg.overrides !== 'object') {
          pkg.overrides = {};
        }
        (pkg.overrides as Record<string, string>)[pkgName] = newVer;
      }
    }

    const trailingNewline = content.endsWith('\n');
    let res = JSON.stringify(pkg, null, indent);
    if (trailingNewline) res += '\n';
    return res;
  }

  /**
   * Patches requirements.txt preserving comments, whitespace, and name normalization.
   */
  public static patchRequirementsTxt(content: string, edits: ManifestEdit[]): string {
    const lines = content.split(/\r?\n/);
    const eol = content.includes('\r\n') ? '\r\n' : '\n';
    const trailingNewline = content.endsWith('\n');

    for (const edit of edits) {
      const targetNorm = edit.packageName.toLowerCase().replace(/[-_]/g, '_');
      let found = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || trimmed.length === 0) continue;

        // Parse package name at start of line: e.g. "urllib3>=1.2.3", "urllib3==1.2.3"
        const match = line.match(/^([a-zA-Z0-9_\-.]+)\s*(==|>=|<=|>|<|~=)?\s*(.*)$/);
        if (match && match[1]) {
          const lineNorm = match[1].toLowerCase().replace(/[-_]/g, '_');
          if (lineNorm === targetNorm) {
            found = true;
            if (edit.editType === 'SET_VERSION') {
              const op = match[2] || '>=';
              lines[i] = `${match[1]}${op}${edit.newVersion}`;
            }
            break;
          }
        }
      }

      if (!found) {
        // Append pin comment line
        const annotation = edit.annotation ?? '# pinned by SecureShip';
        lines.push(`${edit.packageName}>=${edit.newVersion}  ${annotation}`);
      }
    }

    let result = lines.join(eol);
    if (trailingNewline && !result.endsWith(eol)) {
      result += eol;
    }
    return result;
  }

  /**
   * Minimal line-based TOML patching for pyproject.toml without full TOML re-serialization.
   */
  public static patchPyprojectToml(content: string, edits: ManifestEdit[]): string {
    const lines = content.split(/\r?\n/);
    const eol = content.includes('\r\n') ? '\r\n' : '\n';

    for (const edit of edits) {
      let inPoetryDeps = false;
      let inserted = false;

      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i]!.trim();
        if (trimmed === '[tool.poetry.dependencies]') {
          inPoetryDeps = true;
          continue;
        }

        if (inPoetryDeps) {
          if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            // Next section reached, insert before this section
            lines.splice(i, 0, `${edit.packageName} = ">=${edit.newVersion}"`);
            inserted = true;
            break;
          }

          // Check if key exists
          const keyMatch = trimmed.match(/^([a-zA-Z0-9_\-.]+)\s*=/);
          if (keyMatch && keyMatch[1]?.toLowerCase() === edit.packageName.toLowerCase()) {
            lines[i] = `${keyMatch[1]} = ">=${edit.newVersion}"`;
            inserted = true;
            break;
          }
        }
      }

      if (!inserted) {
        if (inPoetryDeps) {
          lines.push(`${edit.packageName} = ">=${edit.newVersion}"`);
        } else {
          lines.push(
            '',
            '[tool.poetry.dependencies]',
            `${edit.packageName} = ">=${edit.newVersion}"`
          );
        }
      }
    }

    return lines.join(eol);
  }

  /**
   * Generates a clean 3-line unified diff between original and patched content.
   */
  public static createUnifiedDiff(
    filePath: string,
    originalText: string,
    patchedText: string
  ): string {
    const posixPath = filePath.replace(/\\/g, '/');
    const oldLines = originalText.split(/\r?\n/);
    const newLines = patchedText.split(/\r?\n/);

    // Simple line diff
    let startDiff = 0;
    while (
      startDiff < oldLines.length &&
      startDiff < newLines.length &&
      oldLines[startDiff] === newLines[startDiff]
    ) {
      startDiff++;
    }

    let oldEnd = oldLines.length - 1;
    let newEnd = newLines.length - 1;
    while (oldEnd >= startDiff && newEnd >= startDiff && oldLines[oldEnd] === newLines[newEnd]) {
      oldEnd--;
      newEnd--;
    }

    const contextBefore = Math.max(0, startDiff - 2);
    const contextAfterOld = Math.min(oldLines.length - 1, oldEnd + 2);
    const contextAfterNew = Math.min(newLines.length - 1, newEnd + 2);

    const oldHunkCount = contextAfterOld - contextBefore + 1;
    const newHunkCount = contextAfterNew - contextBefore + 1;

    const diffLines: string[] = [
      `--- a/${posixPath}`,
      `+++ b/${posixPath}`,
      `@@ -${contextBefore + 1},${Math.max(1, oldHunkCount)} +${contextBefore + 1},${Math.max(1, newHunkCount)} @@`,
    ];

    for (let i = contextBefore; i < startDiff; i++) {
      diffLines.push(` ${oldLines[i] ?? ''}`);
    }
    for (let i = startDiff; i <= oldEnd; i++) {
      diffLines.push(`-${oldLines[i] ?? ''}`);
    }
    for (let i = startDiff; i <= newEnd; i++) {
      diffLines.push(`+${newLines[i] ?? ''}`);
    }
    for (let i = oldEnd + 1; i <= contextAfterOld; i++) {
      diffLines.push(` ${oldLines[i] ?? ''}`);
    }

    return diffLines.join('\n') + '\n';
  }

  private static detectJsonIndent(text: string): number | string {
    const match = text.match(/\n([ \t]+)"/);
    if (!match || !match[1]) return 2;
    if (match[1].includes('\t')) return '\t';
    return match[1].length;
  }
}
