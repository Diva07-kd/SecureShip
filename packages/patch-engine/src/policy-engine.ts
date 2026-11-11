import path from 'node:path';
import { builtinModules } from 'node:module';
import type {
  FindingCategory,
  FindingLocation,
  PatchPolicyResult,
  PatchPolicyViolation,
  Severity,
} from '@secureship/contracts';
import { SecretRedactor } from '@secureship/context-slicer';
import { type ParsedDiffFile, type ParsedHunk } from './diff-parser.js';
import { isPythonStdlibModule } from './python-stdlib.js';

export interface ScopeWindow {
  filePath: string;
  startLine: number;
  endLine: number;
}

export interface PolicyEngineOptions {
  rootDir: string;
  category: FindingCategory;
  findingLocation: FindingLocation;
  scopeWindow?: ScopeWindow;
  maxFiles?: number;
  maxChangedLines?: number;
  maxDiffBytes?: number;
  allowRemovalOnly?: boolean;
  minNewFindingSeverity?: Severity;
  declaredDependencies?: Set<string>;
  existingProjectImports?: Set<string>;
}

export class PatchPolicyEngine {
  private static readonly NODE_BUILTINS = new Set([
    ...builtinModules,
    ...builtinModules.map((m) => `node:${m}`),
  ]);

  private static readonly PROTECTED_PATTERNS = [
    /^\.github\//i,
    /^\.gitlab-ci/i,
    /^\.circleci\//i,
    /^Jenkinsfile/i,
    /^azure-pipelines/i,
    /^\.husky\//i,
    /^\.git\//i,
    /^package\.json$/i,
    /^package-lock\.json$/i,
    /^pnpm-lock\.yaml$/i,
    /^yarn\.lock$/i,
    /^bun\.lockb?$/i,
    /^poetry\.lock$/i,
    /^Pipfile\.lock$/i,
    /^requirements.*\.txt$/i,
    /^pyproject\.toml$/i,
    /^setup\.(py|cfg)$/i,
    /^tox\.ini$/i,
    /^Makefile$/i,
    /^tsconfig.*\.json$/i,
    /^(eslint|prettier|jest|vitest|babel|webpack|vite)\.config\./i,
    /^\.eslintrc/i,
    /^\.prettierrc/i,
    /^secureship\.config\./i,
    /^\.secureship\//i,
  ];

  private static readonly TEST_PATTERNS = [
    /(^|\/)tests?\//i,
    /(^|\/)__tests__\//i,
    /\.test\.[a-z0-9]+$/i,
    /\.spec\.[a-z0-9]+$/i,
    /(^|\/)conftest\.py$/i,
    /(^|\/)fixtures?\//i,
  ];

  private static readonly SENSITIVE_PATTERNS = [
    /^\.env/i,
    /(^|\/)\.env/i,
    /\.pem$/i,
    /\.key$/i,
    /(^|\/)id_rsa/i,
    /(^|\/)id_ed25519/i,
    /(^|\/)id_ecdsa/i,
    /(^|\/)id_dsa/i,
    /(^|\/)credentials/i,
    /(^|\/)\.aws\//i,
    /(^|\/)\.ssh\//i,
    /^\.npmrc$/i,
    /^\.pypirc$/i,
    /^\.netrc$/i,
    /terraform\.tfstate/i,
    /\.pfx$/i,
    /\.p12$/i,
    /\.kdbx$/i,
    /\.keystore$/i,
  ];

  private static readonly SUPPRESSION_REGEXES = [
    /nosemgrep/i,
    /nosec\b/i,
    /\bnoqa\b/i,
    /pylint:\s*disable/i,
    /eslint-disable/i,
    /@ts-ignore\b/i,
    /@ts-nocheck\b/i,
    /#\s*type:\s*ignore\b/i,
    /secureship-ignore/i,
    /checkov:skip/i,
    /trivy:?\s*ignore/i,
    /gitleaks:(allow|skip)/i,
  ];

  private static readonly DANGEROUS_FAMILIES: Array<{
    name: string;
    patterns: RegExp[];
  }> = [
    {
      name: 'EVAL',
      patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/, /\bexecScript\s*\(/],
    },
    {
      name: 'SHELL_EXEC',
      patterns: [
        /\bchild_process\b/,
        /\b(exec|execSync|spawn|spawnSync)\s*\(/,
        /\bsubprocess\./,
        /\bos\.(system|popen)\s*\(/,
      ],
    },
    {
      name: 'DESERIALIZE',
      patterns: [/\bpickle\./, /\bmarshal\./, /\byaml\.(unsafe_load|load)\s*\(/],
    },
    {
      name: 'NETWORK',
      patterns: [
        /\brequests\.(get|post|put|delete|patch|request)\s*\(/,
        /\burllib\.(request|parse)\b/,
        /\bfetch\s*\(/,
        /\bhttp(s)?\.(request|get)\s*\(/,
        /\bnet\.(connect|createConnection)\s*\(/,
        /\bdns\.(lookup|resolve)\s*\(/,
        /\bsocket\.(socket|connect)\s*\(/,
        /\bWebSocket\s*\(/,
      ],
    },
    {
      name: 'CURL',
      patterns: [/\bcurl\s+/, /\bwget\s+/],
    },
    {
      name: 'DYNAMIC_IMPORT',
      patterns: [/\bimport\s*\(/, /\b__import__\s*\(/],
    },
    {
      name: 'BASE64_EXEC',
      patterns: [
        /(atob|Buffer\.from\([^)]*base64[^)]*\)|base64\.b64decode).*?(eval|exec|spawn|system)/s,
      ],
    },
  ];

  /**
   * Evaluates all policy rules against parsed diff files.
   * Reports all discovered violations in strict order.
   */
  public static evaluate(files: ParsedDiffFile[], options: PolicyEngineOptions): PatchPolicyResult {
    const violations: PatchPolicyViolation[] = [];
    const maxFiles = options.maxFiles ?? 1;
    const maxChangedLines = options.maxChangedLines ?? 60;
    const allowRemovalOnly = options.allowRemovalOnly ?? false;

    // 1. Scope Checks
    if (files.length > maxFiles) {
      violations.push({
        code: 'TOO_MANY_FILES',
        detail: `Diff modifies ${files.length} files (maximum permitted: ${maxFiles})`,
      });
    }

    const findingFilePosix = options.findingLocation.filePath.replace(/\\/g, '/');

    let totalChangedLines = 0;
    for (const f of files) {
      totalChangedLines += f.addedLinesCount + f.deletedLinesCount;

      // File must match finding's file
      if (f.newPath !== findingFilePosix && files.length === 1) {
        violations.push({
          code: 'OUTSIDE_SCOPE',
          detail: `Diff modifies file '${f.newPath}' which does not match finding location '${findingFilePosix}'`,
          file: f.newPath,
        });
      }

      // Check enclosing scope if provided
      if (options.scopeWindow && f.newPath === options.scopeWindow.filePath.replace(/\\/g, '/')) {
        const allowedStart = Math.max(1, options.scopeWindow.startLine - 10);
        const allowedEnd = options.scopeWindow.endLine + 10;

        for (const hunk of f.hunks) {
          const hunkEnd = hunk.newStart + hunk.newCount;
          if (hunk.newStart < allowedStart || hunkEnd > allowedEnd + 1) {
            violations.push({
              code: 'OUTSIDE_SCOPE',
              detail: `Changed lines [${hunk.newStart}-${hunkEnd}] fall outside enclosing scope window [${allowedStart}-${allowedEnd}]`,
              file: f.newPath,
              line: hunk.newStart,
            });
          }
        }
      }
    }

    if (totalChangedLines > maxChangedLines) {
      violations.push({
        code: 'TOO_MANY_LINES',
        detail: `Total changed lines (${totalChangedLines}) exceeds maximum permitted ${maxChangedLines}`,
      });
    }

    // 2. Path Checks
    for (const f of files) {
      const p = f.newPath;

      // Sensitive file check (Phase 4 denylist)
      if (PatchPolicyEngine.SENSITIVE_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'SENSITIVE_FILE',
          detail: `File '${p}' matches sensitive denylist pattern`,
          file: p,
        });
      }

      // Test file check
      if (PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'TEST_FILE',
          detail: `Modifying test or fixture file '${p}' is forbidden`,
          file: p,
        });
      }

      // Protected path check
      if (PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'PROTECTED_PATH',
          detail: `Modifying protected project file '${p}' is forbidden`,
          file: p,
        });
      }

      // Dockerfile / Terraform / YAML targets allowed ONLY for IAC findings
      if (options.category !== 'IAC') {
        if (
          /^Dockerfile/i.test(path.basename(p)) ||
          /\.ya?ml$/i.test(p) ||
          /\.tf(vars)?$/i.test(p)
        ) {
          violations.push({
            code: 'PROTECTED_PATH',
            detail: `Modifying infrastructure configuration '${p}' is permitted only for IAC findings`,
            file: p,
          });
        }
      }
    }

    // 3. Anti-Gaming Checks
    for (const f of files) {
      let addedCodeLines = 0;
      let removedCodeLines = 0;
      const removedStatements: string[] = [];

      for (const hunk of f.hunks) {
        for (const line of hunk.lines) {
          if (line.type === 'deleted') {
            const trimmed = line.text.trim();
            if (trimmed.length > 0 && !PatchPolicyEngine.isCommentLine(trimmed, f.newPath)) {
              removedCodeLines++;
              removedStatements.push(trimmed);
            }
          }

          if (line.type === 'added') {
            const trimmed = line.text.trim();
            if (trimmed.length > 0 && !PatchPolicyEngine.isCommentLine(trimmed, f.newPath)) {
              addedCodeLines++;
            }

            // Suppression marker check
            for (const marker of PatchPolicyEngine.SUPPRESSION_REGEXES) {
              if (marker.test(line.text)) {
                violations.push({
                  code: 'SUPPRESSION_MARKER',
                  detail: `Added line contains security suppression marker '${marker.source}': '${trimmed}'`,
                  file: f.newPath,
                });
                break;
              }
            }

            // Commented-out code check (added lines that are comments containing removed code)
            if (PatchPolicyEngine.isCommentLine(trimmed, f.newPath)) {
              const strippedComment = PatchPolicyEngine.stripCommentChars(trimmed);
              for (const removedStmt of removedStatements) {
                if (removedStmt.length >= 6 && strippedComment.includes(removedStmt)) {
                  violations.push({
                    code: 'SUPPRESSION_MARKER',
                    detail: `Added line comments out vulnerable statement: '${trimmed}'`,
                    file: f.newPath,
                  });
                  break;
                }
              }
            }
          }
        }
      }

      if (!allowRemovalOnly) {
        if (addedCodeLines === 0 && removedCodeLines > 0) {
          violations.push({
            code: 'REMOVAL_ONLY',
            detail: `Patch only deletes code (${removedCodeLines} lines removed, 0 added) without fixing logic`,
            file: f.newPath,
          });
        }

        const maxAllowedDeletion = Math.max(10, 3 * addedCodeLines);
        if (removedCodeLines > maxAllowedDeletion) {
          violations.push({
            code: 'EXCESSIVE_DELETION',
            detail: `Excessive deletion: removed ${removedCodeLines} lines against ${addedCodeLines} added (max allowed ${maxAllowedDeletion})`,
            file: f.newPath,
          });
        }
      }
    }

    // 4. Dangerous API Differential Checks (Per hunk)
    for (const f of files) {
      for (const hunk of f.hunks) {
        PatchPolicyEngine.checkDangerousApiHunk(hunk, f.newPath, violations);
      }
    }

    // 5. New Dependency Checks
    for (const f of files) {
      PatchPolicyEngine.checkNewDependencies(f, options, violations);
    }

    // 6. Secret in Patch Checks
    for (const f of files) {
      for (const hunk of f.hunks) {
        for (const line of hunk.lines) {
          if (line.type === 'added') {
            const redacted = SecretRedactor.redactText(line.text);
            if (redacted !== line.text) {
              violations.push({
                code: 'SECRET_IN_PATCH',
                detail: `Added line contains hardcoded secret or sensitive credential token: '${line.text.trim().substring(0, 40)}...'`,
                file: f.newPath,
              });
              break;
            }
          }
        }
      }
    }

    // 7. Hidden Unicode / Trojan Source Checks
    for (const f of files) {
      for (const hunk of f.hunks) {
        for (const line of hunk.lines) {
          if (line.type === 'added') {
            PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
          }
        }
      }
    }

    // Deduplicate violations by code + file + detail
    const seen = new Set<string>();
    const uniqueViolations: PatchPolicyViolation[] = [];
    for (const v of violations) {
      const key = `${v.code}|${v.file ?? ''}|${v.detail}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueViolations.push(v);
      }
    }

    return {
      allowed: uniqueViolations.length === 0,
      violations: uniqueViolations,
    };
  }

  private static checkDangerousApiHunk(
    hunk: ParsedHunk,
    filePath: string,
    violations: PatchPolicyViolation[]
  ): void {
    const deletedText = hunk.lines
      .filter((l) => l.type === 'deleted')
      .map((l) => l.text)
      .join('\n');
    const addedText = hunk.lines
      .filter((l) => l.type === 'added')
      .map((l) => l.text)
      .join('\n');

    for (const fam of PatchPolicyEngine.DANGEROUS_FAMILIES) {
      let addedOccurrences = 0;
      let removedOccurrences = 0;

      for (const pat of fam.patterns) {
        const addMatches = addedText.match(new RegExp(pat.source, 'g'))?.length ?? 0;
        const delMatches = deletedText.match(new RegExp(pat.source, 'g'))?.length ?? 0;
        addedOccurrences += addMatches;
        removedOccurrences += delMatches;
      }

      if (addedOccurrences > removedOccurrences) {
        violations.push({
          code: 'NEW_DANGEROUS_API',
          detail: `Net-new dangerous API introduced in hunk (${fam.name}): ${addedOccurrences} added vs ${removedOccurrences} removed`,
          file: filePath,
          line: hunk.newStart,
        });
      }
    }
  }

  private static checkNewDependencies(
    file: ParsedDiffFile,
    options: PolicyEngineOptions,
    violations: PatchPolicyViolation[]
  ): void {
    const isPy = file.newPath.endsWith('.py');
    const isJs = /\.[jt]sx?$/i.test(file.newPath);

    for (const hunk of file.hunks) {
      const removedImports = new Set<string>();
      for (const l of hunk.lines) {
        if (l.type === 'deleted') {
          for (const mod of PatchPolicyEngine.extractImportedModules(l.text, isPy, isJs)) {
            removedImports.add(mod);
          }
        }
      }

      for (const l of hunk.lines) {
        if (l.type === 'added') {
          const addedImports = PatchPolicyEngine.extractImportedModules(l.text, isPy, isJs);
          for (const mod of addedImports) {
            if (removedImports.has(mod)) {
              continue; // Re-import or modified existing import line
            }

            // Check if relative path import
            if (mod.startsWith('.') || mod.startsWith('/')) {
              continue; // Local relative import
            }

            // Check Node built-in
            if (isJs && PatchPolicyEngine.NODE_BUILTINS.has(mod)) {
              continue;
            }

            // Check Python stdlib
            if (isPy && isPythonStdlibModule(mod)) {
              continue;
            }

            // Check declared project dependency
            if (
              options.declaredDependencies?.has(mod) ||
              options.existingProjectImports?.has(mod)
            ) {
              continue;
            }

            violations.push({
              code: 'NEW_DEPENDENCY',
              detail: `Added import introducing unapproved new dependency: '${mod}'`,
              file: file.newPath,
              line: hunk.newStart,
            });
          }
        }
      }
    }
  }

  private static extractImportedModules(line: string, isPy: boolean, isJs: boolean): string[] {
    const modules: string[] = [];
    const trimmed = line.trim();

    if (isJs) {
      // import ... from 'pkg'
      const fromMatch = trimmed.match(/from\s+['"]([^'"]+)['"]/);
      if (fromMatch?.[1]) {
        modules.push(PatchPolicyEngine.normalizeNpmPkg(fromMatch[1]));
      }

      // import 'pkg'
      const bareImportMatch = trimmed.match(/^import\s+['"]([^'"]+)['"]/);
      if (bareImportMatch?.[1]) {
        modules.push(PatchPolicyEngine.normalizeNpmPkg(bareImportMatch[1]));
      }

      // require('pkg')
      const reqMatch = trimmed.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
      if (reqMatch?.[1]) {
        modules.push(PatchPolicyEngine.normalizeNpmPkg(reqMatch[1]));
      }
    }

    if (isPy) {
      // import foo, bar
      const importMatch = trimmed.match(/^import\s+([a-zA-Z0-9_.,\s]+)/);
      if (importMatch?.[1]) {
        const parts = importMatch[1].split(',').map((p) =>
          p
            .trim()
            .split(/\s+as\s+/)[0]
            ?.trim()
        );
        for (const p of parts) {
          if (p) modules.push(p);
        }
      }

      // from foo.bar import baz
      const fromMatch = trimmed.match(/^from\s+([a-zA-Z0-9_.]+)\s+import/);
      if (fromMatch?.[1]) {
        modules.push(fromMatch[1]);
      }
    }

    return modules;
  }

  private static normalizeNpmPkg(specifier: string): string {
    if (specifier.startsWith('@')) {
      const parts = specifier.split('/');
      return parts.slice(0, 2).join('/');
    }
    return specifier.split('/')[0] ?? specifier;
  }

  private static checkHiddenUnicode(
    text: string,
    filePath: string,
    violations: PatchPolicyViolation[]
  ): void {
    // 1. Trojan Source Bidirectional control characters
    // U+202A to U+202E, U+2066 to U+2069, U+200E, U+200F, U+061C
    const bidiRegex = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;
    if (bidiRegex.test(text)) {
      violations.push({
        code: 'HIDDEN_UNICODE',
        detail: 'Added line contains Trojan Source bidirectional Unicode control characters',
        file: filePath,
      });
      return;
    }

    // 2. Zero-width spaces and joiners
    // U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (ZWNBSP), U+2060 (WJ)
    const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF\u2060]/;
    if (zeroWidthRegex.test(text)) {
      violations.push({
        code: 'HIDDEN_UNICODE',
        detail: 'Added line contains hidden zero-width Unicode characters',
        file: filePath,
      });
      return;
    }

    // 3. Non-printing control characters (excluding standard \t, \r, \n)
    const controlCharRegex = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
    if (controlCharRegex.test(text)) {
      violations.push({
        code: 'HIDDEN_UNICODE',
        detail: 'Added line contains non-printing ASCII control characters',
        file: filePath,
      });
      return;
    }

    // 4. Mixed-script homoglyphs: detect Cyrillic characters mixed with Latin
    const hasLatin = /[a-zA-Z]/.test(text);
    const hasCyrillic = /[\u0400-\u04FF]/.test(text);
    if (hasLatin && hasCyrillic) {
      violations.push({
        code: 'HIDDEN_UNICODE',
        detail: 'Added line contains suspicious mixed-script homoglyph identifiers',
        file: filePath,
      });
    }
  }

  private static isCommentLine(line: string, filePath: string): boolean {
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*') || t.endsWith('*/')) {
      return true;
    }
    if (t.startsWith('#')) {
      return true;
    }
    if (filePath.endsWith('.py') && (t.startsWith('"""') || t.startsWith("'''"))) {
      return true;
    }
    return false;
  }

  private static stripCommentChars(line: string): string {
    return line.replace(/^(\/\/|\/\*|\*|#)\s*/, '').trim();
  }
}
