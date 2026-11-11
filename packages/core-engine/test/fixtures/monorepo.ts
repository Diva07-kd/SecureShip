import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

export class MonorepoFixture {
  public readonly repoRoot: string;
  public readonly coreEngineDir: string;
  public readonly coreEngineSrcDir: string;
  public readonly cliDir: string;
  public readonly cliSrcDir: string;
  public readonly docsDir: string;

  private readonly createdWorktrees: string[] = [];
  private readonly createdDirs: string[] = [];

  private constructor(repoRoot: string) {
    this.repoRoot = repoRoot;
    this.coreEngineDir = path.join(repoRoot, 'packages', 'core-engine');
    this.coreEngineSrcDir = path.join(this.coreEngineDir, 'src');
    this.cliDir = path.join(repoRoot, 'packages', 'cli');
    this.cliSrcDir = path.join(this.cliDir, 'src');
    this.docsDir = path.join(repoRoot, 'docs');
  }

  public static create(): MonorepoFixture {
    // fs.mkdtempSync(os.tmpdir()) without realpath, preserving macOS /var -> /private/var
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-monorepo-'));
    const fixture = new MonorepoFixture(root);
    fixture.initialize();
    return fixture;
  }

  private get gitEnv(): NodeJS.ProcessEnv {
    return {
      ...process.env,
      GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : os.devNull,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'SDET Tester',
      GIT_AUTHOR_EMAIL: 'sdet@secureship.dev',
      GIT_COMMITTER_NAME: 'SDET Tester',
      GIT_COMMITTER_EMAIL: 'sdet@secureship.dev',
    };
  }

  public execGit(args: string[], cwd?: string): string {
    const fullArgs = ['-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args];
    return execFileSync('git', fullArgs, {
      cwd: cwd || this.repoRoot,
      env: this.gitEnv,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  private initialize(): void {
    this.execGit(['init', '-b', 'main']);

    // Create directories
    fs.mkdirSync(this.coreEngineSrcDir, { recursive: true });
    fs.mkdirSync(this.cliSrcDir, { recursive: true });
    fs.mkdirSync(this.docsDir, { recursive: true });

    // Root package.json
    fs.writeFileSync(
      path.join(this.repoRoot, 'package.json'),
      JSON.stringify({ name: 'fixture-monorepo', private: true }, null, 2) + '\n',
      'utf-8'
    );

    // packages/core-engine/package.json
    fs.writeFileSync(
      path.join(this.coreEngineDir, 'package.json'),
      JSON.stringify({ name: '@secureship/core-engine', version: '1.0.0' }, null, 2) + '\n',
      'utf-8'
    );

    // packages/core-engine/src/index.ts (exactly 10 lines)
    const index10Lines =
      [
        'export const line1 = 1;',
        'export const line2 = 2;',
        'export const line3 = 3;',
        'export const line4 = 4;',
        'export const line5 = 5;',
        'export const line6 = 6;',
        'export const line7 = 7;',
        'export const line8 = 8;',
        'export const line9 = 9;',
        'export const line10 = 10;',
      ].join('\n') + '\n';
    fs.writeFileSync(path.join(this.coreEngineSrcDir, 'index.ts'), index10Lines, 'utf-8');

    // packages/core-engine/src/util.ts
    fs.writeFileSync(
      path.join(this.coreEngineSrcDir, 'util.ts'),
      'export const utilValue = "core-engine-util";\n',
      'utf-8'
    );

    // packages/cli/src/index.ts (same filename as core-engine src/index.ts)
    fs.writeFileSync(
      path.join(this.cliSrcDir, 'index.ts'),
      'export const cliIndexValue = "cli-index";\n',
      'utf-8'
    );

    // packages/cli/src/main.ts
    fs.writeFileSync(
      path.join(this.cliSrcDir, 'main.ts'),
      'export const cliMainValue = "cli-main";\n',
      'utf-8'
    );

    // docs/readme.md
    fs.writeFileSync(path.join(this.docsDir, 'readme.md'), '# Monorepo Documentation\n', 'utf-8');

    // .gitignore ignoring ignored/
    fs.writeFileSync(path.join(this.repoRoot, '.gitignore'), 'ignored/\n', 'utf-8');

    // Initial commit
    this.execGit(['add', '.']);
    this.execGit(['commit', '-m', 'Initial monorepo commit']);
  }

  public commitAll(message = 'monorepo update'): void {
    this.execGit(['add', '-A']);
    this.execGit(['commit', '-m', message]);
  }

  public stage(fileOrFiles: string | string[]): void {
    const files = Array.isArray(fileOrFiles) ? fileOrFiles : [fileOrFiles];
    this.execGit(['add', '--', ...files]);
  }

  public addFile(relPath: string, content = ''): void {
    const fullPath = path.join(this.repoRoot, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf-8');
  }

  public addBinaryFile(relPath: string, buffer: Buffer): void {
    const fullPath = path.join(this.repoRoot, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, buffer);
  }

  public modifyFile(relPath: string, content: string): void {
    const fullPath = path.join(this.repoRoot, relPath);
    fs.writeFileSync(fullPath, content, 'utf-8');
  }

  public modifyLines(
    relPath: string,
    startLine: number,
    endLine: number,
    replacementLines: string[]
  ): void {
    const fullPath = path.join(this.repoRoot, relPath);
    const content = fs.readFileSync(fullPath, 'utf-8');
    const lines = content.split('\n');
    // Lines are 1-indexed. startLine to endLine inclusive are replaced.
    lines.splice(startLine - 1, endLine - startLine + 1, ...replacementLines);
    fs.writeFileSync(fullPath, lines.join('\n'), 'utf-8');
  }

  public deleteFile(relPath: string): void {
    const fullPath = path.join(this.repoRoot, relPath);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }

  public renameFile(oldRelPath: string, newRelPath: string): void {
    const oldFull = path.join(this.repoRoot, oldRelPath);
    const newFull = path.join(this.repoRoot, newRelPath);
    fs.mkdirSync(path.dirname(newFull), { recursive: true });
    fs.renameSync(oldFull, newFull);
  }

  public createLinkedWorktree(branchName = 'wt-branch'): {
    worktreeDir: string;
    cleanup: () => void;
  } {
    const wtDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-wt-'));
    fs.rmSync(wtDir, { recursive: true, force: true });
    this.execGit(['worktree', 'add', wtDir, '-b', branchName]);
    this.createdWorktrees.push(wtDir);

    const cleanup = () => {
      try {
        this.execGit(['worktree', 'remove', '--force', wtDir]);
      } catch {}
      try {
        fs.rmSync(wtDir, { recursive: true, force: true });
      } catch {}
    };

    return { worktreeDir: wtDir, cleanup };
  }

  public createNestedRepo(relPath: string): { repoDir: string; cleanup: () => void } {
    const repoDir = path.join(this.repoRoot, relPath);
    fs.mkdirSync(repoDir, { recursive: true });
    this.createdDirs.push(repoDir);

    const fullArgs = [
      '-c',
      'commit.gpgsign=false',
      '-c',
      'core.autocrlf=false',
      'init',
      '-b',
      'main',
    ];
    execFileSync('git', fullArgs, {
      cwd: repoDir,
      env: this.gitEnv,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const cleanup = () => {
      try {
        fs.rmSync(repoDir, { recursive: true, force: true });
      } catch {}
    };

    return { repoDir, cleanup };
  }

  public createSymlink(targetRel: string, linkRel: string): string {
    const targetAbs = path.join(this.repoRoot, targetRel);
    const linkAbs = path.join(this.repoRoot, linkRel);
    fs.mkdirSync(path.dirname(linkAbs), { recursive: true });
    const symlinkType = process.platform === 'win32' ? 'junction' : 'dir';
    fs.symlinkSync(targetAbs, linkAbs, symlinkType);
    return linkAbs;
  }

  public writeHostileConfig(configs: Record<string, string>): void {
    for (const [key, value] of Object.entries(configs)) {
      this.execGit(['config', key, value]);
    }
  }

  public cleanup(): void {
    for (const wt of this.createdWorktrees) {
      try {
        this.execGit(['worktree', 'remove', '--force', wt]);
      } catch {}
      try {
        fs.rmSync(wt, { recursive: true, force: true });
      } catch {}
    }
    try {
      fs.rmSync(this.repoRoot, { recursive: true, force: true });
    } catch {}
  }
}
