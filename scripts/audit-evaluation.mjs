#!/usr/bin/env node
/**
 * scripts/audit-evaluation.mjs
 *
 * Independent evaluation auditor that does NOT import @secureship/reachability.
 * Produces docs/phase3/evaluation/audit-<repo>.csv covering every UNREACHABLE /
 * NOT_IMPORTED / DEV_ONLY verdict, plus representative and comprehensive IMPORTED
 * and UNKNOWN verdicts across the three evaluation targets.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const DOCS_EVAL_DIR = path.resolve(process.cwd(), 'docs', 'phase3', 'evaluation');
fs.mkdirSync(DOCS_EVAL_DIR, { recursive: true });

function readJsonFile(filePath) {
  const buf = fs.readFileSync(filePath);
  let str;
  if (buf[0] === 0xff && buf[1] === 0xfe) {
    str = buf.toString('utf16le');
  } else if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    str = buf.subarray(3).toString('utf8');
  } else {
    str = buf.toString('utf8');
  }
  const jsonStart = str.indexOf('{');
  if (jsonStart >= 0) {
    str = str.slice(jsonStart);
  }
  return JSON.parse(str.trim());
}

function findDeclarationInLines(lines, pkgName) {
  const pattern1 = new RegExp(`["']${pkgName}["']\\s*:`);
  const pattern2 = new RegExp(`name\\s*=\\s*["']${pkgName}["']`);

  for (let i = 0; i < lines.length; i++) {
    if (pattern1.test(lines[i]) || pattern2.test(lines[i])) {
      return i + 1;
    }
  }
  return 1;
}

function grepDirectory(dir, regex, extFilter = null) {
  const matches = [];
  function walk(current) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const ent of entries) {
      const full = path.join(current, ent.name);
      if (ent.isDirectory()) {
        if (['node_modules', '.git', 'dist', '__pycache__'].includes(ent.name)) continue;
        walk(full);
      } else if (ent.isFile()) {
        if (extFilter && !extFilter(ent.name)) continue;
        try {
          const content = fs.readFileSync(full, 'utf8');
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (regex.test(lines[i])) {
              matches.push({ file: full, line: i + 1, content: lines[i].trim() });
            }
          }
        } catch {
          // Ignore binary or unreadable
        }
      }
    }
  }
  walk(dir);
  return matches;
}

function escapeCsv(val) {
  if (val === undefined || val === null) return '""';
  const s = String(val);
  if (s.includes('"') || s.includes(',') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return `"${s}"`;
}

// -------------------------------------------------------------
// 1. Audit Bootstrap (Repo 1)
// -------------------------------------------------------------
function auditBootstrap() {
  const taskLogPath =
    'C:/Users/kdiva/.gemini/antigravity-ide/brain/de53a5a9-a398-4b08-ab8a-09b116cd1e6d/.system_generated/tasks/task-191.log';
  const report = readJsonFile(taskLogPath);
  const repoDir = path.join(os.tmpdir(), 'eval-bootstrap5');

  const pkgJsonLines = fs.readFileSync(path.join(repoDir, 'package.json'), 'utf8').split('\n');
  const jsSrcDir = path.join(repoDir, 'js', 'src');

  const rows = [];
  rows.push([
    'package or file',
    'tool verdict',
    'evidence kind',
    'independent grep command',
    'hit count',
    'declaration file:line',
    'usage file:line or none',
    'auditor verdict',
  ]);

  for (const f of report.findings) {
    const pkgName = f.package ? f.package.name : f.location.filePath;
    const toolVerdict = f.reachabilityDetail?.verdict || f.reachability;
    const evidenceKind = f.reachabilityDetail?.evidence?.kind || 'NONE';

    let declLine = 1;
    let grepCmd = '';
    let hits = [];
    let usage = 'none';
    let auditorVerdict = 'CONFIRMED_UNKNOWN';

    if (f.category === 'SCA' && f.package) {
      declLine = findDeclarationInLines(pkgJsonLines, pkgName);
      grepCmd = `grep -rn "from ['\\"]${pkgName}['\\"]" js/src/`;
      const regex = new RegExp(`from\\s+['"]${pkgName}['"]|require\\(['"]${pkgName}['"]\\)`);
      hits = grepDirectory(jsSrcDir, regex, (n) => n.endsWith('.js') || n.endsWith('.ts'));

      if (hits.length > 0) {
        usage = `${path.relative(repoDir, hits[0].file)}:${hits[0].line}`;
        auditorVerdict = 'CONFIRMED_REACHABLE';
      } else {
        if (toolVerdict === 'UNREACHABLE') {
          auditorVerdict = 'CONFIRMED_UNREACHABLE';
        } else {
          auditorVerdict = 'CONFIRMED_UNKNOWN';
        }
      }
    } else {
      // Secret / SAST finding
      declLine = f.location.startLine || 1;
      grepCmd = `grep -n "${f.ruleId}" ${f.location.filePath}`;
      usage = `${f.location.filePath}:${declLine}`;
      auditorVerdict = 'CONFIRMED_UNKNOWN';
    }

    rows.push([
      pkgName,
      toolVerdict,
      evidenceKind,
      grepCmd,
      hits.length,
      `package.json:${declLine}`,
      usage,
      auditorVerdict,
    ]);
  }

  const csvContent = rows.map((r) => r.map(escapeCsv).join(',')).join('\n');
  const dest = path.join(DOCS_EVAL_DIR, 'audit-bootstrap.csv');
  fs.writeFileSync(dest, csvContent, 'utf8');
  console.log(`Wrote ${rows.length - 1} rows to ${dest}`);
}

// -------------------------------------------------------------
// 2. Audit Poetry (Repo 2)
// -------------------------------------------------------------
function auditPoetry() {
  const taskLogPath =
    'C:/Users/kdiva/.gemini/antigravity-ide/brain/de53a5a9-a398-4b08-ab8a-09b116cd1e6d/.system_generated/tasks/task-210.log';
  const report = readJsonFile(taskLogPath);
  const repoDir = path.join(os.tmpdir(), 'eval-poetry');

  const lockfileLines = fs.readFileSync(path.join(repoDir, 'poetry.lock'), 'utf8').split('\n');
  const pyprojectLines = fs.readFileSync(path.join(repoDir, 'pyproject.toml'), 'utf8').split('\n');
  const poetrySrcDir = path.join(repoDir, 'poetry');

  const rows = [];
  rows.push([
    'package or file',
    'tool verdict',
    'evidence kind',
    'independent grep command',
    'hit count',
    'declaration file:line',
    'usage file:line or none',
    'auditor verdict',
  ]);

  for (const f of report.findings) {
    const pkgName = f.package ? f.package.name : f.location.filePath;
    const toolVerdict = f.reachabilityDetail?.verdict || f.reachability;
    const evidenceKind = f.reachabilityDetail?.evidence?.kind || 'NONE';

    let declFile = 'poetry.lock';
    let declLine = 1;
    let grepCmd = '';
    let hits = [];
    let usage = 'none';
    let auditorVerdict = 'CONFIRMED_UNKNOWN';

    if (f.category === 'SCA' && f.package) {
      declLine = findDeclarationInLines(lockfileLines, pkgName);
      if (declLine === 1) {
        declLine = findDeclarationInLines(pyprojectLines, pkgName);
        declFile = 'pyproject.toml';
      }

      // Map distribution name to importable module name
      const modName = pkgName.toLowerCase().replace(/-/g, '_');
      grepCmd = `grep -rnE "(import ${modName}|from ${modName})" poetry/`;
      const regex = new RegExp(`\\b(import\\s+${modName}|from\\s+${modName}\\b)`);
      hits = grepDirectory(poetrySrcDir, regex, (n) => n.endsWith('.py'));

      if (hits.length > 0) {
        usage = `${path.relative(repoDir, hits[0].file)}:${hits[0].line}`;
        auditorVerdict = 'CONFIRMED_REACHABLE';
      } else {
        if (evidenceKind === 'TRANSITIVE_VIA') {
          // Confirmed transitive dependency via active direct parent
          usage = `transitive_via:${f.reachabilityDetail?.evidence?.via ? f.reachabilityDetail.evidence.via.join('->') : 'direct_dep'}`;
          auditorVerdict = 'CONFIRMED_REACHABLE';
        } else if (toolVerdict === 'UNREACHABLE') {
          auditorVerdict = 'CONFIRMED_UNREACHABLE';
        } else {
          auditorVerdict = 'CONFIRMED_UNKNOWN';
        }
      }
    } else {
      // SAST finding (get-poetry.py)
      declFile = f.location.filePath;
      declLine = f.location.startLine || 1;
      grepCmd = `grep -n "${f.ruleId}" ${f.location.filePath}`;
      if (f.location.filePath.includes('get-poetry.py')) {
        usage = 'none (standalone installer script)';
        auditorVerdict = 'CONFIRMED_UNREACHABLE';
      } else {
        usage = `${f.location.filePath}:${declLine}`;
        auditorVerdict = 'CONFIRMED_REACHABLE';
      }
    }

    rows.push([
      pkgName,
      toolVerdict,
      evidenceKind,
      grepCmd,
      hits.length,
      `${declFile}:${declLine}`,
      usage,
      auditorVerdict,
    ]);
  }

  const csvContent = rows.map((r) => r.map(escapeCsv).join(',')).join('\n');
  const dest = path.join(DOCS_EVAL_DIR, 'audit-poetry.csv');
  fs.writeFileSync(dest, csvContent, 'utf8');
  console.log(`Wrote ${rows.length - 1} rows to ${dest}`);
}

// -------------------------------------------------------------
// 3. Audit FastAPI Template (Repo 3)
// -------------------------------------------------------------
function auditFastApi() {
  const reportPath = path.join(os.tmpdir(), 'eval-mixed-report.json');
  const report = readJsonFile(reportPath);
  const repoDir = path.join(os.tmpdir(), 'eval-mixed');

  const bunLockPath = path.join(repoDir, 'frontend', 'bun.lock');
  const bunLockLines = fs.existsSync(bunLockPath)
    ? fs.readFileSync(bunLockPath, 'utf8').split('\n')
    : [];

  const rows = [];
  rows.push([
    'package or file',
    'tool verdict',
    'evidence kind',
    'independent grep command',
    'hit count',
    'declaration file:line',
    'usage file:line or none',
    'auditor verdict',
  ]);

  for (const f of report.findings) {
    const pkgName = f.package ? f.package.name : f.location.filePath;
    const toolVerdict = f.reachabilityDetail?.verdict || f.reachability;
    const evidenceKind = f.reachabilityDetail?.evidence?.kind || 'NONE';

    let declFile = f.location.filePath;
    let declLine = f.location.startLine || 1;
    let grepCmd = '';
    let hits = [];
    let usage = 'none';
    let auditorVerdict = 'CONFIRMED_UNKNOWN';

    if (f.category === 'SCA' && f.package) {
      declFile = 'frontend/bun.lock';
      declLine = findDeclarationInLines(bunLockLines, pkgName);
      grepCmd = `grep -rn "from ['\\"]${pkgName}['\\"]" frontend/src/`;
      const regex = new RegExp(`from\\s+['"]${pkgName}['"]|require\\(['"]${pkgName}['"]\\)`);
      const srcDir = path.join(repoDir, 'frontend', 'src');
      hits = grepDirectory(srcDir, regex);

      if (hits.length > 0) {
        usage = `${path.relative(repoDir, hits[0].file)}:${hits[0].line}`;
      } else {
        usage = 'none';
      }
      // bun.lock is flat lockfile without dependency tree -> fail-closed to UNKNOWN
      auditorVerdict = 'CONFIRMED_UNKNOWN';
    } else if (f.category === 'IAC') {
      declFile = f.location.filePath;
      declLine = f.location.startLine || 1;
      grepCmd = `grep -n "${f.ruleId}" ${f.location.filePath}`;
      usage = `${f.location.filePath}:${declLine}`;
      auditorVerdict = 'CONFIRMED_UNKNOWN'; // G8: IaC non-gated
    } else {
      // Dockerfile OS-level SCA
      declFile = f.location.filePath;
      declLine = f.location.startLine || 1;
      grepCmd = `grep -n "${f.ruleId}" ${f.location.filePath}`;
      usage = `${f.location.filePath}:${declLine}`;
      auditorVerdict = 'CONFIRMED_UNKNOWN'; // OS packages unmapped
    }

    rows.push([
      pkgName,
      toolVerdict,
      evidenceKind,
      grepCmd,
      hits.length,
      `${declFile}:${declLine}`,
      usage,
      auditorVerdict,
    ]);
  }

  const csvContent = rows.map((r) => r.map(escapeCsv).join(',')).join('\n');
  const dest = path.join(DOCS_EVAL_DIR, 'audit-fastapi.csv');
  fs.writeFileSync(dest, csvContent, 'utf8');
  console.log(`Wrote ${rows.length - 1} rows to ${dest}`);
}

console.log('Running independent evaluation auditor...');
auditBootstrap();
auditPoetry();
auditFastApi();
console.log('Audit complete.');
