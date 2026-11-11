import fs from 'node:fs';
import path from 'node:path';
import { PythonPackageMap } from './package-map.js';

export type PythonResolution =
  | { type: 'BUILTIN'; name: string }
  | { type: 'LOCAL_FILE'; resolvedPath: string }
  | { type: 'PACKAGE'; packageName: string; moduleName: string }
  | { type: 'UNRESOLVED'; specifier: string; reason: string };

const PYTHON_BUILTINS = new Set([
  'abc',
  'aifc',
  'argparse',
  'array',
  'ast',
  'asynchat',
  'asyncio',
  'asyncore',
  'atexit',
  'audioop',
  'base64',
  'bdb',
  'binascii',
  'binhex',
  'bisect',
  'builtins',
  'bz2',
  'cProfile',
  'calendar',
  'cgi',
  'cgitb',
  'chunk',
  'cmath',
  'cmd',
  'code',
  'codecs',
  'codeop',
  'collections',
  'colorsys',
  'compileall',
  'concurrent',
  'configparser',
  'contextlib',
  'contextvars',
  'copy',
  'copyreg',
  'crypt',
  'csv',
  'ctypes',
  'curses',
  'dataclasses',
  'datetime',
  'dbm',
  'decimal',
  'difflib',
  'dis',
  'distutils',
  'doctest',
  'email',
  'encodings',
  'enum',
  'errno',
  'faulthandler',
  'fcntl',
  'filecmp',
  'fileinput',
  'fnmatch',
  'fractions',
  'ftplib',
  'functools',
  'gc',
  'getopt',
  'getpass',
  'gettext',
  'glob',
  'graphlib',
  'grp',
  'gzip',
  'hashlib',
  'heapq',
  'hmac',
  'html',
  'http',
  'idlelib',
  'imaplib',
  'imghdr',
  'imp',
  'importlib',
  'inspect',
  'io',
  'ipaddress',
  'itertools',
  'json',
  'keyword',
  'lib2to3',
  'linecache',
  'locale',
  'logging',
  'lzma',
  'mailbox',
  'mailcap',
  'marshal',
  'math',
  'mimetypes',
  'mmap',
  'modulefinder',
  'msilib',
  'msvcrt',
  'multiprocessing',
  'netrc',
  'nis',
  'nntplib',
  'numbers',
  'operator',
  'optparse',
  'os',
  'ossaudiodev',
  'pathlib',
  'pdb',
  'pickle',
  'pickletools',
  'pipes',
  'pkgutil',
  'platform',
  'plistlib',
  'poplib',
  'posix',
  'posixpath',
  'pprint',
  'profile',
  'pstats',
  'pty',
  'pwd',
  'py_compile',
  'pyclbr',
  'pydoc',
  'queue',
  'quopri',
  'random',
  're',
  'readline',
  'reprlib',
  'resource',
  'rlcompleter',
  'runpy',
  'sched',
  'secrets',
  'select',
  'selectors',
  'shelve',
  'shlex',
  'shutil',
  'signal',
  'site',
  'smtpd',
  'smtplib',
  'sndhdr',
  'socket',
  'socketserver',
  'spwd',
  'sqlite3',
  'ssl',
  'stat',
  'statistics',
  'string',
  'stringprep',
  'struct',
  'subprocess',
  'sunau',
  'symtable',
  'sys',
  'sysconfig',
  'syslog',
  'tabnanny',
  'tarfile',
  'telnetlib',
  'tempfile',
  'termios',
  'test',
  'textwrap',
  'threading',
  'time',
  'timeit',
  'tkinter',
  'token',
  'tokenize',
  'tomllib',
  'trace',
  'traceback',
  'tracemalloc',
  'tty',
  'turtle',
  'turtledemo',
  'types',
  'typing',
  'unicodedata',
  'unittest',
  'urllib',
  'uu',
  'uuid',
  'venv',
  'warnings',
  'wave',
  'weakref',
  'webbrowser',
  'winreg',
  'winsound',
  'wsgiref',
  'xdrlib',
  'xml',
  'xmlrpc',
  'zipapp',
  'zipfile',
  'zipimport',
  'zlib',
  '_thread',
]);

export class PythonModuleResolver {
  private readonly projectRoot: string;

  constructor(projectRoot: string) {
    this.projectRoot = path.resolve(projectRoot);
  }

  /**
   * Resolves a Python import to a builtin, local module file, third-party package, or unresolved.
   */
  public resolve(
    moduleSpecifier: string,
    fromFilePath: string,
    isRelative: boolean,
    relativeLevel: number
  ): PythonResolution {
    const fromDir = path.dirname(fromFilePath);
    const realRoot = fs.existsSync(this.projectRoot)
      ? fs.realpathSync(this.projectRoot)
      : this.projectRoot;

    // 1. Relative import resolution: from . import utils, from ..sub import helper
    if (isRelative || moduleSpecifier.startsWith('.')) {
      let baseDir = fromDir;
      const dotsToTraverse = relativeLevel > 0 ? relativeLevel : 1;
      for (let i = 1; i < dotsToTraverse; i++) {
        baseDir = path.dirname(baseDir);
      }

      const stripped = moduleSpecifier.replace(/^\.+/, '');
      const relativePathCandidate = stripped ? path.join(baseDir, ...stripped.split('.')) : baseDir;

      return this.resolveLocalPythonPath(relativePathCandidate, moduleSpecifier, realRoot);
    }

    // 2. Check Python standard library built-ins
    const rootMod = moduleSpecifier.split('.')[0]!;
    if (PYTHON_BUILTINS.has(rootMod)) {
      return { type: 'BUILTIN', name: rootMod };
    }

    // 3. Check if it resolves to a local package or module in the project root
    const localCandidate = path.join(this.projectRoot, ...moduleSpecifier.split('.'));
    const localRes = this.resolveLocalPythonPath(localCandidate, moduleSpecifier, realRoot);
    if (localRes.type === 'LOCAL_FILE') {
      return localRes;
    }

    // Also check rootMod as a local module or package inside project root
    const rootModCandidate = path.join(this.projectRoot, rootMod);
    const rootModRes = this.resolveLocalPythonPath(rootModCandidate, rootMod, realRoot);
    if (rootModRes.type === 'LOCAL_FILE') {
      return rootModRes;
    }

    // 4. Third-party dependency: map module to package
    const mapped = PythonPackageMap.getImportableModuleNames(rootMod, this.projectRoot);
    if (mapped.source !== 'UNMAPPED' && mapped.modules.length > 0) {
      return {
        type: 'PACKAGE',
        packageName: rootMod,
        moduleName: mapped.modules[0]!,
      };
    }

    // Return package by canonical module name
    return {
      type: 'PACKAGE',
      packageName: rootMod,
      moduleName: rootMod,
    };
  }

  private resolveLocalPythonPath(
    candidatePath: string,
    originalSpecifier: string,
    realRoot: string
  ): PythonResolution {
    const relCandidate = path.relative(realRoot, candidatePath);
    if (relCandidate.startsWith('..') || path.isAbsolute(relCandidate)) {
      return {
        type: 'UNRESOLVED',
        specifier: originalSpecifier,
        reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
      };
    }

    // Check candidatePath.py
    const fileWithExt = `${candidatePath}.py`;
    if (fs.existsSync(fileWithExt)) {
      try {
        const stat = fs.statSync(fileWithExt);
        if (stat.isFile()) {
          const realTarget = fs.realpathSync(fileWithExt);
          const rel = path.relative(realRoot, realTarget);
          if (rel.startsWith('..') || path.isAbsolute(rel)) {
            return {
              type: 'UNRESOLVED',
              specifier: originalSpecifier,
              reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
            };
          }
          return { type: 'LOCAL_FILE', resolvedPath: realTarget };
        }
      } catch {
        // Ignored
      }
    }

    // Check directory with __init__.py
    if (fs.existsSync(candidatePath)) {
      try {
        const stat = fs.statSync(candidatePath);
        if (stat.isDirectory()) {
          const initFile = path.join(candidatePath, '__init__.py');
          if (fs.existsSync(initFile)) {
            const realTarget = fs.realpathSync(initFile);
            const rel = path.relative(realRoot, realTarget);
            if (rel.startsWith('..') || path.isAbsolute(rel)) {
              return {
                type: 'UNRESOLVED',
                specifier: originalSpecifier,
                reason: `Security violation: Path '${originalSpecifier}' escapes project root`,
              };
            }
            return { type: 'LOCAL_FILE', resolvedPath: realTarget };
          }
        }
      } catch {
        // Ignored
      }
    }

    return {
      type: 'UNRESOLVED',
      specifier: originalSpecifier,
      reason: `Could not resolve local Python file for '${originalSpecifier}'`,
    };
  }
}
