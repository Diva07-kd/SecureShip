import fs from 'node:fs';
import path from 'node:path';

export class PythonPackageMap {
  /**
   * Curated static mapping table: normalized PyPI package name -> array of top-level importable modules.
   */
  private static readonly STATIC_MAP: Record<string, string[]> = {
    pyyaml: ['yaml'],
    pillow: ['PIL'],
    beautifulsoup4: ['bs4'],
    'scikit-learn': ['sklearn'],
    'opencv-python': ['cv2'],
    'opencv-python-headless': ['cv2'],
    'python-dateutil': ['dateutil'],
    attrs: ['attr', 'attrs'],
    protobuf: ['google.protobuf'],
    setuptools: ['setuptools', 'pkg_resources'],
    'typing-extensions': ['typing_extensions'],
    'psycopg2-binary': ['psycopg2'],
    mysqlclient: ['MySQLdb'],
    pyjwt: ['jwt'],
    pymongo: ['pymongo', 'bson'],
    'pydantic-core': ['pydantic_core'],
    'apache-airflow': ['airflow'],
    dnspython: ['dns'],
    flask: ['flask'],
    django: ['django'],
    requests: ['requests'],
    numpy: ['numpy'],
    pandas: ['pandas'],
    scipy: ['scipy'],
    pytest: ['pytest'],
    rich: ['rich'],
    click: ['click'],
    fastapi: ['fastapi'],
    uvicorn: ['uvicorn'],
    sqlalchemy: ['sqlalchemy'],
    celery: ['celery'],
    redis: ['redis'],
    jinja2: ['jinja2'],
    markupsafe: ['markupsafe'],
    werkzeug: ['werkzeug'],
    httpx: ['httpx'],
    cryptography: ['cryptography'],
    filelock: ['filelock'],
    urllib3: ['urllib3'],
    certifi: ['certifi'],
    idna: ['idna'],
    'charset-normalizer': ['charset_normalizer'],
    boto3: ['boto3'],
    botocore: ['botocore'],
    six: ['six'],
  };

  /**
   * Normalizes a Python package name per PEP 503 (lowercase, dash/dot/underscore equivalence).
   */
  public static normalizePackageName(name: string): string {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
  }

  /**
   * Normalizes to module name format (underscores).
   */
  public static toModuleIdentifier(name: string): string {
    return name.toLowerCase().replace(/[-_.]+/g, '_');
  }

  /**
   * Resolves possible importable module names for a given package name.
   */
  public static getImportableModuleNames(
    packageName: string,
    targetDir?: string
  ): { modules: string[]; source: 'STATIC' | 'VENV' | 'CANONICAL' | 'UNMAPPED' } {
    const normalized = PythonPackageMap.normalizePackageName(packageName);

    // 1. Check local virtual environment top_level.txt if present
    if (targetDir) {
      const venvModules = PythonPackageMap.scanVenvTopLevel(packageName, targetDir);
      if (venvModules && venvModules.length > 0) {
        return { modules: venvModules, source: 'VENV' };
      }
    }

    // 2. Check static mapping table
    if (PythonPackageMap.STATIC_MAP[normalized]) {
      return { modules: PythonPackageMap.STATIC_MAP[normalized]!, source: 'STATIC' };
    }

    // 3. Canonical direct name: e.g. "requests" -> ["requests"] or "my-tool" -> ["my_tool"]
    const directModule = PythonPackageMap.toModuleIdentifier(packageName);
    if (/^[a-z_][a-z0-9_]*$/.test(directModule)) {
      return { modules: [directModule], source: 'CANONICAL' };
    }

    // 4. Unmapped package
    return { modules: [], source: 'UNMAPPED' };
  }

  /**
   * Inspects top_level.txt in local virtual environment dist-info directories.
   */
  public static scanVenvTopLevel(packageName: string, targetDir: string): string[] | null {
    const venvDirs = ['.venv', 'venv', 'env', '.env'];
    const normPkg = PythonPackageMap.toModuleIdentifier(packageName);

    for (const venvName of venvDirs) {
      const candidateVenv = path.join(targetDir, venvName);
      if (!fs.existsSync(candidateVenv)) continue;

      // Scan site-packages
      const sitePackagesCandidates = [
        path.join(candidateVenv, 'Lib', 'site-packages'), // Windows
        path.join(candidateVenv, 'lib', 'site-packages'),
      ];

      // Also check Linux pythonX.Y/site-packages
      const libDir = path.join(candidateVenv, 'lib');
      if (fs.existsSync(libDir)) {
        try {
          const subdirs = fs.readdirSync(libDir);
          for (const s of subdirs) {
            if (s.startsWith('python')) {
              sitePackagesCandidates.push(path.join(libDir, s, 'site-packages'));
            }
          }
        } catch {
          // Ignored
        }
      }

      for (const sp of sitePackagesCandidates) {
        if (!fs.existsSync(sp)) continue;

        try {
          const entries = fs.readdirSync(sp);
          for (const entry of entries) {
            if (entry.toLowerCase().startsWith(normPkg) && entry.endsWith('.dist-info')) {
              const topLevelPath = path.join(sp, entry, 'top_level.txt');
              if (fs.existsSync(topLevelPath)) {
                const lines = fs
                  .readFileSync(topLevelPath, 'utf8')
                  .split(/\r?\n/)
                  .map((l) => l.trim())
                  .filter((l) => l.length > 0 && !l.startsWith('#'));
                if (lines.length > 0) {
                  return lines;
                }
              }
            }
          }
        } catch {
          // Ignored
        }
      }
    }

    return null;
  }
}
