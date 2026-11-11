import fs from 'node:fs';
import path from 'node:path';
import { resolveDbDir } from '../paths/index.js';
import { OfflineGenerationManifest, OfflineGenerationManifestSchema } from './types.js';

export class DbLocator {
  /**
   * Returns the ID of the current active database generation by reading the CURRENT pointer file.
   */
  public static getCurrentGenerationId(dbDir?: string): string | null {
    const baseDir = dbDir ?? resolveDbDir();
    const currentPath = path.join(baseDir, 'CURRENT');
    if (!fs.existsSync(currentPath)) {
      return null;
    }

    try {
      const id = fs.readFileSync(currentPath, 'utf-8').trim();
      return id.length > 0 ? id : null;
    } catch {
      return null;
    }
  }

  /**
   * Returns the directory for a specific generation ID.
   */
  public static getGenerationDir(generationId: string, dbDir?: string): string {
    const baseDir = dbDir ?? resolveDbDir();
    return path.join(baseDir, 'generations', generationId);
  }

  /**
   * Reads and validates the generation manifest (manifest.json).
   */
  public static loadGenerationManifest(
    generationId: string,
    dbDir?: string
  ): OfflineGenerationManifest | null {
    const genDir = DbLocator.getGenerationDir(generationId, dbDir);
    const manifestPath = path.join(genDir, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      return null;
    }

    try {
      const raw = fs.readFileSync(manifestPath, 'utf-8');
      return OfflineGenerationManifestSchema.parse(JSON.parse(raw));
    } catch {
      return null;
    }
  }

  /**
   * Returns true if there is an active generation with a valid manifest and directory.
   */
  public static hasValidGeneration(dbDir?: string): boolean {
    const active = DbLocator.getActiveGeneration(dbDir);
    return active !== null;
  }

  /**
   * Returns the active generation info if valid, or null otherwise.
   */
  public static getActiveGeneration(
    dbDir?: string
  ): { id: string; dir: string; manifest: OfflineGenerationManifest } | null {
    const id = DbLocator.getCurrentGenerationId(dbDir);
    if (!id) return null;

    const dir = DbLocator.getGenerationDir(id, dbDir);
    if (!fs.existsSync(dir)) return null;

    const manifest = DbLocator.loadGenerationManifest(id, dbDir);
    if (!manifest) return null;

    return { id, dir, manifest };
  }

  /**
   * Resolves the Trivy cache directory inside a generation directory.
   */
  public static getTrivyCacheDir(generationDir: string): string {
    return path.join(generationDir, 'trivy');
  }

  /**
   * Resolves the OSV-Scanner database cache directory inside a generation directory.
   */
  public static getOsvDbDir(generationDir: string): string {
    return path.join(generationDir, 'osv');
  }

  /**
   * Lists all existing generation directory IDs in the generations folder.
   */
  public static listGenerations(dbDir?: string): string[] {
    const baseDir = dbDir ?? resolveDbDir();
    const gensDir = path.join(baseDir, 'generations');
    if (!fs.existsSync(gensDir)) return [];

    try {
      return fs
        .readdirSync(gensDir, { withFileTypes: true })
        .filter((dirent) => dirent.isDirectory())
        .map((dirent) => dirent.name)
        .sort();
    } catch {
      return [];
    }
  }
}
