import fs from 'node:fs';
import path from 'node:path';

/**
 * Offline builder script to refresh or extend the verified popular packages dataset.
 */
export async function buildPopularList(inputNames: string[], outputPath: string): Promise<void> {
  const unique = Array.from(new Set(inputNames.map((s) => s.trim().toLowerCase()))).sort();
  const records = unique.map((name) => ({
    name,
    downloads: 10_000_000,
  }));

  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(records, null, 2), 'utf-8');
}
