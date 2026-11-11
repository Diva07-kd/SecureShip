import fs from 'node:fs';
import path from 'node:path';
export function getSafeFile(userPath) {
  const base = '/var/data';
  const safe = path.resolve(base, path.basename(userPath));
  return fs.readFileSync(safe, 'utf-8');
}
