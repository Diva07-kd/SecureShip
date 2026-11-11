import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const corpusDir = path.resolve('packages/benchmark/corpus/gate3');
const hash = crypto.createHash('sha256');

function collectFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

const allFiles = collectFiles(corpusDir).sort();

console.log(`Hashing ${allFiles.length} files across Gate 3 corpus...`);

for (const filePath of allFiles) {
  const relPath = path.relative(corpusDir, filePath).replace(/\\/g, '/');
  const content = fs.readFileSync(filePath);
  hash.update(relPath + '\0');
  hash.update(content);
}

const fullHash = hash.digest('hex');
console.log(`Method: SHA-256 over all sorted relative filepaths (POSIX, NUL-delimited) and file contents in packages/benchmark/corpus/gate3`);
console.log(`Full Corpus Hash: ${fullHash}`);
