import fs from 'node:fs';
export function getFile(userPath) {
  return fs.readFileSync('/var/data/' + userPath, 'utf-8');
}
