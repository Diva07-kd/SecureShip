import { execFileSync } from 'node:child_process';
export function getGitCommit() {
  return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf-8' });
}
