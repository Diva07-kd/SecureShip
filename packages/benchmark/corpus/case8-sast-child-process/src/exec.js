import child_process from 'node:child_process';
export function run(userCmd) {
  child_process.execSync(`sh scripts/${userCmd}.sh`);
}

