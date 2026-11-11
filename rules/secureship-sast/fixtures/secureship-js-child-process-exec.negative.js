import child_process from 'node:child_process';

// Negative fixture: safe static command or array execFile
function checkVersion() {
  child_process.execFile('git', ['--version']);
}

function runConstantCommand() {
  child_process.exec('uptime');
}
