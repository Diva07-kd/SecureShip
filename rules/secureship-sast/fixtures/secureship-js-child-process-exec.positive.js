import child_process from 'node:child_process';

// Positive fixture: command built with string concatenation
function pingHost(host) {
  child_process.exec('ping -c 1 ' + host);
}

function runDynamicScript(scriptName) {
  child_process.execSync(`sh scripts/${scriptName}.sh`);
}
