import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __setupDir = path.dirname(fileURLToPath(import.meta.url));
if (path.resolve(process.cwd()) !== path.resolve(__setupDir)) {
  try {
    process.chdir(__setupDir);
  } catch {}
}

process.on('warning', (warning: Error) => {
  const isDep0190 =
    warning.name === 'DeprecationWarning' &&
    ((warning as { code?: string }).code === 'DEP0190' ||
      warning.message.includes('DEP0190') ||
      warning.message.includes('shell option true'));

  if (isDep0190) {
    const errorMsg = `CRITICAL SECURITY FAILURE: Node DEP0190 warning detected: ${warning.message}`;
    console.error(`\n❌ ${errorMsg}\n`);
    throw new Error(errorMsg);
  }
});
