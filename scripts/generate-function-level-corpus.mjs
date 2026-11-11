import fs from 'node:fs';
import path from 'node:path';

const baseDir = path.resolve('packages/benchmark/corpus/function-level');

function writeFixture(caseName, files, expected) {
  const caseDir = path.join(baseDir, caseName);
  fs.mkdirSync(caseDir, { recursive: true });
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(caseDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf8');
  }
  fs.writeFileSync(
    path.join(caseDir, 'reachability-expected.json'),
    JSON.stringify(expected, null, 2),
    'utf8'
  );
}

console.log('Generating 62 Function-Level Benchmark Corpus Fixtures...');

function createNpmLockfile(pkgName, version = '4.17.21') {
  return JSON.stringify({
    name: 'test-app',
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { [pkgName]: `^${version}` } },
      [`node_modules/${pkgName}`]: { version },
    },
  });
}

// ---------------------------------------------------------
// 1. BINDING FORMS (Cases 01 - 10)
// ---------------------------------------------------------

// 01: ESM Default Import (Unused vulnerable symbol)
writeFixture(
  '01-binding-esm-default-unused',
  {
    'package.json': JSON.stringify({
      name: 'app-01',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import _ from 'lodash';\nconsole.log(_.map([1, 2], x => x * 2));\n`,
  },
  {
    id: '01-binding-esm-default-unused',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'HIGH',
    groundTruthUsed: false,
  }
);

// 02: ESM Named Import (Vulnerable symbol used)
writeFixture(
  '02-binding-esm-named-used',
  {
    'package.json': JSON.stringify({
      name: 'app-02',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import { template } from 'lodash';\nconst compiled = template('hello <%= user %>');\n`,
  },
  {
    id: '02-binding-esm-named-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 03: ESM Renamed Import (Vulnerable symbol called via local alias)
writeFixture(
  '03-binding-esm-renamed-used',
  {
    'package.json': JSON.stringify({
      name: 'app-03',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import { template as myCompiler } from 'lodash';\nconst res = myCompiler('test');\n`,
  },
  {
    id: '03-binding-esm-renamed-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 04: ESM Namespace Import (Unused symbol)
writeFixture(
  '04-binding-esm-namespace-unused',
  {
    'package.json': JSON.stringify({
      name: 'app-04',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import * as _ from 'lodash';\nconsole.log(_.isEqual(1, 1));\n`,
  },
  {
    id: '04-binding-esm-namespace-unused',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'HIGH',
    groundTruthUsed: false,
  }
);

// 05: CJS Require Whole Module (Vulnerable symbol used)
writeFixture(
  '05-binding-cjs-require-used',
  {
    'package.json': JSON.stringify({
      name: 'app-05',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconst fn = _.template('hi');\n`,
  },
  {
    id: '05-binding-cjs-require-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 06: CJS Require Destructuring (Vulnerable symbol used)
writeFixture(
  '06-binding-cjs-destructure-used',
  {
    'package.json': JSON.stringify({
      name: 'app-06',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const { template } = require('lodash');\nconsole.log(template);\n`,
  },
  {
    id: '06-binding-cjs-destructure-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 07: CJS Require Renamed (Vulnerable symbol used)
writeFixture(
  '07-binding-cjs-renamed-used',
  {
    'package.json': JSON.stringify({
      name: 'app-07',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const { template: tplEngine } = require('lodash');\nconst res = tplEngine('abc');\n`,
  },
  {
    id: '07-binding-cjs-renamed-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 08: TypeScript Import-Equals (Unused)
writeFixture(
  '08-binding-ts-import-equals-unused',
  {
    'package.json': JSON.stringify({
      name: 'app-08',
      main: 'src/index.ts',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.ts': `import _ = require('lodash');\nexport const x = _.flatten([1, [2]]);\n`,
  },
  {
    id: '08-binding-ts-import-equals-unused',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'HIGH',
    groundTruthUsed: false,
  }
);

// 09: Dynamic Import Promise (Used)
writeFixture(
  '09-binding-dynamic-import-promise-used',
  {
    'package.json': JSON.stringify({
      name: 'app-09',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import('lodash').then(_ => { _.template('hello'); });\n`,
  },
  {
    id: '09-binding-dynamic-import-promise-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 10: Dynamic Import Await (Unused)
writeFixture(
  '10-binding-dynamic-import-await-unused',
  {
    'package.json': JSON.stringify({
      name: 'app-10',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `async function run() {\n  const _ = await import('lodash');\n  console.log(_.keys({ a: 1 }));\n}\nrun();\n`,
  },
  {
    id: '10-binding-dynamic-import-await-unused',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'HIGH',
    groundTruthUsed: false,
  }
);

// ---------------------------------------------------------
// 2. NAMESPACE ESCAPE FORMS (Cases 11 - 23)
// ---------------------------------------------------------

// 11: Escape via Function Argument
writeFixture(
  '11-escape-argument-passed',
  {
    'package.json': JSON.stringify({
      name: 'app-11',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nfunction helper(lib) { return lib; }\nhelper(_);\n`,
  },
  {
    id: '11-escape-argument-passed',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 12: Escape via Function Return
writeFixture(
  '12-escape-returned-from-fn',
  {
    'package.json': JSON.stringify({
      name: 'app-12',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nfunction getUtil() { return _; }\ngetUtil();\n`,
  },
  {
    id: '12-escape-returned-from-fn',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 13: Escape via Default Export
writeFixture(
  '13-escape-default-export',
  {
    'package.json': JSON.stringify({
      name: 'app-13',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nexport default _;\n`,
  },
  {
    id: '13-escape-default-export',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 14: Escape via CJS Module Exports
writeFixture(
  '14-escape-cjs-module-exports',
  {
    'package.json': JSON.stringify({
      name: 'app-14',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `module.exports = require('lodash');\n`,
  },
  {
    id: '14-escape-cjs-module-exports',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 15: Escape via Object Literal Property
writeFixture(
  '15-escape-stored-in-object',
  {
    'package.json': JSON.stringify({
      name: 'app-15',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconst registry = { helper: _ };\nconsole.log(registry);\n`,
  },
  {
    id: '15-escape-stored-in-object',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 16: Escape via Array Literal Element
writeFixture(
  '16-escape-stored-in-array',
  {
    'package.json': JSON.stringify({
      name: 'app-16',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconst plugins = [_];\nconsole.log(plugins.length);\n`,
  },
  {
    id: '16-escape-stored-in-array',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 17: Escape via Object Spread
writeFixture(
  '17-escape-object-spread',
  {
    'package.json': JSON.stringify({
      name: 'app-17',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconst clone = { ..._ };\nconsole.log(clone);\n`,
  },
  {
    id: '17-escape-object-spread',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 18: Escape via Enumeration (Object.keys)
writeFixture(
  '18-escape-enumeration-object-keys',
  {
    'package.json': JSON.stringify({
      name: 'app-18',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconsole.log(Object.keys(_));\n`,
  },
  {
    id: '18-escape-enumeration-object-keys',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 19: Escape via Non-Literal Computed Property Access
writeFixture(
  '19-escape-computed-property-dynamic',
  {
    'package.json': JSON.stringify({
      name: 'app-19',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconst method = process.argv[2];\n_[method]('val');\n`,
  },
  {
    id: '19-escape-computed-property-dynamic',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 20: Escape via Reassigned Binding (let)
writeFixture(
  '20-escape-reassigned-let',
  {
    'package.json': JSON.stringify({
      name: 'app-20',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `let _ = require('lodash');\n_ = Object.assign({}, _);\nconsole.log(_);\n`,
  },
  {
    id: '20-escape-reassigned-let',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 21: Python Escape via getattr
writeFixture(
  '21-escape-python-getattr',
  {
    'requirements.txt': 'requests==2.30.0\n',
    'app.py': `import requests\nattr_name = 'get'\nfn = getattr(requests, attr_name)\nfn('http://example.com')\n`,
  },
  {
    id: '21-escape-python-getattr',
    package: 'requests',
    ecosystem: 'pip',
    ruleId: 'CVE-2023-32681',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 22: Python Escape via Wildcard Import
writeFixture(
  '22-escape-python-wildcard-import',
  {
    'requirements.txt': 'requests==2.30.0\n',
    'app.py': `from requests import *\nprint(get('http://example.com'))\n`,
  },
  {
    id: '22-escape-python-wildcard-import',
    package: 'requests',
    ecosystem: 'pip',
    ruleId: 'CVE-2023-32681',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 23: Escape Marker via createRequire
writeFixture(
  '23-escape-create-require-marker',
  {
    'package.json': JSON.stringify({
      name: 'app-23',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import { createRequire } from 'module';\nimport _ from 'lodash';\nconst req = createRequire(import.meta.url);\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '23-escape-create-require-marker',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// ---------------------------------------------------------
// 3. PRECONDITION BREAKS (Cases 24 - 35)
// ---------------------------------------------------------

// 24: P1 Break - Unresolved entrypoint
writeFixture(
  '24-precondition-p1-no-entrypoint',
  {
    'package.json': JSON.stringify({
      name: 'app-24',
      main: 'src/index.js',
      bin: { 'cli-tool': 'missing-cli.js' },
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '24-precondition-p1-no-entrypoint',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'NO_ENTRYPOINT',
    groundTruthUsed: false,
  }
);

// 25: P2 Break - Parse error in source file
writeFixture(
  '25-precondition-p2-parse-error',
  {
    'package.json': JSON.stringify({
      name: 'app-25',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconst x = ; // syntax error\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '25-precondition-p2-parse-error',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'PARSE_ERROR',
    groundTruthUsed: false,
  }
);

// 26: P3 Break - Unresolved local import
writeFixture(
  '26-precondition-p3-unresolved-local-import',
  {
    'package.json': JSON.stringify({
      name: 'app-26',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nimport { missingFn } from './non-existent-file.js';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '26-precondition-p3-unresolved-local-import',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'UNRESOLVED_IMPORT',
    groundTruthUsed: false,
  }
);

// 27: P3 Break - Dynamic import with variable
writeFixture(
  '27-precondition-p3-dynamic-import-var',
  {
    'package.json': JSON.stringify({
      name: 'app-27',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconst modName = 'axios';\nimport(modName);\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '27-precondition-p3-dynamic-import-var',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'DYNAMIC_IMPORT',
    groundTruthUsed: false,
  }
);

// 28: P3 Break - Eval marker in production code
writeFixture(
  '28-precondition-p3-eval-present',
  {
    'package.json': JSON.stringify({
      name: 'app-28',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\neval("console.log('dynamic')");\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '28-precondition-p3-eval-present',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'DYNAMIC_IMPORT',
    groundTruthUsed: false,
  }
);

// 29: P4 Break - Package mentioned in Dockerfile
writeFixture(
  '29-precondition-p4-dockerfile-reference',
  {
    'package.json': JSON.stringify({
      name: 'app-29',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    Dockerfile: 'FROM node:18\nRUN npm install lodash\nCMD ["node", "index.js"]\n',
    'index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '29-precondition-p4-dockerfile-reference',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'CONFIG_REFERENCE',
    groundTruthUsed: false,
  }
);

// 30: P4 Break - Package mentioned in unparsed source file
writeFixture(
  '30-precondition-p4-unparsed-text-file',
  {
    'package.json': JSON.stringify({
      name: 'app-30',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'scripts/deploy.sh': '#!/bin/bash\necho "Running lodash deployment script"\n',
    'index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '30-precondition-p4-unparsed-text-file',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'CONFIG_REFERENCE',
    groundTruthUsed: false,
  }
);

// 31: P5 Break - Dependents present (non-leaf direct package)
writeFixture(
  '31-precondition-p5-dependents-present',
  {
    'package.json': JSON.stringify({
      name: 'app-31',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21', 'my-helper': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-31',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '^4.17.21', 'my-helper': '^1.0.0' } },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/my-helper': {
          version: '1.0.0',
          dependencies: { lodash: '^4.17.21' },
        },
      },
    }),
    'index.js': `import _ from 'lodash';\nimport helper from 'my-helper';\nconsole.log(_.map([1], x => x), helper);\n`,
  },
  {
    id: '31-precondition-p5-dependents-present',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'NOT_LEAF_PACKAGE',
    groundTruthUsed: false,
  }
);

// 32: P5 Break - Missing lockfile tree
writeFixture(
  '32-precondition-p5-no-lockfile',
  {
    'package.json': JSON.stringify({
      name: 'app-32',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '32-precondition-p5-no-lockfile',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'NO_LOCKFILE_TREE',
    groundTruthUsed: false,
  }
);

// 33: P6 Break - Bin exposure (package provides CLI binary)
writeFixture(
  '33-precondition-p6-bin-exposure',
  {
    'package.json': JSON.stringify({
      name: 'app-33',
      main: 'index.js',
      dependencies: { semver: '^7.3.5' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-33',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { semver: '^7.3.5' } },
        'node_modules/semver': {
          version: '7.3.5',
          bin: { semver: 'bin/semver.js' },
        },
      },
    }),
    'index.js': `import semver from 'semver';\nconsole.log(semver.valid('1.0.0'));\n`,
  },
  {
    id: '33-precondition-p6-bin-exposure',
    package: 'semver',
    ecosystem: 'npm',
    ruleId: 'CVE-2022-25883',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'MEDIUM', // P6 bin exposure caps at MEDIUM
    groundTruthUsed: false,
  }
);

// 34: P7 Break - Tampered dataset manifest SHA mismatch
writeFixture(
  '34-precondition-p7-tampered-dataset',
  {
    'package.json': JSON.stringify({
      name: 'app-34',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '34-precondition-p7-tampered-dataset',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    simulateTamper: true,
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'INTEGRITY_FAILED',
    groundTruthUsed: false,
  }
);

// 35: P10 Break - npm specifier alias
writeFixture(
  '35-precondition-p10-npm-alias',
  {
    'package.json': JSON.stringify({
      name: 'app-35',
      main: 'index.js',
      dependencies: {
        lodash: '^4.17.21',
        mylodash: 'npm:lodash@^4.17.21',
      },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-35',
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: {
            lodash: '^4.17.21',
            mylodash: 'npm:lodash@^4.17.21',
          },
        },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/mylodash': { name: 'lodash', version: '4.17.21' },
      },
    }),
    'index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '35-precondition-p10-npm-alias',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'ALIASED_PACKAGE',
    groundTruthUsed: false,
  }
);

// ---------------------------------------------------------
// 4. HEURISTIC CANDIDATE TRAPS (Cases 36 - 41)
// ---------------------------------------------------------

// 36: Heuristic Stoplist Trap ("method of")
writeFixture(
  '36-heuristic-stoplist-trap',
  {
    'package.json': JSON.stringify({
      name: 'app-36',
      main: 'index.js',
      dependencies: { somepkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('somepkg', '1.0.0'),
    'index.js': `const p = require('somepkg');\nconsole.log(p);\n`,
  },
  {
    id: '36-heuristic-stoplist-trap',
    package: 'somepkg',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99991',
    description: 'Vulnerability in the method of somepkg execution',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedNotes: 'symbol data unavailable',
    groundTruthUsed: false,
  }
);

// 37: Heuristic Version String Trap ("1.2.3")
writeFixture(
  '37-heuristic-version-string-trap',
  {
    'package.json': JSON.stringify({
      name: 'app-37',
      main: 'index.js',
      dependencies: { somepkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('somepkg', '1.0.0'),
    'index.js': `const p = require('somepkg');\nconsole.log(p);\n`,
  },
  {
    id: '37-heuristic-version-string-trap',
    package: 'somepkg',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99992',
    description: 'Vulnerability in version 1.2.3 of somepkg',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedNotes: 'symbol data unavailable',
    groundTruthUsed: false,
  }
);

// 38: Heuristic Prefix Mismatch Trap (axios.get on lodash)
writeFixture(
  '38-heuristic-prefix-mismatch-trap',
  {
    'package.json': JSON.stringify({
      name: 'app-38',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconsole.log(_.map([1], x => x));\n`,
  },
  {
    id: '38-heuristic-prefix-mismatch-trap',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99993',
    description: 'Vulnerability triggered by calling axios.get()',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedNotes: 'symbol data unavailable',
    groundTruthUsed: false,
  }
);

// 39: Valid Heuristic Candidate (Caps at LOW, Never Suppressible)
writeFixture(
  '39-heuristic-valid-match-low',
  {
    'package.json': JSON.stringify({
      name: 'app-39',
      main: 'index.js',
      dependencies: { samplelib: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('samplelib', '1.0.0'),
    'index.js': `const s = require('samplelib');\nconsole.log(s.cleanFunction());\n`,
  },
  {
    id: '39-heuristic-valid-match-low',
    package: 'samplelib',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99994',
    description: 'Calling samplelib.vulnerableFunction() causes crash',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'LOW', // Heuristic is permanently LOW
    groundTruthUsed: false,
  }
);

// 40: Heuristic Identifier Boundary < 2 characters Trap
writeFixture(
  '40-heuristic-short-id-trap',
  {
    'package.json': JSON.stringify({
      name: 'app-40',
      main: 'index.js',
      dependencies: { somepkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('somepkg', '1.0.0'),
    'index.js': `const p = require('somepkg');\nconsole.log(p);\n`,
  },
  {
    id: '40-heuristic-short-id-trap',
    package: 'somepkg',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99995',
    description: 'Vulnerability in function a() of somepkg',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedNotes: 'symbol data unavailable',
    groundTruthUsed: false,
  }
);

// 41: Heuristic Identifier Boundary > 64 characters Trap
writeFixture(
  '41-heuristic-long-id-trap',
  {
    'package.json': JSON.stringify({
      name: 'app-41',
      main: 'index.js',
      dependencies: { somepkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('somepkg', '1.0.0'),
    'index.js': `const p = require('somepkg');\nconsole.log(p);\n`,
  },
  {
    id: '41-heuristic-long-id-trap',
    package: 'somepkg',
    ecosystem: 'npm',
    ruleId: 'CVE-2026-99996',
    description: `Calling somepkg.${'x'.repeat(65)}() is dangerous`,
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedNotes: 'symbol data unavailable',
    groundTruthUsed: false,
  }
);

// ---------------------------------------------------------
// 5. DATASET API COMPLEXITIES & INVOCATION FORMS (Cases 42 - 53)
// ---------------------------------------------------------

// 42: kind: METHOD with matching via export
writeFixture(
  '42-method-via-chain-used',
  {
    'package.json': JSON.stringify({
      name: 'app-42',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconst res = _.chain({ a: 1 }).template().value();\nconsole.log(res);\n`,
  },
  {
    id: '42-method-via-chain-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 43: kind: METHOD without matching via export
writeFixture(
  '43-method-without-via-chain',
  {
    'package.json': JSON.stringify({
      name: 'app-43',
      main: 'index.js',
      dependencies: { customlib: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('customlib', '1.0.0'),
    'index.js': `const c = require('customlib');\nconsole.log(c.other());\n`,
  },
  {
    id: '43-method-without-via-chain',
    package: 'customlib',
    ecosystem: 'npm',
    ruleId: 'CUSTOM-CVE-METHOD-NO-VIA',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'ENTRYPOINTS_INCOMPLETE',
    groundTruthUsed: false,
    customDataset: {
      version: '1.0.0',
      datasetId: 'test-method-no-via',
      entries: [
        {
          id: 'CUSTOM-CVE-METHOD-NO-VIA',
          aliases: [],
          ecosystem: 'npm',
          package: 'customlib',
          entryPoints: [{ module: '.', export: 'vulnerableMethod', kind: 'METHOD', via: [] }],
          triggeredOn: 'CALL',
          entryPointsComplete: true,
          sourceUrls: ['https://example.com/advisory'],
          fixCommitUrls: ['https://example.com/fix'],
          verifiedAt: '2026-10-25',
          verifiedBy: 'Test Runner',
          notes: 'Test method without via',
        },
      ],
    },
  }
);

// 44: triggeredOn: IMPORT_TIME Entry (Blocked from pruning)
writeFixture(
  '44-dataset-triggered-on-import',
  {
    'package.json': JSON.stringify({
      name: 'app-44',
      main: 'index.js',
      dependencies: { importpkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('importpkg', '1.0.0'),
    'index.js': `const p = require('importpkg');\nconst x = 1;\n`,
  },
  {
    id: '44-dataset-triggered-on-import',
    package: 'importpkg',
    ecosystem: 'npm',
    ruleId: 'CUSTOM-CVE-IMPORT-TIME',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'TRIGGER_NOT_CALL',
    groundTruthUsed: true, // Importing it triggers the bug!
    customDataset: {
      version: '1.0.0',
      datasetId: 'test-import-time',
      entries: [
        {
          id: 'CUSTOM-CVE-IMPORT-TIME',
          aliases: [],
          ecosystem: 'npm',
          package: 'importpkg',
          entryPoints: [{ module: '.', export: 'init', kind: 'FUNCTION' }],
          triggeredOn: 'IMPORT_TIME',
          entryPointsComplete: true,
          sourceUrls: ['https://example.com/advisory'],
          fixCommitUrls: ['https://example.com/fix'],
          verifiedAt: '2026-10-25',
          verifiedBy: 'Test Runner',
          notes: 'Test import time trigger',
        },
      ],
    },
  }
);

// 45: entryPointsComplete: false Entry (Blocked from HIGH pruning)
writeFixture(
  '45-dataset-incomplete-entrypoints',
  {
    'package.json': JSON.stringify({
      name: 'app-45',
      main: 'index.js',
      dependencies: { incomppkg: '^1.0.0' },
    }),
    'package-lock.json': createNpmLockfile('incomppkg', '1.0.0'),
    'index.js': `const p = require('incomppkg');\nconsole.log(p.safe());\n`,
  },
  {
    id: '45-dataset-incomplete-entrypoints',
    package: 'incomppkg',
    ecosystem: 'npm',
    ruleId: 'CUSTOM-CVE-INCOMPLETE-ENTRYPOINTS',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'ENTRYPOINTS_INCOMPLETE',
    groundTruthUsed: false,
    customDataset: {
      version: '1.0.0',
      datasetId: 'test-incomplete-entrypoints',
      entries: [
        {
          id: 'CUSTOM-CVE-INCOMPLETE-ENTRYPOINTS',
          aliases: [],
          ecosystem: 'npm',
          package: 'incomppkg',
          entryPoints: [{ module: '.', export: 'vulnerable', kind: 'FUNCTION' }],
          triggeredOn: 'CALL',
          entryPointsComplete: false,
          sourceUrls: ['https://example.com/advisory'],
          fixCommitUrls: ['https://example.com/fix'],
          verifiedAt: '2026-10-25',
          verifiedBy: 'Test Runner',
          notes: 'Test incomplete entry points',
        },
      ],
    },
  }
);

// 46: Deep Subpath Import without mapping (Treated as escape)
writeFixture(
  '46-subpath-unknown-mapping',
  {
    'package.json': JSON.stringify({
      name: 'app-46',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const fp = require('lodash/fp');\nconsole.log(fp);\n`,
  },
  {
    id: '46-subpath-unknown-mapping',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'NAMESPACE_ESCAPES',
    expectedConfidence: 'MEDIUM',
    groundTruthUsed: true,
  }
);

// 47: Deep Subpath Import with mapped symbol
writeFixture(
  '47-subpath-known-mapping-used',
  {
    'package.json': JSON.stringify({
      name: 'app-47',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const template = require('lodash/template');\nconsole.log(template('hi'));\n`,
  },
  {
    id: '47-subpath-known-mapping-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 48: Literal Computed Access
writeFixture(
  '48-usage-literal-computed-access',
  {
    'package.json': JSON.stringify({
      name: 'app-48',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nconst fn = _['template'];\nfn('msg');\n`,
  },
  {
    id: '48-usage-literal-computed-access',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 49: Single-Assignment Member Aliasing
writeFixture(
  '49-usage-member-aliasing',
  {
    'package.json': JSON.stringify({
      name: 'app-49',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nconst myTpl = _.template;\nmyTpl('hello');\n`,
  },
  {
    id: '49-usage-member-aliasing',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 50: Optional Chaining Call
writeFixture(
  '50-usage-optional-chaining',
  {
    'package.json': JSON.stringify({
      name: 'app-50',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\n_?.template?.('hello');\n`,
  },
  {
    id: '50-usage-optional-chaining',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 51: Tagged Template Expression
writeFixture(
  '51-usage-tagged-template',
  {
    'package.json': JSON.stringify({
      name: 'app-51',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\n_.template\`hello <%= name %>\`;\n`,
  },
  {
    id: '51-usage-tagged-template',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 52: New Constructor Invocation
writeFixture(
  '52-usage-new-constructor',
  {
    'package.json': JSON.stringify({
      name: 'app-52',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `const _ = require('lodash');\nnew _.template('hello');\n`,
  },
  {
    id: '52-usage-new-constructor',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 53: Callback Reference (Used without call)
writeFixture(
  '53-usage-callback-reference',
  {
    'package.json': JSON.stringify({
      name: 'app-53',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'index.js': `import _ from 'lodash';\nexport function entrypoint() {\n  console.log('main');\n}\nfunction uncalledCallbackHolder() {\n  const list = ['a'].map(_.template);\n  return list;\n}\nentrypoint();\n`,
  },
  {
    id: '53-usage-callback-reference',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'SYMBOL_REFERENCED',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// ---------------------------------------------------------
// 6. PYTHON, FRAMEWORKS, & SCOPING (Cases 54 - 62)
// ---------------------------------------------------------

// 54: Python Standard Module Import (Unused vulnerable symbol)
writeFixture(
  '54-python-standard-import-unused',
  {
    'requirements.txt': 'requests==2.30.0\n',
    'Pipfile.lock': JSON.stringify({ default: { requests: { version: '==2.30.0' } }, develop: {} }),
    'app.py': `import requests\nprint(requests.__version__)\n`,
  },
  {
    id: '54-python-standard-import-unused',
    package: 'requests',
    ecosystem: 'pip',
    ruleId: 'CVE-2023-32681',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'MEDIUM', // Python SCA uninvoked is capped at MEDIUM
    groundTruthUsed: false,
  }
);

// 55: Python From-Import (Used vulnerable symbol)
writeFixture(
  '55-python-from-import-used',
  {
    'requirements.txt': 'requests==2.30.0\n',
    'app.py': `from requests import Session\ns = Session()\ns.get('https://example.com')\n`,
  },
  {
    id: '55-python-from-import-used',
    package: 'requests',
    ecosystem: 'pip',
    ruleId: 'CVE-2023-32681',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 56: Python Alias Import (Used vulnerable symbol)
writeFixture(
  '56-python-alias-import-used',
  {
    'requirements.txt': 'requests==2.30.0\n',
    'app.py': `import requests as req\ns = req.Session()\nprint(s)\n`,
  },
  {
    id: '56-python-alias-import-used',
    package: 'requests',
    ecosystem: 'pip',
    ruleId: 'CVE-2023-32681',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

// 57: Python Uninvoked Medium Cap (P9 Ecosystem Rule)
writeFixture(
  '57-python-uninvoked-medium-cap',
  {
    'requirements.txt': 'pyyaml==5.3.1\n',
    'Pipfile.lock': JSON.stringify({ default: { pyyaml: { version: '==5.3.1' } }, develop: {} }),
    'app.py': `import yaml\nyaml.safe_load('a: 1')\n`,
  },
  {
    id: '57-python-uninvoked-medium-cap',
    package: 'pyyaml',
    ecosystem: 'pip',
    ruleId: 'CVE-2020-14343',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'MEDIUM', // Never HIGH for PyPI per P9
    groundTruthUsed: false,
  }
);

// 58: Framework File Mention (.vue)
writeFixture(
  '58-framework-vue-mention',
  {
    'package.json': JSON.stringify({
      name: 'app-58',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/App.vue': `<template><div>{{ count }}</div></template>\n<script>\nimport _ from 'lodash';\nexport default { data: () => ({ count: _.map([1], x => x) }) }\n</script>\n`,
    'index.js': `import _ from 'lodash';\nimport App from './src/App.vue';\nconsole.log(_.map([1], x => x), App);\n`,
  },
  {
    id: '58-framework-vue-mention',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'CONFIG_REFERENCE',
    groundTruthUsed: false,
  }
);

// 59: Framework File Mention (.svelte)
writeFixture(
  '59-framework-svelte-mention',
  {
    'package.json': JSON.stringify({
      name: 'app-59',
      main: 'index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/Widget.svelte': `<script>\nimport _ from 'lodash';\nlet items = _.isEqual(1, 1);\n</script>\n<p>{items}</p>\n`,
    'index.js': `import _ from 'lodash';\nimport Widget from './src/Widget.svelte';\nconsole.log(_.map([1], x => x), Widget);\n`,
  },
  {
    id: '59-framework-svelte-mention',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
    expectedBlockedBy: 'CONFIG_REFERENCE',
    groundTruthUsed: false,
  }
);

// 60: Test-Only Usage (Production Uninvoked)
writeFixture(
  '60-test-only-usage',
  {
    'package.json': JSON.stringify({
      name: 'app-60',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import _ from 'lodash';\nexport const res = _.map([1], x => x);\n`,
    'test/app.test.js': `import _ from 'lodash';\nconst t = _.template('test');\nconsole.log(t);\n`,
  },
  {
    id: '60-test-only-usage',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'UNINVOKED_SYMBOL',
    expectedConfidence: 'HIGH',
    groundTruthUsed: false,
  }
);

// 61: Dead-File Usage (Counts as Possibly Used under F1)
writeFixture(
  '61-dead-file-usage-counts-as-used',
  {
    'package.json': JSON.stringify({
      name: 'app-61',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/index.js': `import _ from 'lodash';\nconsole.log(_.map([1], x => x));\n`,
    'src/dead-unused-module.js': `import _ from 'lodash';\n_.template('vulnerable');\n`,
  },
  {
    id: '61-dead-file-usage-counts-as-used',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'SYMBOL_REFERENCED',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true, // Non-test source file contains it -> counts as possibly used
  }
);

// 62: Multi-Hop Call Path Proven
writeFixture(
  '62-multihop-call-path-proven',
  {
    'package.json': JSON.stringify({
      name: 'app-62',
      main: 'src/main.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': createNpmLockfile('lodash'),
    'src/main.js': `import { serviceCall } from './service.js';\nexport function entrypoint() {\n  serviceCall();\n}\nentrypoint();\n`,
    'src/service.js': `import { renderTemplate } from './renderer.js';\nexport function serviceCall() {\n  renderTemplate();\n}\n`,
    'src/renderer.js': `import _ from 'lodash';\nexport function renderTemplate() {\n  _.template('hello');\n}\n`,
  },
  {
    id: '62-multihop-call-path-proven',
    package: 'lodash',
    ecosystem: 'npm',
    ruleId: 'CVE-2021-23337',
    expectedVerdict: 'REACHABLE_CALL_PATH',
    expectedKind: 'SYMBOL_CALL_PATH',
    expectedConfidence: 'HIGH',
    groundTruthUsed: true,
  }
);

console.log('Successfully generated 62 function-level benchmark fixtures.');
