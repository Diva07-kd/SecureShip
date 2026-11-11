import fs from 'node:fs';
import path from 'node:path';

const baseDir = path.resolve('packages/benchmark/corpus/gate2');

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

console.log('Generating 31 Gate 2 Reachability Corpus Fixtures...');

// 1. prod-import-esm
writeFixture(
  '01-prod-import-esm',
  {
    'package.json': JSON.stringify({
      name: 'app-01',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-01',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '^4.17.21' } },
        'node_modules/lodash': { version: '4.17.21' },
      },
    }),
    'src/index.js': `import _ from 'lodash';\nconsole.log(_.map([1, 2], x => x * 2));\n`,
  },
  {
    id: '01-prod-import-esm',
    category: 'SCA',
    package: 'lodash',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 2. prod-import-cjs
writeFixture(
  '02-prod-import-cjs',
  {
    'package.json': JSON.stringify({
      name: 'app-02',
      main: 'index.js',
      dependencies: { express: '^4.18.2' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-02',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { express: '^4.18.2' } },
        'node_modules/express': { version: '4.18.2' },
      },
    }),
    'index.js': `const express = require('express');\nconst app = express();\n`,
  },
  {
    id: '02-prod-import-cjs',
    category: 'SCA',
    package: 'express',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 3. test-only-import (Amendment A4: max MEDIUM confidence, never auto-suppressed)
writeFixture(
  '03-test-only-import',
  {
    'package.json': JSON.stringify({
      name: 'app-03',
      main: 'index.js',
      devDependencies: { mocha: '^10.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-03',
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { mocha: '^10.0.0' } },
        'node_modules/mocha': { version: '10.0.0', dev: true },
      },
    }),
    'index.js': `console.log('production app');\n`,
    'test/app.test.js': `const mocha = require('mocha');\n`,
  },
  {
    id: '03-test-only-import',
    category: 'SCA',
    package: 'mocha',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'DEV_ONLY',
    expectedConfidence: 'MEDIUM',
  }
);

// 4. dev-only-dependency (Amendment A4: max MEDIUM confidence)
writeFixture(
  '04-dev-only-dependency',
  {
    'package.json': JSON.stringify({
      name: 'app-04',
      main: 'index.js',
      devDependencies: { nodemon: '^3.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-04',
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { nodemon: '^3.0.0' } },
        'node_modules/nodemon': { version: '3.0.0', dev: true },
      },
    }),
    'index.js': `console.log('production server');\n`,
  },
  {
    id: '04-dev-only-dependency',
    category: 'SCA',
    package: 'nodemon',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'DEV_ONLY',
    expectedConfidence: 'MEDIUM',
  }
);

// 5. transitive-via-prod
writeFixture(
  '05-transitive-via-prod',
  {
    'package.json': JSON.stringify({
      name: 'app-05',
      main: 'index.js',
      dependencies: { 'prod-lib': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-05',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'prod-lib': '^1.0.0' } },
        'node_modules/prod-lib': {
          version: '1.0.0',
          dependencies: { 'nested-dep': '^2.0.0' },
        },
        'node_modules/nested-dep': { version: '2.0.0' },
      },
    }),
    'index.js': `import { foo } from 'prod-lib';\nfoo();\n`,
  },
  {
    id: '05-transitive-via-prod',
    category: 'SCA',
    package: 'nested-dep',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'TRANSITIVE_VIA',
    expectedConfidence: 'MEDIUM',
  }
);

// 6. transitive-via-dev-only
writeFixture(
  '06-transitive-via-dev-only',
  {
    'package.json': JSON.stringify({
      name: 'app-06',
      main: 'index.js',
      devDependencies: { 'dev-tool': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-06',
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { 'dev-tool': '^1.0.0' } },
        'node_modules/dev-tool': {
          version: '1.0.0',
          dev: true,
          dependencies: { 'dev-nested': '^1.0.0' },
        },
        'node_modules/dev-nested': { version: '1.0.0', dev: true },
      },
    }),
    'index.js': `console.log('prod');\n`,
  },
  {
    id: '06-transitive-via-dev-only',
    category: 'SCA',
    package: 'dev-nested',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'DEV_ONLY',
    expectedConfidence: 'MEDIUM',
  }
);

// 7. type-only-import (Amendment A4: max MEDIUM confidence)
writeFixture(
  '07-type-only-import',
  {
    'package.json': JSON.stringify({
      name: 'app-07',
      main: 'dist/index.js',
      devDependencies: { '@types/node': '^20.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-07',
      lockfileVersion: 3,
      packages: {
        '': { devDependencies: { '@types/node': '^20.0.0' } },
        'node_modules/@types/node': { version: '20.0.0', dev: true },
      },
    }),
    'src/index.ts': `import type { Buffer } from '@types/node';\nexport const b: Buffer = null as any;\n`,
  },
  {
    id: '07-type-only-import',
    category: 'SCA',
    package: '@types/node',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'DEV_ONLY',
    expectedConfidence: 'MEDIUM',
  }
);

// 8. dynamic-import-var
writeFixture(
  '08-dynamic-import-var',
  {
    'package.json': JSON.stringify({
      name: 'app-08',
      main: 'index.js',
      dependencies: { 'target-pkg': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-08',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'target-pkg': '^1.0.0' } },
        'node_modules/target-pkg': { version: '1.0.0' },
      },
    }),
    'index.js': `const mod = getDynamicName();\nimport(mod).then(m => m.run());\n`,
  },
  {
    id: '08-dynamic-import-var',
    category: 'SCA',
    package: 'target-pkg',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'DYNAMIC_UNKNOWN',
    expectedConfidence: 'LOW',
  }
);

// 9. dynamic-require-eval
writeFixture(
  '09-dynamic-require-eval',
  {
    'package.json': JSON.stringify({
      name: 'app-09',
      main: 'index.js',
      dependencies: { 'target-pkg': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-09',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'target-pkg': '^1.0.0' } },
        'node_modules/target-pkg': { version: '1.0.0' },
      },
    }),
    'index.js': `eval("const p = require('target-pkg'); p();");\n`,
  },
  {
    id: '09-dynamic-require-eval',
    category: 'SCA',
    package: 'target-pkg',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'DYNAMIC_UNKNOWN',
    expectedConfidence: 'LOW',
  }
);

// 10. config-only-usage (Amendment A5)
writeFixture(
  '10-config-only-usage',
  {
    'package.json': JSON.stringify({
      name: 'app-10',
      main: 'index.js',
      dependencies: { 'babel-core': '^7.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-10',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'babel-core': '^7.0.0' } },
        'node_modules/babel-core': { version: '7.0.0' },
      },
    }),
    'index.js': `console.log('pure production logic');\n`,
    '.babelrc': JSON.stringify({ presets: ['babel-core'] }),
  },
  {
    id: '10-config-only-usage',
    category: 'SCA',
    package: 'babel-core',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'CONFIG_REFERENCE',
    expectedConfidence: 'MEDIUM',
  }
);

// 11. script-bin-usage (Amendment A5)
writeFixture(
  '11-script-bin-usage',
  {
    'package.json': JSON.stringify({
      name: 'app-11',
      main: 'index.js',
      scripts: { clean: 'rimraf dist' },
      dependencies: { rimraf: '^5.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-11',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { rimraf: '^5.0.0' } },
        'node_modules/rimraf': { version: '5.0.0' },
      },
    }),
    'index.js': `console.log('running build');\n`,
  },
  {
    id: '11-script-bin-usage',
    category: 'SCA',
    package: 'rimraf',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'CONFIG_REFERENCE',
    expectedConfidence: 'MEDIUM',
  }
);

// 12. tsconfig-path-alias
writeFixture(
  '12-tsconfig-path-alias',
  {
    'tsconfig.json': JSON.stringify({
      compilerOptions: {
        baseUrl: '.',
        paths: { '@core/*': ['src/core/*'] },
      },
    }),
    'package.json': JSON.stringify({
      name: 'app-12',
      main: 'src/index.ts',
      dependencies: { 'shared-lib': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-12',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'shared-lib': '^1.0.0' } },
        'node_modules/shared-lib': { version: '1.0.0' },
      },
    }),
    'src/index.ts': `import { run } from '@core/runner';\nrun();\n`,
    'src/core/runner.ts': `import s from 'shared-lib';\nexport function run() { s(); }\n`,
  },
  {
    id: '12-tsconfig-path-alias',
    category: 'SCA',
    package: 'shared-lib',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 13. tsconfig-baseurl
writeFixture(
  '13-tsconfig-baseurl',
  {
    'tsconfig.json': JSON.stringify({
      compilerOptions: {
        baseUrl: './src',
      },
    }),
    'package.json': JSON.stringify({
      name: 'app-13',
      main: 'src/index.ts',
      dependencies: { 'utils-lib': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-13',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'utils-lib': '^1.0.0' } },
        'node_modules/utils-lib': { version: '1.0.0' },
      },
    }),
    'src/index.ts': `import { doWork } from 'services/worker';\ndoWork();\n`,
    'src/services/worker.ts': `import u from 'utils-lib';\nexport function doWork() { u(); }\n`,
  },
  {
    id: '13-tsconfig-baseurl',
    category: 'SCA',
    package: 'utils-lib',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 14. reexport-chain
writeFixture(
  '14-reexport-chain',
  {
    'package.json': JSON.stringify({
      name: 'app-14',
      main: 'src/index.js',
      dependencies: { 'deep-pkg': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-14',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'deep-pkg': '^1.0.0' } },
        'node_modules/deep-pkg': { version: '1.0.0' },
      },
    }),
    'src/index.js': `export * from './barrel.js';\n`,
    'src/barrel.js': `export { val } from './mid.js';\n`,
    'src/mid.js': `export { deep as val } from 'deep-pkg';\n`,
  },
  {
    id: '14-reexport-chain',
    category: 'SCA',
    package: 'deep-pkg',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 15. workspace-package
writeFixture(
  '15-workspace-package',
  {
    'pnpm-workspace.yaml': `packages:\n  - 'packages/*'\n`,
    'package.json': JSON.stringify({ name: 'root', private: true }),
    'packages/app/package.json': JSON.stringify({
      name: 'app',
      main: 'index.js',
      dependencies: { 'shared-ui': 'workspace:*' },
    }),
    'packages/app/index.js': `import { Button } from 'shared-ui';\nconsole.log(Button);\n`,
    'packages/shared-ui/package.json': JSON.stringify({
      name: 'shared-ui',
      main: 'index.js',
      dependencies: { chalk: '^5.0.0' },
    }),
    'packages/shared-ui/index.js': `import chalk from 'chalk';\nexport const Button = chalk.blue('btn');\n`,
  },
  {
    id: '15-workspace-package',
    category: 'SCA',
    package: 'chalk',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 16. circular-imports
writeFixture(
  '16-circular-imports',
  {
    'package.json': JSON.stringify({
      name: 'app-16',
      main: 'src/index.js',
      dependencies: { 'circ-lib': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-16',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'circ-lib': '^1.0.0' } },
        'node_modules/circ-lib': { version: '1.0.0' },
      },
    }),
    'src/index.js': `import './a.js';\n`,
    'src/a.js': `import './b.js';\nexport const a = 1;\n`,
    'src/b.js': `import './a.js';\nimport c from 'circ-lib';\nexport const b = 2;\n`,
  },
  {
    id: '16-circular-imports',
    category: 'SCA',
    package: 'circ-lib',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 17. dead-file-sast (Confidence LOW, never auto-suppressed)
writeFixture(
  '17-dead-file-sast',
  {
    'package.json': JSON.stringify({
      name: 'app-17',
      main: 'src/index.js',
    }),
    'src/index.js': `console.log('main alive');\n`,
    'src/orphaned.js': `const secret = eval(process.env.CODE);\n`,
  },
  {
    id: '17-dead-file-sast',
    category: 'SAST',
    filePath: 'src/orphaned.js',
    expectedVerdict: 'UNREACHABLE',
    expectedKind: 'DEAD_FILE',
    expectedConfidence: 'LOW',
  }
);

// 18. python-alias-pyyaml
writeFixture(
  '18-python-alias-pyyaml',
  {
    'requirements.txt': `PyYAML==6.0.1\n`,
    'main.py': `import yaml\nprint(yaml.safe_load("name: secure"))\n`,
  },
  {
    id: '18-python-alias-pyyaml',
    category: 'SCA',
    package: 'PyYAML',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 19. python-alias-pillow
writeFixture(
  '19-python-alias-pillow',
  {
    'pyproject.toml': `[tool.poetry.dependencies]\npython = "^3.10"\nPillow = "^10.0.0"\n`,
    'poetry.lock': `[[package]]\nname = "pillow"\nversion = "10.0.0"\n`,
    'app.py': `from PIL import Image\nprint(Image)\n`,
  },
  {
    id: '19-python-alias-pillow',
    category: 'SCA',
    package: 'Pillow',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 20. python-conditional-import
writeFixture(
  '20-python-conditional-import',
  {
    'pyproject.toml': `[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "^2.31.0"\n`,
    'poetry.lock': `[[package]]\nname = "requests"\nversion = "2.31.0"\n`,
    'main.py': `if True:\n    import requests\n    print(requests.__version__)\n`,
  },
  {
    id: '20-python-conditional-import',
    category: 'SCA',
    package: 'requests',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 21. python-unmapped-package
writeFixture(
  '21-python-unmapped-package',
  {
    'requirements.txt': `internal-corp-custom-lib==1.0.0\n`,
    'main.py': `print("hello")\n`,
  },
  {
    id: '21-python-unmapped-package',
    category: 'SCA',
    package: 'internal-corp-custom-lib',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'UNMAPPED_PACKAGE',
    expectedConfidence: 'LOW',
  }
);

// 22. unsupported-language (Ruby / non-supported grammar)
writeFixture(
  '22-unsupported-language-go',
  {
    Gemfile: `source "https://rubygems.org"\ngem "json"\n`,
    'main.rb': `require 'json'\nputs "Ruby"\n`,
  },
  {
    id: '22-unsupported-language-go',
    category: 'SAST',
    filePath: 'main.rb',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'UNSUPPORTED_LANGUAGE',
    expectedConfidence: 'LOW',
  }
);

// 23. no-entrypoint-found
writeFixture(
  '23-no-entrypoint-found',
  {
    'package.json': JSON.stringify({ name: 'empty-pkg' }),
    'helper.js': `const x = 1;\nmodule.exports = x;\n`,
  },
  {
    id: '23-no-entrypoint-found',
    category: 'SAST',
    filePath: 'helper.js',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'NO_ENTRYPOINT',
    expectedConfidence: 'LOW',
  }
);

// 24. lockfile-tree-missing
writeFixture(
  '24-lockfile-tree-missing',
  {
    'package.json': JSON.stringify({
      name: 'app-24',
      main: 'index.js',
      dependencies: { 'flat-pkg': '^1.0.0' },
    }),
    'index.js': `console.log("running");\n`,
  },
  {
    id: '24-lockfile-tree-missing',
    category: 'SCA',
    package: 'transitive-unknown',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'NO_LOCKFILE_TREE',
    expectedConfidence: 'LOW',
  }
);

// 25. declared-unused-but-transitive-of-prod-dep (Amendment A1/A15)
writeFixture(
  '25-declared-unused-but-transitive-of-prod-dep',
  {
    'package.json': JSON.stringify({
      name: 'app-25',
      main: 'index.js',
      dependencies: {
        'prod-pkg': '^1.0.0',
        'transitive-pkg': '^1.0.0',
      },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-25',
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: { 'prod-pkg': '^1.0.0', 'transitive-pkg': '^1.0.0' },
        },
        'node_modules/prod-pkg': {
          version: '1.0.0',
          dependencies: { 'transitive-pkg': '^1.0.0' },
        },
        'node_modules/transitive-pkg': { version: '1.0.0' },
      },
    }),
    'index.js': `import { run } from 'prod-pkg';\nrun();\n`,
  },
  {
    id: '25-declared-unused-but-transitive-of-prod-dep',
    category: 'SCA',
    package: 'transitive-pkg',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'TRANSITIVE_VIA',
    expectedConfidence: 'MEDIUM',
  }
);

// 26. flat-requirements-transitive-python (Amendment A1/A15)
writeFixture(
  '26-flat-requirements-transitive-python',
  {
    'requirements.txt': `requests==2.31.0\nurllib3==1.26.18\n`,
    'main.py': `import requests\nprint(requests.get("https://example.com"))\n`,
  },
  {
    id: '26-flat-requirements-transitive-python',
    category: 'SCA',
    package: 'urllib3',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'NO_LOCKFILE_TREE',
    expectedConfidence: 'LOW',
  }
);

// 27. package-named-only-in-dockerfile-ci (Amendment A5/A15)
writeFixture(
  '27-package-named-only-in-dockerfile-ci',
  {
    'package.json': JSON.stringify({
      name: 'app-27',
      main: 'index.js',
      dependencies: { 'docker-tool': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-27',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'docker-tool': '^1.0.0' } },
        'node_modules/docker-tool': { version: '1.0.0' },
      },
    }),
    'index.js': `console.log("prod ready");\n`,
    Dockerfile: `FROM node:20\nRUN npm install -g docker-tool\nCMD ["node", "index.js"]\n`,
  },
  {
    id: '27-package-named-only-in-dockerfile-ci',
    category: 'SCA',
    package: 'docker-tool',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'CONFIG_REFERENCE',
    expectedConfidence: 'MEDIUM',
  }
);

// 28. syntax-error-file (Amendment A6/A15)
writeFixture(
  '28-syntax-error-file',
  {
    'package.json': JSON.stringify({
      name: 'app-28',
      main: 'index.js',
      dependencies: { 'unused-dep': '^1.0.0' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-28',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'unused-dep': '^1.0.0' } },
        'node_modules/unused-dep': { version: '1.0.0' },
      },
    }),
    'index.js': `import './broken.js';\nconsole.log("start");\n`,
    'broken.js': `function ((( invalid syntax syntax !!\n`,
  },
  {
    id: '28-syntax-error-file',
    category: 'SCA',
    package: 'unused-dep',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'PARSE_FAILURE',
    expectedConfidence: 'LOW',
  }
);

// 29. python-312-syntax-file (Amendment A13/A15)
writeFixture(
  '29-python-312-syntax-file',
  {
    'requirements.txt': `unused-py-pkg==1.0.0\n`,
    'main.py': `type Point[T] = tuple[T, T]\nprint("Python 3.12 syntax")\n`,
  },
  {
    id: '29-python-312-syntax-file',
    category: 'SCA',
    package: 'unused-py-pkg',
    expectedVerdict: 'UNKNOWN',
    expectedKind: 'UNMAPPED_PACKAGE',
    expectedConfidence: 'LOW',
  }
);

// 30. two-workspace-monorepo (Amendment A8/A15)
writeFixture(
  '30-two-workspace-monorepo',
  {
    'pnpm-workspace.yaml': `packages:\n  - 'packages/*'\n`,
    'package.json': JSON.stringify({ name: 'root', private: true }),
    'packages/web/package.json': JSON.stringify({
      name: 'web',
      main: 'index.js',
      dependencies: { axios: '^1.0.0' },
    }),
    'packages/web/index.js': `import axios from 'axios';\nconsole.log(axios);\n`,
    'packages/cli/package.json': JSON.stringify({
      name: 'cli',
      main: 'index.js',
      dependencies: { axios: '^1.0.0' },
    }),
    'packages/cli/index.js': `console.log("cli without axios");\n`,
  },
  {
    id: '30-two-workspace-monorepo',
    category: 'SCA',
    package: 'axios',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

// 31. diff-mode-unchanged-import (Amendment A2/A15)
writeFixture(
  '31-diff-mode-unchanged-import',
  {
    'package.json': JSON.stringify({
      name: 'app-31',
      main: 'src/index.js',
      dependencies: { lodash: '^4.17.21' },
    }),
    'package-lock.json': JSON.stringify({
      name: 'app-31',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { lodash: '^4.17.21' } },
        'node_modules/lodash': { version: '4.17.21' },
      },
    }),
    'src/index.js': `const _ = require('lodash');\nconsole.log(_);\n`,
  },
  {
    id: '31-diff-mode-unchanged-import',
    category: 'SCA',
    package: 'lodash',
    expectedVerdict: 'REACHABLE_IMPORT',
    expectedKind: 'PACKAGE_IMPORTED',
    expectedConfidence: 'HIGH',
  }
);

console.log('✨ All 31 Gate 2 Reachability Corpus Fixtures created successfully!');
