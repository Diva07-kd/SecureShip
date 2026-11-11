import fs from 'node:fs';
import path from 'node:path';

const corpusDir = path.resolve('packages/benchmark/corpus');

const cases = [
  // --- SECRET ---
  {
    id: 'case1-secrets-prod',
    description: 'True positive AWS key in production source file',
    category: 'SECRET',
    expectedFindings: [
      { file: 'src/aws-client.ts', ruleId: 'aws-access-key-id', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'src/aws-client.ts': 'export const AWS_ACCESS_KEY = "AKIAI44QH8DHBE123456";\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'aws-access-key-id',
        file: 'src/aws-client.ts',
        line: 1,
        snippet: 'AKIA...[REDACTED]',
      },
    },
  },
  {
    id: 'case2-secrets-test-dummy',
    description: 'False positive trap: dummy credentials in test directory',
    category: 'SECRET',
    expectedFindings: [
      { file: 'tests/auth.test.ts', ruleId: 'aws-access-key-id', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'tests/auth.test.ts': 'describe("auth", () => { const dummy = "AKIAI44QH8DHBEMOCK01"; });\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'aws-access-key-id',
        file: 'tests/auth.test.ts',
        line: 1,
        snippet: 'const dummy = "AKIAI44QH8DHBEMOCK01";',
      },
    },
  },
  {
    id: 'case5-secrets-placeholder',
    description: 'False positive trap: documentation placeholder AWS key',
    category: 'SECRET',
    expectedFindings: [
      { file: 'docs/config.example.js', ruleId: 'aws-access-key-id', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'docs/config.example.js': 'module.exports = { key: "AKIAIOSFODNN7EXAMPLE" };\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'aws-access-key-id',
        file: 'docs/config.example.js',
        line: 1,
        snippet: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      },
    },
  },
  {
    id: 'case6-secrets-docs-example',
    description: 'False positive trap: example token in docs guide',
    category: 'SECRET',
    expectedFindings: [
      { file: 'docs/guide.md', ruleId: 'gitlab-pat', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'docs/guide.md': '# Setup Guide\nUse token `sample_token_placeholder` in demo.\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'gitlab-pat',
        file: 'docs/guide.md',
        line: 2,
        snippet: 'Use sample token glpat-abcdef1234567890wxyz in demo',
      },
    },
  },
  {
    id: 'case7-secrets-wrongly-suppressed',
    description: 'True positive secret wrongly suppressed by Gate 1 inside test fixtures',
    category: 'SECRET',
    expectedFindings: [
      { file: 'tests/fixtures/prod-keys.ts', ruleId: 'gitlab-pat', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'tests/fixtures/prod-keys.ts': 'export const LIVE_PAT = "glpat-secretlive1234567890";\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'gitlab-pat',
        file: 'tests/fixtures/prod-keys.ts',
        line: 1,
        snippet: 'export const LIVE_PAT = "glpat-secretlive1234567890";',
      },
    },
  },
  {
    id: 'case21-secrets-stripe',
    description: 'True positive Stripe API secret key in production billing service',
    category: 'SECRET',
    expectedFindings: [
      { file: 'src/billing.ts', ruleId: 'stripe-api-key', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'src/billing.ts': 'export const STRIPE_KEY = "sk_" + "live_51Abcdef1234567890xyz";\n',
    },
    fixtures: {
      'gitleaks.sarif': {
        ruleId: 'stripe-api-key',
        file: 'src/billing.ts',
        line: 1,
        snippet: 'sk_live_...[REDACTED]',
      },
    },
  },

  // --- SAST ---
  {
    id: 'case3-sast-eval',
    description: 'True positive dynamic eval execution vulnerability',
    category: 'SAST',
    expectedFindings: [
      {
        file: 'src/eval-dynamic.js',
        ruleId: 'rules.secureship-sast.secureship-js-eval',
        label: 'TRUE_POSITIVE',
      },
      {
        file: 'src/eval-static.js',
        ruleId: 'rules.secureship-sast.secureship-js-eval',
        label: 'FALSE_POSITIVE_TRAP',
      },
    ],
    files: {
      'src/eval-dynamic.js': 'function run(userInput) { return eval(userInput); }\n',
      'src/eval-static.js': 'function runStatic() { return eval("2 + 2"); }\n',
    },
    fixtures: {
      'opengrep.sarif': {
        ruleId: 'rules.secureship-sast.secureship-js-eval',
        file: 'src/eval-dynamic.js',
        line: 1,
        snippet: 'eval(userInput)',
      },
    },
  },
  {
    id: 'case8-sast-child-process',
    description: 'True positive unsafe child_process.exec command execution',
    category: 'SAST',
    expectedFindings: [
      {
        file: 'src/exec.js',
        ruleId: 'rules.secureship-sast.secureship-js-child-process-exec',
        label: 'TRUE_POSITIVE',
      },
    ],
    files: {
      'src/exec.js':
        'const { exec } = require("child_process"); function run(userCmd) { exec(userCmd); }\n',
    },
    fixtures: {
      'opengrep.sarif': {
        ruleId: 'rules.secureship-sast.secureship-js-child-process-exec',
        file: 'src/exec.js',
        line: 1,
        snippet: 'exec(userCmd)',
      },
    },
  },
  {
    id: 'case9-sast-sql-concat',
    description: 'True positive SQL query string concatenation injection',
    category: 'SAST',
    expectedFindings: [
      {
        file: 'src/query.js',
        ruleId: 'rules.secureship-sast.secureship-js-sql-concat',
        label: 'TRUE_POSITIVE',
      },
    ],
    files: {
      'src/query.js':
        'function getUser(db, id) { return db.query("SELECT * FROM users WHERE id = " + id); }\n',
    },
    fixtures: {
      'opengrep.sarif': {
        ruleId: 'rules.secureship-sast.secureship-js-sql-concat',
        file: 'src/query.js',
        line: 1,
        snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
      },
    },
  },
  {
    id: 'case10-sast-md5-checksum',
    description: 'False positive trap: safe MD5 hash used for non-cryptographic cache key',
    category: 'SAST',
    expectedFindings: [
      {
        file: 'src/cache.js',
        ruleId: 'rules.secureship-sast.secureship-py-insecure-hash',
        label: 'FALSE_POSITIVE_TRAP',
      },
    ],
    files: {
      'src/cache.js':
        '// Safe: non-cryptographic checksum for caching assets\nconst crypto = require("crypto");\nfunction cacheKey(str) { return crypto.createHash("sha256").update(str).digest("hex"); }\n',
    },
    fixtures: {},
  },
  {
    id: 'case11-sast-python-pickle',
    description: 'True positive Python pickle deserialization vulnerability',
    category: 'SAST',
    expectedFindings: [
      {
        file: 'app.py',
        ruleId: 'rules.secureship-sast.secureship-py-pickle-load',
        label: 'TRUE_POSITIVE',
      },
    ],
    files: {
      'app.py':
        'import pickle\ndef load_data(untrusted_stream):\n    return pickle.loads(untrusted_stream)\n',
    },
    fixtures: {
      'opengrep.sarif': {
        ruleId: 'rules.secureship-sast.secureship-py-pickle-load',
        file: 'app.py',
        line: 3,
        snippet: 'pickle.loads(untrusted_stream)',
      },
    },
  },

  // --- SCA ---
  {
    id: 'case4-sca-lockfile',
    description: 'True positive known vulnerable dependency in package-lock.json',
    category: 'SCA',
    expectedFindings: [
      { file: 'package-lock.json', ruleId: 'CVE-2020-28500', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'package.json': JSON.stringify(
        { name: 'case4', dependencies: { lodash: '4.17.15' } },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'case4',
          lockfileVersion: 2,
          packages: {
            'node_modules/lodash': { version: '4.17.15' },
          },
          dependencies: {
            lodash: { version: '4.17.15' },
          },
        },
        null,
        2
      ),
    },
    fixtures: {
      'osv-scanner.sarif': {
        ruleId: 'CVE-2020-28500',
        file: 'package-lock.json',
        line: 1,
        snippet: 'lodash@4.17.15',
      },
    },
  },
  {
    id: 'case12-sca-axios',
    description: 'True positive Axios SSRF vulnerability in lockfile',
    category: 'SCA',
    expectedFindings: [
      { file: 'package-lock.json', ruleId: 'CVE-2020-28168', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'package.json': JSON.stringify(
        { name: 'case12', dependencies: { axios: '0.21.0' } },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'case12',
          lockfileVersion: 2,
          packages: {
            'node_modules/axios': { version: '0.21.0' },
          },
          dependencies: {
            axios: { version: '0.21.0' },
          },
        },
        null,
        2
      ),
    },
    fixtures: {
      'osv-scanner.sarif': {
        ruleId: 'CVE-2020-28168',
        file: 'package-lock.json',
        line: 1,
        snippet: 'axios@0.21.0',
      },
    },
  },
  {
    id: 'case13-sca-minimist',
    description: 'True positive Minimist prototype pollution vulnerability',
    category: 'SCA',
    expectedFindings: [
      { file: 'package-lock.json', ruleId: 'CVE-2020-7598', label: 'TRUE_POSITIVE' },
    ],
    files: {
      'package.json': JSON.stringify(
        { name: 'case13', dependencies: { minimist: '1.2.0' } },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'case13',
          lockfileVersion: 2,
          packages: {
            'node_modules/minimist': { version: '1.2.0' },
          },
          dependencies: {
            minimist: { version: '1.2.0' },
          },
        },
        null,
        2
      ),
    },
    fixtures: {
      'osv-scanner.sarif': {
        ruleId: 'CVE-2020-7598',
        file: 'package-lock.json',
        line: 1,
        snippet: 'minimist@1.2.0',
      },
    },
  },
  {
    id: 'case14-sca-dev-dependency',
    description: 'False positive trap: dev-only testing tool in devDependencies',
    category: 'SCA',
    expectedFindings: [
      { file: 'tests/package-lock.json', ruleId: 'CVE-2020-28500', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'tests/package.json': JSON.stringify(
        { name: 'case14-test', devDependencies: { lodash: '4.17.15' } },
        null,
        2
      ),
      'tests/package-lock.json': JSON.stringify(
        {
          name: 'case14-test',
          lockfileVersion: 2,
          packages: {
            'node_modules/lodash': { version: '4.17.15', dev: true },
          },
          dependencies: {
            lodash: { version: '4.17.15', dev: true },
          },
        },
        null,
        2
      ),
    },
    fixtures: {
      'osv-scanner.sarif': {
        ruleId: 'CVE-2020-28500',
        file: 'tests/package-lock.json',
        line: 1,
        snippet: 'lodash@4.17.15',
      },
    },
  },
  {
    id: 'case15-sca-clean-package',
    description: 'False positive trap: completely clean modern dependencies without CVEs',
    category: 'SCA',
    expectedFindings: [
      { file: 'package-lock.json', ruleId: 'CVE-NONE', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'package.json': JSON.stringify(
        { name: 'case15-clean', dependencies: { zod: '3.24.1' } },
        null,
        2
      ),
      'package-lock.json': JSON.stringify(
        {
          name: 'case15-clean',
          lockfileVersion: 2,
          packages: {
            'node_modules/zod': { version: '3.24.1' },
          },
          dependencies: {
            zod: { version: '3.24.1' },
          },
        },
        null,
        2
      ),
    },
    fixtures: {},
  },

  // --- IAC ---
  {
    id: 'case16-iac-terraform-sg-open',
    description: 'True positive open 0.0.0.0/0 ingress in Terraform AWS security group',
    category: 'IAC',
    expectedFindings: [{ file: 'main.tf', ruleId: 'CKV_AWS_24', label: 'TRUE_POSITIVE' }],
    files: {
      'main.tf': `resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Insecure open ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}\n`,
    },
    fixtures: {
      'checkov.sarif': {
        ruleId: 'CKV_AWS_24',
        file: 'main.tf',
        line: 1,
        snippet: 'cidr_blocks = ["0.0.0.0/0"]',
      },
    },
  },
  {
    id: 'case17-iac-dockerfile-root',
    description: 'True positive Dockerfile missing non-root USER instruction',
    category: 'IAC',
    expectedFindings: [{ file: 'Dockerfile', ruleId: 'CKV_DOCKER_3', label: 'TRUE_POSITIVE' }],
    files: {
      Dockerfile: `FROM alpine:3.18
RUN apk add --no-cache curl
ENTRYPOINT ["curl"]
`,
    },
    fixtures: {
      'checkov.sarif': {
        ruleId: 'CKV_DOCKER_3',
        file: 'Dockerfile',
        line: 1,
        snippet: 'FROM alpine:3.18',
      },
    },
  },
  {
    id: 'case18-iac-k8s-privileged',
    description: 'True positive Kubernetes privileged container definition',
    category: 'IAC',
    expectedFindings: [{ file: 'pod.yaml', ruleId: 'CKV_K8S_16', label: 'TRUE_POSITIVE' }],
    files: {
      'pod.yaml': `apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: pwned
    image: alpine:latest
    securityContext:
      privileged: true
`,
    },
    fixtures: {
      'checkov.sarif': {
        ruleId: 'CKV_K8S_16',
        file: 'pod.yaml',
        line: 9,
        snippet: 'privileged: true',
      },
    },
  },
  {
    id: 'case19-iac-terraform-examples',
    description: 'False positive trap: demo terraform in examples/ directory suppressed by Gate 1',
    category: 'IAC',
    expectedFindings: [
      { file: 'examples/demo/main.tf', ruleId: 'CKV_AWS_24', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      'examples/demo/main.tf': `resource "aws_security_group" "demo" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}\n`,
    },
    fixtures: {
      'checkov.sarif': {
        ruleId: 'CKV_AWS_24',
        file: 'examples/demo/main.tf',
        line: 1,
        snippet: 'cidr_blocks = ["0.0.0.0/0"]',
      },
    },
  },
  {
    id: 'case20-iac-dockerfile-multistage',
    description: 'False positive trap: clean hardened Dockerfile with dedicated non-root USER',
    category: 'IAC',
    expectedFindings: [
      { file: 'Dockerfile', ruleId: 'CKV_DOCKER_3', label: 'FALSE_POSITIVE_TRAP' },
    ],
    files: {
      Dockerfile: `FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
FROM node:20-alpine
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
CMD ["node", "server.js"]
`,
    },
    fixtures: {},
  },
];

for (const c of cases) {
  const dir = path.join(corpusDir, c.id);
  fs.mkdirSync(dir, { recursive: true });

  // 1. Write expected.json
  const exp = {
    id: c.id,
    description: c.description,
    category: c.category,
    expectedFindings: c.expectedFindings,
  };
  fs.writeFileSync(path.join(dir, 'expected.json'), JSON.stringify(exp, null, 2) + '\n');

  // 2. Write source files
  for (const [relPath, content] of Object.entries(c.files)) {
    const filePath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content, 'utf-8');
  }

  // 3. Write canned SARIF fixtures
  const fixDir = path.join(dir, 'fixtures');
  fs.mkdirSync(fixDir, { recursive: true });
  for (const [toolFile, ruleInfo] of Object.entries(c.fixtures)) {
    const sarif = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: toolFile.replace('.sarif', ''),
              rules: [
                {
                  id: ruleInfo.ruleId,
                  name: ruleInfo.ruleId,
                  shortDescription: { text: ruleInfo.ruleId },
                },
              ],
            },
          },
          results: [
            {
              ruleId: ruleInfo.ruleId,
              level: 'error',
              message: { text: `Finding for ${ruleInfo.ruleId}` },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: ruleInfo.file },
                    region: {
                      startLine: ruleInfo.line,
                      endLine: ruleInfo.line,
                      snippet: { text: ruleInfo.snippet },
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    fs.writeFileSync(path.join(fixDir, toolFile), JSON.stringify(sarif, null, 2) + '\n');
  }
}

console.log(`Successfully generated ${cases.length} benchmark corpus cases in ${corpusDir}`);
