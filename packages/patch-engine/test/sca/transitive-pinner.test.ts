import { describe, it, expect } from 'vitest';
import type { LockfileGraph } from '@secureship/reachability';
import type { ScaPatchProposal } from '@secureship/contracts';
import { TransitivePinner, type ManifestEdit } from '../../src/sca/transitive-pinner.js';

describe('TransitivePinner Unit Tests', () => {
  const dummyGraph: LockfileGraph = {
    format: 'NPM_V2_V3',
    nodes: new Map([
      [
        'express',
        {
          name: 'express',
          isDirect: true,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: ['body-parser'],
        },
      ],
      [
        'body-parser',
        {
          name: 'body-parser',
          isDirect: false,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: ['raw-body'],
        },
      ],
      [
        'raw-body',
        {
          name: 'raw-body',
          isDirect: false,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: ['bytes'],
        },
      ],
      [
        'bytes',
        {
          name: 'bytes',
          isDirect: false,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: [],
        },
      ],
      [
        'urllib3',
        {
          name: 'urllib3',
          isDirect: false,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: [],
        },
      ],
      [
        'requests',
        {
          name: 'requests',
          isDirect: true,
          isDev: false,
          isOptional: false,
          isPeer: false,
          dependencies: ['urllib3'],
        },
      ],
    ]),
    dependentsMap: new Map([
      ['body-parser', new Set(['express'])],
      ['raw-body', new Set(['body-parser'])],
      ['bytes', new Set(['raw-body'])],
      ['urllib3', new Set(['requests'])],
    ]),
    directProdDependencies: new Set(['express', 'requests']),
    directDevDependencies: new Set(),
  };

  describe('computeFix strategies', () => {
    it('direct npm dependency -> DIRECT_UPGRADE with SET_VERSION', () => {
      const pinner = new TransitivePinner(dummyGraph, '/mock/project');
      const proposal: ScaPatchProposal = {
        findingFingerprint: 'fp-1',
        packageManager: 'npm',
        targetPackage: 'express',
        currentVersion: '4.18.1',
        targetVersion: '4.18.2',
        isTransitive: false,
        strategy: 'DIRECT_UPGRADE',
        manifestPath: 'package.json',
        attempt: 1,
        generatedAt: new Date().toISOString(),
      };

      const result = pinner.computeFix(proposal);
      expect(result.kind).toBe('DIRECT_UPGRADE');
      if (result.kind === 'DIRECT_UPGRADE') {
        expect(result.manifestEdits).toHaveLength(1);
        expect(result.manifestEdits[0]).toMatchObject({
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'express',
          newVersion: '4.18.2',
        });
      }
    });

    it('transitive 2-hop pip dependency -> TRANSITIVE_PIN with pin comment annotation', () => {
      const pinner = new TransitivePinner(dummyGraph, '/mock/project');
      const proposal: ScaPatchProposal = {
        findingFingerprint: 'fp-2',
        packageManager: 'pip',
        targetPackage: 'urllib3',
        currentVersion: '1.26.4',
        targetVersion: '1.26.5',
        isTransitive: true,
        strategy: 'TRANSITIVE_PIN',
        manifestPath: 'requirements.txt',
        attempt: 1,
        generatedAt: new Date().toISOString(),
      };

      const result = pinner.computeFix(proposal);
      expect(result.kind).toBe('TRANSITIVE_PIN');
      if (result.kind === 'TRANSITIVE_PIN') {
        expect(result.manifestEdits).toHaveLength(1);
        expect(result.manifestEdits[0]).toMatchObject({
          filePath: 'requirements.txt',
          editType: 'ADD_PIN_COMMENT',
          packageName: 'urllib3',
          newVersion: '1.26.5',
        });
        expect(result.manifestEdits[0]?.annotation).toContain('pinned by SecureShip');
      }
    });

    it('transitive 3-hop npm dependency -> OVERRIDES_INJECTION with ADD_OVERRIDES', () => {
      const pinner = new TransitivePinner(dummyGraph, '/mock/project');
      const proposal: ScaPatchProposal = {
        findingFingerprint: 'fp-3',
        packageManager: 'npm',
        targetPackage: 'bytes',
        currentVersion: '3.0.0',
        targetVersion: '3.1.2',
        isTransitive: true,
        strategy: 'OVERRIDES_INJECTION',
        manifestPath: 'package.json',
        attempt: 1,
        generatedAt: new Date().toISOString(),
      };

      const result = pinner.computeFix(proposal);
      expect(result.kind).toBe('OVERRIDES_INJECTION');
      if (result.kind === 'OVERRIDES_INJECTION') {
        expect(result.manifestEdits).toHaveLength(1);
        expect(result.manifestEdits[0]).toMatchObject({
          filePath: 'package.json',
          editType: 'ADD_OVERRIDES',
          packageName: 'bytes',
          newVersion: '3.1.2',
        });
      }
    });
  });

  describe('applyEdits and manifest patching', () => {
    it('package.json: preserves 2-space indentation and newline', () => {
      const input =
        '{\n  "name": "my-app",\n  "dependencies": {\n    "express": "4.18.0"\n  }\n}\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'express',
          newVersion: '4.18.2',
        },
      ];

      const patched = TransitivePinner.patchPackageJson(input, edits);
      expect(patched).toContain('  "express": "4.18.2"');
      expect(patched.endsWith('\n')).toBe(true);
      expect(JSON.parse(patched).dependencies.express).toBe('4.18.2');
    });

    it('package.json: handles ADD_OVERRIDES into root overrides', () => {
      const input = '{\n  "name": "my-app",\n  "dependencies": {\n    "foo": "1.0.0"\n  }\n}\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'package.json',
          editType: 'ADD_OVERRIDES',
          packageName: 'bar',
          newVersion: '2.0.0',
        },
      ];

      const patched = TransitivePinner.patchPackageJson(input, edits);
      const parsed = JSON.parse(patched);
      expect(parsed.overrides).toEqual({ bar: '2.0.0' });
    });

    it('requirements.txt: preserves comments and blank lines, updates target version', () => {
      const input =
        '# Main dependencies\nflask==2.0.1\n\n# Networking\nurllib3>=1.26.0\nrequests==2.25.1\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'requirements.txt',
          editType: 'SET_VERSION',
          packageName: 'urllib3',
          newVersion: '1.26.5',
        },
      ];

      const patched = TransitivePinner.patchRequirementsTxt(input, edits);
      expect(patched).toContain('# Main dependencies');
      expect(patched).toContain('\n\n# Networking');
      expect(patched).toContain('urllib3>=1.26.5');
      expect(patched).toContain('requests==2.25.1');
    });

    it('requirements.txt: matches underscore and hyphen normalized package names', () => {
      const input = 'google_auth_oauthlib>=0.4.1\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'requirements.txt',
          editType: 'SET_VERSION',
          packageName: 'google-auth-oauthlib',
          newVersion: '0.4.6',
        },
      ];

      const patched = TransitivePinner.patchRequirementsTxt(input, edits);
      expect(patched).toBe('google_auth_oauthlib>=0.4.6\n');
    });

    it('requirements.txt: appends pin comment if target package is not already listed', () => {
      const input = 'flask==2.0.1\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'requirements.txt',
          editType: 'ADD_PIN_COMMENT',
          packageName: 'urllib3',
          newVersion: '1.26.5',
          annotation: '# pinned by SecureShip to avoid CVE-1234',
        },
      ];

      const patched = TransitivePinner.patchRequirementsTxt(input, edits);
      expect(patched).toContain('flask==2.0.1');
      expect(patched).toContain('urllib3>=1.26.5  # pinned by SecureShip to avoid CVE-1234');
    });

    it('pyproject.toml: adds or updates dependency in [tool.poetry.dependencies]', () => {
      const input =
        '[tool.poetry]\nname = "my-pkg"\n\n[tool.poetry.dependencies]\npython = "^3.9"\nrequests = "^2.26.0"\n\n[build-system]\nrequires = ["poetry-core"]\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'pyproject.toml',
          editType: 'ADD_CONSTRAINT',
          packageName: 'urllib3',
          newVersion: '1.26.5',
        },
      ];

      const patched = TransitivePinner.patchPyprojectToml(input, edits);
      expect(patched).toContain('urllib3 = ">=1.26.5"');
      expect(patched).toContain('[build-system]');
    });

    it('applyEdits: does not touch files outside ManifestEdit list', () => {
      const customFiles = new Map<string, string>([
        ['package.json', '{\n  "dependencies": { "a": "1.0" }\n}'],
        ['other.json', '{\n  "foo": "bar"\n}'],
      ]);

      const pinner = new TransitivePinner(dummyGraph, '/mock/project');
      const edits: ManifestEdit[] = [
        {
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'a',
          newVersion: '2.0',
        },
      ];

      const result = pinner.applyEdits(edits, customFiles);
      expect(result.has('package.json')).toBe(true);
      expect(result.has('other.json')).toBe(false);
    });

    it('createUnifiedDiff: generates a valid unified diff with headers and hunk markers', () => {
      const original = '{\n  "dependencies": {\n    "foo": "1.0.0"\n  }\n}\n';
      const patched = '{\n  "dependencies": {\n    "foo": "1.0.1"\n  }\n}\n';

      const diff = TransitivePinner.createUnifiedDiff('package.json', original, patched);
      expect(diff).toContain('--- a/package.json');
      expect(diff).toContain('+++ b/package.json');
      expect(diff).toContain('@@');
      expect(diff).toContain('-    "foo": "1.0.0"');
      expect(diff).toContain('+    "foo": "1.0.1"');
    });

    it('computeFix: handles poetry and unsupported package manager', () => {
      const pinner = new TransitivePinner(dummyGraph, '/mock/project');
      const poetryProposal: ScaPatchProposal = {
        findingFingerprint: 'fp-poetry',
        packageManager: 'poetry',
        targetPackage: 'requests',
        currentVersion: '2.25.0',
        targetVersion: '2.26.0',
        isTransitive: false,
        strategy: 'DIRECT_UPGRADE',
        manifestPath: 'pyproject.toml',
        attempt: 1,
        generatedAt: new Date().toISOString(),
      };

      const poetryRes = pinner.computeFix(poetryProposal);
      expect(poetryRes.kind).toBe('DIRECT_UPGRADE');

      const unsupportedProposal: ScaPatchProposal = {
        ...poetryProposal,
        // @ts-expect-error testing unsupported package manager
        packageManager: 'cargo',
      };
      const unsupportedRes = pinner.computeFix(unsupportedProposal);
      expect(unsupportedRes.kind).toBe('UNSUPPORTED');
    });

    it('patchPackageJson: updates devDependencies and handles missing dependencies block', () => {
      const input = '{\n  "devDependencies": {\n    "mocha": "8.0.0"\n  }\n}\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'mocha',
          newVersion: '9.0.0',
        },
        {
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'new-dep',
          newVersion: '1.0.0',
        },
      ];

      const patched = TransitivePinner.patchPackageJson(input, edits);
      const parsed = JSON.parse(patched);
      expect(parsed.devDependencies.mocha).toBe('9.0.0');
      expect(parsed.dependencies['new-dep']).toBe('1.0.0');
    });

    it('patchPackageJson: returns content unchanged if malformed JSON', () => {
      const malformed = 'not-valid-json';
      const edits: ManifestEdit[] = [
        {
          filePath: 'package.json',
          editType: 'SET_VERSION',
          packageName: 'foo',
          newVersion: '1.0.0',
        },
      ];
      expect(TransitivePinner.patchPackageJson(malformed, edits)).toBe(malformed);
    });

    it('patchPyprojectToml: updates existing key in [tool.poetry.dependencies] and handles section creation', () => {
      const inputWithKey = '[tool.poetry.dependencies]\nurllib3 = "^1.26.0"\nrequests = "^2.0.0"\n';
      const edits: ManifestEdit[] = [
        {
          filePath: 'pyproject.toml',
          editType: 'ADD_CONSTRAINT',
          packageName: 'urllib3',
          newVersion: '1.26.5',
        },
      ];
      const patched = TransitivePinner.patchPyprojectToml(inputWithKey, edits);
      expect(patched).toContain('urllib3 = ">=1.26.5"');

      const inputNoSection = '[tool.other]\nfoo = "bar"\n';
      const patchedNoSection = TransitivePinner.patchPyprojectToml(inputNoSection, edits);
      expect(patchedNoSection).toContain('[tool.poetry.dependencies]');
      expect(patchedNoSection).toContain('urllib3 = ">=1.26.5"');
    });
  });
});
