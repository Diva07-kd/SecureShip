import { describe, it, expect } from 'vitest';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';
import { detectInstallScripts } from '../../src/supply-chain/detectors/install-script.detector.js';
import { detectHighEntropy } from '../../src/supply-chain/detectors/entropy.detector.js';
import { detectBinConfusion } from '../../src/supply-chain/detectors/bin-confusion.detector.js';
import { detectEmptyPackage } from '../../src/supply-chain/detectors/pkg-empty.detector.js';
import {
  detectTyposquats,
  PopularListIndex,
} from '../../src/supply-chain/detectors/typosquat.detector.js';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
});

describe('T7 — Benign Corpus & False-Positive Verification Suite', () => {
  describe('1. Natural Language & Internationalization (i18n)', () => {
    it('does NOT flag legitimate Chinese, Arabic, or Hebrew strings without bidi overrides', () => {
      const code = `
        const greetings = {
          chinese: "你好，世界！欢迎使用 SecureShip",
          arabic: "مرحبا بالعالم! أهلا بك",
          hebrew: "שלום עולם! ברוכים הבאים",
        };
      `;
      const hits = detectUnicodeAttacks(code, 'i18n.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('does NOT flag ZWJ emoji sequences (e.g. family 👨‍👩‍👧‍👦, rainbow flag 🏳️‍🌈) as SC-UNI-002', () => {
      const code = `
        const icons = {
          family: "👨‍👩‍👧‍👦",
          rainbowFlag: "🏳️‍🌈",
          technologist: "👩‍💻",
        };
      `;
      const hits = detectUnicodeAttacks(code, 'emojis.js', POLICY);
      const zwHits = hits.filter((h) => h.ruleId === 'SC-UNI-002');
      expect(zwHits.length).toBe(0);
    });

    it('permits UTF-8 BOM at start of file without false positive', () => {
      const content = '\uFEFFconst APP_NAME = "SecureShip";\nconsole.log(APP_NAME);';
      const hits = detectUnicodeAttacks(content, 'bom-file.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('handles Windows CRLF line endings without false positives or column drift', () => {
      const content = 'const a = 1;\r\nconst b = 2;\r\nconst c = 3;\r\n';
      const hits = detectUnicodeAttacks(content, 'crlf.js', POLICY);
      expect(hits.length).toBe(0);
    });
  });

  describe('2. Benign High-Entropy Exclusions & Web Assets', () => {
    it('does NOT flag Subresource Integrity (SRI) hashes', () => {
      const code = `
        export const SRI_HASHES = {
          react: "sha512-YJv8ZgK6X9F8P1C+1d7R6lG4B7H+vB1E2Q3W4E5R6T7Y8U9I0O=",
          vue: "sha384-H8Y7F6D5S4A3Q2W1E0R9T8Y7U6I5O4P3A2S1D0F=",
        };
      `;
      const hits = detectHighEntropy(code, 'sri.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('does NOT flag Data URI images, fonts, and inline assets', () => {
      const code = `
        const fontWoff2 = "data:font/woff2;base64,d09GMgABAAAAAAw0AA4AAAAAG3gAAAvgAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP0ZGVE0cGHACGACDEggKGZJcE4NGBfE4BN9qABwDIAvBEA==";
        const iconPng = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==";
      `;
      const hits = detectHighEntropy(code, 'assets.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('does NOT flag sourceMappingURL or sourceURL annotations', () => {
      const code = `
        function add(a, b) { return a + b; }
        //# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWRkLmpzIiwic291cmNlcyI6WyJhZGQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsU0FBZ0IsR0FBRyxDQUFDLENBQVcsRUFBRSxDQUFXO0lBQzFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUNmLENBQUMifQ==
      `;
      const hits = detectHighEntropy(code, 'bundle.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('does NOT flag standard UUID literals', () => {
      const code = `
        const ID_1 = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        const ID_2 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
      `;
      const hits = detectHighEntropy(code, 'uuids.js', POLICY);
      expect(hits.length).toBe(0);
    });

    it('does NOT flag standard Apache, MIT, or BSD copyright headers', () => {
      const code = `
        /*
         * Copyright (c) 2026 SecureShip Monorepo Project Contributors
         * Licensed under the Apache License, Version 2.0 (the "License");
         * you may not use this file except in compliance with the License.
         */
        export const VERSION = "1.0.0";
      `;
      const hits = detectHighEntropy(code, 'license.js', POLICY);
      expect(hits.length).toBe(0);
    });
  });

  describe('3. Legitimate Package Lifecycle & Bin Specifications', () => {
    it('does NOT flag exact standard "node-gyp rebuild" postinstall', () => {
      const pkgJson = {
        name: 'native-addon-ok',
        version: '1.0.0',
        scripts: { install: 'node-gyp rebuild' },
      };
      const hits = detectInstallScripts(pkgJson, os.tmpdir(), POLICY, {
        packageName: 'native-addon-ok',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });
      expect(hits.length).toBe(0);
    });

    it('does NOT flag standard CLI binaries pointing within package', () => {
      const pkgJson = {
        name: 'secureship-cli',
        version: '1.0.0',
        bin: {
          secureship: './bin/secureship.js',
          sship: './bin/sship.js',
        },
      };
      const hits = detectBinConfusion(pkgJson, POLICY, {
        packageName: 'secureship-cli',
        version: '1.0.0',
        ecosystem: 'npm',
        packageDir: os.tmpdir(),
        now: () => new Date('2026-01-01T00:00:00Z'),
      });
      expect(hits.length).toBe(0);
    });

    it('does NOT flag legitimate packages with source code in src/ or lib/', () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-benign-pkg-'));
      try {
        fs.mkdirSync(path.join(tempDir, 'src'));
        fs.writeFileSync(
          path.join(tempDir, 'package.json'),
          JSON.stringify({ name: 'benign-pkg', version: '1.0.0' })
        );
        fs.writeFileSync(path.join(tempDir, 'src', 'index.ts'), 'export const ready = true;');
        fs.writeFileSync(path.join(tempDir, 'README.md'), '# Benign Package');

        const hits = detectEmptyPackage(
          tempDir,
          {},
          {
            packageName: 'benign-pkg',
            version: '1.0.0',
            ecosystem: 'npm',
            packageDir: tempDir,
            now: () => new Date('2026-01-01T00:00:00Z'),
          }
        );
        expect(hits.length).toBe(0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('does NOT flag popular packages against themselves as typosquats', async () => {
      const popularIndex = new PopularListIndex([
        { name: 'typescript' },
        { name: 'vitest' },
        { name: 'eslint' },
        { name: 'prettier' },
      ]);

      const hits1 = await detectTyposquats('typescript', 'npm', popularIndex, POLICY);
      expect(hits1.length).toBe(0);

      const hits2 = await detectTyposquats('vitest', 'npm', popularIndex, POLICY);
      expect(hits2.length).toBe(0);
    });
  });
});
