import { describe, it, expect } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');

describe('LAYER D & G: GitHub Actions Workflow Verification (DEV-6, D1-D5, G2)', () => {
  const releaseYmlPath = path.resolve(repoRoot, '.github/workflows/release.yml');
  const ciYmlPath = path.resolve(repoRoot, '.github/workflows/ci.yml');

  const releaseDoc = YAML.parse(fs.readFileSync(releaseYmlPath, 'utf-8'));
  const ciDoc = YAML.parse(fs.readFileSync(ciYmlPath, 'utf-8'));

  // Load baseline release.yml from commit 70c3087b863d06538a6b7116eaa4d22e25073e29
  const baselineRaw = execSync(
    'git show 70c3087b863d06538a6b7116eaa4d22e25073e29:.github/workflows/release.yml',
    { encoding: 'utf-8', cwd: repoRoot }
  );
  const baselineDoc = YAML.parse(baselineRaw);

  // D1. oven-sh/setup-bun bun-version matches semver and is not latest
  describe('D1: Pinned Bun version in release workflow', () => {
    it('pins bun-version to exact semver /^\d+\.\d+\.\d+$/ and not "latest"', () => {
      const buildJob = releaseDoc.jobs['build-binaries'];
      const bunStep = buildJob.steps.find(
        (s: { uses?: string }) => s.uses && s.uses.startsWith('oven-sh/setup-bun')
      );
      expect(bunStep).toBeDefined();

      const bunVersion = String(bunStep.with['bun-version']);
      expect(bunVersion).toMatch(/^\d+\.\d+\.\d+$/);
      expect(bunVersion).not.toBe('latest');
    });
  });

  // D2. Matrix targets/binary names unchanged; tag trigger, permissions, needs chain, provenance publish unchanged vs baseline
  describe('D2: Invariant matrix, triggers, permissions, needs chain, and provenance vs baseline', () => {
    it('preserves the exact 4 matrix targets and binary names', () => {
      const matrixInclude = releaseDoc.jobs['build-binaries'].strategy.matrix.include;
      const baselineInclude = baselineDoc.jobs['build-binaries'].strategy.matrix.include;

      expect(matrixInclude.length).toBe(4);
      expect(baselineInclude.length).toBe(4);

      const actualTargets = matrixInclude.map(
        (m: { target: string; binary_name: string; os: string }) => ({
          os: m.os,
          target: m.target,
          binary_name: m.binary_name,
        })
      );
      const baselineTargets = baselineInclude.map(
        (m: { target: string; binary_name: string; os: string }) => ({
          os: m.os,
          target: m.target,
          binary_name: m.binary_name,
        })
      );

      expect(actualTargets).toEqual(baselineTargets);
    });

    it('preserves tag trigger, permissions, and needs chain vs baseline', () => {
      // D2: Diff the parsed objects outside the two edited jobs and assert deep equality
      const strippedRelease = JSON.parse(JSON.stringify(releaseDoc));
      delete strippedRelease.jobs['build-binaries'];
      delete strippedRelease.jobs['publish-github-release'];

      const strippedBaseline = JSON.parse(JSON.stringify(baselineDoc));
      delete strippedBaseline.jobs['build-binaries'];
      delete strippedBaseline.jobs['publish-github-release'];

      expect(strippedRelease).toEqual(strippedBaseline);

      // publish-npm contains --provenance step
      const npmPublishStep = releaseDoc.jobs['publish-npm'].steps.find(
        (s: { run?: string }) => s.run && s.run.includes('pnpm publish')
      );
      expect(npmPublishStep).toBeDefined();
      expect(npmPublishStep.run).toContain('--provenance');
    });
  });

  // D3. build-binaries order: compile -> package-standalone -> smoke-standalone, upload paths
  describe('D3: build-binaries execution pipeline and upload artifact scope', () => {
    it('executes in exact order: compile -> package-standalone -> smoke-standalone', () => {
      const buildJob = releaseDoc.jobs['build-binaries'];
      const steps = buildJob.steps;

      const compileIdx = steps.findIndex(
        (s: { run?: string }) => s.run && s.run.includes('bun build') && s.run.includes('--compile')
      );
      const packageIdx = steps.findIndex(
        (s: { run?: string }) => s.run && s.run.includes('package-standalone.mjs')
      );
      const smokeIdx = steps.findIndex(
        (s: { run?: string }) => s.run && s.run.includes('smoke-standalone.mjs')
      );

      expect(compileIdx).toBeGreaterThanOrEqual(0);
      expect(packageIdx).toBeGreaterThan(compileIdx);
      expect(smokeIdx).toBeGreaterThan(packageIdx);
    });

    it('upload artifact step contains only archives and .sha256 files, not the bare binary', () => {
      const buildJob = releaseDoc.jobs['build-binaries'];
      const uploadStep = buildJob.steps.find(
        (s: { uses?: string }) => s.uses && s.uses.startsWith('actions/upload-artifact')
      );
      expect(uploadStep).toBeDefined();

      const uploadPath = String(uploadStep.with.path);
      const paths = uploadPath
        .trim()
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      expect(paths.length).toBeGreaterThan(0);
      for (const p of paths) {
        expect(p).toMatch(/\.(tar\.gz|zip|sha256)$/);
      }

      // Ensure bare wildcard or bare binary is NOT uploaded
      expect(uploadPath.trim()).not.toBe('release-dist/*');
      expect(uploadPath).not.toContain('release-dist/${{ matrix.binary_name }}');
    });
  });

  // D4. publish-github-release contains no `|| true` and enforces >=4 archives
  describe('D4: publish-github-release rigor and fail-closed validation', () => {
    it('contains no "|| true" and fails when SHA256SUMS.txt is empty or has fewer than 4 archives', () => {
      const pubJob = releaseDoc.jobs['publish-github-release'];
      const shaStep = pubJob.steps.find(
        (s: { run?: string }) => s.run && s.run.includes('sha256sum')
      );
      expect(shaStep).toBeDefined();

      const runScript = String(shaStep.run);
      expect(runScript).not.toContain('|| true');
      expect(runScript).toContain('-z "$COUNT"');
      expect(runScript).toContain('"$COUNT" -lt 4');
      expect(runScript).toContain('exit 1');
    });
  });

  // D5. actionlint exits 0
  describe('D5: actionlint exit status', () => {
    it('actionlint exits 0 with zero lint violations on all workflows', () => {
      const probe = spawnSync('actionlint', ['-version'], { encoding: 'utf-8' });
      if (probe.error || probe.status !== 0) {
        console.log('Skipping actionlint test: actionlint binary not found on PATH.');
        return;
      }

      const res = spawnSync('actionlint', [], { encoding: 'utf-8', cwd: repoRoot });
      expect(res.status).toBe(0);
      expect(res.stderr || res.stdout).toBe('');
    });
  });

  // G2. Bun version equality between CI and release.yml
  describe('G2: Bun version alignment between CI and release.yml', () => {
    it('asserts that bun-version in CI standalone-verify matches release.yml exactly', () => {
      const releaseBunStep = releaseDoc.jobs['build-binaries'].steps.find(
        (s: { uses?: string }) => s.uses && s.uses.startsWith('oven-sh/setup-bun')
      );
      const releaseBunVersion = String(releaseBunStep.with['bun-version']);

      const ciVerifyJob = ciDoc.jobs['standalone-verify'];
      expect(ciVerifyJob).toBeDefined();
      const ciBunStep = ciVerifyJob.steps.find(
        (s: { uses?: string }) => s.uses && s.uses.startsWith('oven-sh/setup-bun')
      );
      expect(ciBunStep).toBeDefined();
      const ciBunVersion = String(ciBunStep.with['bun-version']);

      expect(ciBunVersion).toBe(releaseBunVersion);
      expect(ciBunVersion).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });
});
