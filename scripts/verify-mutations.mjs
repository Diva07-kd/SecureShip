#!/usr/bin/env node
/**
 * scripts/verify-mutations.mjs
 *
 * Implements `pnpm verify:mutations` as required by Phase 4 Amendment A18:
 * For each mutation M1 to M21:
 *  1. Applies the fault to a TEMP COPY of the repo.
 *  2. Runs the relevant verification test suite.
 *  3. Records the patch applied and the exact failing test names.
 *  4. Confirms bidirectional integrity: fails under mutation and passes cleanly when restored.
 *  5. Writes docs/phase4/mutation-log.md from the run.
 *  6. Exits with code 0 on complete verification.
 *
 * Supports --phase 3 flag to run the 17 Phase 3 mutations (N1-N17).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT_DIR = process.cwd();
const phaseArgIndex = process.argv.indexOf('--phase');
const phaseArg = phaseArgIndex !== -1 ? process.argv[phaseArgIndex + 1] : 'C';
const isPhase3 = phaseArg === '3';
const isPhase4 = phaseArg === '4';
const isPhase5 = phaseArg === '5';
const isPhaseC = phaseArg === 'C' || phaseArg === 'c';
const _isPhaseB = phaseArg === 'B' || phaseArg === 'b' || phaseArg === '6B';

const PHASE4_MUTATIONS = [
  {
    id: 'M1',
    description: 'repo config enabling AI or setting baseUrl',
    targetFile: 'packages/core-engine/src/config/load-config.ts',
    original: `      if ('ai' in obj) {
        console.warn(
          \`[SECURITY WARNING] Repository config at '\${configPath}' contains forbidden key 'ai'. AI configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'ai'.\`
        );
        delete obj.ai;
      }`,
    mutated: `      if (false && 'ai' in obj) {
        delete obj.ai;
      }`,
    testFile: 'packages/core-engine/test/config-loader.test.ts',
    testFilter: 'ignores forbidden ai and gate3',
  },
  {
    id: 'M2',
    description: 'skipped consent check',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          if (!consentCheck.consented) {
            throw new AiError(
              consentCheck.reason ||
                'AI consent has not been granted. Run "secureship ai enable" to record consent.',
              'CONFIG_ERROR'
            );
          }`,
    mutated: `          if (false && !consentCheck.consented) {
            throw new AiError('AI consent has not been granted.', 'CONFIG_ERROR');
          }`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'enforces consent check on non-dry-run scans',
  },
  {
    id: 'M3',
    description: 'following redirects',
    targetFile: 'packages/ai/src/providers/http-client.ts',
    original: `        redirect: 'error',`,
    mutated: `        redirect: 'follow', // MUTATION: follows redirects`,
    testFile: 'packages/ai/test/http-client.test.ts',
    testFilter: 'refuses redirects',
  },
  {
    id: 'M4',
    description: 'allowing http to non-loopback',
    targetFile: 'packages/ai/src/providers/http-client.ts',
    original: `    if (!isLoopback && url.protocol !== 'https:') {
      throw new AiError(
        \`Insecure endpoint '\${urlString}': HTTPS is strictly required for non-loopback hosts.\`,
        'CONFIG_ERROR'
      );
    }`,
    mutated: `    if (false && !isLoopback && url.protocol !== 'https:') {
      throw new AiError('Insecure endpoint', 'CONFIG_ERROR');
    }`,
    testFile: 'packages/ai/test/http-client.test.ts',
    testFilter: 'strictly requires HTTPS for non-loopback endpoints',
  },
  {
    id: 'M5',
    description: 'removed citation verification',
    targetFile: 'packages/ai/src/triage/skeptic.ts',
    original: `    if (!citationCheck.valid) {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
      sanitizedRationale = OutputSanitizer.sanitizeRationale(
        \`[Citation verification failed: \${citationCheck.failureReason}] \${sanitizedRationale}\`
      );
    }`,
    mutated: `    if (false && !citationCheck.valid) {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
    }`,
    testFile: 'packages/ai/test/skeptic.test.ts',
    testFilter: 'downgrades to NEEDS_HUMAN_REVIEW when citation quote is fabricated or missing',
  },
  {
    id: 'M6',
    description: 'removed injection heuristic AND consistency check together',
    targetFile: 'packages/ai/src/triage/skeptic.ts',
    original: `    if (injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
      sanitizedRationale = OutputSanitizer.sanitizeRationale(
        \`[Security Warning: Potential prompt injection detected in code slice] \${sanitizedRationale}\`
      );
    }

    // 10. Self-Consistency Sample in Suppress Mode (A6)
    let consistencyResult: { samples: number; agreed: boolean } | undefined;
    if (isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {`,
    mutated: `    if (false && injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
    }

    // 10. Self-Consistency Sample in Suppress Mode (A6)
    let consistencyResult: { samples: number; agreed: boolean } | undefined;
    if (false && isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {`,
    testFile: 'packages/ai/test/skeptic.test.ts',
    testFilter: 'locks verdict to NEEDS_HUMAN_REVIEW when prompt injection is detected',
  },
  {
    id: 'M7',
    description: 'suppressing HIGH by default',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `            const neverSuppress = new Set(
              userConfig.gate3?.neverSuppressSeverities ?? ['CRITICAL', 'HIGH']
            );`,
    mutated: `            const neverSuppress = new Set(['CRITICAL']); // MUTATION_M7: suppressing HIGH by default`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'never suppresses HIGH severity findings by default',
  },
  {
    id: 'M8',
    description: 'suppressing IAC',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `            const isQualifying =
              finding.category === 'SAST' &&
              !neverSuppress.has(finding.severity) &&`,
    mutated: `            const isQualifying =
              (finding.category === 'SAST' || finding.category === 'IAC') &&
              !neverSuppress.has(finding.severity) &&`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'never suppresses IAC findings',
  },
  {
    id: 'M9',
    description: 'sending SECRET or credential-class findings',
    targetFile: 'packages/context-slicer/src/slicer.ts',
    original: `    // 1. Skip SECRET category findings
    if (finding.category === 'SECRET') {
      return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
    }

    // 2. Skip credential-class findings (A5)
    if (ContextSlicer.isCredentialClassFinding(finding)) {
      return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
    }`,
    mutated: `    // 1. Skip SECRET category findings
    if (false && finding.category === 'SECRET') {
      return { skipped: true, skipReason: 'SECRET', findingId: finding.id };
    }

    // 2. Skip credential-class findings (A5)
    if (false && ContextSlicer.isCredentialClassFinding(finding)) {
      return { skipped: true, skipReason: 'CREDENTIAL_CLASS', findingId: finding.id };
    }`,
    testFile: 'packages/context-slicer/test/slicer.test.ts',
    testFilter: 'rejects SECRET category findings immediately',
  },
  {
    id: 'M10',
    description: 'skipped slicer redaction',
    targetFile: 'packages/context-slicer/src/redactor.ts',
    original: `  public static redactText(input: string): string {
    if (!input || typeof input !== 'string') {`,
    mutated: `  public static redactText(input: string): string {
    return input; // MUTATION: skipped slicer redaction
    if (!input || typeof input !== 'string') {`,
    testFile: 'packages/context-slicer/test/slicer.test.ts',
    testFilter: 'slices JS/TS function and redacts embedded secrets with two passes',
  },
  {
    id: 'M11',
    description: 'removed denylist',
    targetFile: 'packages/context-slicer/src/slicer.ts',
    original: `    // 4. Denylist check on file path
    const rawFilePath = finding.location.filePath;
    if (SlicerDenylist.isDenylisted(rawFilePath)) {
      return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
    }`,
    mutated: `    // 4. Denylist check on file path
    const rawFilePath = finding.location.filePath;
    if (false && SlicerDenylist.isDenylisted(rawFilePath)) {
      return { skipped: true, skipReason: 'DENYLIST_MATCH', findingId: finding.id };
    }`,
    testFile: 'packages/context-slicer/test/slicer.test.ts',
    testFilter: 'enforces sensitive file denylist',
  },
  {
    id: 'M12',
    description: 'following symlinks outside root',
    targetFile: 'packages/context-slicer/src/denylist.ts',
    original: `  public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
    try {`,
    mutated: `  public static isWithinRoot(workspaceRoot: string, targetPath: string): boolean {
    return true; // MUTATION: ignore symlink jail escapes
    try {`,
    testFile: 'packages/context-slicer/test/slicer.test.ts',
    testFilter: 'prevents symlink jailbreaks and path traversal outside root',
  },
  {
    id: 'M13',
    description: 'fixed (non-random) nonce',
    targetFile: 'packages/ai/src/prompts/prompt-builder.ts',
    original: `    let nonce = crypto.randomBytes(16).toString('hex');
    while (contentToInspect.includes(nonce)) {
      nonce = crypto.randomBytes(16).toString('hex');
    }`,
    mutated: `    let nonce = 'FIXED_NONCE_VALUE_12345'; // MUTATION: fixed non-random nonce
    while (false && contentToInspect.includes(nonce)) {
      nonce = crypto.randomBytes(16).toString('hex');
    }`,
    testFile: 'packages/ai/test/prompt-builder.test.ts',
    testFilter: 'generates random and non-fixed nonces per request',
  },
  {
    id: 'M14',
    description: 'dropping Gate 3 suppressed findings without a ledger entry',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `            if (isQualifying) {
              ledger.suppress(
                finding,
                'GATE3_LIKELY_FALSE_POSITIVE',
                triageRes.triage.rationale,
                'Gate 3 AI Triage'
              );`,
    mutated: `            if (isQualifying) {
              // MUTATION: dropped without ledger entry`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'records Gate 3 suppressed findings in the suppression ledger',
  },
  {
    id: 'M15',
    description: 'provider failure changing the exit code',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          if (triageRes.warning) budgetTracker.addWarning(triageRes.warning);`,
    mutated: `          if (triageRes.warning) {
            throw new Error(\`FATAL_PROVIDER_ERROR: \${triageRes.warning}\`); // MUTATION: provider failure changing the exit code
          }`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'provider failure falls back gracefully without failing the scan',
  },
  {
    id: 'M16',
    description: 'printing the API key in verbose output',
    targetFile: 'packages/cli/src/commands/scan.ts',
    original: `    console.log(\`Duration    : \${c.bold(\`\${report.durationMs}ms\`)}\\n\`);`,
    mutated: `    console.log(\`Duration    : \${c.bold(\`\${report.durationMs}ms\`)}\\n\`);
    if (options.verbose) {
      console.log(\`VERBOSE_KEY: \${process.env.ANTHROPIC_API_KEY || ''}\`);
    }`,
    testFile: 'packages/cli/test/ai-cli.test.ts',
    testFilter: 'never prints API key in verbose or report output',
  },
  {
    id: 'M17',
    description: 'running Gate 3 on already-suppressed findings',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `      if (gate1Res.shouldSuppress) {
        ledger.suppress(
          finding,
          gate1Res.suppressionReason!,
          gate1Res.suppressionDetail!,
          'Gate 1 Scope Classifier'
        );
        continue;
      }`,
    mutated: `      if (gate1Res.shouldSuppress) {
        ledger.suppress(
          finding,
          gate1Res.suppressionReason!,
          gate1Res.suppressionDetail!,
          'Gate 1 Scope Classifier'
        );
        // MUTATION_M17: continue omitted, so Gate 1 suppressed finding is sent to Gate 3
      }`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'skips already-suppressed findings and never sends them to Gate 3',
  },
  {
    id: 'M18',
    description: 'egress report undercounting files',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          budgetTracker.recordFindingSent();
          budgetTracker.recordFiles(sliceResult.filesSent);`,
    mutated: `          budgetTracker.recordFindingSent();
          // MUTATION_M18: omit recording files sent in egress report`,
    testFile: 'packages/core-engine/test/gate3-integration.test.ts',
    testFilter: 'egress-accounting',
    expectedTest: 'egress-accounting',
  },
  {
    id: 'M19',
    description: 'localhost.evil.com treated as loopback',
    targetFile: 'packages/ai/src/providers/http-client.ts',
    original: `    // 1. Literal 'localhost'
    if (clean === 'localhost') {
      return true;
    }`,
    mutated: `    // 1. Literal 'localhost'
    if (clean.includes('localhost')) { // MUTATION: lax loopback check
      return true;
    }`,
    testFile: 'packages/ai/test/http-client.test.ts',
    testFilter: 'correctly classifies loopback hosts and rejects lookalikes',
  },
  {
    id: 'M20',
    description: 'identical prompts used for consistency samples',
    targetFile: 'packages/ai/src/prompts/prompt-builder.ts',
    original: `    if (variant === 1) {
      // Consistency sample variant 1: reordered sections and rephrased query`,
    mutated: `    if (false && variant === 1) { // MUTATION: identical prompt variant 0 used for consistency
      // Consistency sample variant 1: reordered sections and rephrased query`,
    testFile: 'packages/ai/test/prompt-builder.test.ts',
    testFilter: 'consistency prompt variants produce different user prompts',
  },
  {
    id: 'M21',
    description: 'unsanitized model output (ANSI/bidi) reaching the terminal',
    targetFile: 'packages/ai/src/sanitize/output-sanitizer.ts',
    original: `    let clean = text
      .replace(OutputSanitizer.ANSI_ESCAPE_REGEX, '')
      .replace(OutputSanitizer.BIDI_OVERRIDES_REGEX, '')
      .replace(OutputSanitizer.ZERO_WIDTH_REGEX, '')
      .replace(OutputSanitizer.CONTROL_CHARS_REGEX, '')
      .replace(OutputSanitizer.DANGEROUS_LINK_SCHEMES_REGEX, '[$1](advisory-neutralized)');`,
    mutated: `    let clean = text; // MUTATION: skipped ANSI, bidi, and control sanitization`,
    testFile: 'packages/ai/test/sanitizer.test.ts',
    testFilter: 'strips ANSI color escapes',
    expectedTest: 'strips ANSI color escapes',
  },
];

const PHASE3_MUTATIONS = [
  {
    id: 'N1',
    description: 'Uncertainty (parse error) forced to evaluate as UNREACHABLE',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    // Precondition 2: No parse errors in production scope (Amendment A6)
    if (stats.hasAnyParseErrorInProduction) {`,
    mutated: `    // Precondition 2: No parse errors in production scope (Amendment A6)
    if (false && stats.hasAnyParseErrorInProduction) { // MUTATION_N1: parse error check bypassed`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N1: Mutation',
  },
  {
    id: 'N2',
    description: 'Dynamic import markers (eval, require(var)) ignored in prod scope',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    // Precondition 4: No dynamic imports in production scope
    if (stats.hasAnyDynamicInProduction) {`,
    mutated: `    // Precondition 4: No dynamic imports in production scope
    if (false && stats.hasAnyDynamicInProduction) { // MUTATION_N2: dynamic import check bypassed`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N2: Mutation',
  },
  {
    id: 'N3',
    description: 'Type-only TypeScript imports counted as runtime imports',
    targetFile: 'packages/reachability/src/js/js-import-extractor.ts',
    original: `            const specifier = JsImportExtractor.unquote(sourceNode.text);
            const isTypeOnly = JsImportExtractor.isTypeOnlyImport(node);`,
    mutated: `            const specifier = JsImportExtractor.unquote(sourceNode.text);
            const isTypeOnly = false; // MUTATION_N3: type-only treated as runtime`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N3: Mutation',
  },
  {
    id: 'N4',
    description: 'CRITICAL severity findings suppressed by default in Gate 2',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          const neverSuppress = new Set(config.gate2?.neverSuppressSeverities ?? ['CRITICAL']);`,
    mutated: `          const neverSuppress = new Set(); // MUTATION_N4: CRITICAL can be suppressed`,
    testFile: 'packages/core-engine/test/scan-orchestrator.test.ts',
    testFilter:
      'suppresses qualifying unreachable SCA findings in suppress mode, but preserves CRITICAL findings',
  },
  {
    id: 'N5',
    description: 'SAST dead-file findings suppressed in Gate 2',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          const isQualifyingSca =
            finding.category === 'SCA' &&
            detail.verdict === 'UNREACHABLE' &&
            (detail.analysisConfidence === 'HIGH' ||
              (detail.analysisConfidence === 'MEDIUM' && detail.evidence.kind === 'DEV_ONLY')) &&
            !neverSuppress.has(finding.severity);`,
    mutated: `          const isQualifyingSca =
            (finding.category === 'SCA' || finding.category === 'SAST') &&
            detail.verdict === 'UNREACHABLE' &&
            detail.analysisConfidence === 'HIGH' &&
            !neverSuppress.has(finding.severity); // MUTATION_N5: SAST suppressed`,
    testFile: 'packages/core-engine/test/scan-orchestrator.test.ts',
    testFilter:
      'suppresses qualifying unreachable SCA findings in suppress mode, but preserves CRITICAL findings',
  },
  {
    id: 'N6',
    description: 'Gate 2 suppressed findings dropped without ledger record (P1 violation)',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `          if (isQualifyingSca) {
            let suppressionDetail =
              detail.evidence.notes ??
              \`Package \${finding.package?.name ?? ''} is not imported from production code\`;
            if (detail.evidence.kind === 'UNINVOKED_SYMBOL') {
              const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
              const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
              const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
              suppressionDetail = \`Symbol '\${symStr}' from source \${srcStr} is not invoked (Dataset URLs: \${urlStr})\`;
            }
            ledger.suppress(
              finding,
              'GATE2_UNREACHABLE',
              suppressionDetail,
              'Gate 2 Reachability Engine'
            );
            continue;
          }`,
    mutated: `          if (isQualifyingSca) {
            // MUTATION_N6: Silently drop without ledger recording
            continue;
          }`,
    testFile: 'packages/core-engine/test/scan-orchestrator.test.ts',
    testFilter:
      'suppresses qualifying unreachable SCA findings in suppress mode, but preserves CRITICAL findings',
  },
  {
    id: 'N7',
    description: 'String literal reference scan bypassed',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    // Precondition 7: Reference scan across scripts, configs, and string literals (Amendment A5 & Fix C6)
    const refMatch = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames);`,
    mutated: `    // Precondition 7: Reference scan across scripts, configs, and string literals (Amendment A5 & Fix C6)
    const refMatch = { isReferenced: false, incompleteScan: false }; // MUTATION_N7: bypassed`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N7: Mutation',
  },
  {
    id: 'N8',
    description: 'Imports escaping project root followed',
    targetFile: 'packages/reachability/src/js/js-module-resolver.ts',
    original: `    // Upfront security check: prevent escaping project root
    const relCandidate = path.relative(realRoot, candidatePath);
    if (relCandidate.startsWith('..') || path.isAbsolute(relCandidate)) {
      return {
        type: 'UNRESOLVED',
        specifier: originalSpecifier,
        reason: \`Security violation: Path '\${originalSpecifier}' escapes project root\`,
      };
    }`,
    mutated: `    // Upfront security check: prevent escaping project root
    const relCandidate = path.relative(realRoot, candidatePath);
    if (false && (relCandidate.startsWith('..') || path.isAbsolute(relCandidate))) {
      return {
        type: 'UNRESOLVED',
        specifier: originalSpecifier,
        reason: \`Security violation: Path '\${originalSpecifier}' escapes project root\`,
      };
    }`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N8: Mutation',
  },
  {
    id: 'N9',
    description: 'WASM integrity check skipped',
    targetFile: 'packages/reachability/src/manifest/wasm-manifest.ts',
    original: `  const actualHash = computeSha256(buffer);
  return {
    valid: actualHash === entry.sha256 && buffer.length === entry.bytes,
    actualHash,
    expectedHash: entry.sha256,
  };`,
    mutated: `  const actualHash = computeSha256(buffer);
  return {
    valid: true, // MUTATION_N9: skip verification
    actualHash,
    expectedHash: entry.sha256,
  };`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N9: Mutation',
  },
  {
    id: 'N10',
    description: 'Gate 1 TEST_OR_MOCK overwritten by Gate 2',
    targetFile: 'packages/reachability/src/sast/sast-reachability-analyzer.ts',
    original: `    // Gate 1 Preservation: Gate 1 TEST_OR_MOCK verdict (UNREACHABLE) from Phase 1 is never overwritten by weaker Gate 2
    if (finding.scopeTag === 'TEST_OR_MOCK' || finding.scopeTag === 'EXAMPLE') {`,
    mutated: `    // Gate 1 Preservation: Gate 1 TEST_OR_MOCK verdict (UNREACHABLE) from Phase 1 is never overwritten by weaker Gate 2
    if (false && (finding.scopeTag === 'TEST_OR_MOCK' || finding.scopeTag === 'EXAMPLE')) {`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N10: Mutation',
  },
  {
    id: 'N11',
    description: 'Transitive-dependent check bypassed (Amendment A1)',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    if (transitiveRes.isTransitiveVia) {`,
    mutated: `    if (false && transitiveRes.isTransitiveVia) { // MUTATION_N11: transitive check bypassed`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N11: Mutation',
  },
  {
    id: 'N12',
    description: 'Diff mode graph built only from changed files instead of whole repo',
    targetFile: 'packages/reachability/src/graph/import-graph.ts',
    original: `    // 1. Detect production entrypoints
    const entrypointRes = EntrypointDetector.detect(projectRoot, options.userConfigEntrypoints);
    graph.entrypoints = entrypointRes.entrypoints;`,
    mutated: `    // 1. Detect production entrypoints
    const entrypointRes = EntrypointDetector.detect(projectRoot, options.userConfigEntrypoints);
    graph.entrypoints = [path.join(projectRoot, 'changed.js')]; // MUTATION_N12: diff mode restricted to changed files only`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N12: Mutation',
  },
  {
    id: 'N13',
    description: 'Extraction cache read from inside target directory',
    targetFile: 'packages/reachability/src/cache/external-cache.ts',
    original: `    this.cacheDir = ExternalExtractionCache.getCacheDirectory(targetHash);`,
    mutated: `    this.cacheDir = path.join(targetDir, '.secureship-cache'); // MUTATION_N13: in-repo cache`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N13: Mutation',
  },
  {
    id: 'N14',
    description:
      'Reference scanner cap hits ignored (evaluating UNREACHABLE-HIGH despite budget truncation)',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    const refMatch = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames);
    if (refMatch.incompleteScan) {`,
    mutated: `    const refMatch = ReferenceScanner.scan(projectRoot, packageName, candidateModuleNames);
    if (false && refMatch.incompleteScan) { // MUTATION_N14: cap hits ignored`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N14: Mutation',
  },
  {
    id: 'N15',
    description: 'Python SCA finding assigned UNREACHABLE with HIGH confidence (Rule C1 violation)',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    // Rule C1: In Phase 3, Python SCA findings are NEVER assigned UNREACHABLE with HIGH confidence
    const finalConfidence: Confidence = isPythonEco ? 'MEDIUM' : 'HIGH';`,
    mutated: `    // Rule C1: In Phase 3, Python SCA findings are NEVER assigned UNREACHABLE with HIGH confidence
    const finalConfidence: Confidence = 'HIGH'; // MUTATION_N15: Python allowed HIGH`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N15: Mutation',
  },
  {
    id: 'N16',
    description: 'DEV_ONLY finding labeled as [NOT IMPORTED] or HIGH confidence',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      return {
        verdict: 'UNREACHABLE',
        analysisConfidence: 'MEDIUM', // Amendment A4: dev-only never HIGH
        evidence: {
          kind: 'DEV_ONLY',
          via: [packageName],
          notes: 'Declared strictly in devDependencies and not reachable from production code',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };`,
    mutated: `      return {
        verdict: 'UNREACHABLE',
        analysisConfidence: 'HIGH', // MUTATION_N16: HIGH on dev-only
        evidence: {
          kind: 'NOT_IMPORTED', // MUTATION_N16: NOT_IMPORTED instead of DEV_ONLY
          via: [packageName],
          notes: 'Declared strictly in devDependencies and not reachable from production code',
        },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N16: Mutation',
  },
  {
    id: 'N17',
    description: 'verify:wasm comparing only against manifest without byte check',
    targetFile: 'packages/reachability/src/manifest/wasm-manifest.ts',
    original: `  const actualHash = computeSha256(buffer);
  return {
    valid: actualHash === entry.sha256 && buffer.length === entry.bytes,
    actualHash,
    expectedHash: entry.sha256,
  };`,
    mutated: `  const actualHash = computeSha256(buffer);
  return {
    valid: true, // MUTATION_N17: always valid, bypass byte check
    actualHash,
    expectedHash: entry.sha256,
  };`,
    testFile: 'packages/reachability/test/verification/reachability.verify.test.ts',
    testFilter: 'N17: Mutation',
  },
];

const PHASE5_MUTATIONS = [
  {
    id: 'P1',
    description: 'Allow paths outside root',
    targetFile: 'packages/patch-engine/src/diff-parser.ts',
    original: `    // Reject absolute paths, UNC paths, and drive letters
    if (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\\0')) {
      throw new PatchPolicyViolationError(
        'OUTSIDE_ROOT',
        \`Absolute or invalid path rejected: '\${rawPath}'\`
      );
    }`,
    mutated: `    // Reject absolute paths, UNC paths, and drive letters
    if (false && (p.startsWith('/') || p.startsWith('//') || /^[a-zA-Z]:/.test(p) || p.includes('\\0'))) {
      throw new PatchPolicyViolationError(
        'OUTSIDE_ROOT',
        \`Absolute or invalid path rejected: '\${rawPath}'\`
      );
    }`,
    testFile: 'packages/patch-engine/test/diff-parser.test.ts',
    testFilter: 'rejects absolute paths and path traversal with OUTSIDE_ROOT',
  },
  {
    id: 'P2',
    description: 'Allow protected paths',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `      // Protected path check
      if (PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'PROTECTED_PATH',
          detail: \`Modifying protected project file '\${p}' is forbidden\`,
          file: p,
        });
      }`,
    mutated: `      // Protected path check
      if (false && PatchPolicyEngine.PROTECTED_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'PROTECTED_PATH',
          detail: \`Modifying protected project file '\${p}' is forbidden\`,
          file: p,
        });
      }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter: 'rejects protected files',
  },
  {
    id: 'P3',
    description: 'Allow test-file edits',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `      // Test file check
      if (PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'TEST_FILE',
          detail: \`Modifying test or fixture file '\${p}' is forbidden\`,
          file: p,
        });
      }`,
    mutated: `      // Test file check
      if (false && PatchPolicyEngine.TEST_PATTERNS.some((pattern) => pattern.test(p))) {
        violations.push({
          code: 'TEST_FILE',
          detail: \`Modifying test or fixture file '\${p}' is forbidden\`,
          file: p,
        });
      }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter: 'rejects test and fixture files with TEST_FILE',
  },
  {
    id: 'P4',
    description: 'Skip suppression-marker check',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `            // Suppression marker check
            for (const marker of PatchPolicyEngine.SUPPRESSION_REGEXES) {
              if (marker.test(line.text)) {
                violations.push({
                  code: 'SUPPRESSION_MARKER',
                  detail: \`Added line contains security suppression marker '\${marker.source}': '\${trimmed}'\`,
                  file: f.newPath,
                });
                break;
              }
            }`,
    mutated: `            // Suppression marker check
            for (const marker of [] as RegExp[]) {
              if (marker.test(line.text)) {
                violations.push({
                  code: 'SUPPRESSION_MARKER',
                  detail: \`Added line contains security suppression marker '\${marker.source}': '\${trimmed}'\`,
                  file: f.newPath,
                });
                break;
              }
            }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter: 'detects all suppression markers with SUPPRESSION_MARKER',
  },
  {
    id: 'P5',
    description: 'Skip hidden-Unicode / Trojan Source check',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `    // 7. Hidden Unicode / Trojan Source Checks
    for (const f of files) {
      for (const hunk of f.hunks) {
        for (const line of hunk.lines) {
          if (line.type === 'added') {
            PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
          }
        }
      }
    }`,
    mutated: `    // 7. Hidden Unicode / Trojan Source Checks
    for (const f of files) {
      for (const hunk of f.hunks) {
        for (const line of hunk.lines) {
          if (false && line.type === 'added') {
            PatchPolicyEngine.checkHiddenUnicode(line.text, f.newPath, violations);
          }
        }
      }
    }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter:
      'rejects Trojan Source bidirectional characters and hidden Unicode with HIDDEN_UNICODE',
  },
  {
    id: 'P6',
    description: 'Skip net-new dangerous API check',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `    // 4. Dangerous API Differential Checks (Per hunk)
    for (const f of files) {
      for (const hunk of f.hunks) {
        PatchPolicyEngine.checkDangerousApiHunk(hunk, f.newPath, violations);
      }
    }`,
    mutated: `    // 4. Dangerous API Differential Checks (Per hunk)
    for (const f of files) {
      for (const hunk of f.hunks) {
        // MUTATION_P6: skip dangerous API differential check
      }
    }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter: 'rejects net-new dangerous APIs with NEW_DANGEROUS_API',
  },
  {
    id: 'P7',
    description: 'Skip new-dependency check',
    targetFile: 'packages/patch-engine/src/policy-engine.ts',
    original: `    // 5. New Dependency Checks
    for (const f of files) {
      PatchPolicyEngine.checkNewDependencies(f, options, violations);
    }`,
    mutated: `    // 5. New Dependency Checks
    for (const f of files) {
      // MUTATION_P7: skip new dependency check
    }`,
    testFile: 'packages/patch-engine/test/policy-engine.test.ts',
    testFilter: 'rejects new unapproved dependencies with NEW_DEPENDENCY',
  },
  {
    id: 'P8',
    description: 'Apply with fuzzy context',
    targetFile: 'packages/patch-engine/src/applier.ts',
    original: `    for (let i = 0; i < expected.length; i++) {
      if (lines[startIndex + i] !== expected[i]) {
        return false;
      }
    }`,
    mutated: `    for (let i = 0; i < expected.length; i++) {
      if (false && lines[startIndex + i] !== expected[i]) {
        return false;
      }
    }`,
    testFile: 'packages/patch-engine/test/applier.test.ts',
    testFilter: 'fails closed with CONTEXT_MISMATCH when context cannot be found',
  },
  {
    id: 'P9',
    description: 'Treat scanner-missing RESCAN as PASS',
    targetFile: 'packages/core-engine/src/remediation/verification-ladder.ts',
    original: `      if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
        // Mutation 9: Originating scanner missing MUST NOT be treated as PASS. It must be INCONCLUSIVE.
        rescanOutcome = 'INCONCLUSIVE';
        rescanDetail = \`Originating scanner '\${finding.scannerName}' not available in environment; cannot verify remediation\`;
      }`,
    mutated: `      if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
        rescanOutcome = 'PASS';
        rescanDetail = \`Originating scanner '\${finding.scannerName}' not available in environment; cannot verify remediation\`;
      }`,
    testFile: 'packages/core-engine/test/remediation/verification-ladder.test.ts',
    testFilter: 'originating scanner is missing',
  },
  {
    id: 'P10',
    description: 'Ignore NEW_FINDINGS',
    targetFile: 'packages/core-engine/src/remediation/verification-ladder.ts',
    original: `            if (qualifyingNew.length > 0) {
              // Mutation 10: Must not ignore NEW_FINDINGS
              newFindingsOutcome = 'FAIL';
              newFindingsDetail = \`Net-new finding introduced: \${qualifyingNew[0]!.ruleId} (\${qualifyingNew[0]!.severity}) in \${qualifyingNew[0]!.location.filePath}\`;
              break;
            }`,
    mutated: `            if (false && qualifyingNew.length > 0) {
              newFindingsOutcome = 'FAIL';
              newFindingsDetail = \`Net-new finding introduced: \${qualifyingNew[0]!.ruleId} (\${qualifyingNew[0]!.severity}) in \${qualifyingNew[0]!.location.filePath}\`;
              break;
            }`,
    testFile: 'packages/core-engine/test/remediation/verification-ladder.test.ts',
    testFilter: 'fails ladder when net-new finding is introduced on patched shadow copy',
  },
  {
    id: 'P11',
    description: 'Baseline-fail treated as PASS',
    targetFile: 'packages/sandbox/src/runner/baseline-runner.ts',
    original: `    if (baselineResult.timedOut || baselineResult.exitCode !== 0) {
      return {
        id: stageId,
        outcome: 'INCONCLUSIVE',
        detail: \`Baseline \${stageId} failed or timed out (exit code \${baselineResult.exitCode}). Cannot verify regression without clean baseline.\`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
        exitCode: null,
        baselineExitCode: baselineResult.exitCode,
        outputSha256: baselineResult.outputSha256,
        outputTail: baselineResult.outputTail,
      };
    }`,
    mutated: `    if (false && (baselineResult.timedOut || baselineResult.exitCode !== 0)) {
      return {
        id: stageId,
        outcome: 'INCONCLUSIVE',
        detail: \`Baseline \${stageId} failed or timed out\`,
        durationMs: Date.now() - startTime,
      };
    }`,
    testFile: 'packages/sandbox/test/baseline-runner.test.ts',
    testFilter: 'returns INCONCLUSIVE when baseline fails',
  },
  {
    id: 'P12',
    description: 'Patched-fail retried until pass',
    targetFile: 'packages/sandbox/src/runner/baseline-runner.ts',
    original: `    // Still fails => FAIL (regression detected)
    return {
      id: stageId,
      outcome: 'FAIL',
      detail: \`Patched \${stageId} failed (exit code \${patchedResult.exitCode}), introducing a regression against clean baseline\`,
      durationMs: Date.now() - startTime,
      argv: [command.command, ...command.args],
      exitCode: patchedResult.exitCode,
      baselineExitCode: baselineResult.exitCode,
      outputSha256: patchedResult.outputSha256,
      outputTail: patchedResult.outputTail,
    };`,
    mutated: `    // Still fails => FAIL (regression detected)
    return {
      id: stageId,
      outcome: 'PASS',
      detail: \`Patched \${stageId} failed (exit code \${patchedResult.exitCode}), introducing a regression against clean baseline\`,
      durationMs: Date.now() - startTime,
      argv: [command.command, ...command.args],
      exitCode: 0,
      baselineExitCode: baselineResult.exitCode,
      outputSha256: patchedResult.outputSha256,
      outputTail: patchedResult.outputTail,
    };`,
    testFile: 'packages/sandbox/test/baseline-runner.test.ts',
    testFilter: 'returns FAIL when baseline passes and patched fails on rerun',
  },
  {
    id: 'P13',
    description: 'Report VERIFIED_RUNTIME when dynamic stages were skipped',
    targetFile: 'packages/core-engine/src/remediation/verification-ladder.ts',
    original: `    if (anyDynamicPassed) {
      return 'VERIFIED_RUNTIME';
    }

    return 'VERIFIED_STATIC';`,
    mutated: `    if (true || anyDynamicPassed) {
      return 'VERIFIED_RUNTIME';
    }

    return 'VERIFIED_STATIC';`,
    testFile: 'packages/core-engine/test/remediation/verification-ladder.test.ts',
    testFilter: 'runs static ladder cleanly and reports VERIFIED_STATIC',
  },
  {
    id: 'P14',
    description: 'Enable container network in non-install stages',
    targetFile: 'packages/sandbox/src/backends/container-backend.ts',
    original: `    const networkMode = options.network ? 'bridge' : 'none';`,
    mutated: `    const networkMode = 'bridge';`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'zero network access in non-install stages',
  },
  {
    id: 'P15',
    description: 'Add a capability or drop no-new-privileges',
    targetFile: 'packages/sandbox/src/backends/container-backend.ts',
    original: `      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',`,
    mutated: `      '--cap-add=SYS_ADMIN',`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'drops all capabilities and enforces no-new-privileges',
  },
  {
    id: 'P16',
    description: 'Mount docker.sock or host home',
    targetFile: 'packages/sandbox/src/backends/container-backend.ts',
    original: `      \`-v=\${translatedShadow}:/work:rw\`,`,
    mutated: `      \`-v=\${translatedShadow}:/work:rw\`,
      '-v=/var/run/docker.sock:/var/run/docker.sock',`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'never mounts docker.sock or host home directory',
  },
  {
    id: 'P17',
    description: 'Pass ambient host environment into container',
    targetFile: 'packages/sandbox/src/backends/container-backend.ts',
    original: `      '-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
    ];`,
    mutated: `      '-e',
      'CI=1',
      '-e',
      'HOME=/tmp',
      '-e',
      'LANG=C.UTF-8',
      '-e',
      \`USER=\${process.env.USER}\`,
    ];`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'never forwards ambient host environment',
  },
  {
    id: 'P18',
    description: 'Run repo scripts on host without trust',
    targetFile: 'packages/sandbox/src/backends/host-backend.ts',
    original: `    if (!this.isRepoTrusted()) {
      const repoHash = HostBackend.computeRepoHash(this.repoDir);
      throw new Error(
        \`Host Execution Refused: Repository at '\${this.repoDir}' (hash \${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.\`
      );
    }`,
    mutated: `    if (false && !this.isRepoTrusted()) {
      const repoHash = HostBackend.computeRepoHash(this.repoDir);
      throw new Error(
        \`Host Execution Refused: Repository at '\${this.repoDir}' (hash \${repoHash.substring(0, 12)}) is not trusted for host execution. Run 'secureship sandbox trust-host' to explicitly authorize.\`
      );
    }`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'HostBackend refuses execution on untrusted repository',
  },
  {
    id: 'P19',
    description: 'Let repo config set backend, commands, or images',
    targetFile: 'packages/core-engine/src/config/load-config.ts',
    original: `      if ('sandbox' in obj) {
        console.warn(
          \`[SECURITY WARNING] Repository config at '\${configPath}' contains forbidden key 'sandbox'. Sandbox configuration may only be specified in per-user config (~/.secureship/), CLI flags, or environment variables. Ignoring 'sandbox'.\`
        );
        delete obj.sandbox;
      }`,
    mutated: `      if (false && 'sandbox' in obj) {
        delete obj.sandbox;
      }`,
    testFile: 'packages/core-engine/test/config-loader.test.ts',
    testFilter: 'ignores forbidden ai and gate3',
  },
  {
    id: 'P20',
    description: 'Include .env / sensitive denylist files in shadow copy',
    targetFile: 'packages/sandbox/src/shadow/shadow-copy.ts',
    original: `        if (ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
          continue;
        }`,
    mutated: `        if (false && ShadowCopy.SENSITIVE_EXCLUDE_PATTERNS.some((pat) => pat.test(relPosix))) {
          continue;
        }`,
    testFile: 'packages/sandbox/test/shadow-copy.test.ts',
    testFilter: 'creates filtered shadow copy excluding .git',
  },
  {
    id: 'P21',
    description: 'Modify the original working tree',
    targetFile: 'packages/sandbox/src/shadow/shadow-copy.ts',
    original: `      if (currentHash !== expectedHash) {
        throw new Error(
          \`Integrity Violation: Source file '\${relPath}' was modified in original repository tree! (expected \${expectedHash}, got \${currentHash})\`
        );
      }`,
    mutated: `      if (false && currentHash !== expectedHash) {
        throw new Error(
          \`Integrity Violation: Source file '\${relPath}' was modified in original repository tree!\`
        );
      }`,
    testFile: 'packages/sandbox/test/shadow-copy.test.ts',
    testFilter: 'detects tampering in source directory via verifyOriginalUnchanged',
  },
  {
    id: 'P22',
    description: 'fix apply skipping HMAC signature verification',
    targetFile: 'packages/core-engine/src/remediation/fix-store.ts',
    original: `    if (!stored.validSig) {
      return {
        success: false,
        exitCode: 2,
        error: \`HMAC signature verification failed: fix bundle '\${fixId}' has an invalid signature or was tampered with.\`,
      };
    }`,
    mutated: `    if (false && !stored.validSig) {
      return {
        success: false,
        exitCode: 2,
        error: \`HMAC signature verification failed\`,
      };
    }`,
    testFile: 'packages/core-engine/test/remediation/fix-store.test.ts',
    testFilter: 'detects tampered fix reports with HMAC mismatch',
  },
  {
    id: 'P23',
    description: 'fix apply skipping base file SHA-256 hash check',
    targetFile: 'packages/core-engine/src/remediation/fix-store.ts',
    original: `      if (currentHash !== baseFile.sha256) {
        return {
          success: false,
          exitCode: 2,
          error: \`Base file hash mismatch for '\${baseFile.path}'. The file was modified since fix generation. Expected \${baseFile.sha256}, got \${currentHash}.\`,
        };
      }`,
    mutated: `      if (false && currentHash !== baseFile.sha256) {
        return {
          success: false,
          exitCode: 2,
          error: \`Base file hash mismatch\`,
        };
      }`,
    testFile: 'packages/core-engine/test/remediation/fix-store.test.ts',
    testFilter: 'rejects apply when base file hash does not match',
  },
  {
    id: 'P24',
    description: 'fix apply skipping clean git tree check',
    targetFile: 'packages/core-engine/src/remediation/fix-store.ts',
    original: `    if (!isGitRepo) {
      if (!allowNonGit) {
        return {
          success: false,
          exitCode: 2,
          error:
            'Repository is not a Git working tree. To apply outside a Git tree, rerun with --allow-non-git.',
        };
      }
    }`,
    mutated: `    if (false && !isGitRepo) {
      if (!allowNonGit) {
        return {
          success: false,
          exitCode: 2,
          error: 'Repository is not a Git working tree',
        };
      }
    }`,
    testFile: 'packages/core-engine/test/remediation/fix-store.test.ts',
    testFilter: 'rejects apply on non-git directory without --allow-non-git',
  },
  {
    id: 'P25',
    description: 'Auto-commit or auto-branch',
    targetFile: 'packages/core-engine/src/remediation/fix-store.ts',
    original: `    return {
      success: true,
      exitCode: 0,
      appliedFiles,
    };`,
    mutated: `    try { execFileSync('git', ['commit', '-am', 'auto-commit'], { cwd: repoPath }); } catch {}
    return {
      success: true,
      exitCode: 0,
      appliedFiles,
    };`,
    testFile: 'packages/core-engine/test/remediation/fix-store.test.ts',
    testFilter: 'never auto-commits or auto-branches on apply',
  },
  {
    id: 'P26',
    description: 'Non-atomic file write',
    targetFile: 'packages/patch-engine/src/applier.ts',
    original: `    try {
      fs.writeFileSync(tempFile, content, {
        encoding: 'utf8',
        mode: mode ?? 0o644,
      });
      fs.renameSync(tempFile, targetPath);
    } catch (err) {`,
    mutated: `    try {
      fs.writeFileSync(targetPath, content, {
        encoding: 'utf8',
        mode: mode ?? 0o644,
      });
    } catch (err) {`,
    testFile: 'packages/patch-engine/test/applier.test.ts',
    testFilter: 'atomicWrite writes file atomically preserving mode',
  },
  {
    id: 'P27',
    description: 'EOL / BOM not preserved',
    targetFile: 'packages/patch-engine/src/applier.ts',
    original: `    if (format.hasBom) {
      result = '\\uFEFF' + result;
    }`,
    mutated: `    if (false && format.hasBom) {
      result = '\\uFEFF' + result;
    }`,
    testFile: 'packages/patch-engine/test/applier.test.ts',
    testFilter: 'preserves UTF-8 BOM',
  },
  {
    id: 'P28',
    description: 'Leave orphan containers after abort/SIGINT',
    targetFile: 'packages/sandbox/src/backends/container-backend.ts',
    original: `  public async cleanup(): Promise<void> {
    if (this.nativeFallbackBackend) {
      await this.nativeFallbackBackend.cleanup();
    }

    const runtime = this.resolvedRuntime;
    if (!runtime) return;

    try {
      // Remove any container associated with this run ID
      await SafeProcessRunner.run(
        runtime,
        ['rm', '-f', '--filter', \`label=secureship.run=\${this.runId}\`],
        { timeoutMs: 5000 }
      );
    } catch {
      // Ignore cleanup error
    }
  }`,
    mutated: `  public async cleanup(): Promise<void> {
    return;
  }`,
    testFile: 'packages/sandbox/test/backends.test.ts',
    testFilter: 'ContainerBackend cleanup removes labeled containers',
  },
];

const PHASEB_MUTATIONS = [
  {
    id: 'B1',
    description: 'heuristic source treated as HIGH',
    targetFile: 'packages/reachability/src/symbols/candidate-extractor.ts',
    original: `  return sorted.map((symbol) => ({
    symbol,
    source: 'HEURISTIC_TEXT',
    confidence: 'LOW' as const,
  }));`,
    mutated: `  return sorted.map((symbol) => ({
    symbol,
    source: 'HEURISTIC_TEXT',
    confidence: 'HIGH' as const, // MUTATION_B1: heuristic source treated as HIGH
  }));`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B1: Mutation',
  },
  {
    id: 'B2',
    description: 'only the first candidate checked',
    targetFile: 'packages/reachability/src/symbols/candidate-extractor.ts',
    original: `    if (curatedCandidates.length > 0) {
      return curatedCandidates;
    }`,
    mutated: `    if (curatedCandidates.length > 0) {
      return curatedCandidates.slice(0, 1); // MUTATION_B2: only first candidate
    }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B2: Mutation',
  },
  {
    id: 'B3',
    description: 'escapes ignored',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `            if (b.importedName === 'default' || b.importedName === 'namespace') {
              recordEscape(
                b.packageRoot,
                'ARGUMENT_PASS',
                line,
                \`Passed '\${arg.text}' to '\${fn.text}'\`
              );
            }`,
    mutated: `            if (false && (b.importedName === 'default' || b.importedName === 'namespace')) { // MUTATION_B3: escapes ignored
              recordEscape(
                b.packageRoot,
                'ARGUMENT_PASS',
                line,
                \`Passed '\${arg.text}' to '\${fn.text}'\`
              );
            }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B3: Mutation',
  },
  {
    id: 'B4',
    description: 'computed access ignored',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `    // 3. Literal computed call: _['template'](...)
    if (fn.type === 'subscript_expression') {`,
    mutated: `    // 3. Literal computed call: _['template'](...)
    if (false && fn.type === 'subscript_expression') { // MUTATION_B4: computed access ignored`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B4: Mutation',
  },
  {
    id: 'B5',
    description: 'import * ignored',
    targetFile: 'packages/reachability/src/symbol-usage/python-symbol-usage-extractor.ts',
    original: `      if (child.type === 'wildcard_import') {
        escapes.push({
          packageRoot: parsed.packageRoot,
          reason: 'WILDCARD_IMPORT',
          file: relativePath,
          line,
          detail: \`from \${rawSpecifier} import *\`,
        });
      }`,
    mutated: `      if (false && child.type === 'wildcard_import') { // MUTATION_B5: import * ignored
        escapes.push({
          packageRoot: parsed.packageRoot,
          reason: 'WILDCARD_IMPORT',
          file: relativePath,
          line,
          detail: \`from \${rawSpecifier} import *\`,
        });
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B5: Mutation',
  },
  {
    id: 'B6',
    description: 'only calls (not references) counted',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `      if (root && prop) {
        recordUsage(
          root.packageRoot,
          prop.text,
          'member_access',
          line,
          false,
          \`\${root.rootName}.\${prop.text}\`
        );
      }`,
    mutated: `      if (false && root && prop) { // MUTATION_B6: member_access non-call omitted
        recordUsage(
          root.packageRoot,
          prop.text,
          'member_access',
          line,
          false,
          \`\${root.rootName}.\${prop.text}\`
        );
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B6: Mutation',
  },
  {
    id: 'B7',
    description: 'destructuring rename ignored',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `          if (value.type === 'identifier') {
            const alias = value.text;`,
    mutated: `          if (false && value.type === 'identifier') { // MUTATION_B7: destructuring rename ignored
            const alias = value.text;`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B7: Mutation',
  },
  {
    id: 'B8',
    description: 'unknown subpath treated as no use',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `      if (!isLocal && subpath && !isStatementTypeOnly) {
        escapes.push({
          packageRoot,
          reason: 'UNKNOWN_SUBPATH',
          file: relativePath,
          line,
          detail: \`Default import of subpath '\${rawSpecifier}'\`,
        });
      }`,
    mutated: `      if (false && !isLocal && subpath && !isStatementTypeOnly) { // MUTATION_B8: unknown subpath treated as no use
        escapes.push({
          packageRoot,
          reason: 'UNKNOWN_SUBPATH',
          file: relativePath,
          line,
          detail: \`Default import of subpath '\${rawSpecifier}'\`,
        });
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B8: Mutation',
  },
  {
    id: 'B9',
    description: 'createRequire ignored',
    targetFile: 'packages/reachability/src/symbol-usage/js-symbol-usage-extractor.ts',
    original: `      if (
        node.type === 'identifier' &&
        (node.text === 'createRequire' || node.text === 'require.context')
      ) {
        hasCreateRequire = true;
      }`,
    mutated: `      if (
        false && node.type === 'identifier' &&
        (node.text === 'createRequire' || node.text === 'require.context')
      ) { // MUTATION_B9: createRequire ignored
        hasCreateRequire = true;
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B9: Mutation',
  },
  {
    id: 'B10',
    description: 'leaf-dependents check skipped',
    targetFile: 'packages/reachability/src/lockfile/lockfile-tree-parser.ts',
    original: `    // Dependents must be empty
    const dependents = graph.dependentsMap.get(norm);
    return !dependents || dependents.size === 0;`,
    mutated: `    // Dependents must be empty
    return true; // MUTATION_B10: leaf-dependents check skipped`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B10: Mutation',
  },
  {
    id: 'B11',
    description: 'bin check skipped',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    return false;
  }

  /**
   * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.`,
    mutated: `    return true; // MUTATION_B11: bin check skipped
  }

  /**
   * Filters and annotates findings based on Snyk-grade 3-state reachability triage filter.`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B11: Mutation',
  },
  {
    id: 'B12',
    description: 'reference scan of unparsed files skipped',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    for (const f of files) {
      if (!f.hasParseError) {
        excludeFiles.add(f.filePath);
        excludeFiles.add(f.relativePath);
      }
    }`,
    mutated: `    for (const f of files) {
      if (true) { // MUTATION_B12: exclude even unparsed files
        excludeFiles.add(f.filePath);
        excludeFiles.add(f.relativePath);
      }
    }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B12: Mutation',
  },
  {
    id: 'B13',
    description: 'dead-file usage ignored',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    const nonTestFiles = Array.from(graph.files.values()).filter(
      (f) => !EntrypointDetector.isTestOrMockFile(f.relativePath)
    );`,
    mutated: `    const nonTestFiles = Array.from(graph.files.values()).filter(
      (f) => f.isReachable && !EntrypointDetector.isTestOrMockFile(f.relativePath) // MUTATION_B13: dead-file usage ignored
    );`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B13: Mutation',
  },
  {
    id: 'B14',
    description: 'parse-error files ignored',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    // P2: Zero parse errors in all non-test source files
    if (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError)) {`,
    mutated: `    // P2: Zero parse errors in all non-test source files
    if (false && (stats.hasAnyParseErrorInProduction || nonTestFiles.some((f) => f.hasParseError))) {`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B14: Mutation',
  },
  {
    id: 'B15',
    description: 'IMPORT_TIME treated as CALL',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      if (datasetEntry.triggeredOn !== 'CALL') {
        return ScaReachabilityAnalyzer.blockedResult(
          'TRIGGER_NOT_CALL',
          \`Vulnerability triggers on \${datasetEntry.triggeredOn}; not eligible for function call pruning\`,
          chain,
          packageName
        );
      }`,
    mutated: `      if (false && datasetEntry.triggeredOn !== 'CALL') { // MUTATION_B15: IMPORT_TIME treated as CALL
        return ScaReachabilityAnalyzer.blockedResult(
          'TRIGGER_NOT_CALL',
          \`Vulnerability triggers on \${datasetEntry.triggeredOn}; not eligible for function call pruning\`,
          chain,
          packageName
        );
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B15: Mutation',
  },
  {
    id: 'B16',
    description: 'incomplete entry treated as complete',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      if (!datasetEntry.entryPointsComplete) {
        return ScaReachabilityAnalyzer.blockedResult(
          'ENTRYPOINTS_INCOMPLETE',
          'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
          chain,
          packageName
        );
      }`,
    mutated: `      if (false && !datasetEntry.entryPointsComplete) { // MUTATION_B16: incomplete treated as complete
        return ScaReachabilityAnalyzer.blockedResult(
          'ENTRYPOINTS_INCOMPLETE',
          'Dataset entry points are flagged as incomplete; cannot prove uninvoked status',
          chain,
          packageName
        );
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B16: Mutation',
  },
  {
    id: 'B17',
    description: 'repo dataset honored',
    targetFile: 'packages/reachability/src/symbols/dataset-loader.ts',
    original: `    if (this.isRepoResidentPath(resolvedCustom, projectRoot)) {`,
    mutated: `    if (false && this.isRepoResidentPath(resolvedCustom, projectRoot)) { // MUTATION_B17: repo dataset honored`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B17: Mutation',
  },
  {
    id: 'B18',
    description: 'integrity check skipped',
    targetFile: 'packages/reachability/src/symbols/dataset-loader.ts',
    original: `        if (manifest.sha256 !== actualHash) {`,
    mutated: `        if (false && manifest.sha256 !== actualHash) { // MUTATION_B18: integrity check skipped`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B18: Mutation',
  },
  {
    id: 'B19',
    description: 'tier gating bypassed',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `    if (functionLevelConfigEnabled) {
      if (tierCaps.allowCallPathReachability) {
        functionLevel = true;
      } else {`,
    mutated: `    if (functionLevelConfigEnabled) {
      if (true || tierCaps.allowCallPathReachability) { // MUTATION_B19: tier gating bypassed
        functionLevel = true;
      } else {`,
    testFile: 'packages/core-engine/test/reachability-symbol-wiring.test.ts',
    testFilter: 'records skippedTier',
  },
  {
    id: 'B20',
    description: 'REACHABLE_CALL_PATH emitted without a chain',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      const isCallPathProven = provenChain !== null;`,
    mutated: `      const isCallPathProven = true; // MUTATION_B20: emit without proven chain`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B20: Mutation',
  },
  {
    id: 'B21',
    description: 'call graph used to downgrade',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'REACHABLE_IMPORT';`,
    mutated: `      const verdict = isCallPathProven ? 'REACHABLE_CALL_PATH' : 'UNREACHABLE'; // MUTATION_B21: call graph downgrades to UNREACHABLE`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B21: Mutation',
  },
  {
    id: 'B22',
    description: 'Python UNINVOKED set to HIGH',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `    } else if (isPythonEco || !isBinSafe) {
      finalConfidence = 'MEDIUM';
    } else {`,
    mutated: `    } else if (false && (isPythonEco || !isBinSafe)) { // MUTATION_B22: Python set to HIGH
      finalConfidence = 'MEDIUM';
    } else {`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B22: Mutation',
  },
  {
    id: 'B23',
    description: 'exception turned into UNREACHABLE',
    targetFile: 'packages/reachability/src/sca/sca-reachability-analyzer.ts',
    original: `      if (isEligibleEco && isFunctionLevelEnabled) {
        return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
          finding,
          packageName,
          normPkg,
          candidateModuleNames,
          chain,
          graph,
          lockfileGraph,
          projectRoot,
          options
        );
      }`,
    mutated: `      if (isEligibleEco && isFunctionLevelEnabled) {
        try {
          return ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport(
            finding,
            packageName,
            normPkg,
            candidateModuleNames,
            chain,
            graph,
            lockfileGraph,
            projectRoot,
            options
          );
        } catch {
          return { verdict: 'UNREACHABLE', analysisConfidence: 'HIGH', evidence: { kind: 'UNINVOKED_SYMBOL' }, limitations: [] }; // MUTATION_B23: fail-open
        }
      }`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B23: Mutation',
  },
  {
    id: 'B24',
    description: 'ledger loses symbol detail',
    targetFile: 'packages/core-engine/src/orchestrator/scan-orchestrator.ts',
    original: `            if (detail.evidence.kind === 'UNINVOKED_SYMBOL') {
              const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
              const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
              const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
              suppressionDetail = \`Symbol '\${symStr}' from source \${srcStr} is not invoked (Dataset URLs: \${urlStr})\`;
            }`,
    mutated: `            if (false && detail.evidence.kind === 'UNINVOKED_SYMBOL') { // MUTATION_B24: ledger loses symbol detail
              const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
              const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
              const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
              suppressionDetail = \`Symbol '\${symStr}' from source \${srcStr} is not invoked (Dataset URLs: \${urlStr})\`;
            }`,
    testFile: 'packages/core-engine/test/reachability-symbol-wiring.test.ts',
    testFilter: 'Suppression Ledger: suppressed finding includes symbol',
  },
  {
    id: 'B25',
    description: 'stale cache facts served after version bump',
    targetFile: 'packages/reachability/src/cache/external-cache.ts',
    original: `      if (
        entry.version !== ExternalExtractionCache.ANALYZER_VERSION ||
        entry.manifestHash !== getWasmManifestHash() ||
        entry.contentHash !== currentContentHash
      ) {`,
    mutated: `      if (
        (false && entry.version !== ExternalExtractionCache.ANALYZER_VERSION) ||
        entry.manifestHash !== getWasmManifestHash() ||
        entry.contentHash !== currentContentHash
      ) { // MUTATION_B25: stale cache facts served`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B25: Mutation',
  },
  {
    id: 'B26',
    description: 'nondeterministic ordering',
    targetFile: 'packages/reachability/src/symbols/candidate-extractor.ts',
    original: `  return candidates.sort((a, b) => a.symbol.localeCompare(b.symbol));
}

/**
 * Extracts candidates from title and description`,
    mutated: `  return candidates.sort((a, b) => b.symbol.localeCompare(a.symbol)); // MUTATION_B26: reversed ordering
}

/**
 * Extracts candidates from title and description`,
    testFile: 'packages/reachability/test/verification/phaseB.verify.test.ts',
    testFilter: 'B26: Mutation',
  },
];

const PHASEC_MUTATIONS = [
  {
    id: 'C1',
    description:
      'Pin authority guard: remote manifest mismatch must fail hard and never override pin',
    targetFile: 'packages/cli/src/commands/install-tools.ts',
    original: `          if (remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
            throw new Error(
              \`Security violation: Remote checksum manifest (\${remoteHash}) does not match authoritative bundled pin (\${asset.sha256}) for \${toolDef.name}! Aborting install to prevent trust downgrade.\`
            );
          }`,
    mutated: `          if (false && remoteHash.toLowerCase() !== asset.sha256.toLowerCase()) {
            throw new Error('Security violation');
          }`,
    testFile: 'packages/cli/test/install-tools.test.ts',
    testFilter: 'fails hard when remote manifest hash does not match authoritative pin',
  },
  {
    id: 'C2',
    description: 'Hash compare guard: downloaded asset checksum mismatch aborts install',
    targetFile: 'packages/cli/src/commands/install-tools.ts',
    original: `      if (computedSha !== asset.sha256.toLowerCase()) {
        throw new Error(
          \`Cryptographic checksum mismatch! Expected SHA-256 \${asset.sha256}, got \${computedSha}. Aborting install.\`
        );
      }`,
    mutated: `      if (false && computedSha !== asset.sha256.toLowerCase()) {
        throw new Error('Cryptographic checksum mismatch');
      }`,
    testFile: 'packages/cli/test/install-tools.test.ts',
    testFilter: 'aborts installation and removes temp file on SHA-256 integrity mismatch',
  },
  {
    id: 'C3',
    description: 'SafeTarReader traversal/absolute entry guard',
    targetFile: 'packages/core-engine/src/offline/tar-bundle.ts',
    original: `        if (
          entryName.startsWith('/') ||
          entryName.startsWith('\\\\') ||
          entryName.includes('..') ||
          entryName.includes('\\0') ||
          /^[a-zA-Z]:/.test(entryName)
        ) {
          throw new Error(
            \`Security violation: Prohibited path traversal or absolute entry '\${entryName}'.\`
          );
        }`,
    mutated: `        if (false) {
          throw new Error('Security violation');
        }`,
    testFile: 'packages/core-engine/test/bundle-offline.test.ts',
    testFilter: 'rejects path traversal attempts in archive extraction',
  },
  {
    id: 'C4',
    description: 'Ed25519 signature verification guard in offline bundle importer',
    targetFile: 'packages/core-engine/src/offline/bundle-service.ts',
    original: `        if (!verified) {
          throw new Error(
            \`[Security Violation] Signature verification failed for bundle '\${manifest.bundleId}' against all provided trusted public keys.\`
          );
        }`,
    mutated: `        if (false && !verified) {
          throw new Error('Signature verification failed');
        }`,
    testFile: 'packages/core-engine/test/bundle-offline.test.ts',
    testFilter: 'rejects bundle signed with untrusted key',
  },
  {
    id: 'C5',
    description: 'Anti-rollback guard: rejecting older offline bundles unless --allow-downgrade',
    targetFile: 'packages/core-engine/src/offline/bundle-service.ts',
    original: `        if (bundleCreated < activeCreated && !options.allowDowngrade) {
          throw new Error(
            \`[Security Violation] Anti-rollback rejected: Bundle timestamp (\${manifest.createdAt}) is older than installed generation '\${activeGen.id}' (\${activeGen.manifest.createdAt}). Use --allow-downgrade to override.\`
          );
        }`,
    mutated: `        if (false && bundleCreated < activeCreated && !options.allowDowngrade) {
          throw new Error('Anti-rollback rejected');
        }`,
    testFile: 'packages/core-engine/test/bundle-offline.test.ts',
    testFilter: 'enforces anti-rollback protection unless --allow-downgrade is passed',
  },
  {
    id: 'C6',
    description: 'Atomic swap guard: publishing generation atomically via CURRENT pointer rename',
    targetFile: 'packages/core-engine/src/offline/bundle-service.ts',
    original: `      // Atomic pointer swap to CURRENT
      const tempCurrent = path.join(targetDbDir, \`.CURRENT.tmp-\${process.pid}\`);
      fs.writeFileSync(tempCurrent, genId);
      fs.renameSync(tempCurrent, path.join(targetDbDir, 'CURRENT'));`,
    mutated: `      // Atomic pointer swap to CURRENT (MUTATED: skipped rename)
      const tempCurrent = path.join(targetDbDir, \`.CURRENT.tmp-\${process.pid}\`);
      fs.writeFileSync(tempCurrent, genId);`,
    testFile: 'packages/core-engine/test/bundle-offline.test.ts',
    testFilter: 'rejects unsigned bundle when trusted keys are required or allowUnsigned is false',
  },
  {
    id: 'C7',
    description: 'Offline egress guard: strictly blocking unauthorized outbound operations',
    targetFile: 'packages/core-engine/src/offline/egress-guard.ts',
    original: `  throw new Error(
    \`[Security Violation] Feature '\${feature}' requires outbound network access and is blocked in offline mode (--offline).\`
  );`,
    mutated: `  // MUTATION_C7: skipped egress block
  return;`,
    testFile: 'packages/core-engine/test/offline.test.ts',
    testFilter: 'blocks cloud AI egress without loopback in offline mode',
  },
  {
    id: 'C8',
    description: 'Stale DB guard: evaluating database expiration when age exceeds maxDbAgeDays',
    targetFile: 'packages/core-engine/src/offline/freshness-evaluator.ts',
    original: `    if (isExpired) {
      status = 'EXPIRED';
    } else if (isStale) {`,
    mutated: `    if (false && isExpired) {
      status = 'EXPIRED';
    } else if (isStale) {`,
    testFile: 'packages/core-engine/test/offline.test.ts',
    testFilter: 'evaluates expired generation',
  },
  {
    id: 'C9',
    description:
      'Planted binary guard: preventing execution of binaries planted inside target directory',
    targetFile: 'packages/core-engine/src/paths/index.ts',
    original: `    if (
      relative === '' ||
      (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\\\'))
    ) {
      throw new Error(
        \`Security violation: Scanner binary '\${candidatePath}' resides inside target directory '\${targetDir}'. Execution blocked to prevent planted-binary attack.\`
      );
    }`,
    mutated: `    if (
      false && (
      relative === '' ||
      (!relative.startsWith('..') && !path.isAbsolute(relative) && !relative.startsWith('\\\\')))
    ) {
      throw new Error('Security violation');
    }`,
    testFile: 'packages/scanner-adapters/test/paths.test.ts',
    testFilter:
      'assertNotInsideTarget throws security violation when tool resides inside targetDir',
  },
];

let selectedMutations;
let phaseName;
let docFolder;

if (isPhase3) {
  selectedMutations = PHASE3_MUTATIONS;
  phaseName = 'Phase 3 (N1 to N17)';
  docFolder = 'phase3';
} else if (isPhase4) {
  selectedMutations = PHASE4_MUTATIONS;
  phaseName = 'Phase 4 (M1 to M21)';
  docFolder = 'phase4';
} else if (isPhase5) {
  selectedMutations = PHASE5_MUTATIONS;
  phaseName = 'Phase 5 (P1 to P28)';
  docFolder = 'phase5';
} else if (isPhaseC) {
  selectedMutations = PHASEC_MUTATIONS;
  phaseName = 'Phase C (C1 to C9)';
  docFolder = 'phase-c';
} else {
  selectedMutations = PHASEB_MUTATIONS;
  phaseName = 'Phase B (B1 to B26)';
  docFolder = 'phaseB';
}

const DOCS_DIR = path.resolve(ROOT_DIR, 'docs', docFolder);
fs.mkdirSync(DOCS_DIR, { recursive: true });

console.log(`== SecureShip Mutation Integrity Verification (${phaseName}) ==\n`);

// 1. Create an isolated temporary copy of the repository
const tempRepoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-mut-repo-'));
console.log(`Setting up isolated temp repo in ${tempRepoDir}...`);

// Copy all root configuration files
for (const file of fs.readdirSync(ROOT_DIR)) {
  const full = path.join(ROOT_DIR, file);
  if (fs.statSync(full).isFile()) {
    fs.copyFileSync(full, path.join(tempRepoDir, file));
  }
}

// Copy packages (excluding node_modules and dist)
fs.cpSync(path.join(ROOT_DIR, 'packages'), path.join(tempRepoDir, 'packages'), {
  recursive: true,
  filter: (src) => !src.includes('node_modules'),
});

// Create junction to root node_modules
fs.symlinkSync(
  path.join(ROOT_DIR, 'node_modules'),
  path.join(tempRepoDir, 'node_modules'),
  'junction'
);

// Create junctions to each package's node_modules
for (const pkg of fs.readdirSync(path.join(ROOT_DIR, 'packages'))) {
  const pkgNodeModules = path.join(ROOT_DIR, 'packages', pkg, 'node_modules');
  if (fs.existsSync(pkgNodeModules)) {
    const dest = path.join(tempRepoDir, 'packages', pkg, 'node_modules');
    fs.symlinkSync(pkgNodeModules, dest, 'junction');
  }
}

console.log('Isolated temp repo created successfully.\n');

function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
}

function runVitest(cwd, testFile, filter) {
  const vitestCli = path.resolve('node_modules/vitest/vitest.mjs');
  const args = filter ? [vitestCli, 'run', testFile, '-t', filter] : [vitestCli, 'run', testFile];
  const res = spawnSync(process.execPath, args, {
    cwd,
    encoding: 'utf8',
  });

  const rawOutput = (res.stdout || '') + (res.stderr || '');
  const cleanOutput = stripAnsi(rawOutput);

  // Classify compile/syntax/transform/typecheck errors as INVALID MUTATION (R13)
  const isSyntaxOrTransformError =
    cleanOutput.includes('Transform failed') ||
    cleanOutput.includes('SyntaxError') ||
    cleanOutput.includes('unexpected token') ||
    cleanOutput.includes('Failed to parse source') ||
    cleanOutput.includes('Cannot find name');

  if (isSyntaxOrTransformError) {
    return {
      exitCode: res.status,
      output: cleanOutput,
      failingTests: [],
      invalidMutation: true,
    };
  }

  const failingTests = [];
  const lines = cleanOutput.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // 1. Matches: "FAIL <suite> > ... > <testName>"
    const failMatch = line.match(/^FAIL\s+.+?>\s+(.+)$/);
    if (failMatch && failMatch[1]) {
      const name = failMatch[1].includes('>')
        ? failMatch[1].split('>').pop().trim()
        : failMatch[1].trim();
      failingTests.push(name);
      continue;
    }
    // 2. Matches: "× <testName> <duration>"
    const xMatch = line.match(/^[×✕]\s+(.+?)(?:\s+\d+m?s)?$/);
    if (xMatch && xMatch[1]) {
      const name = xMatch[1].includes('>') ? xMatch[1].split('>').pop().trim() : xMatch[1].trim();
      failingTests.push(name);
      continue;
    }
  }

  // Fallback: check "AssertionError" or "Error:"
  if (res.status !== 0 && failingTests.length === 0) {
    for (const line of lines) {
      if (line.includes('AssertionError:') || line.includes('Error:')) {
        failingTests.push(line.trim());
      }
    }
  }

  return {
    exitCode: res.status,
    output: cleanOutput,
    failingTests: Array.from(new Set(failingTests)),
    invalidMutation: false,
  };
}

const results = [];
const detailedProofs = {};

for (const m of selectedMutations) {
  process.stdout.write(`Evaluating Mutation ${m.id}: ${m.description}... `);

  const fullTarget = path.join(tempRepoDir, m.targetFile);
  if (!fs.existsSync(fullTarget)) {
    console.error(`ERROR: Target file ${fullTarget} not found.`);
    process.exit(1);
  }

  const originalContent = fs.readFileSync(fullTarget, 'utf8');
  if (!originalContent.includes(m.original)) {
    console.error(`ERROR: Original pattern for mutation ${m.id} not found in ${m.targetFile}.`);
    process.exit(1);
  }

  // 1. Apply mutation
  const mutatedContent = originalContent.replace(m.original, m.mutated);
  fs.writeFileSync(fullTarget, mutatedContent, 'utf8');

  const tsupCli = path.resolve('node_modules/tsup/dist/cli-default.js');

  // If CLI file mutated, rebuild CLI bundle in tempRepoDir
  if (m.targetFile.startsWith('packages/cli/')) {
    spawnSync(process.execPath, [tsupCli], { cwd: path.join(tempRepoDir, 'packages', 'cli') });
  }

  // 2. Run vitest under mutation
  const mutRun = runVitest(tempRepoDir, m.testFile, m.testFilter);

  // 3. Verify that the mutation caused a test failure
  if (mutRun.invalidMutation) {
    console.error(
      `\nERROR: Mutation ${m.id} produced an INVALID MUTATION (syntax/transform/compile error)!`
    );
    console.error('Vitest output:\n', mutRun.output);
    fs.writeFileSync(fullTarget, originalContent, 'utf8');
    process.exit(1);
  }

  if (mutRun.exitCode === 0 || mutRun.failingTests.length === 0) {
    console.log('FAIL! (Mutation was NOT caught by any test)');
    console.log('Exit code:', mutRun.exitCode);
    console.log('Vitest output:\n', mutRun.output);
    // Restore file before exit
    fs.writeFileSync(fullTarget, originalContent, 'utf8');
    process.exit(1);
  }

  // Check failing test against expected pattern (R13)
  const expectedPattern = m.expectedTest || m.testFilter;
  if (expectedPattern) {
    const patternRegex = new RegExp(expectedPattern, 'i');
    const matched = mutRun.failingTests.some((t) => patternRegex.test(t));
    if (!matched) {
      console.error(
        `\nERROR: Mutation ${m.id} was caught by test(s) [${mutRun.failingTests.join(', ')}], which did NOT match expected pattern "${expectedPattern}"!`
      );
      fs.writeFileSync(fullTarget, originalContent, 'utf8');
      process.exit(1);
    }
  }

  console.log(`CAUGHT! (${mutRun.failingTests.length} failing test(s))`);

  // 4. Restore file and verify test passes cleanly (Bidirectional proof)
  fs.writeFileSync(fullTarget, originalContent, 'utf8');
  if (m.targetFile.startsWith('packages/cli/')) {
    spawnSync(process.execPath, [tsupCli], { cwd: path.join(tempRepoDir, 'packages', 'cli') });
  }

  const restoreRun = runVitest(tempRepoDir, m.testFile, m.testFilter);
  if (restoreRun.exitCode !== 0) {
    console.error(`ERROR: Mutation ${m.id} did not pass after restoration!`);
    process.exit(1);
  }

  detailedProofs[m.id] = {
    failingRun: mutRun,
    restoredRun: restoreRun,
    failingTests: mutRun.failingTests,
  };

  results.push({
    id: m.id,
    description: m.description,
    targetFile: m.targetFile,
    testFile: m.testFile,
    patch: m.mutated.trim(),
    failingTests: mutRun.failingTests,
    status: 'CAUGHT',
  });
}

// Clean up temp repo
try {
  fs.rmSync(tempRepoDir, { recursive: true, force: true });
} catch {}

console.log(`\nAll ${selectedMutations.length} mutations successfully verified and caught.`);

// Generate markdown mutation log
let phaseTitle = 'Phase B: Mutation Verification Log (B1–B26)';
let phaseSpec = 'Phase B Function-Level Reachability specification';
if (isPhase3) {
  phaseTitle = 'Phase 3: Mutation Verification Log (N1–N17)';
  phaseSpec = 'Phase 3 specification';
} else if (isPhase4) {
  phaseTitle = 'Phase 4: Mutation Verification Log (M1–M21)';
  phaseSpec = 'Phase 4 Amendment A18 specification';
} else if (isPhase5) {
  phaseTitle = 'Phase 5: Mutation Verification Log (P1–P28)';
  phaseSpec = 'Phase 5 Gate 4 Verified Remediation specification';
} else if (isPhaseC) {
  phaseTitle = 'Phase C: Mutation Verification Log (C1–C9)';
  phaseSpec = 'Phase C Container & Air-Gap Completeness specification';
}

let md = `# SecureShip ${phaseTitle}

In accordance with ${phaseSpec}, this log records the real execution of \`pnpm verify:mutations\`. Each mutation was applied to an isolated temporary copy of the repository in \`$env:TEMP\`, evaluated against the verification test suite, and confirmed to fail with specific failing test names.

**Verification Attestation:** Exactly ${selectedMutations.length} out of ${selectedMutations.length} mutations were successfully caught (0 uncaught mutations). Bidirectional proof confirms that each test fails under mutation and passes cleanly when restored.

---

## 1. Mutation Summary Table

| ID | Description | Target File | Verification Test | Status | Failing Test(s) |
| :--- | :--- | :--- | :--- | :---: | :--- |
`;

for (const r of results) {
  const tests = r.failingTests.map((t) => `\`${t}\``).join('<br>');
  md += `| **${r.id}** | ${r.description} | \`${r.targetFile}\` | \`${r.testFile}\` | **${r.status}** | ${tests} |\n`;
}

md += `\n---\n\n## 2. Bidirectional Proofs (Pass on Restoration)\n\n`;

for (const r of results) {
  const proof = detailedProofs[r.id];
  const item = selectedMutations.find((m) => m.id === r.id);
  md += `### Mutation ${r.id}: ${item.description}\n\n`;
  md += `- **Target File:** \`${item.targetFile}\`\n`;
  md += `- **Verification Suite:** \`${item.testFile}\`\n`;
  md += `- **Applied Mutation Patch:**\n\`\`\`diff\n- ${item.original.split('\n').join('\n- ')}\n+ ${item.mutated.split('\n').join('\n+ ')}\n\`\`\`\n`;
  md += `- **Mutation Test Run (Exit Code ${proof.failingRun.exitCode} - FAILING):**\n`;
  for (const t of proof.failingTests) {
    md += `  - ❌ \`${t}\`\n`;
  }
  md += `- **Restored Code Run (Exit Code ${proof.restoredRun.exitCode} - PASSING):**\n`;
  md += `  - ✅ Clean restoration confirmed; 0 test failures.\n\n`;
}

md += `## 3. Detailed Patch Log\n\n`;
for (const r of results) {
  md += `### ${r.id}: ${r.description}\n\n`;
  md += `- **Target:** \`${r.targetFile}\`\n`;
  md += `- **Test Suite:** \`${r.testFile}\`\n`;
  md += `\`\`\`typescript\n// Applied Mutation:\n${r.patch}\n\`\`\`\n\n`;
  md += `**Failing Test Names:**\n`;
  for (const t of r.failingTests) {
    md += `- \`${t}\`\n`;
  }
  md += `\n`;
}

const logPath = path.resolve(DOCS_DIR, 'mutation-log.md');
fs.writeFileSync(logPath, md, 'utf8');
console.log(`Mutation verification log written to ${logPath}`);

// Format with prettier (R13, R14)
try {
  const prettierCli = require.resolve('prettier/bin/prettier.cjs');
  spawnSync(process.execPath, [prettierCli, '--write', logPath], { cwd: ROOT_DIR });
  console.log(`Formatted ${logPath} with prettier.`);
} catch (err) {
  console.warn(`Prettier formatting note: ${err.message}`);
}

console.log('== Mutation Integrity Verification Complete (Exit Code 0) ==');
