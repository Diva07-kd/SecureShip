import type { ScaPatchProposal } from '@secureship/contracts';
import { MinVersionResolver } from './min-version-resolver.js';

export interface ScaPolicyValidationResult {
  allowed: boolean;
  violations: Array<{
    code: string;
    detail: string;
  }>;
}

export interface ScaPolicyOptions {
  allowMajorBump?: boolean;
}

export class ScaPatchPolicyEngine {
  /**
   * Validates a candidate SCA patch proposal against strict safety rules.
   */
  public static validate(
    proposal: ScaPatchProposal,
    options: ScaPolicyOptions = {}
  ): ScaPolicyValidationResult {
    const violations: Array<{ code: string; detail: string }> = [];

    // 1. Verify strategy is supported
    if (!['DIRECT_UPGRADE', 'TRANSITIVE_PIN', 'OVERRIDES_INJECTION'].includes(proposal.strategy)) {
      violations.push({
        code: 'UNSUPPORTED_STRATEGY',
        detail: `SCA remediation strategy '${proposal.strategy}' is not supported`,
      });
    }

    // 2. Verify target version is strictly greater than current version
    const cur = MinVersionResolver.parseVersion(proposal.currentVersion);
    const target = MinVersionResolver.parseVersion(proposal.targetVersion);

    if (cur.isValid && target.isValid) {
      const cmp = MinVersionResolver.compare(target, cur);
      if (cmp <= 0) {
        violations.push({
          code: 'NON_INCREMENTING_VERSION',
          detail: `Target version '${proposal.targetVersion}' must be strictly greater than current version '${proposal.currentVersion}'`,
        });
      }

      // 3. Check for major version bump if not permitted
      if (
        !options.allowMajorBump &&
        MinVersionResolver.isMajorBump(proposal.currentVersion, proposal.targetVersion)
      ) {
        violations.push({
          code: 'BREAKING_MAJOR_BUMP',
          detail: `Upgrade from '${proposal.currentVersion}' to '${proposal.targetVersion}' is a breaking major version bump. Pass --allow-major-bump to authorize.`,
        });
      }
    }

    // 4. Validate manifest path
    const manifestBasename =
      proposal.manifestPath
        .split(/[\/\\]/)
        .pop()
        ?.toLowerCase() ?? '';
    const isManifest =
      manifestBasename === 'package.json' ||
      (manifestBasename.startsWith('requirements') && manifestBasename.endsWith('.txt')) ||
      manifestBasename === 'pyproject.toml' ||
      manifestBasename === 'pipfile';

    if (!isManifest) {
      violations.push({
        code: 'INVALID_MANIFEST_TARGET',
        detail: `SCA patch target '${proposal.manifestPath}' is not a recognized package manifest`,
      });
    }

    return {
      allowed: violations.length === 0,
      violations,
    };
  }
}
