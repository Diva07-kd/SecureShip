export interface EgressGuardContext {
  isLoopback?: boolean;
  isOfflineLicense?: boolean;
}

/**
 * Asserts that a feature or operation is permitted under the current offline mode policy.
 * Throws an explicit security violation error if outbound network access is attempted while --offline is active.
 */
export function assertOfflineAllowed(
  feature: 'fleet' | 'cloud-ai' | 'update-check' | 'license-activation' | 'install-tools' | string,
  isOffline: boolean,
  context?: EgressGuardContext
): void {
  if (!isOffline) {
    return;
  }

  // Permitted offline exceptions
  if (feature === 'cloud-ai' && context?.isLoopback) {
    return;
  }

  if (feature === 'license-activation' && context?.isOfflineLicense) {
    return;
  }

  throw new Error(
    `[Security Violation] Feature '${feature}' requires outbound network access and is blocked in offline mode (--offline).`
  );
}
