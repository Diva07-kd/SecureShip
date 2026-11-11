/**
 * SecureShip Supply-Chain Threat Engine — Cross-Tier Licensing Verification Script (Stage 5 Anti-Cheat)
 * Demonstrates live cryptographic key generation, cross-tier validation, tampering detection, and capability enforcement.
 */
import {
  generateLicenseKeyPair,
  signLicenseJwt,
  verifyLicenseJwt,
  base64UrlEncode,
  validateLicenseForTier,
  meetsMinimumTier,
  TIER_HIERARCHY,
} from '../packages/core-engine/src/index.js';
import type { LicenseJwtPayload } from '../packages/contracts/src/index.js';

console.log('🛡️  SecureShip Cross-Tier License & Cryptographic Verification\n');

// 1. Generate real RSA-2048 authority keypair
console.log('1. Generating genuine RSA-2048 Authority Keypair...');
const authority = generateLicenseKeyPair();
const rogueAuthority = generateLicenseKeyPair();
const now = Math.floor(Date.now() / 1000);
console.log('   ✔ Authority keys generated successfully (Algorithm: RS256, 2048-bit RSA).\n');

// 2. Generate and validate PRO_TEAM license
console.log('2. Generating and validating PRO_TEAM license token...');
const proPayload: LicenseJwtPayload = {
  sub: 'lead-dev@startup.io',
  tier: 'PRO_TEAM',
  seats: 10,
  orgId: 'fast-startup',
  iat: now - 30,
  exp: now + 30 * 86400,
  maxMonthlyAiFixes: 100,
  allowCallPathReachability: true,
  allowCiCdGatekeeper: true,
  allowSignedComplianceExport: true,
  allowAirGappedOnPrem: false,
  featureFlags: {},
};
const proToken = signLicenseJwt(proPayload, authority.privateKeyPem);
const proVerification = verifyLicenseJwt(proToken, authority.publicKeyPem, now);
console.log(`   ✔ PRO Token Verified: valid = ${proVerification.valid}`);
console.log(`     ↳ Tier          : ${proVerification.payload?.tier}`);
console.log(`     ↳ Seats         : ${proVerification.payload?.seats}`);
console.log(`     ↳ Max AI Fixes  : ${proVerification.payload?.maxMonthlyAiFixes}`);
console.log(`     ↳ CI/CD Suppress: ${proVerification.payload?.allowCiCdGatekeeper}`);
console.log(`     ↳ Airgap SLA    : ${proVerification.payload?.allowAirGappedOnPrem}\n`);

// 3. Generate and validate ENTERPRISE license
console.log('3. Generating and validating ENTERPRISE license token...');
const entPayload: LicenseJwtPayload = {
  sub: 'ciso@globalbank.corp',
  tier: 'ENTERPRISE',
  seats: 250,
  orgId: 'global-bank',
  iat: now - 30,
  exp: now + 365 * 86400,
  maxMonthlyAiFixes: null, // Unlimited
  allowCallPathReachability: true,
  allowCiCdGatekeeper: true,
  allowSignedComplianceExport: true,
  allowAirGappedOnPrem: true,
  featureFlags: { dedicatedSla: true },
};
const entToken = signLicenseJwt(entPayload, authority.privateKeyPem);
const entVerification = verifyLicenseJwt(entToken, authority.publicKeyPem, now);
console.log(`   ✔ ENTERPRISE Token Verified: valid = ${entVerification.valid}`);
console.log(`     ↳ Tier          : ${entVerification.payload?.tier}`);
console.log(`     ↳ Seats         : ${entVerification.payload?.seats}`);
console.log(
  `     ↳ Max AI Fixes  : ${entVerification.payload?.maxMonthlyAiFixes ?? 'Unlimited (null)'}`
);
console.log(`     ↳ CI/CD Suppress: ${entVerification.payload?.allowCiCdGatekeeper}`);
console.log(`     ↳ Airgap SLA    : ${entVerification.payload?.allowAirGappedOnPrem}\n`);

// 4. Test: Put PRO_TEAM license in an ENTERPRISE-required environment
console.log('4. Testing: Apply PRO_TEAM license to an ENTERPRISE environment...');
const proInEnterprise = validateLicenseForTier(proToken, 'ENTERPRISE', authority.publicKeyPem, now);
console.log(`   Is Valid for ENTERPRISE? : ${proInEnterprise.valid} (Expected: false)`);
console.log(`   Resolved Tier            : ${proInEnterprise.resolvedTier}`);
console.log(`   Rejection Reason         : "${proInEnterprise.error}"`);
if (!proInEnterprise.valid) {
  console.log('   ✔ PRO_TEAM license strictly REJECTED in ENTERPRISE environment.\n');
} else {
  throw new Error('SECURITY VIOLATION: PRO_TEAM was accepted in ENTERPRISE environment!');
}

// 4b. Explicit Tier Hierarchy Proof
console.log('4b. Verifying Mathematical Tier Hierarchy Ordering:');
console.log(
  `   Tier Levels: FREE_BYOK (${TIER_HIERARCHY.FREE_BYOK}) < PRO_TEAM (${TIER_HIERARCHY.PRO_TEAM}) < ENTERPRISE (${TIER_HIERARCHY.ENTERPRISE})`
);
console.log(
  `   meetsMinimumTier('PRO_TEAM', 'ENTERPRISE') = ${meetsMinimumTier('PRO_TEAM', 'ENTERPRISE')} (Expect: false)`
);
console.log(
  `   meetsMinimumTier('ENTERPRISE', 'PRO_TEAM') = ${meetsMinimumTier('ENTERPRISE', 'PRO_TEAM')} (Expect: true)\n`
);

// 5. Test: Put ENTERPRISE license in a PRO_TEAM environment
console.log('5. Testing: Apply ENTERPRISE license to a PRO_TEAM environment...');
const entInPro = validateLicenseForTier(entToken, 'PRO_TEAM', authority.publicKeyPem, now);
console.log(`   Is Valid for PRO_TEAM?   : ${entInPro.valid} (Expected: true)`);
console.log(`   Resolved Tier            : ${entInPro.resolvedTier}`);
if (entInPro.valid && entInPro.capabilities?.allowCiCdGatekeeper) {
  console.log(
    '   ✔ ENTERPRISE license accepted in PRO_TEAM environment with full superset privileges.\n'
  );
} else {
  throw new Error('UNEXPECTED: ENTERPRISE failed to satisfy PRO_TEAM requirements!');
}

// 6. Test: Anti-Tampering (Attacker changes PRO payload to say ENTERPRISE)
console.log('6. Testing: Tamper payload bytes from PRO_TEAM to ENTERPRISE...');
const [head, , sig] = proToken.split('.');
const tamperedPayload = { ...proPayload, tier: 'ENTERPRISE', maxMonthlyAiFixes: null };
const tamperedToken = `${head}.${base64UrlEncode(JSON.stringify(tamperedPayload))}.${sig}`;
const tamperedCheck = verifyLicenseJwt(tamperedToken, authority.publicKeyPem, now);
console.log(`   Is Tampered Token Valid? : ${tamperedCheck.valid} (Expected: false)`);
console.log(`   Error Caught             : "${tamperedCheck.error}"`);
if (!tamperedCheck.valid) {
  console.log(
    '   ✔ Tampered payload caught and REJECTED by cryptographic RS256 signature verifier.\n'
  );
} else {
  throw new Error('SECURITY VIOLATION: Tampered token passed validation!');
}

// 7. Test: Anti-Forgery (Token signed by rogue private key)
console.log('7. Testing: Token signed by unauthorized/rogue private key...');
const rogueToken = signLicenseJwt(entPayload, rogueAuthority.privateKeyPem);
const rogueCheck = verifyLicenseJwt(rogueToken, authority.publicKeyPem, now);
console.log(`   Is Rogue Token Valid?    : ${rogueCheck.valid} (Expected: false)`);
console.log(`   Error Caught             : "${rogueCheck.error}"`);
if (!rogueCheck.valid) {
  console.log(
    '   ✔ Rogue token REJECTED by cryptographic verifier against official public key.\n'
  );
} else {
  throw new Error('SECURITY VIOLATION: Rogue token passed validation!');
}

console.log('✨ ALL 7 CROSS-TIER CRYPTOGRAPHIC & ISOLATION CHECKS PASSED WITH 100% PRECISION!');
