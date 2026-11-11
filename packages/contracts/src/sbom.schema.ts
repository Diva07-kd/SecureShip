import { z } from 'zod';

export const SbomFormatSchema = z.enum(['cyclonedx', 'spdx']);
export type SbomFormat = z.infer<typeof SbomFormatSchema>;

// ============================================================================
// CycloneDX 1.5 Specification (EU CRA / US EO 14028 Compliant)
// ============================================================================

export const CycloneDxHashSchema = z.object({
  alg: z.string(),
  content: z.string(),
});
export type CycloneDxHash = z.infer<typeof CycloneDxHashSchema>;

export const CycloneDxLicenseItemSchema = z.object({
  license: z
    .object({
      id: z.string().optional(),
      name: z.string().optional(),
      url: z.string().optional(),
    })
    .optional(),
  expression: z.string().optional(),
});
export type CycloneDxLicenseItem = z.infer<typeof CycloneDxLicenseItemSchema>;

export const CycloneDxVulnerabilityRatingSchema = z.object({
  severity: z.string(),
  score: z.number().optional(),
  method: z.string().optional(),
});
export type CycloneDxVulnerabilityRating = z.infer<typeof CycloneDxVulnerabilityRatingSchema>;

export const CycloneDxVulnerabilitySchema = z.object({
  id: z.string(),
  source: z.object({ name: z.string() }).optional(),
  ratings: z.array(CycloneDxVulnerabilityRatingSchema).optional(),
  description: z.string().optional(),
  detail: z.string().optional(),
  recommendation: z.string().optional(),
});
export type CycloneDxVulnerability = z.infer<typeof CycloneDxVulnerabilitySchema>;

export const CycloneDxComponentTypeSchema = z.enum([
  'application',
  'framework',
  'library',
  'container',
  'operating-system',
  'device',
  'firmware',
  'file',
]);
export type CycloneDxComponentType = z.infer<typeof CycloneDxComponentTypeSchema>;

export const CycloneDxComponentSchema = z.object({
  type: CycloneDxComponentTypeSchema,
  name: z.string(),
  version: z.string(),
  purl: z.string().optional(),
  cpe: z.string().optional(),
  description: z.string().optional(),
  scope: z.enum(['required', 'optional', 'excluded']).optional(),
  hashes: z.array(CycloneDxHashSchema).optional(),
  licenses: z.array(CycloneDxLicenseItemSchema).optional(),
  vulnerabilities: z.array(CycloneDxVulnerabilitySchema).optional(),
});
export type CycloneDxComponent = z.infer<typeof CycloneDxComponentSchema>;

export const CycloneDxDependencySchema = z.object({
  ref: z.string(),
  dependsOn: z.array(z.string()).optional(),
});
export type CycloneDxDependency = z.infer<typeof CycloneDxDependencySchema>;

export const CycloneDxToolSchema = z.object({
  vendor: z.string(),
  name: z.string(),
  version: z.string(),
});
export type CycloneDxTool = z.infer<typeof CycloneDxToolSchema>;

export const CycloneDxMetadataSchema = z.object({
  timestamp: z.string(),
  tools: z.array(CycloneDxToolSchema),
  component: CycloneDxComponentSchema.optional(),
});
export type CycloneDxMetadata = z.infer<typeof CycloneDxMetadataSchema>;

export const CycloneDxBomSchema = z.object({
  $schema: z.string().optional(),
  bomFormat: z.literal('CycloneDX'),
  specVersion: z.literal('1.5'),
  serialNumber: z.string(),
  version: z.number().int().positive(),
  metadata: CycloneDxMetadataSchema,
  components: z.array(CycloneDxComponentSchema),
  dependencies: z.array(CycloneDxDependencySchema).optional(),
  vulnerabilities: z.array(CycloneDxVulnerabilitySchema).optional(),
});
export type CycloneDxBom = z.infer<typeof CycloneDxBomSchema>;

// ============================================================================
// SPDX 2.3 Specification (ISO/IEC 5962:2021 Standard)
// ============================================================================

export const SpdxChecksumSchema = z.object({
  algorithm: z.string(),
  checksumValue: z.string(),
});
export type SpdxChecksum = z.infer<typeof SpdxChecksumSchema>;

export const SpdxExternalRefSchema = z.object({
  referenceCategory: z.string(),
  referenceType: z.string(),
  referenceLocator: z.string(),
  comment: z.string().optional(),
});
export type SpdxExternalRef = z.infer<typeof SpdxExternalRefSchema>;

export const SpdxPackageSchema = z.object({
  name: z.string(),
  SPDXID: z.string(),
  versionInfo: z.string(),
  downloadLocation: z.string(),
  filesAnalyzed: z.boolean(),
  licenseConcluded: z.string(),
  licenseDeclared: z.string(),
  licenseComments: z.string().optional(),
  description: z.string().optional(),
  homepage: z.string().optional(),
  originator: z.string().optional(),
  externalRefs: z.array(SpdxExternalRefSchema).optional(),
  checksums: z.array(SpdxChecksumSchema).optional(),
});
export type SpdxPackage = z.infer<typeof SpdxPackageSchema>;

export const SpdxRelationshipSchema = z.object({
  spdxElementId: z.string(),
  relatedSpdxElement: z.string(),
  relationshipType: z.string(),
  comment: z.string().optional(),
});
export type SpdxRelationship = z.infer<typeof SpdxRelationshipSchema>;

export const SpdxCreationInfoSchema = z.object({
  creators: z.array(z.string()),
  created: z.string(),
  licenseListVersion: z.string().optional(),
});
export type SpdxCreationInfo = z.infer<typeof SpdxCreationInfoSchema>;

export const SpdxBomSchema = z.object({
  spdxVersion: z.literal('SPDX-2.3'),
  dataLicense: z.literal('CC0-1.0'),
  SPDXID: z.string(),
  name: z.string(),
  documentNamespace: z.string(),
  creationInfo: SpdxCreationInfoSchema,
  packages: z.array(SpdxPackageSchema),
  relationships: z.array(SpdxRelationshipSchema),
});
export type SpdxBom = z.infer<typeof SpdxBomSchema>;

// ============================================================================
// License Compliance Specification
// ============================================================================

export const LicenseViolationSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
export type LicenseViolationSeverity = z.infer<typeof LicenseViolationSeveritySchema>;

export const LicenseViolationSchema = z.object({
  packageName: z.string(),
  version: z.string(),
  license: z.string(),
  reason: z.string(),
  severity: LicenseViolationSeveritySchema,
  ecosystem: z.string().optional(),
  path: z.string().optional(),
});
export type LicenseViolation = z.infer<typeof LicenseViolationSchema>;

export const LicenseComplianceResultSchema = z.object({
  status: z.enum(['COMPLIANT', 'NON_COMPLIANT']),
  totalPackages: z.number().int().nonnegative(),
  compliantCount: z.number().int().nonnegative(),
  violationCount: z.number().int().nonnegative(),
  allowedList: z.array(z.string()).optional(),
  deniedList: z.array(z.string()).optional(),
  violations: z.array(LicenseViolationSchema),
});
export type LicenseComplianceResult = z.infer<typeof LicenseComplianceResultSchema>;
