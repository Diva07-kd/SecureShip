import { z } from 'zod';
import { NormalizedFindingSchema } from './finding.schema.js';

export const SuppressionReasonCodeSchema = z.enum([
  'GATE1_TEST_OR_MOCK',
  'GATE1_EXAMPLE',
  'GATE1_DOCUMENTATION',
  'USER_IGNORE_RULE',
  'BASELINE_KNOWN',
  'GATE2_UNREACHABLE',
  'GATE3_LIKELY_FALSE_POSITIVE',
  'SUPPLY_CHAIN_ALLOWLISTED',
]);
export type SuppressionReasonCode = z.infer<typeof SuppressionReasonCodeSchema>;

export const SuppressedFindingSchema = z.object({
  finding: NormalizedFindingSchema,
  reasonCode: SuppressionReasonCodeSchema,
  detail: z.string(),
  source: z.string(),
});
export type SuppressedFinding = z.infer<typeof SuppressedFindingSchema>;
