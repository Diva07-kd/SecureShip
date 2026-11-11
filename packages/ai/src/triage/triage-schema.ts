import { z } from 'zod';
import { AiVerdictSchema, ConfidenceSchema } from '@secureship/contracts';

export const RawModelCitationSchema = z.object({
  file: z.string().default(''),
  line: z.number().int().positive(),
  quote: z.string().max(200),
});
export type RawModelCitation = z.infer<typeof RawModelCitationSchema>;

export const RawModelTriageSchema = z.object({
  verdict: AiVerdictSchema,
  confidence: ConfidenceSchema,
  rationale: z.string().max(600),
  citations: z.array(RawModelCitationSchema).max(5).default([]),
  exploitabilityNotes: z.string().max(300).optional(),
});
export type RawModelTriage = z.infer<typeof RawModelTriageSchema>;

export class TriageParser {
  /**
   * Extracts and validates structured triage object from raw LLM output.
   */
  public static parse(rawText: string): RawModelTriage {
    if (!rawText || typeof rawText !== 'string') {
      throw new Error('Empty model output');
    }

    let jsonStr = rawText.trim();

    // 1. Try markdown JSON code fence ```json ... ```
    const fenceMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch && fenceMatch[1]) {
      jsonStr = fenceMatch[1].trim();
    } else {
      // 2. Try outermost braces { ... }
      const firstBrace = jsonStr.indexOf('{');
      const lastBrace = jsonStr.lastIndexOf('}');
      if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        jsonStr = jsonStr.slice(firstBrace, lastBrace + 1);
      }
    }

    const parsedJson = JSON.parse(jsonStr);
    return RawModelTriageSchema.parse(parsedJson);
  }
}
