import { describe, it, expect } from 'vitest';
import { TriageParser } from '../src/triage/triage-schema.js';

describe('TriageParser & Schema Suite', () => {
  it('throws on empty or non-string input', () => {
    expect(() => TriageParser.parse('')).toThrow(/Empty model output/);
    // @ts-expect-error testing invalid type
    expect(() => TriageParser.parse(null)).toThrow(/Empty model output/);
    // @ts-expect-error testing invalid type
    expect(() => TriageParser.parse(undefined)).toThrow(/Empty model output/);
  });

  it('parses pure JSON string', () => {
    const raw = JSON.stringify({
      verdict: 'LIKELY_FALSE_POSITIVE',
      confidence: 'HIGH',
      rationale: 'Sanitized via validator',
      citations: [{ file: 'app.ts', line: 12, quote: 'validator.escape(x)' }],
    });
    const parsed = TriageParser.parse(raw);
    expect(parsed.verdict).toBe('LIKELY_FALSE_POSITIVE');
    expect(parsed.confidence).toBe('HIGH');
    expect(parsed.citations).toHaveLength(1);
    expect(parsed.exploitabilityNotes).toBeUndefined();
  });

  it('extracts JSON from markdown code fence with json identifier', () => {
    const raw =
      'Here is the triage:\n```json\n{"verdict": "LIKELY_TRUE_POSITIVE", "confidence": "HIGH", "rationale": "Direct concatenation with user input", "citations": []}\n```\nHope this helps!';
    const parsed = TriageParser.parse(raw);
    expect(parsed.verdict).toBe('LIKELY_TRUE_POSITIVE');
  });

  it('extracts JSON from generic markdown code fence', () => {
    const raw =
      '```\n{"verdict": "NEEDS_HUMAN_REVIEW", "confidence": "MEDIUM", "rationale": "Complex data flow", "citations": []}\n```';
    const parsed = TriageParser.parse(raw);
    expect(parsed.verdict).toBe('NEEDS_HUMAN_REVIEW');
  });

  it('extracts JSON enclosed in prose without fences', () => {
    const raw =
      'After careful analysis: {"verdict": "LIKELY_FALSE_POSITIVE", "confidence": "LOW", "rationale": "Test helper", "citations": []} - End of report.';
    const parsed = TriageParser.parse(raw);
    expect(parsed.verdict).toBe('LIKELY_FALSE_POSITIVE');
  });

  it('parses optional exploitabilityNotes and citation defaults', () => {
    const raw = JSON.stringify({
      verdict: 'LIKELY_TRUE_POSITIVE',
      confidence: 'HIGH',
      rationale: 'Unauthenticated RCE',
      citations: [{ line: 5, quote: 'child_process.exec(cmd)' }],
      exploitabilityNotes: 'Accessible via public POST endpoint',
    });
    const parsed = TriageParser.parse(raw);
    expect(parsed.exploitabilityNotes).toBe('Accessible via public POST endpoint');
    expect(parsed.citations[0]?.file).toBe('');
  });

  it('throws on invalid JSON syntax', () => {
    expect(() => TriageParser.parse('This is not json at all')).toThrow();
  });

  it('throws on schema validation failures', () => {
    const invalidVerdict = JSON.stringify({
      verdict: 'UNKNOWN_VERDICT',
      confidence: 'HIGH',
      rationale: 'bad verdict',
    });
    expect(() => TriageParser.parse(invalidVerdict)).toThrow();
  });
});
