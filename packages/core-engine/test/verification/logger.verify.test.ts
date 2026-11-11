import { describe, it, expect, vi } from 'vitest';
import { SecureShipLogger } from '../../src/logger/secureship-logger.js';

describe('Part G Verification: Logger', () => {
  const FAKE_TOKEN = 'ghp_' + 'C'.repeat(36);

  it('G1: redacts tokens in message and metadata for human and JSON mode', () => {
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    try {
      // JSON mode
      const jsonLogger = new SecureShipLogger({ json: true });
      jsonLogger.info(`Connected with token ${FAKE_TOKEN}`, { apiKey: 'secret_123' });

      expect(stdoutSpy).toHaveBeenCalled();
      const lastOutput = stdoutSpy.mock.calls[0]?.[0] as string;
      expect(lastOutput).toBeDefined();
      expect(lastOutput).not.toContain(FAKE_TOKEN);
      expect(lastOutput).toContain('ghp_...[REDACTED]');

      // Human mode
      const humanLogger = new SecureShipLogger({ json: false });
      humanLogger.info(`Deploying with ${FAKE_TOKEN}`);
      expect(consoleSpy).toHaveBeenCalled();
      const humanCall = consoleSpy.mock.calls[0]?.[0] as string;
      expect(humanCall).not.toContain(FAKE_TOKEN);
    } finally {
      stdoutSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  });

  it('G2: JSON mode produces valid parseable JSON lines', () => {
    const lines: string[] = [];
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      lines.push(chunk.toString());
      return true;
    });

    try {
      const logger = new SecureShipLogger({ json: true });
      logger.info('System initialized', { port: 8080 });
      logger.warn('Resource warning', { usage: '85%' });

      expect(lines.length).toBeGreaterThanOrEqual(2);
      for (const line of lines) {
        const parsed = JSON.parse(line.trim());
        expect(parsed).toHaveProperty('timestamp');
        expect(parsed).toHaveProperty('level');
        expect(parsed).toHaveProperty('message');
      }
    } finally {
      stdoutSpy.mockRestore();
    }
  });

  it('G3: logging errors, undefined, and non-primitive values does not throw', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    try {
      const logger = new SecureShipLogger({ json: false });
      const err = new Error('Test error with stack trace');
      expect(() => logger.error('Failure encountered', err, { context: 'test' })).not.toThrow();
      expect(() => logger.info('Undefined check', undefined)).not.toThrow();
    } finally {
      consoleSpy.mockRestore();
      logSpy.mockRestore();
    }
  });
});
