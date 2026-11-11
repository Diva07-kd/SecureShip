import { describe, it, expect, vi } from 'vitest';
import { SecureShipLogger } from '../src/logger/secureship-logger.js';

describe('SecureShipLogger Coverage & Resilience Suite', () => {
  it('supports child logger with nested prefixes', () => {
    const parent = new SecureShipLogger({ level: 'debug', prefix: 'Root' });
    const child = parent.child('Sub');
    expect(child).toBeDefined();

    const writeSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      child.debug('Child debug message');
      expect(writeSpy).toHaveBeenCalled();
      const output = writeSpy.mock.calls[0]?.[0];
      expect(output).toContain('[Root:Sub]');
      expect(output).toContain('Child debug message');
    } finally {
      writeSpy.mockRestore();
    }
  });

  it('formats human output across all levels and redacts secrets and metadata', () => {
    const logger = new SecureShipLogger({ level: 'debug', prefix: 'TestApp' });

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      // Debug
      logger.debug('Debug secret: AKIA1234567890123456', { key: 'secret_123' });
      expect(logSpy).toHaveBeenCalled();
      expect(logSpy.mock.calls[0]?.[0]).toContain('DEBUG');
      expect(logSpy.mock.calls[0]?.[0]).toContain('[REDACTED]');

      // Info
      logger.info('Info message', { user: 'alice' });
      expect(logSpy.mock.calls[2]?.[0]).toContain('INFO');
      expect(logSpy.mock.calls[2]?.[0]).toContain('Info message');

      // Warn
      logger.warn('Warning alert', { code: 404 });
      expect(logSpy.mock.calls[4]?.[0]).toContain('WARN');
      expect(logSpy.mock.calls[4]?.[0]).toContain('Warning alert');

      // Error
      logger.error('Error failure', { status: 'FAILED' });
      expect(errSpy).toHaveBeenCalled();
      expect(errSpy.mock.calls[0]?.[0]).toContain('ERROR');
      expect(errSpy.mock.calls[0]?.[0]).toContain('Error failure');
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });

  it('outputs pure JSON to stdout/stderr in json mode', () => {
    const logger = new SecureShipLogger({ level: 'debug', json: true, prefix: 'JsonApp' });

    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    try {
      logger.info('Structured info message', { count: 42 });
      expect(stdoutSpy).toHaveBeenCalled();
      const stdoutCall = stdoutSpy.mock.calls[0]?.[0] as string;
      const parsedStdout = JSON.parse(stdoutCall.trim());
      expect(parsedStdout.level).toBe('info');
      expect(parsedStdout.prefix).toBe('JsonApp');
      expect(parsedStdout.message).toBe('Structured info message');
      expect(parsedStdout.metadata.count).toBe(42);

      logger.error('Structured error message', new Error('Fatal'));
      expect(stderrSpy).toHaveBeenCalled();
      const stderrCall = stderrSpy.mock.calls[0]?.[0] as string;
      const parsedStderr = JSON.parse(stderrCall.trim());
      expect(parsedStderr.level).toBe('error');
      expect(parsedStderr.message).toBe('Structured error message');
      expect(parsedStderr.metadata.errorMessage).toBe('Fatal');
    } finally {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    }
  });

  it('filters log levels properly based on configured threshold', () => {
    const logger = new SecureShipLogger({ level: 'warn', prefix: 'FilterApp' });

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      logger.debug('Ignored debug');
      logger.info('Ignored info');
      expect(logSpy).not.toHaveBeenCalled();

      logger.warn('Captured warn');
      expect(logSpy).toHaveBeenCalledTimes(1);

      logger.error('Captured error');
      expect(errSpy).toHaveBeenCalledTimes(1);
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });
});
