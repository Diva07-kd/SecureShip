import pc from 'picocolors';
import { SecretRedactor } from '../security/secret-redactor.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LoggerOptions {
  level?: LogLevel;
  json?: boolean;
  prefix?: string;
}

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export class SecureShipLogger {
  private level: LogLevel;
  private json: boolean;
  private prefix: string;

  constructor(options: LoggerOptions = {}) {
    this.level = options.level ?? 'info';
    this.json = options.json ?? false;
    this.prefix = options.prefix ?? 'SECURESHIP';
  }

  public setLevel(level: LogLevel): void {
    this.level = level;
  }

  public setJsonMode(json: boolean): void {
    this.json = json;
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[this.level];
  }

  public debug(message: string, metadata?: Record<string, unknown>): void {
    if (!this.shouldLog('debug')) return;
    this.emit('debug', message, metadata);
  }

  public info(message: string, metadata?: Record<string, unknown>): void {
    if (!this.shouldLog('info')) return;
    this.emit('info', message, metadata);
  }

  public warn(message: string, metadata?: Record<string, unknown>): void {
    if (!this.shouldLog('warn')) return;
    this.emit('warn', message, metadata);
  }

  public error(message: string, error?: unknown, metadata?: Record<string, unknown>): void {
    if (!this.shouldLog('error')) return;
    const combinedMeta = {
      ...(metadata ?? {}),
      ...(error instanceof Error
        ? { errorName: error.name, errorMessage: error.message, stack: error.stack }
        : error
          ? { rawError: String(error) }
          : {}),
    };
    this.emit('error', message, combinedMeta);
  }

  private emit(level: LogLevel, message: string, metadata?: Record<string, unknown>): void {
    const redactedMsg = SecretRedactor.redactText(message);
    const redactedMeta = metadata ? SecretRedactor.redactObject(metadata) : undefined;

    if (this.json) {
      const payload: Record<string, unknown> = {
        timestamp: new Date().toISOString(),
        level,
        prefix: this.prefix,
        message: redactedMsg,
        ...(redactedMeta ? { metadata: redactedMeta } : {}),
      };
      const stream = level === 'error' ? process.stderr : process.stdout;
      stream.write(JSON.stringify(payload) + '\n');
      return;
    }

    // Human formatted output
    let tag = `[${this.prefix}]`;
    switch (level) {
      case 'debug':
        tag = pc.gray(`${tag} DEBUG`);
        break;
      case 'info':
        tag = pc.cyan(`${tag} INFO`);
        break;
      case 'warn':
        tag = pc.yellow(`${tag} WARN`);
        break;
      case 'error':
        tag = pc.red(`${tag} ERROR`);
        break;
    }

    const output = `${tag} ${redactedMsg}`;
    if (level === 'error') {
      console.error(output);
      if (redactedMeta && Object.keys(redactedMeta).length > 0) {
        console.error(pc.gray(JSON.stringify(redactedMeta, null, 2)));
      }
    } else {
      console.log(output);
      if (redactedMeta && Object.keys(redactedMeta).length > 0) {
        console.log(pc.gray(JSON.stringify(redactedMeta, null, 2)));
      }
    }
  }

  public child(prefix: string): SecureShipLogger {
    return new SecureShipLogger({
      level: this.level,
      json: this.json,
      prefix: `${this.prefix}:${prefix}`,
    });
  }
}

export const logger = new SecureShipLogger();
