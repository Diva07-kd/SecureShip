import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { HttpClient } from '../providers/http-client.js';

export interface AiConsentRecord {
  consentedAt: string;
  endpointBinding: string; // scheme + host + port
  provider: string;
  model: string;
}

export class ConsentManager {
  private readonly consentFilePath: string;

  constructor(explicitConsentPath?: string) {
    this.consentFilePath = explicitConsentPath || ConsentManager.getDefaultConsentPath();
  }

  public static computeBinding(url: URL): string {
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    return `${url.protocol}//${url.hostname.toLowerCase()}:${port}`;
  }

  public static recordConsent(
    baseUrl: string,
    model: string,
    provider = 'openai',
    consentPath?: string
  ): AiConsentRecord & { boundOrigin: string } {
    const mgr = new ConsentManager(consentPath);
    const rec = mgr.recordConsent(provider, model, baseUrl);
    return { ...rec, boundOrigin: rec.endpointBinding };
  }

  public static checkConsent(
    baseUrl: string,
    provider = 'openai',
    consentPath?: string
  ): { consented: boolean; boundOrigin?: string; reason?: string } {
    const mgr = new ConsentManager(consentPath);
    const res = mgr.hasConsent(provider, baseUrl);
    return {
      consented: res.consented,
      boundOrigin: res.record?.endpointBinding,
      reason: res.reason,
    };
  }

  public hasConsent(
    provider: string,
    endpointUrl: string
  ): { consented: boolean; record?: AiConsentRecord; reason?: string } {
    if (!fs.existsSync(this.consentFilePath)) {
      return {
        consented: false,
        reason: 'Consent not granted. Run "secureship ai enable" to review and record consent.',
      };
    }

    try {
      const content = fs.readFileSync(this.consentFilePath, 'utf-8');
      const record = JSON.parse(content) as AiConsentRecord;

      const targetUrl = HttpClient.validateEndpointUrl(endpointUrl);
      const targetBinding = ConsentManager.computeBinding(targetUrl);

      if (record.endpointBinding !== targetBinding) {
        return {
          consented: false,
          record,
          reason: `Endpoint binding change detected (stored '${record.endpointBinding}', current '${targetBinding}'). Re-consent required with "secureship ai enable".`,
        };
      }

      if (record.provider !== provider) {
        return {
          consented: false,
          record,
          reason: `Provider change detected (consented for '${record.provider}', requested '${provider}'). Re-consent required with "secureship ai enable".`,
        };
      }

      return {
        consented: true,
        record,
      };
    } catch {
      return {
        consented: false,
        reason:
          'Consent record could not be read or parsed. Re-consent with "secureship ai enable".',
      };
    }
  }

  public recordConsent(provider: string, model: string, endpointUrl: string): AiConsentRecord {
    const validatedUrl = HttpClient.validateEndpointUrl(endpointUrl);
    const binding = ConsentManager.computeBinding(validatedUrl);

    const record: AiConsentRecord = {
      consentedAt: new Date().toISOString(),
      endpointBinding: binding,
      provider,
      model,
    };

    const dir = path.dirname(this.consentFilePath);
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.consentFilePath, JSON.stringify(record, null, 2), {
        encoding: 'utf-8',
        mode: 0o600,
      });
      if (process.platform !== 'win32') {
        try {
          fs.chmodSync(this.consentFilePath, 0o600);
        } catch {}
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Failed to save AI consent record to '${this.consentFilePath}': ${msg}`);
    }

    return record;
  }

  public revokeConsent(): boolean {
    try {
      if (fs.existsSync(this.consentFilePath)) {
        fs.unlinkSync(this.consentFilePath);
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  public getConsentPath(): string {
    return this.consentFilePath;
  }

  public static getDefaultConsentPath(): string {
    const baseDir =
      process.platform === 'win32'
        ? process.env.LOCALAPPDATA
          ? path.join(process.env.LOCALAPPDATA, 'secureship')
          : path.join(os.homedir(), '.secureship')
        : process.env.XDG_CONFIG_HOME
          ? path.join(process.env.XDG_CONFIG_HOME, 'secureship')
          : path.join(os.homedir(), '.secureship');

    return path.join(baseDir, 'ai-consent.json');
  }
}
