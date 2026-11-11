import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { FleetIngestPayloadSchema } from '@secureship/contracts';
import { FleetStore, FleetStoreValidationError } from '../storage/fleet-store.js';

/**
 * Thrown when a request body exceeds configured byte limits.
 */
export class PayloadTooLargeError extends Error {
  constructor(message = 'Payload too large') {
    super(message);
    this.name = 'PayloadTooLargeError';
  }
}

/**
 * Options for configuring the SecureShip Fleet Server.
 *
 * Security Rationale (D9):
 * Removing wildcard CORS alone does not protect users against browser attacks:
 * - Simple cross-origin POST requests (mode: no-cors, Content-Type: text/plain) bypass standard preflights.
 * - DNS rebinding attacks can make malicious domains appear same-origin to local ports.
 * Therefore, FleetServer enforces Host header validation, strict origin filtering,
 * required application/json Content-Type on POST, and timing-safe token authentication.
 * Non-loopback deployments must explicitly configure authToken, allowedHosts, and allowedOrigins.
 *
 * Route Security Architecture (D7, D9):
 * - Default-Deny Gate: Every route requires valid authentication by default when a token is configured.
 *   The only explicit public routes are GET / and GET /dashboard (serving HTML only, zero telemetry data).
 * - Docker / Reverse-Proxy Deployments: When deployed behind reverse proxies, Kubernetes ingress,
 *   or container networks, operators MUST configure `allowedHosts` and `allowedOrigins`.
 * - Token Secrecy: Raw tokens are NEVER retained on the FleetServer instance (D6). Only the SHA-256
 *   digest is held in a module-scoped WeakMap, preventing token extraction via JSON serialization
 *   or object inspection.
 * - Legacy Ingest Deprecation: Ingest authentication via body `fleetToken` is deprecated and capped
 *   to `legacyBodyTokenMaxBytes` (2 MiB). Full payloads (up to 10 MiB) require header authentication.
 */
export interface FleetServerOptions {
  /** Port to listen on. Defaults to 4000. Use 0 for dynamic ephemeral port allocation. */
  port?: number;
  /** Host interface to bind. Defaults to '127.0.0.1'. Non-loopback hosts require authToken. */
  host?: string;
  /** FleetStore instance for persisting fleet telemetry. */
  store?: FleetStore;
  /** Secret bearer token required for authenticating endpoints. */
  authToken?: string;
  /** Explicit whitelist of allowed Origin URLs (e.g. 'https://ciso.internal.corp'). Wildcard '*' forbidden. */
  allowedOrigins?: string[];
  /** Additional allowed Host headers beyond loopback interfaces. */
  allowedHosts?: string[];
  /** Whether to permit legacy ingest payloads with body-level fleetToken (default: true). */
  allowLegacyBodyToken?: boolean;
  /** Maximum body size for legacy body-authenticated ingest requests (default: 2 MiB). */
  legacyBodyTokenMaxBytes?: number;
  /** Maximum body size for header-authenticated requests (default: 10 MiB). */
  maxBodyBytes?: number;
  /** Server headers timeout in milliseconds (default: 15000 ms). */
  headersTimeoutMs?: number;
  /** Server request timeout in milliseconds (default: 60000 ms). */
  requestTimeoutMs?: number;
}

/**
 * Module-level WeakMap retaining only SHA-256 digest of configured auth tokens (D6).
 * Raw token strings are never stored on FleetServer instances.
 */
const tokenDigests = new WeakMap<FleetServer, Buffer>();

/**
 * Constant-time comparison of two tokens using SHA-256 digests (DEV-3).
 */
export function tokensMatch(provided: string | undefined | null, expected: string): boolean {
  if (!provided || typeof provided !== 'string') return false;
  const h1 = crypto.createHash('sha256').update(provided).digest();
  const h2 = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(h1, h2);
}

export class FleetServer {
  private server: http.Server | null = null;
  private readonly port: number;
  private readonly host: string;
  public readonly store: FleetStore;
  private readonly allowedOrigins?: string[];
  private readonly allowedHosts?: string[];
  private readonly allowLegacyBodyToken: boolean;
  private readonly legacyBodyTokenMaxBytes: number;
  private readonly maxBodyBytes: number;
  private readonly headersTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private resolvedPort: number = 0;

  constructor(options: FleetServerOptions = {}) {
    this.port = options.port ?? 4000;
    this.host = options.host ?? '127.0.0.1';
    this.store = options.store ?? new FleetStore();
    this.allowedHosts = options.allowedHosts ? [...options.allowedHosts] : undefined;

    // Validate and store authToken digest (D6, I8)
    if (options.authToken !== undefined) {
      if (typeof options.authToken !== 'string' || options.authToken.trim().length === 0) {
        throw new Error('authToken must be a non-empty string');
      }
      const digest = crypto.createHash('sha256').update(options.authToken).digest();
      tokenDigests.set(this, digest);
    }

    // Body limit options validation (DEV-3)
    this.allowLegacyBodyToken = options.allowLegacyBodyToken ?? true;
    this.legacyBodyTokenMaxBytes = options.legacyBodyTokenMaxBytes ?? 2 * 1024 * 1024;
    this.maxBodyBytes = options.maxBodyBytes ?? 10 * 1024 * 1024;
    this.headersTimeoutMs = options.headersTimeoutMs ?? 15000;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 60000;

    if (
      !Number.isInteger(this.legacyBodyTokenMaxBytes) ||
      this.legacyBodyTokenMaxBytes <= 0 ||
      !Number.isInteger(this.maxBodyBytes) ||
      this.maxBodyBytes <= 0 ||
      !Number.isInteger(this.headersTimeoutMs) ||
      this.headersTimeoutMs <= 0 ||
      !Number.isInteger(this.requestTimeoutMs) ||
      this.requestTimeoutMs <= 0
    ) {
      throw new Error('Server byte limit and timeout options must be positive integers');
    }

    if (this.legacyBodyTokenMaxBytes > this.maxBodyBytes) {
      throw new Error('legacyBodyTokenMaxBytes must be less than or equal to maxBodyBytes');
    }

    if (this.headersTimeoutMs > this.requestTimeoutMs) {
      throw new Error('headersTimeoutMs must be less than or equal to requestTimeoutMs');
    }

    if (options.allowedOrigins) {
      for (const origin of options.allowedOrigins) {
        if (origin === '*') {
          throw new Error("Wildcard '*' origin is not allowed in allowedOrigins");
        }
        try {
          const parsed = new URL(origin);
          if (
            (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
            parsed.origin !== origin
          ) {
            throw new Error(`Invalid origin in allowedOrigins: ${origin}`);
          }
        } catch {
          throw new Error(`Invalid origin in allowedOrigins: ${origin}`);
        }
      }
      this.allowedOrigins = [...options.allowedOrigins];
    }
  }

  private hasAuthToken(): boolean {
    return tokenDigests.has(this);
  }

  private verifyToken(provided: string | undefined | null): boolean {
    if (!provided || typeof provided !== 'string') return false;
    const expectedDigest = tokenDigests.get(this);
    if (!expectedDigest) return false;
    const providedDigest = crypto.createHash('sha256').update(provided).digest();
    return crypto.timingSafeEqual(providedDigest, expectedDigest);
  }

  private hasValidHeaderToken(req: http.IncomingMessage): boolean {
    if (!this.hasAuthToken()) return false;

    // 1. Authorization: Bearer <token> (case-insensitive scheme)
    const authHeader = req.headers['authorization'];
    if (typeof authHeader === 'string') {
      const match = authHeader.match(/^Bearer\s+(.+)$/i);
      if (match && match[1] && this.verifyToken(match[1].trim())) {
        return true;
      }
    }

    // 2. x-fleet-token (D8)
    const xToken = req.headers['x-fleet-token'];
    if (typeof xToken === 'string') {
      if (this.verifyToken(xToken.trim())) {
        return true;
      }
    }

    return false;
  }

  private isLoopbackHost(h: string): boolean {
    const hostLower = h.toLowerCase().trim();
    if (hostLower === 'localhost' || hostLower === '::1' || hostLower === '[::1]') {
      return true;
    }
    if (hostLower.startsWith('127.')) {
      const parts = hostLower.split('.');
      if (parts.length === 4) {
        return parts.every((p) => {
          const n = Number(p);
          return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
        });
      }
    }
    return false;
  }

  public async start(): Promise<number> {
    if (this.server) return this.resolvedPort;

    // Fail-safe guard against insecure exposed deployments without authentication
    if (!this.isLoopbackHost(this.host) && !this.hasAuthToken()) {
      throw new Error(
        `Insecure deployment: non-loopback host '${this.host}' requires authToken to be configured`
      );
    }

    // Emit warning when starting on loopback without authToken (D1, I8)
    if (!this.hasAuthToken()) {
      process.emitWarning(
        'SecureShip Fleet server starting without authentication configured. API endpoints are open.',
        {
          code: 'SECURESHIP_FLEET_NO_AUTH',
          type: 'SecurityWarning',
        }
      );
    }

    return new Promise((resolve, reject) => {
      this.server = http.createServer(
        {
          connectionsCheckingInterval: Math.min(5000, this.headersTimeoutMs),
        },
        async (req, res) => {
          try {
            await this.handleRequest(req, res);
          } catch (err: unknown) {
            if (res.headersSent) return;
            if (err instanceof PayloadTooLargeError) {
              res.writeHead(413, {
                'Content-Type': 'application/json',
                Connection: 'close',
              });
              res.write(JSON.stringify({ error: 'Payload too large' }));
              req.on('data', () => {});
              if (req.readableEnded) {
                res.end();
              } else {
                req.once('end', () => {
                  if (!res.writableEnded) res.end();
                });
                const timer = setTimeout(() => {
                  if (!res.writableEnded) res.end();
                }, 1000);
                if (typeof timer.unref === 'function') timer.unref();
              }
              res.once('finish', () => {
                req.destroy();
              });
            } else if (
              err instanceof SyntaxError ||
              (err instanceof Error && err.name === 'SyntaxError')
            ) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Invalid JSON body' }));
            } else {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Internal server error' }));
            }
          }
        }
      );

      this.server.headersTimeout = this.headersTimeoutMs;
      this.server.requestTimeout = this.requestTimeoutMs;

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.port, this.host, () => {
        const address = this.server?.address();
        if (address && typeof address === 'object') {
          this.resolvedPort = address.port;
        } else {
          this.resolvedPort = this.port;
        }
        resolve(this.resolvedPort);
      });
    });
  }

  public async stop(): Promise<void> {
    if (!this.server) return;

    return new Promise((resolve, reject) => {
      this.server?.close((err) => {
        this.server = null;
        if (err) reject(err);
        else resolve();
      });
    });
  }

  public getUrl(): string {
    return `http://${this.host}:${this.resolvedPort || this.port}`;
  }

  private isHostAllowed(hostHeader: string | undefined): boolean {
    if (!hostHeader || typeof hostHeader !== 'string') return false;

    let hostname = hostHeader.toLowerCase().trim();
    if (hostname.startsWith('[')) {
      const closeBracket = hostname.indexOf(']');
      if (closeBracket !== -1) {
        hostname = hostname.slice(0, closeBracket + 1);
      }
    } else {
      const colonIdx = hostname.indexOf(':');
      if (colonIdx !== -1) {
        hostname = hostname.slice(0, colonIdx);
      }
    }

    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '::1' ||
      this.isLoopbackHost(hostname)
    ) {
      return true;
    }

    const optHost = this.host.toLowerCase().trim();
    const isWildcard =
      optHost === '0.0.0.0' || optHost === '::' || optHost === '[::]' || optHost === '*';
    if (!isWildcard) {
      if (hostname === optHost || hostname === `[${optHost}]`) {
        return true;
      }
    }

    if (this.allowedHosts) {
      const rawHostLower = hostHeader.toLowerCase().trim();
      for (const h of this.allowedHosts) {
        const hLower = h.toLowerCase().trim();
        if (hLower === rawHostLower || hLower === hostname) {
          return true;
        }
      }
    }

    return false;
  }

  private isOriginAllowed(origin: string | undefined, hostHeader: string): boolean {
    if (!origin || typeof origin !== 'string' || origin.toLowerCase() === 'null') {
      return false;
    }

    const hostLower = hostHeader.toLowerCase().trim();
    if (origin.toLowerCase() === `http://${hostLower}`) {
      return true;
    }

    if (this.allowedOrigins) {
      return this.allowedOrigins.includes(origin);
    }

    return /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(origin);
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const rawHost = req.headers.host;

    // 1. Host check defeats DNS rebinding and runs first
    if (!this.isHostAllowed(rawHost)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Forbidden host' }));
      return;
    }

    const parsedUrl = new URL(req.url ?? '/', `http://${rawHost || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const method = req.method?.toUpperCase();

    // 2. Security headers
    res.setHeader('Vary', 'Origin');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (pathname.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
    }

    // 3. Origin policy
    const rawOrigin = req.headers.origin;
    const origin = typeof rawOrigin === 'string' ? rawOrigin : undefined;

    if (origin !== undefined) {
      if (this.isOriginAllowed(origin, rawHost || '')) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-fleet-token');
      } else {
        if (method === 'OPTIONS' || pathname.startsWith('/api/')) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Origin not allowed' }));
          return;
        }
      }
    }

    // 4. Preflight OPTIONS response
    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // 5. Default-Deny Gate (D7)
    // Public set: GET / and GET /dashboard (HTML only, no telemetry)
    const isPublic = method === 'GET' && (pathname === '/' || pathname === '/dashboard');
    if (isPublic) {
      const html = this.getDashboardHtml();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    // Non-public routes require authentication when token is configured
    if (this.hasAuthToken()) {
      const isHeaderTokenValid = this.hasValidHeaderToken(req);

      if (!isHeaderTokenValid) {
        // Only POST /api/ingest can proceed to body-level token evaluation if enabled (D9)
        const isLegacyIngestCandidate =
          method === 'POST' && pathname === '/api/ingest' && this.allowLegacyBodyToken;

        if (!isLegacyIngestCandidate) {
          res.writeHead(401, {
            'Content-Type': 'application/json',
            'WWW-Authenticate': 'Bearer',
          });
          res.end(JSON.stringify({ error: 'Unauthorized: Invalid fleet token' }));
          return;
        }

        // Handle unauthenticated legacy ingest body token flow (D9)
        await this.handleLegacyIngestBodyToken(req, res);
        return;
      }
    }

    // 6. POST requests require Content-Type application/json
    if (method === 'POST') {
      const ct = req.headers['content-type'];
      const isJson =
        typeof ct === 'string' && ct.split(';')[0]!.trim().toLowerCase() === 'application/json';
      if (!isJson) {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
        return;
      }
    }

    // 7. Authenticated Endpoint Routing
    // 7.1 Ingest Endpoint (POST /api/ingest)
    if (method === 'POST' && pathname === '/api/ingest') {
      const body = await this.readJsonBody(req, this.maxBodyBytes);
      const parsed = FleetIngestPayloadSchema.safeParse(body);

      if (!parsed.success) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({ error: 'Invalid Fleet Ingest Payload', details: parsed.error.issues })
        );
        return;
      }

      // Verify HMAC-SHA256 signature if provided or if corporate policy requires audit
      if (parsed.data.signature) {
        const expectedHmac = crypto
          .createHmac('sha256', parsed.data.fleetToken)
          .update(
            `${parsed.data.repoName}:${parsed.data.commitSha}:${parsed.data.durationMs}:${parsed.data.summary.totalReported}`
          )
          .digest('hex');

        if (parsed.data.signature !== expectedHmac) {
          const policy = this.store.getPolicy();
          if (policy.requireHmacAudit) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({ error: 'Tamper-proof audit failed: Invalid HMAC-SHA256 signature' })
            );
            return;
          }
        }
      }

      const summary = this.store.ingest(parsed.data);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success', repo: summary }));
      return;
    }

    // 7.2 Repositories Endpoint (GET /api/fleet/repos)
    if (method === 'GET' && pathname === '/api/fleet/repos') {
      const repos = this.store.getRepos();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(repos));
      return;
    }

    // 7.3 Executive Summary Endpoint (GET /api/fleet/summary)
    if (method === 'GET' && pathname === '/api/fleet/summary') {
      const summary = this.store.getExecutiveSummary();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(summary));
      return;
    }

    // 7.4 Global SBOM Search Endpoint (GET /api/fleet/sbom)
    if (method === 'GET' && pathname === '/api/fleet/sbom') {
      const q = parsedUrl.searchParams.get('q') || '';
      const results = this.store.searchSbom(q);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(results));
      return;
    }

    // 7.5 EU Cyber Resilience Act (CRA) Compliance Export (GET /api/fleet/compliance/cra)
    if (method === 'GET' && pathname === '/api/fleet/compliance/cra') {
      const craReport = this.store.generateCraComplianceReport();
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="eu-cra-cyclonedx-1.5.json"',
      });
      res.end(JSON.stringify(craReport, null, 2));
      return;
    }

    // 7.6 Central Corporate Policy (GET & POST /api/policy)
    if (pathname === '/api/policy') {
      if (method === 'GET') {
        const policy = this.store.getPolicy();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(policy));
        return;
      }

      if (method === 'POST') {
        const updates = await this.readJsonBody(req, this.maxBodyBytes);
        if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid policy payload: must be a plain object' }));
          return;
        }
        try {
          const updated = this.store.updatePolicy(updates);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(updated));
          return;
        } catch (err: unknown) {
          if (err instanceof FleetStoreValidationError) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid policy payload', details: err.details }));
            return;
          }
          throw err;
        }
      }
    }

    // Unknown endpoint yields 404 for authenticated callers (D7)
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  }

  /**
   * Handles legacy ingest requests authenticated via body-level fleetToken (D9).
   * Capped to legacyBodyTokenMaxBytes (2 MiB). Fails with 401 on any JSON or token mismatch
   * before running Zod validation to prevent oracle/amplification attacks.
   */
  private async handleLegacyIngestBodyToken(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    // Pre-check Content-Length against legacyBodyTokenMaxBytes
    const clHeader = req.headers['content-length'];
    if (clHeader) {
      const cl = parseInt(clHeader, 10);
      if (!isNaN(cl) && cl > this.legacyBodyTokenMaxBytes) {
        req.resume();
        throw new PayloadTooLargeError();
      }
    }

    const raw = await this.readRawBody(req, this.legacyBodyTokenMaxBytes);

    let bodyObj: unknown;
    try {
      bodyObj = JSON.parse(raw);
    } catch {
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
      });
      res.end(JSON.stringify({ error: 'Unauthorized: Invalid fleet token' }));
      return;
    }

    if (
      !bodyObj ||
      typeof bodyObj !== 'object' ||
      Array.isArray(bodyObj) ||
      typeof (bodyObj as Record<string, unknown>).fleetToken !== 'string' ||
      !this.verifyToken((bodyObj as Record<string, unknown>).fleetToken as string)
    ) {
      res.writeHead(401, {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
      });
      res.end(JSON.stringify({ error: 'Unauthorized: Invalid fleet token' }));
      return;
    }

    // Now caller is authenticated via legacy body token; enforce Content-Type check (D7)
    const ct = req.headers['content-type'];
    const isJson =
      typeof ct === 'string' && ct.split(';')[0]!.trim().toLowerCase() === 'application/json';
    if (!isJson) {
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
      return;
    }

    // Caller is authenticated and Content-Type is valid; run Zod schema validation
    const parsed = FleetIngestPayloadSchema.safeParse(bodyObj);
    if (!parsed.success) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({ error: 'Invalid Fleet Ingest Payload', details: parsed.error.issues })
      );
      return;
    }

    if (parsed.data.signature) {
      const expectedHmac = crypto
        .createHmac('sha256', parsed.data.fleetToken)
        .update(
          `${parsed.data.repoName}:${parsed.data.commitSha}:${parsed.data.durationMs}:${parsed.data.summary.totalReported}`
        )
        .digest('hex');

      if (parsed.data.signature !== expectedHmac) {
        const policy = this.store.getPolicy();
        if (policy.requireHmacAudit) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({ error: 'Tamper-proof audit failed: Invalid HMAC-SHA256 signature' })
          );
          return;
        }
      }
    }

    const summary = this.store.ingest(parsed.data);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'success', repo: summary }));
  }

  private getDashboardHtml(): string {
    try {
      const currentDir = path.dirname(fileURLToPath(import.meta.url));
      const candidates = [
        path.resolve(currentDir, '../ui/ciso-dashboard.html'),
        path.resolve(currentDir, '../../src/ui/ciso-dashboard.html'),
        path.resolve(currentDir, '../../packages/fleet/src/ui/ciso-dashboard.html'),
        path.resolve(currentDir, '../../packages/fleet/dist/ui/ciso-dashboard.html'),
        path.resolve(process.cwd(), 'packages/fleet/src/ui/ciso-dashboard.html'),
        path.resolve(process.cwd(), 'packages/fleet/dist/ui/ciso-dashboard.html'),
      ];

      for (const p of candidates) {
        if (fs.existsSync(p)) {
          return fs.readFileSync(p, 'utf8');
        }
      }
    } catch {
      // Fall through to fallback
    }

    return `<!DOCTYPE html><html><head><title>SecureShip Fleet</title></head><body style="background:#0b0f19;color:#fff;font-family:sans-serif;padding:32px;"><h1>SecureShip Fleet CISO Cockpit</h1><p>Dashboard active and listening for telemetry.</p></body></html>`;
  }

  private async readRawBody(req: http.IncomingMessage, maxBytes: number): Promise<string> {
    const clHeader = req.headers['content-length'];
    if (clHeader) {
      const cl = parseInt(clHeader, 10);
      if (!isNaN(cl) && cl > maxBytes) {
        req.resume();
        throw new PayloadTooLargeError();
      }
    }

    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalLength = 0;
      let exceeded = false;

      const onData = (chunk: Buffer) => {
        if (exceeded) return;
        totalLength += chunk.length;
        if (totalLength > maxBytes) {
          exceeded = true;
          req.removeListener('data', onData);
          req.resume();
          reject(new PayloadTooLargeError());
        } else {
          chunks.push(chunk);
        }
      };

      req.on('data', onData);

      req.once('end', () => {
        if (exceeded) return;
        resolve(Buffer.concat(chunks).toString('utf8'));
      });

      req.once('error', (err) => {
        if (exceeded) return;
        reject(err);
      });
    });
  }

  private async readJsonBody(
    req: http.IncomingMessage,
    maxBytes: number = this.maxBodyBytes
  ): Promise<Record<string, unknown>> {
    const raw = await this.readRawBody(req, maxBytes);
    if (!raw || raw.trim().length === 0) return {};
    return JSON.parse(raw);
  }
}
