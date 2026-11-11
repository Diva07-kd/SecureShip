import { describe, it, expect } from 'vitest';
import http from 'node:http';
import { HttpClient } from '../src/providers/http-client.js';

describe('HttpClient Hardened Security Suite (A3, A10)', () => {
  it('correctly classifies loopback hosts and rejects lookalikes', () => {
    // Valid loopback hosts
    expect(HttpClient.isLoopbackHost('localhost')).toBe(true);
    expect(HttpClient.isLoopbackHost('127.0.0.1')).toBe(true);
    expect(HttpClient.isLoopbackHost('127.0.0.2')).toBe(true);
    expect(HttpClient.isLoopbackHost('127.255.255.254')).toBe(true);
    expect(HttpClient.isLoopbackHost('::1')).toBe(true);
    expect(HttpClient.isLoopbackHost('[::1]')).toBe(true);

    // Lookalikes and non-loopback hosts must be REJECTED
    expect(HttpClient.isLoopbackHost('localhost.evil.com')).toBe(false);
    expect(HttpClient.isLoopbackHost('127.0.0.1.nip.io')).toBe(false);
    expect(HttpClient.isLoopbackHost('not-localhost')).toBe(false);
    expect(HttpClient.isLoopbackHost('192.168.1.1')).toBe(false);
    expect(HttpClient.isLoopbackHost('api.openai.com')).toBe(false);
  });

  it('rejects URLs with embedded credentials', () => {
    expect(() => HttpClient.validateEndpointUrl('http://user:pass@localhost:8080/v1')).toThrowError(
      /embedded credentials/i
    );
  });

  it('rejects URLs with fragments', () => {
    expect(() => HttpClient.validateEndpointUrl('http://localhost:8080/v1#fragment')).toThrowError(
      /fragments/i
    );
  });

  it('rejects non-http(s) schemes', () => {
    expect(() => HttpClient.validateEndpointUrl('ftp://localhost:8080/v1')).toThrowError(/scheme/i);
  });

  it('strictly requires HTTPS for non-loopback endpoints', () => {
    expect(() => HttpClient.validateEndpointUrl('http://api.openai.com/v1')).toThrowError(
      /HTTPS is strictly required/i
    );

    expect(() => HttpClient.validateEndpointUrl('https://api.openai.com/v1')).not.toThrow();

    // Loopback allows http
    expect(() => HttpClient.validateEndpointUrl('http://localhost:11434/v1')).not.toThrow();
  });

  it('refuses redirects (redirect: error)', async () => {
    const redirectServer = http.createServer((req, res) => {
      if (req.url === '/other') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('followed');
      } else {
        res.writeHead(302, {
          Location: `http://127.0.0.1:${(redirectServer.address() as { port: number }).port}/other`,
        });
        res.end();
      }
    });

    await new Promise<void>((resolve) => redirectServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (redirectServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/redirect`;

    try {
      await expect(HttpClient.request(url)).rejects.toThrow();
    } finally {
      await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
    }
  });

  it('enforces 1 MB response size cap', async () => {
    const hugePayload = 'X'.repeat(1_048_576 + 100);
    const largeServer = http.createServer((_req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Content-Length': Buffer.byteLength(hugePayload).toString(),
      });
      res.end(hugePayload);
    });

    await new Promise<void>((resolve) => largeServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (largeServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/huge`;

    try {
      await expect(HttpClient.request(url)).rejects.toThrowError(
        /exceeds maximum allowable limit/i
      );
    } finally {
      await new Promise<void>((resolve) => largeServer.close(() => resolve()));
    }
  });

  it('maps HTTP 401/403 to AUTH error', async () => {
    const authServer = http.createServer((_req, res) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
    });

    await new Promise<void>((resolve) => authServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (authServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/auth`;

    try {
      await expect(HttpClient.request(url)).rejects.toMatchObject({
        code: 'AUTH',
        status: 401,
      });
    } finally {
      await new Promise<void>((resolve) => authServer.close(() => resolve()));
    }
  });

  it('handles 429 with Retry-After header', async () => {
    let requests = 0;
    const rateServer = http.createServer((_req, res) => {
      requests++;
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': '1',
      });
      res.end(JSON.stringify({ error: 'Rate limit reached' }));
    });

    await new Promise<void>((resolve) => rateServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (rateServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/rate`;

    try {
      await expect(HttpClient.request(url)).rejects.toMatchObject({
        code: 'RATE_LIMIT',
        status: 429,
        retryAfterMs: 1000,
      });
      expect(requests).toBe(1);
    } finally {
      await new Promise<void>((resolve) => rateServer.close(() => resolve()));
    }
  });

  it('maps HTTP 400 and 422 to MALFORMED error, and 500 to SERVER error', async () => {
    let mode = 400;
    const errServer = http.createServer((_req, res) => {
      res.writeHead(mode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Failure ${mode}` }));
    });

    await new Promise<void>((resolve) => errServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (errServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/err`;

    try {
      mode = 400;
      await expect(HttpClient.request(url)).rejects.toMatchObject({
        code: 'MALFORMED',
        status: 400,
      });

      mode = 422;
      await expect(HttpClient.request(url)).rejects.toMatchObject({
        code: 'MALFORMED',
        status: 422,
      });

      mode = 500;
      await expect(HttpClient.request(url)).rejects.toMatchObject({
        code: 'SERVER',
        status: 500,
      });
    } finally {
      await new Promise<void>((resolve) => errServer.close(() => resolve()));
    }
  });

  it('handles request timeout and abort signal', async () => {
    const slowServer = http.createServer((_req, res) => {
      setTimeout(() => {
        res.writeHead(200);
        res.end('ok');
      }, 500);
    });

    await new Promise<void>((resolve) => slowServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (slowServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/slow`;

    try {
      // Timeout
      await expect(HttpClient.request(url, { timeoutMs: 50 })).rejects.toMatchObject({
        code: 'TIMEOUT',
      });

      // Signal aborted before request
      const preAborted = AbortSignal.abort();
      await expect(HttpClient.request(url, { signal: preAborted })).rejects.toMatchObject({
        code: 'ABORTED',
      });

      // Signal aborted during request
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 30);
      await expect(HttpClient.request(url, { signal: controller.signal })).rejects.toMatchObject({
        code: 'ABORTED',
      });
    } finally {
      await new Promise<void>((resolve) => slowServer.close(() => resolve()));
    }
  });

  it('tests loopback host edge cases and concurrency limiter', async () => {
    expect(HttpClient.isLoopbackHost('')).toBe(false);
    expect(HttpClient.isLoopbackHost('0:0:0:0:0:0:0:1')).toBe(true);

    HttpClient.setMaxConcurrency(1);
    HttpClient.setMaxConcurrency(0); // Should not change

    let active = 0;
    let maxObserved = 0;
    const concurrentServer = http.createServer((_req, res) => {
      active++;
      maxObserved = Math.max(maxObserved, active);
      setTimeout(() => {
        active--;
        res.writeHead(200);
        res.end('ok');
      }, 60);
    });

    await new Promise<void>((resolve) => concurrentServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (concurrentServer.address() as { port: number }).port;
    const url = `http://127.0.0.1:${port}/concurrent`;

    try {
      await Promise.all([
        HttpClient.request(url),
        HttpClient.request(url),
        HttpClient.request(url),
      ]);
      expect(maxObserved).toBe(1);
    } finally {
      HttpClient.setMaxConcurrency(2);
      await new Promise<void>((resolve) => concurrentServer.close(() => resolve()));
    }
  });
});
