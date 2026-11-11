import { AiError } from './provider.interface.js';

export interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface HttpResponse {
  status: number;
  headers: Headers;
  text: string;
}

export class HttpClient {
  public static readonly MAX_RESPONSE_SIZE = 1_048_576; // 1 MB cap
  public static readonly DEFAULT_TIMEOUT_MS = 60_000;
  private static maxConcurrency = 2;
  private static activeRequests = 0;
  private static globalBackoffUntil = 0;
  private static waitQueue: Array<() => void> = [];

  /**
   * Sets the maximum concurrent HTTP provider requests (default 2).
   */
  public static setMaxConcurrency(max: number): void {
    if (max > 0) {
      HttpClient.maxConcurrency = max;
    }
  }

  /**
   * Determines if a hostname is strictly a local loopback interface.
   * Allowed: literal 'localhost', 127.0.0.0/8, and [::1].
   * Explicitly rejects lookalikes such as 'localhost.evil.com'.
   */
  public static isLoopbackHost(hostname: string): boolean {
    if (!hostname) return false;
    let clean = hostname.toLowerCase().trim();

    // Strip IPv6 brackets if present: [::1] -> ::1
    if (clean.startsWith('[') && clean.endsWith(']')) {
      clean = clean.slice(1, -1);
    }

    // 1. Literal 'localhost'
    if (clean === 'localhost') {
      return true;
    }

    // 2. IPv6 loopback
    if (clean === '::1' || clean === '0:0:0:0:0:0:0:1') {
      return true;
    }

    // 3. IPv4 127.0.0.0/8 range: 127.x.x.x
    const ipv4Regex =
      /^127\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    if (ipv4Regex.test(clean)) {
      return true;
    }

    return false;
  }

  /**
   * Validates endpoint URL according to strict endpoint and consent rules (A3).
   */
  public static validateEndpoint(urlString: string): URL {
    return HttpClient.validateEndpointUrl(urlString);
  }

  public static validateEndpointUrl(urlString: string): URL {
    let url: URL;
    try {
      url = new URL(urlString);
    } catch {
      throw new AiError(`Invalid endpoint URL '${urlString}': malformed URL.`, 'CONFIG_ERROR');
    }

    // Reject non-http(s) schemes
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new AiError(
        `Invalid scheme '${url.protocol}' in endpoint URL '${urlString}'. Only http: and https: are permitted.`,
        'CONFIG_ERROR'
      );
    }

    // Reject embedded credentials
    if (url.username || url.password) {
      throw new AiError(
        `Security violation: embedded credentials in endpoint URL '${urlString}' are strictly prohibited.`,
        'CONFIG_ERROR'
      );
    }

    // Reject fragments
    if (url.hash) {
      throw new AiError(
        `URL fragments ('${url.hash}') are prohibited in endpoint URL '${urlString}'.`,
        'CONFIG_ERROR'
      );
    }

    // HTTPS is required for non-loopback hosts
    const isLoopback = HttpClient.isLoopbackHost(url.hostname);
    if (!isLoopback && url.protocol !== 'https:') {
      throw new AiError(
        `Insecure endpoint '${urlString}': HTTPS is strictly required for non-loopback hosts.`,
        'CONFIG_ERROR'
      );
    }

    return url;
  }

  /**
   * Performs an HTTP request with hardened security constraints:
   * - redirect: 'error' (never follow redirects)
   * - 1 MB response size limit
   * - Concurrency throttled (max 2 concurrent requests)
   * - Global backoff on 429
   * - AbortSignal support
   */
  public static async request(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse> {
    const validatedUrl = HttpClient.validateEndpointUrl(url);

    // Acquire concurrency slot
    await HttpClient.acquireSlot(options.signal);

    try {
      // Check global rate limit backoff
      const now = Date.now();
      if (HttpClient.globalBackoffUntil > now) {
        const delay = HttpClient.globalBackoffUntil - now;
        await HttpClient.sleep(delay, options.signal);
      }

      return await HttpClient.executeFetch(validatedUrl.toString(), options);
    } finally {
      HttpClient.releaseSlot();
    }
  }

  private static async executeFetch(
    url: string,
    options: HttpRequestOptions
  ): Promise<HttpResponse> {
    const timeoutMs = options.timeoutMs ?? HttpClient.DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();

    let timeoutId: NodeJS.Timeout | null = null;
    if (timeoutMs > 0) {
      timeoutId = setTimeout(() => {
        controller.abort(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    }

    // Chain caller's AbortSignal if provided
    let abortListener: (() => void) | null = null;
    if (options.signal) {
      if (options.signal.aborted) {
        if (timeoutId) clearTimeout(timeoutId);
        throw new AiError('Operation aborted by user', 'ABORTED');
      }
      abortListener = () => {
        controller.abort(new Error('Operation aborted by user'));
      };
      options.signal.addEventListener('abort', abortListener, { once: true });
    }

    try {
      const response = await fetch(url, {
        method: options.method || 'GET',
        headers: options.headers,
        body: options.body,
        redirect: 'error',
        signal: controller.signal,
      });

      // Check Content-Length cap if provided
      const contentLengthHeader = response.headers.get('content-length');
      if (contentLengthHeader) {
        const length = parseInt(contentLengthHeader, 10);
        if (!isNaN(length) && length > HttpClient.MAX_RESPONSE_SIZE) {
          throw new AiError(
            `Response size (${length} bytes) exceeds maximum allowable limit of ${HttpClient.MAX_RESPONSE_SIZE} bytes.`,
            'TOO_LARGE',
            response.status
          );
        }
      }

      // Read text with size monitoring
      const responseText = await response.text();
      if (Buffer.byteLength(responseText, 'utf8') > HttpClient.MAX_RESPONSE_SIZE) {
        throw new AiError(
          `Response payload exceeds maximum allowable limit of ${HttpClient.MAX_RESPONSE_SIZE} bytes.`,
          'TOO_LARGE',
          response.status
        );
      }

      // Handle HTTP status codes
      if (!response.ok) {
        let retryAfterMs: number | undefined;
        if (response.status === 429) {
          const retryAfterHeader = response.headers.get('retry-after');
          if (retryAfterHeader) {
            const parsedSeconds = parseInt(retryAfterHeader, 10);
            if (!isNaN(parsedSeconds)) {
              retryAfterMs = parsedSeconds * 1000;
            }
          }
          // Default 429 backoff: 2000 ms if header missing
          retryAfterMs = retryAfterMs ?? 2000;
          HttpClient.globalBackoffUntil = Date.now() + retryAfterMs;
        }

        let errorCode: import('./provider.interface.js').AiErrorCode = 'SERVER';
        if (response.status === 401 || response.status === 403) {
          errorCode = 'AUTH';
        } else if (response.status === 429) {
          errorCode = 'RATE_LIMIT';
        } else if (response.status === 400 || response.status === 422) {
          errorCode = 'MALFORMED';
        }

        throw new AiError(
          `Provider request failed with HTTP ${response.status}: ${responseText.slice(0, 300)}`,
          errorCode,
          response.status,
          retryAfterMs
        );
      }

      return {
        status: response.status,
        headers: response.headers,
        text: responseText,
      };
    } catch (err: unknown) {
      if (err instanceof AiError) {
        throw err;
      }
      if (controller.signal.aborted) {
        const reason = controller.signal.reason;
        const msg = reason instanceof Error ? reason.message : String(reason);
        if (msg.includes('timed out')) {
          throw new AiError(msg, 'TIMEOUT');
        }
        throw new AiError(msg || 'Request aborted', 'ABORTED');
      }
      const msg = err instanceof Error ? err.message : String(err);
      throw new AiError(`Network communication failure: ${msg}`, 'NETWORK');
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      if (options.signal && abortListener) {
        options.signal.removeEventListener('abort', abortListener);
      }
    }
  }

  private static async acquireSlot(signal?: AbortSignal): Promise<void> {
    if (HttpClient.activeRequests < HttpClient.maxConcurrency) {
      HttpClient.activeRequests++;
      return;
    }

    return new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        const idx = HttpClient.waitQueue.indexOf(proceed);
        if (idx !== -1) HttpClient.waitQueue.splice(idx, 1);
        reject(new AiError('Request aborted while waiting in queue', 'ABORTED'));
      };

      const proceed = () => {
        if (signal) signal.removeEventListener('abort', onAbort);
        HttpClient.activeRequests++;
        resolve();
      };

      if (signal) {
        if (signal.aborted) {
          return reject(new AiError('Request aborted before slot acquisition', 'ABORTED'));
        }
        signal.addEventListener('abort', onAbort, { once: true });
      }

      HttpClient.waitQueue.push(proceed);
    });
  }

  private static releaseSlot(): void {
    HttpClient.activeRequests = Math.max(0, HttpClient.activeRequests - 1);
    const next = HttpClient.waitQueue.shift();
    if (next) {
      next();
    }
  }

  private static sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, ms);
      if (signal) {
        signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(new AiError('Aborted during rate limit backoff', 'ABORTED'));
          },
          { once: true }
        );
      }
    });
  }
}
