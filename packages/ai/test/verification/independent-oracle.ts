import http from 'node:http';
import https from 'node:https';
import type { AddressInfo, Socket } from 'node:net';

export interface RecordedRequest {
  method: string;
  url: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  rawBody: string;
  jsonBody?: Record<string, unknown>;
  receivedAt: number;
}

export interface ScriptedResponse {
  statusCode?: number;
  headers?: Record<string, string>;
  body?: string | Record<string, unknown>;
  delayMs?: number;
  slowDrip?: boolean;
  destroySocket?: boolean;
  truncated?: boolean;
}

export type RequestHandler = (
  req: RecordedRequest,
  res: http.ServerResponse
) => ScriptedResponse | void | Promise<ScriptedResponse | void>;

export class FakeLlmHttpServer {
  private server: http.Server | https.Server;
  private sockets = new Set<Socket>();
  public recordedRequests: RecordedRequest[] = [];
  private handlers: RequestHandler[] = [];
  private defaultResponse: ScriptedResponse = {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: { ok: true },
  };

  constructor(options?: { httpsOptions?: https.ServerOptions }) {
    const requestListener: http.RequestListener = (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      req.on('end', async () => {
        const rawBody = Buffer.concat(chunks).toString('utf-8');
        let jsonBody: Record<string, unknown> | undefined;
        try {
          if (rawBody.trim().startsWith('{') || rawBody.trim().startsWith('[')) {
            jsonBody = JSON.parse(rawBody);
          }
        } catch {}

        const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
        const recorded: RecordedRequest = {
          method: req.method || 'GET',
          url: req.url || '/',
          path: parsedUrl.pathname,
          headers: req.headers,
          rawBody,
          jsonBody,
          receivedAt: Date.now(),
        };
        this.recordedRequests.push(recorded);

        let scripted: ScriptedResponse | undefined;
        for (const handler of this.handlers) {
          const result = await handler(recorded, res);
          if (result) {
            scripted = result;
            break;
          }
        }

        const resp: ScriptedResponse = scripted ?? this.defaultResponse;

        if (resp.destroySocket) {
          req.socket.destroy();
          return;
        }

        if (resp.delayMs && resp.delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, resp.delayMs));
        }

        const statusCode = resp.statusCode || 200;
        const headers = resp.headers || { 'Content-Type': 'application/json' };

        if (resp.slowDrip) {
          res.writeHead(statusCode, headers);
          const fullBody =
            typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body ?? {});
          const half = Math.floor(fullBody.length / 2);
          res.write(fullBody.slice(0, half));
          setTimeout(() => {
            res.end(fullBody.slice(half));
          }, 300);
          return;
        }

        if (resp.truncated) {
          // Set Content-Length larger than sent body
          const partial = '{"status":"incomplete"';
          res.writeHead(statusCode, {
            ...headers,
            'Content-Length': '500',
          });
          res.end(partial);
          return;
        }

        res.writeHead(statusCode, headers);
        const payload = typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body ?? {});
        res.end(payload);
      });
    };

    if (options?.httpsOptions) {
      this.server = https.createServer(options.httpsOptions, requestListener);
    } else {
      this.server = http.createServer(requestListener);
    }

    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
    });
  }

  public async start(host: string = '127.0.0.1'): Promise<string> {
    return new Promise((resolve, reject) => {
      this.server.listen(0, host, () => {
        const addr = this.server.address() as AddressInfo;
        const protocol = this.server instanceof https.Server ? 'https' : 'http';
        resolve(`${protocol}://${host}:${addr.port}`);
      });
      this.server.on('error', reject);
    });
  }

  public get port(): number {
    const addr = this.server.address() as AddressInfo;
    return addr?.port || 0;
  }

  public get baseUrl(): string {
    const protocol = this.server instanceof https.Server ? 'https' : 'http';
    return `${protocol}://127.0.0.1:${this.port}`;
  }

  public setDefaultResponse(resp: ScriptedResponse): void {
    this.defaultResponse = resp;
  }

  public addHandler(handler: RequestHandler): void {
    this.handlers.unshift(handler);
  }

  public clearHandlers(): void {
    this.handlers = [];
  }

  public clearRequests(): void {
    this.recordedRequests = [];
  }

  public async stop(): Promise<void> {
    for (const socket of this.sockets) {
      try {
        socket.destroy();
      } catch {}
    }
    this.sockets.clear();
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }

  public static makeAnthropicResponse(
    content: string | Record<string, unknown>,
    usage = { input_tokens: 100, output_tokens: 50 }
  ): Record<string, unknown> {
    const text = typeof content === 'string' ? content : JSON.stringify(content);
    return {
      id: `msg_oracle_${Math.random().toString(36).slice(2)}`,
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text }],
      model: 'claude-test',
      usage,
    };
  }

  public static makeOpenAiResponse(
    content: string | Record<string, unknown>,
    usage = { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 }
  ): Record<string, unknown> {
    const text = typeof content === 'string' ? content : JSON.stringify(content);
    return {
      id: `chatcmpl_oracle_${Math.random().toString(36).slice(2)}`,
      object: 'chat.completion',
      choices: [
        {
          index: 0,
          message: { role: 'assistant', content: text },
          finish_reason: 'stop',
        },
      ],
      usage,
    };
  }
}
