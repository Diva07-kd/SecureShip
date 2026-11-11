export interface SandboxRunOptions {
  workdir?: string;
  stageName?: string;
  timeoutMs?: number;
  network?: boolean;
  env?: Record<string, string>;
  outputCapBytes?: number;
}

export interface SandboxRunResult {
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  stdout: string;
  stderr: string;
  outputSha256: string;
  outputTail: string;
  command: string;
  argv: string[];
}

export interface ISandboxBackend {
  readonly name: 'container' | 'host' | 'fake' | 'none' | 'native-isolated';
  run(command: string, args: string[], options?: SandboxRunOptions): Promise<SandboxRunResult>;
  cleanup(): Promise<void>;
  isAvailable(): Promise<boolean>;
  getMetadata(): {
    backend: 'container' | 'host' | 'none' | 'native-isolated';
    runtime?: string;
    runtimeVersion?: string;
    imageDigest?: string;
    isolation?: string;
    networkIsolated?: boolean;
  };
}
