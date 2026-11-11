import pc from 'picocolors';
import readline from 'node:readline';
import {
  AnthropicProvider,
  ConsentManager,
  HttpClient,
  OpenAiProvider,
  UserConfigLoader,
  type UserConfig,
} from '@secureship/ai';

export interface AiEnableOptions {
  provider?: string;
  model?: string;
  baseUrl?: string;
  gate3?: 'off' | 'annotate' | 'suppress';
  yes?: boolean;
}

export class AiCommand {
  public static async enable(options: AiEnableOptions): Promise<number> {
    const isInteractive = Boolean(process.stdin.isTTY && !options.yes);

    let provider = options.provider;
    let model = options.model;
    let baseUrl = options.baseUrl;
    const gate3 = options.gate3 ?? 'annotate';

    if (!isInteractive) {
      if (!options.yes) {
        console.error(
          pc.red(
            'Error: Non-interactive `ai enable` requires explicit --provider, --model, --base-url and --yes to avoid hanging in CI.'
          )
        );
        return 2;
      }
      if (!provider || !model) {
        console.error(
          pc.red('Error: Both --provider and --model are required for non-interactive `ai enable`.')
        );
        return 2;
      }
    } else {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      const question = (query: string): Promise<string> =>
        new Promise((resolve) => rl.question(query, resolve));

      try {
        if (!provider) {
          const ans = await question(
            `Select LLM provider (${pc.cyan('openai')} / ${pc.cyan('anthropic')}): `
          );
          provider = ans.trim() || 'openai';
        }
        if (!model) {
          const ans = await question(`Model name (required, e.g. gpt-4o or claude-3-5-sonnet): `);
          model = ans.trim();
        }
        if (!baseUrl) {
          const defaultBase =
            provider === 'anthropic' ? 'https://api.anthropic.com/v1' : 'https://api.openai.com/v1';
          const ans = await question(`Base URL [${defaultBase}]: `);
          baseUrl = ans.trim() || defaultBase;
        }
      } finally {
        rl.close();
      }
    }

    if (!provider || !['openai', 'anthropic', 'fake'].includes(provider)) {
      console.error(pc.red(`Error: Invalid provider "${provider}". Allowed: openai, anthropic.`));
      return 2;
    }

    if (!model) {
      console.error(pc.red('Error: Model name is required (no default).'));
      return 2;
    }

    const defaultBase =
      provider === 'anthropic' ? 'https://api.anthropic.com/v1' : 'https://api.openai.com/v1';
    const effectiveBaseUrl = baseUrl || defaultBase;

    // Validate endpoint format, scheme, loopback per A3
    try {
      HttpClient.validateEndpoint(effectiveBaseUrl);
    } catch (err: unknown) {
      console.error(
        pc.red(`Endpoint validation failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 2;
    }

    // Consent binding (A3)
    const consent = ConsentManager.recordConsent(effectiveBaseUrl, model);

    // Save user configuration (A1)
    const existing = UserConfigLoader.loadUserConfig();
    const updated: UserConfig = {
      ...existing,
      ai: true,
      provider: provider as 'anthropic' | 'openai' | 'fake',
      model,
      baseUrl: effectiveBaseUrl,
      gate3: {
        mode: gate3,
        neverSuppressSeverities: existing.gate3?.neverSuppressSeverities ?? ['CRITICAL', 'HIGH'],
        minConfidence: existing.gate3?.minConfidence ?? 'HIGH',
        consistencyChecks: existing.gate3?.consistencyChecks ?? 2,
        sliceTokens: existing.gate3?.sliceTokens ?? 6000,
        budgetTokens: existing.gate3?.budgetTokens ?? 100000,
        maxFindings: existing.gate3?.maxFindings ?? 10,
        concurrency: existing.gate3?.concurrency ?? 2,
      },
    };
    UserConfigLoader.saveUserConfig(updated);

    console.log(pc.green('\n✔ Gate 3 AI Triage successfully enabled!'));
    console.log(`  • Provider  : ${pc.bold(provider)}`);
    console.log(`  • Model     : ${pc.bold(model)}`);
    console.log(`  • Base URL  : ${pc.bold(effectiveBaseUrl)}`);
    console.log(`  • Gate 3    : ${pc.bold(gate3)}`);
    console.log(`  • Consent   : ${pc.green(`Bound to ${consent.boundOrigin}`)}`);
    console.log(
      pc.gray(
        '\nNote: API keys are read from environment variables (ANTHROPIC_API_KEY / OPENAI_API_KEY) and never stored.'
      )
    );
    return 0;
  }

  public static async disable(): Promise<number> {
    const existing = UserConfigLoader.loadUserConfig();
    UserConfigLoader.saveUserConfig({
      ...existing,
      ai: false,
    });
    console.log(pc.yellow('\n○ Gate 3 AI Triage has been disabled.'));
    return 0;
  }

  public static async status(): Promise<number> {
    const config = UserConfigLoader.loadUserConfig();
    console.log(pc.bold(pc.cyan('\n🤖 SecureShip Gate 3 AI Status\n')));
    console.log(`  • AI Enabled     : ${config.ai ? pc.green('Yes') : pc.yellow('No')}`);
    console.log(`  • Provider       : ${pc.cyan(config.provider ?? '(not set)')}`);
    console.log(`  • Model          : ${pc.cyan(config.model ?? '(not set)')}`);
    console.log(`  • Base URL       : ${pc.cyan(config.baseUrl ?? '(not set)')}`);
    console.log(`  • Gate 3 Mode    : ${pc.cyan(config.gate3?.mode ?? 'annotate')}`);

    if (config.baseUrl) {
      const consent = ConsentManager.checkConsent(config.baseUrl);
      if (consent.consented) {
        console.log(`  • Consent Status : ${pc.green(`Valid (bound to ${consent.boundOrigin})`)}`);
      } else {
        console.log(`  • Consent Status : ${pc.red(`Missing or mismatched (${consent.reason})`)}`);
      }
    }

    const hasKey = Boolean(
      process.env.ANTHROPIC_API_KEY ||
        process.env.OPENAI_API_KEY ||
        process.env.SECURESHIP_AI_API_KEY
    );
    console.log(`  • API Key Present: ${hasKey ? pc.green('Yes (via env)') : pc.yellow('No')}`);
    console.log();
    return 0;
  }

  public static async test(): Promise<number> {
    const config = UserConfigLoader.loadUserConfig();
    const providerName = config.provider || 'openai';
    const model = config.model;

    if (!model) {
      console.error(pc.red('Error: AI model is not configured. Run `secureship ai enable` first.'));
      return 1;
    }

    const defaultBase =
      providerName === 'anthropic' ? 'https://api.anthropic.com/v1' : 'https://api.openai.com/v1';
    const baseUrl = config.baseUrl || defaultBase;

    try {
      HttpClient.validateEndpoint(baseUrl);
    } catch (err: unknown) {
      console.error(
        pc.red(`Endpoint validation failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }

    const consent = ConsentManager.checkConsent(baseUrl);
    if (!consent.consented) {
      console.error(
        pc.red(
          `Consent missing for endpoint '${baseUrl}': ${consent.reason}. Run \`secureship ai enable\` first.`
        )
      );
      return 1;
    }

    const apiKey =
      providerName === 'anthropic'
        ? process.env.ANTHROPIC_API_KEY || process.env.SECURESHIP_AI_API_KEY
        : process.env.OPENAI_API_KEY || process.env.SECURESHIP_AI_API_KEY;

    const provider = providerName === 'anthropic' ? new AnthropicProvider() : new OpenAiProvider();

    console.log(pc.cyan(`Testing connection to ${providerName} (${baseUrl})...`));
    const startTime = Date.now();
    try {
      await provider.sendTriageRequest({
        model,
        baseUrl,
        apiKey,
        systemPrompt: 'You are a test connection assistant.',
        userPrompt: 'ping',
        maxTokens: 10,
        temperature: 0,
      });
      const latency = Date.now() - startTime;
      console.log(pc.green(`✔ Ping successful (${latency}ms)!`));
      console.log(`  • Provider : ${pc.bold(providerName)}`);
      console.log(`  • Model    : ${pc.bold(model)}`);
      console.log(`  • Endpoint : ${pc.bold(baseUrl)}`);
      console.log(`  • Latency  : ${pc.bold(`${latency}ms`)}`);
      return 0;
    } catch (err: unknown) {
      const latency = Date.now() - startTime;
      let rawMsg = err instanceof Error ? err.message : String(err);
      if (apiKey) {
        rawMsg = rawMsg.replace(new RegExp(apiKey, 'g'), '[REDACTED_KEY]');
      }
      console.error(pc.red(`✖ Connection test failed (${latency}ms): ${rawMsg}`));
      return 1;
    }
  }
}
