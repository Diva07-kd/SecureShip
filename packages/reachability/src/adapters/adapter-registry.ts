import type { SupportedLanguage } from '../parsers/tree-sitter-loader.js';
import type { ILanguageAdapter } from './language-adapter.interface.js';
import { JsLanguageAdapter } from './js-adapter.js';
import { PythonLanguageAdapter } from './python-adapter.js';
import { GoLanguageAdapter } from './go-adapter.js';
import { JavaLanguageAdapter } from './java-adapter.js';
import { RustLanguageAdapter } from './rust-adapter.js';
import { CsharpLanguageAdapter } from './csharp-adapter.js';

export class AdapterRegistry {
  private static adapters: Map<SupportedLanguage, ILanguageAdapter> = new Map();

  static {
    // Register default production adapters
    AdapterRegistry.registerAdapter(new JsLanguageAdapter('javascript'));
    AdapterRegistry.registerAdapter(new JsLanguageAdapter('typescript'));
    AdapterRegistry.registerAdapter(new JsLanguageAdapter('tsx'));
    AdapterRegistry.registerAdapter(new PythonLanguageAdapter());
    AdapterRegistry.registerAdapter(new GoLanguageAdapter());
    AdapterRegistry.registerAdapter(new JavaLanguageAdapter());
    AdapterRegistry.registerAdapter(new RustLanguageAdapter());
    AdapterRegistry.registerAdapter(new CsharpLanguageAdapter());
  }

  /**
   * Registers a language adapter for a specific language.
   */
  public static registerAdapter(adapter: ILanguageAdapter): void {
    AdapterRegistry.adapters.set(adapter.language, adapter);
  }

  /**
   * Gets the adapter registered for the given language.
   */
  public static getAdapter(language: SupportedLanguage): ILanguageAdapter {
    const adapter = AdapterRegistry.adapters.get(language);
    if (!adapter) {
      throw new Error(`No language adapter registered for language: '${language}'`);
    }
    return adapter;
  }

  /**
   * Checks whether an adapter is registered for a given language.
   */
  public static hasAdapter(language: SupportedLanguage): boolean {
    return AdapterRegistry.adapters.has(language);
  }

  /**
   * Returns list of all languages supported by registered adapters.
   */
  public static getSupportedLanguages(): SupportedLanguage[] {
    return Array.from(AdapterRegistry.adapters.keys());
  }
}
