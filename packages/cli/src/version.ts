/**
 * CLI Version definition.
 * In production bundle (tsup), __CLI_VERSION__ is replaced at compile-time with package.json version.
 * In test/dev environments, falls back to static package version.
 */
declare const __CLI_VERSION__: string | undefined;

export const CLI_VERSION: string =
  typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '1.0.0-beta.1';
