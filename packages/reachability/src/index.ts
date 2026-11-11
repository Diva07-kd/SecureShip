export * from './manifest/wasm-manifest.js';
export * from './parsers/tree-sitter-loader.js';
export * from './cache/external-cache.js';
export * from './js/js-import-extractor.js';
export * from './js/js-module-resolver.js';
export * from './js/tsconfig-resolver.js';
export * from './python/python-import-extractor.js';
export * from './python/python-module-resolver.js';
export * from './python/package-map.js';
export * from './entrypoints/entrypoint-detector.js';
export * from './reference/reference-scanner.js';
export * from './lockfile/lockfile-tree-parser.js';
export * from './graph/import-graph.js';
export * from './sca/sca-reachability-analyzer.js';
export * from './sast/sast-reachability-analyzer.js';
export * from './capabilities/index.js';
export * from './reachability-engine.js';
export type {
  ExtractionResult,
  ResolvedModule,
  ILanguageAdapter,
} from './adapters/language-adapter.interface.js';
export * from './adapters/adapter-registry.js';
export * from './adapters/go-adapter.js';
export * from './adapters/java-adapter.js';
export * from './adapters/rust-adapter.js';
export * from './adapters/csharp-adapter.js';
export * from './adapters/js-adapter.js';
export * from './adapters/python-adapter.js';
export * from './taint/taint-catalog.js';
export * from './taint/call-graph-extractor.js';
export * from './taint/taint-engine.js';
export * from './symbols/index.js';
export * from './symbol-usage/index.js';
export * from './standalone-exec.js';
