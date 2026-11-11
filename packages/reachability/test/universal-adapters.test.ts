import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  TreeSitterLoader,
  AdapterRegistry,
  GoLanguageAdapter,
  JavaLanguageAdapter,
  RustLanguageAdapter,
  CsharpLanguageAdapter,
  ImportGraph,
  LockfileTreeParser,
  type SupportedLanguage,
} from '../src/index.js';

describe('Universal Language Adapters & Multi-Language Graph Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('AdapterRegistry', () => {
    it('registers all 8 standard production languages', () => {
      const langs = AdapterRegistry.getSupportedLanguages();
      expect(langs).toContain('javascript');
      expect(langs).toContain('typescript');
      expect(langs).toContain('tsx');
      expect(langs).toContain('python');
      expect(langs).toContain('go');
      expect(langs).toContain('java');
      expect(langs).toContain('rust');
      expect(langs).toContain('c_sharp');
    });

    it('retrieves the proper adapter instance for each language', () => {
      expect(AdapterRegistry.getAdapter('go')).toBeInstanceOf(GoLanguageAdapter);
      expect(AdapterRegistry.getAdapter('java')).toBeInstanceOf(JavaLanguageAdapter);
      expect(AdapterRegistry.getAdapter('rust')).toBeInstanceOf(RustLanguageAdapter);
      expect(AdapterRegistry.getAdapter('c_sharp')).toBeInstanceOf(CsharpLanguageAdapter);
    });

    it('throws meaningful error when requesting unregistered language', () => {
      expect(() => AdapterRegistry.getAdapter('ruby' as unknown as SupportedLanguage)).toThrow(
        "No language adapter registered for language: 'ruby'"
      );
    });
  });

  describe('GoLanguageAdapter', () => {
    const adapter = new GoLanguageAdapter();

    it('extracts package declaration and imports accurately via Tree-sitter WASM', () => {
      const code = `
package main

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/ping", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": "pong"})
    })
    r.Run()
}
`;
      const parseRes = TreeSitterLoader.parseFile(code, 'go');
      expect(parseRes.hasError).toBe(false);
      expect(parseRes.tree).not.toBeNull();

      const ext = adapter.extract(parseRes.tree!.rootNode);
      expect(ext.packageDeclaration).toBe('main');
      expect(ext.imports.map((i) => i.specifier)).toEqual([
        'fmt',
        'net/http',
        'github.com/gin-gonic/gin',
      ]);
    });

    it('resolves Go standard library and third-party modules correctly', () => {
      const tmp = os.tmpdir();
      const stdRes = adapter.resolve('fmt', path.join(tmp, 'main.go'), tmp);
      expect(stdRes).toEqual({ type: 'STANDARD_LIB', name: 'fmt' });

      const netRes = adapter.resolve('net/http', path.join(tmp, 'main.go'), tmp);
      expect(netRes).toEqual({ type: 'STANDARD_LIB', name: 'net/http' });

      const pkgRes = adapter.resolve('github.com/gin-gonic/gin', path.join(tmp, 'main.go'), tmp);
      expect(pkgRes).toEqual({
        type: 'PACKAGE',
        packageName: 'github.com/gin-gonic/gin',
      });
    });
  });

  describe('JavaLanguageAdapter', () => {
    const adapter = new JavaLanguageAdapter();

    it('extracts package declaration and imports accurately via Tree-sitter WASM', () => {
      const code = `
package com.secureship.engine;

import java.io.InputStream;
import java.util.Collections;
import org.springframework.boot.SpringApplication;
import org.springframework.web.bind.annotation.RestController;

public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
`;
      const parseRes = TreeSitterLoader.parseFile(code, 'java');
      expect(parseRes.hasError).toBe(false);
      expect(parseRes.tree).not.toBeNull();

      const ext = adapter.extract(parseRes.tree!.rootNode);
      expect(ext.packageDeclaration).toBe('com.secureship.engine');
      expect(ext.imports.map((i) => i.specifier)).toEqual([
        'java.io.InputStream',
        'java.util.Collections',
        'org.springframework.boot.SpringApplication',
        'org.springframework.web.bind.annotation.RestController',
      ]);
    });

    it('resolves Java standard library and external packages correctly', () => {
      const tmp = os.tmpdir();
      const stdRes = adapter.resolve('java.util.Collections', path.join(tmp, 'App.java'), tmp);
      expect(stdRes).toEqual({ type: 'STANDARD_LIB', name: 'java.util.Collections' });

      const pkgRes = adapter.resolve(
        'org.springframework.boot.SpringApplication',
        path.join(tmp, 'App.java'),
        tmp
      );
      expect(pkgRes).toEqual({
        type: 'PACKAGE',
        packageName: 'org.springframework',
      });
    });
  });

  describe('RustLanguageAdapter', () => {
    const adapter = new RustLanguageAdapter();

    it('extracts use declarations and extern crates accurately via Tree-sitter WASM', () => {
      const code = `
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tokio::net::TcpListener;
extern crate alloc;

fn main() {
    let mut map = HashMap::new();
    map.insert("key", "val");
}
`;
      const parseRes = TreeSitterLoader.parseFile(code, 'rust');
      expect(parseRes.hasError).toBe(false);
      expect(parseRes.tree).not.toBeNull();

      const ext = adapter.extract(parseRes.tree!.rootNode);
      const specifiers = ext.imports.map((i) => i.specifier);
      expect(specifiers).toContain('std::collections::HashMap');
      expect(specifiers).toContain('std::sync::Arc');
      expect(specifiers).toContain('tokio::net::TcpListener');
      expect(specifiers).toContain('alloc');
    });

    it('resolves Rust standard library and external crates correctly', () => {
      const tmp = os.tmpdir();
      const stdRes = adapter.resolve('std::collections::HashMap', path.join(tmp, 'main.rs'), tmp);
      expect(stdRes).toEqual({ type: 'STANDARD_LIB', name: 'std::collections::HashMap' });

      const crateRes = adapter.resolve('tokio::net::TcpListener', path.join(tmp, 'main.rs'), tmp);
      expect(crateRes).toEqual({
        type: 'PACKAGE',
        packageName: 'tokio',
      });
    });
  });

  describe('CsharpLanguageAdapter', () => {
    const adapter = new CsharpLanguageAdapter();

    it('extracts using directives and namespace accurately via Tree-sitter WASM', () => {
      const code = `
using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace SecureShip.Api
{
    public class Controller
    {
    }
}
`;
      const parseRes = TreeSitterLoader.parseFile(code, 'c_sharp');
      expect(parseRes.hasError).toBe(false);
      expect(parseRes.tree).not.toBeNull();

      const ext = adapter.extract(parseRes.tree!.rootNode);
      expect(ext.packageDeclaration).toBe('SecureShip.Api');
      const specs = ext.imports.map((i) => i.specifier);
      expect(specs).toContain('System');
      expect(specs).toContain('System.Collections.Generic');
      expect(specs).toContain('Microsoft.AspNetCore.Mvc');
      expect(specs).toContain('Newtonsoft.Json');
    });

    it('resolves .NET BCL and NuGet packages correctly', () => {
      const tmp = os.tmpdir();
      const bclRes = adapter.resolve('System.Collections.Generic', path.join(tmp, 'App.cs'), tmp);
      expect(bclRes).toEqual({ type: 'STANDARD_LIB', name: 'System.Collections.Generic' });

      const msRes = adapter.resolve('Microsoft.AspNetCore.Mvc', path.join(tmp, 'App.cs'), tmp);
      expect(msRes).toEqual({ type: 'STANDARD_LIB', name: 'Microsoft.AspNetCore.Mvc' });

      const nugetRes = adapter.resolve('Newtonsoft.Json', path.join(tmp, 'App.cs'), tmp);
      expect(nugetRes).toEqual({
        type: 'PACKAGE',
        packageName: 'Newtonsoft.Json',
      });
    });
  });

  describe('Multi-Language ImportGraph & Reachability', () => {
    it('constructs whole-repository import graph across multi-language files', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-multilang-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        // Create Go entrypoint
        fs.writeFileSync(
          path.join(testDir, 'main.go'),
          `package main\nimport "fmt"\nimport "github.com/gin-gonic/gin"\nfunc main() { fmt.Println("Go Reachable") }\n`
        );

        // Create Rust file
        fs.mkdirSync(path.join(testDir, 'src'), { recursive: true });
        fs.writeFileSync(
          path.join(testDir, 'src', 'main.rs'),
          `use std::io;\nuse serde::Deserialize;\nfn main() { println!("Rust Reachable"); }\n`
        );

        // Create C# file
        fs.writeFileSync(
          path.join(testDir, 'Program.cs'),
          `using System;\nusing Newtonsoft.Json;\nclass Program { static void Main() {} }\n`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });
        const stats = graph.toJSON();

        expect(stats.totalFiles).toBeGreaterThanOrEqual(3);
        expect(stats.hasAnyParseErrorInProduction).toBe(false);

        // All 3 entrypoints should be discovered
        expect(stats.entrypoints).toContain('main.go');
        expect(stats.entrypoints).toContain('src/main.rs');
        expect(stats.entrypoints).toContain('Program.cs');

        // Check package dependencies recorded
        const goNode = Array.from(graph.files.values()).find((f) => f.relativePath === 'main.go');
        expect(goNode).toBeDefined();
        expect(goNode!.isReachable).toBe(true);
        expect(goNode!.packageDependencies.has('github.com/gin-gonic/gin')).toBe(true);

        const rustNode = Array.from(graph.files.values()).find(
          (f) => f.relativePath === 'src/main.rs'
        );
        expect(rustNode).toBeDefined();
        expect(rustNode!.isReachable).toBe(true);
        expect(rustNode!.packageDependencies.has('serde')).toBe(true);

        const csNode = Array.from(graph.files.values()).find(
          (f) => f.relativePath === 'Program.cs'
        );
        expect(csNode).toBeDefined();
        expect(csNode!.isReachable).toBe(true);
        expect(csNode!.packageDependencies.has('Newtonsoft.Json')).toBe(true);
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });

  describe('Multi-Language Lockfile Tree Parsing', () => {
    it('parses go.mod dependencies and identifies direct vs indirect', () => {
      const testDir = path.join(os.tmpdir(), `secureship-gomod-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        fs.writeFileSync(
          path.join(testDir, 'go.mod'),
          `module myapp\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/stretchr/testify v1.8.4 // indirect\n)\n`
        );

        const res = LockfileTreeParser.parse(testDir);
        expect(res.success).toBe(true);
        if (res.success) {
          expect(res.graph.format).toBe('GO_MOD');
          expect(res.graph.directProdDependencies.has('github.com/gin-gonic/gin')).toBe(true);
          expect(res.graph.directProdDependencies.has('github.com/stretchr/testify')).toBe(false);

          const ginNode = res.graph.nodes.get('github.com/gin-gonic/gin');
          expect(ginNode).toBeDefined();
          expect(ginNode!.isDirect).toBe(true);
          expect(ginNode!.version).toBe('v1.9.1');

          const testNode = res.graph.nodes.get('github.com/stretchr/testify');
          expect(testNode).toBeDefined();
          expect(testNode!.isDirect).toBe(false);
        }
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });

    it('parses Cargo.lock and resolves crate dependencies', () => {
      const testDir = path.join(os.tmpdir(), `secureship-cargo-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        fs.writeFileSync(
          path.join(testDir, 'Cargo.toml'),
          `[package]\nname = "myapp"\nversion = "0.1.0"\n\n[dependencies]\ntokio = "1.36.0"\n`
        );
        fs.writeFileSync(
          path.join(testDir, 'Cargo.lock'),
          `version = 3\n\n[[package]]\nname = "tokio"\nversion = "1.36.0"\ndependencies = [\n "bytes",\n]\n\n[[package]]\nname = "bytes"\nversion = "1.5.0"\n`
        );

        const res = LockfileTreeParser.parse(testDir);
        expect(res.success).toBe(true);
        if (res.success) {
          expect(res.graph.format).toBe('CARGO_LOCK');
          expect(res.graph.directProdDependencies.has('tokio')).toBe(true);
          expect(res.graph.directProdDependencies.has('bytes')).toBe(false);

          const tokioNode = res.graph.nodes.get('tokio');
          expect(tokioNode).toBeDefined();
          expect(tokioNode!.dependencies).toContain('bytes');

          // Trace transitive via
          const trace = LockfileTreeParser.traceTransitiveVia(
            res.graph,
            'bytes',
            new Set(['tokio'])
          );
          expect(trace.isTransitiveVia).toBe(true);
          expect(trace.viaChain).toEqual(['tokio', 'bytes']);
        }
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });
});
