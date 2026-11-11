import { describe, it, expect, beforeAll } from 'vitest';
import {
  TreeSitterLoader,
  JsSymbolUsageExtractor,
  PythonSymbolUsageExtractor,
} from '../src/index.js';

describe('Phase B Fuzz and Metamorphic Suite (500 Projects)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  interface GeneratedProject {
    index: number;
    language: 'javascript' | 'python';
    code: string;
    alias: string;
    groundTruthUsed: boolean;
    usageForm: string;
  }

  function generateProject(seed: number): GeneratedProject {
    const isJs = seed % 2 === 0;
    const isUsed = (seed * 13 + 7) % 3 !== 0; // ~66% used, 33% uninvoked
    const aliasChoices = isJs ? ['_', 'ld', 'lodashUtil', 'util'] : ['yaml', 'yml', 'yamlLib'];
    const alias = aliasChoices[seed % aliasChoices.length]!;

    if (isJs) {
      if (!isUsed) {
        const safeForms = [
          `import ${alias} from 'lodash';\nexport function calc() { return ${alias}.isEqual(1, 1); }\ncalc();`,
          `import ${alias} from 'lodash';\nexport function fn() { return ${alias}.map([1, 2], x => x * 2); }\nfn();`,
          `import ${alias} from 'lodash';\nexport function check() { return ${alias}.filter([1, 2], x => x > 1); }\ncheck();`,
        ];
        return {
          index: seed,
          language: 'javascript',
          code: safeForms[seed % safeForms.length]!,
          alias,
          groundTruthUsed: false,
          usageForm: 'SAFE_SYMBOL',
        };
      } else {
        const usedForms = [
          // 1. Direct member call
          {
            form: 'MEMBER_CALL',
            code: `import ${alias} from 'lodash';\nexport function render() { return ${alias}.template('hello')(); }\nrender();`,
          },
          // 2. Named import call
          {
            form: 'NAMED_CALL',
            code: `import { template } from 'lodash';\nexport function render() { return template('world')(); }\nrender();`,
          },
          // 3. Computed literal access
          {
            form: 'COMPUTED_LITERAL',
            code: `import ${alias} from 'lodash';\nexport function render() { return ${alias}['template']('hi')(); }\nrender();`,
          },
          // 4. Aliased member
          {
            form: 'ALIASED_MEMBER',
            code: `import ${alias} from 'lodash';\nconst myTpl = ${alias}.template;\nexport function render() { return myTpl('test')(); }\nrender();`,
          },
          // 5. Destructuring
          {
            form: 'DESTRUCTURE',
            code: `import ${alias} from 'lodash';\nconst { template } = ${alias};\nexport function render() { return template('xyz')(); }\nrender();`,
          },
          // 6. Argument escape
          {
            form: 'ESCAPE_ARG',
            code: `import ${alias} from 'lodash';\nfunction passTo(x) { return x; }\npassTo(${alias});`,
          },
          // 7. Return escape
          {
            form: 'ESCAPE_RETURN',
            code: `import ${alias} from 'lodash';\nexport function getLib() { return ${alias}; }`,
          },
          // 8. Container store escape
          {
            form: 'ESCAPE_CONTAINER',
            code: `import ${alias} from 'lodash';\nconst store = { lib: ${alias} };`,
          },
        ];
        const chosen = usedForms[seed % usedForms.length]!;
        return {
          index: seed,
          language: 'javascript',
          code: chosen.code,
          alias,
          groundTruthUsed: true,
          usageForm: chosen.form,
        };
      }
    } else {
      // Python
      if (!isUsed) {
        const safeForms = [
          `import ${alias}\ndef run():\n    return ${alias}.safe_load("a: 1")\nrun()`,
          `from yaml import safe_load\ndef run():\n    return safe_load("b: 2")\nrun()`,
        ];
        return {
          index: seed,
          language: 'python',
          code: safeForms[seed % safeForms.length]!,
          alias,
          groundTruthUsed: false,
          usageForm: 'SAFE_SYMBOL',
        };
      } else {
        const usedForms = [
          {
            form: 'PY_MEMBER_CALL',
            code: `import ${alias}\ndef run():\n    return ${alias}.load("evil: string")\nrun()`,
          },
          {
            form: 'PY_FROM_CALL',
            code: `from yaml import load\ndef run():\n    return load("evil: data")\nrun()`,
          },
          {
            form: 'PY_WILDCARD_ESCAPE',
            code: `from yaml import *\ndef run():\n    return 1\nrun()`,
          },
          {
            form: 'PY_GETATTR_ESCAPE',
            code: `import ${alias}\ndef run(m):\n    return getattr(${alias}, m)\nrun("load")`,
          },
        ];
        const chosen = usedForms[seed % usedForms.length]!;
        return {
          index: seed,
          language: 'python',
          code: chosen.code,
          alias,
          groundTruthUsed: true,
          usageForm: chosen.form,
        };
      }
    }
  }

  it('generates 500 randomized projects and enforces ZERO false-uninvoked verdicts', () => {
    let falseUninvokedCount = 0;
    let totalEvaluated = 0;
    let usedCount = 0;
    let uninvokedCount = 0;

    for (let seed = 0; seed < 500; seed++) {
      const proj = generateProject(seed);
      totalEvaluated++;

      const { tree } = TreeSitterLoader.parseFile(proj.code, proj.language);
      expect(tree).not.toBeNull();

      if (proj.language === 'javascript') {
        const facts = JsSymbolUsageExtractor.extract(
          tree!.rootNode,
          '/src/index.js',
          'src/index.js'
        );
        const hasTemplateCallOrRef = facts.usageFacts.some(
          (u) => u.symbol.toLowerCase() === 'template'
        );
        const hasEscape = facts.escapes.length > 0;
        const isDetectedUsed = hasTemplateCallOrRef || hasEscape;

        if (proj.groundTruthUsed && !isDetectedUsed) {
          falseUninvokedCount++;
        }
        if (proj.groundTruthUsed) usedCount++;
        else uninvokedCount++;
      } else {
        const facts = PythonSymbolUsageExtractor.extract(
          tree!.rootNode,
          '/app/main.py',
          'app/main.py'
        );
        const hasLoadCallOrRef = facts.usageFacts.some((u) => u.symbol.toLowerCase() === 'load');
        const hasEscape = facts.escapes.length > 0;
        const isDetectedUsed = hasLoadCallOrRef || hasEscape;

        if (proj.groundTruthUsed && !isDetectedUsed) {
          falseUninvokedCount++;
        }
        if (proj.groundTruthUsed) usedCount++;
        else uninvokedCount++;
      }
    }

    expect(totalEvaluated).toBe(500);
    expect(usedCount).toBeGreaterThan(250);
    expect(uninvokedCount).toBeGreaterThan(100);
    expect(falseUninvokedCount).toBe(0); // HARD REQUIREMENT: ZERO FALSE-UNINVOKED
  });

  it('Metamorphic Flipping: injecting any usage form to an uninvoked project flips away from uninvoked', () => {
    // Generate an uninvoked project
    let proj: GeneratedProject | null = null;
    for (let s = 0; s < 100; s++) {
      const p = generateProject(s);
      if (
        !p.groundTruthUsed &&
        p.language === 'javascript' &&
        p.code.includes(`import ${p.alias} from`)
      ) {
        proj = p;
        break;
      }
    }
    expect(proj).not.toBeNull();
    expect(proj!.groundTruthUsed).toBe(false);

    const { tree: beforeTree } = TreeSitterLoader.parseFile(proj!.code, 'javascript');
    const beforeFacts = JsSymbolUsageExtractor.extract(
      beforeTree!.rootNode,
      '/src/index.js',
      'src/index.js'
    );
    expect(beforeFacts.usageFacts.some((u) => u.symbol === 'template')).toBe(false);
    expect(beforeFacts.escapes).toHaveLength(0);

    // Injected usage forms
    const injectedUsageForms = [
      `\n${proj!.alias}.template('injected');`,
      `\nconst t = ${proj!.alias}.template;`,
      `\n${proj!.alias}['template']('injected');`,
      `\nsomeFn(${proj!.alias});`,
      `\nconst copy = { ...${proj!.alias} };`,
    ];

    for (const injected of injectedUsageForms) {
      const flippedCode = proj!.code + injected;
      const { tree: afterTree } = TreeSitterLoader.parseFile(flippedCode, 'javascript');
      const afterFacts = JsSymbolUsageExtractor.extract(
        afterTree!.rootNode,
        '/src/index.js',
        'src/index.js'
      );

      const isUsedNow =
        afterFacts.usageFacts.some((u) => u.symbol === 'template') || afterFacts.escapes.length > 0;

      expect(isUsedNow).toBe(true);
    }
  });

  it('Metamorphic Equivalence: renaming aliases or reordering produces equivalent facts', () => {
    const codeA = `
      import _ from 'lodash';
      _.isEqual(1, 1);
      _.template('test');
    `;
    const codeB = `
      import customAlias from 'lodash';
      customAlias.isEqual(1, 1);
      customAlias.template('test');
    `;

    const { tree: treeA } = TreeSitterLoader.parseFile(codeA, 'javascript');
    const { tree: treeB } = TreeSitterLoader.parseFile(codeB, 'javascript');

    const factsA = JsSymbolUsageExtractor.extract(treeA!.rootNode, '/src/a.js', 'src/a.js');
    const factsB = JsSymbolUsageExtractor.extract(treeB!.rootNode, '/src/b.js', 'src/b.js');

    const symbolsA = factsA.usageFacts.map((u) => u.symbol).sort();
    const symbolsB = factsB.usageFacts.map((u) => u.symbol).sort();

    expect(symbolsA).toEqual(symbolsB);
    expect(factsA.escapes.length).toBe(factsB.escapes.length);
  });
});
