import { describe, expect, it, vi } from 'vitest';
import type {
  ExtNormalizedFinding,
  ExtScanReport,
  ExtSeverity,
} from '../src/types/extension-types.js';

vi.mock('vscode', () => ({
  TreeItem: class {
    constructor(
      public label: string,
      public cs: number
    ) {}
  },
  TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
  ThemeIcon: class {
    constructor(
      public id: string,
      public color?: unknown
    ) {}
  },
  ThemeColor: class {
    constructor(public id: string) {}
  },
  EventEmitter: class {
    event = () => {};
    fire = vi.fn();
    dispose = vi.fn();
  },
  Uri: { file: (p: string) => ({ fsPath: p }) },
  Range: class {
    constructor(
      public sl: number,
      public sc: number,
      public el: number,
      public ec: number
    ) {}
  },
}));

import { FindingsPanelProvider, FindingsTreeItem } from '../src/panel/findings-panel.js';

function getItemLabel(item: { label?: unknown } | undefined): string {
  if (!item || item.label === undefined || item.label === null) return '';
  if (typeof item.label === 'string') return item.label;
  if (typeof item.label === 'object' && 'label' in item.label) {
    return String((item.label as { label: unknown }).label);
  }
  return String(item.label);
}

function makeReport(partialFindings: Partial<ExtNormalizedFinding>[]): ExtScanReport {
  const findings: ExtNormalizedFinding[] = partialFindings.map((pf, idx) => ({
    id: `finding-${idx}`,
    fingerprint: `${idx}`.padStart(64, '0'),
    ruleId: pf.ruleId || `RULE-${idx}`,
    scannerName: 'opengrep',
    category: pf.category || 'SAST',
    severity: pf.severity || 'HIGH',
    title: pf.title || `Finding title ${idx}`,
    description: pf.description || 'Finding description',
    location: pf.location || {
      filePath: 'src/file.ts',
      startLine: idx + 1,
      endLine: idx + 1,
    },
    ...pf,
  }));

  const bySeverity: Record<ExtSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const f of findings) {
    bySeverity[f.severity]++;
  }

  return {
    schemaVersion: '1.2',
    target: '/workspace',
    findings,
    summary: {
      totalRaw: findings.length,
      totalReported: findings.length,
      totalSuppressed: 0,
      bySeverity,
      byCategory: {},
    },
  };
}

describe('FindingsPanelProvider', () => {
  it('severity groups appear in CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO order', async () => {
    const provider = new FindingsPanelProvider();
    const report = makeReport([
      { severity: 'LOW' },
      { severity: 'CRITICAL' },
      { severity: 'INFO' },
      { severity: 'HIGH' },
      { severity: 'MEDIUM' },
    ]);

    provider.updateReport(report);
    const rootItems = (await provider.getChildren()) as FindingsTreeItem[];

    expect(rootItems).toHaveLength(5);
    expect(getItemLabel(rootItems[0])).toContain('CRITICAL');
    expect(getItemLabel(rootItems[1])).toContain('HIGH');
    expect(getItemLabel(rootItems[2])).toContain('MEDIUM');
    expect(getItemLabel(rootItems[3])).toContain('LOW');
    expect(getItemLabel(rootItems[4])).toContain('INFO');
  });

  it('severity groups show correct count in label', async () => {
    const provider = new FindingsPanelProvider();
    const report = makeReport([{ severity: 'HIGH' }, { severity: 'HIGH' }, { severity: 'HIGH' }]);

    provider.updateReport(report);
    const rootItems = (await provider.getChildren()) as FindingsTreeItem[];

    expect(rootItems).toHaveLength(1);
    expect(getItemLabel(rootItems[0])).toContain('3');
    expect(getItemLabel(rootItems[0])).toBe('HIGH (3)');
  });

  it('empty severity groups are omitted from root', async () => {
    const provider = new FindingsPanelProvider();
    const report = makeReport([{ severity: 'HIGH' }, { severity: 'HIGH' }]);

    provider.updateReport(report);
    const rootItems = (await provider.getChildren()) as FindingsTreeItem[];

    expect(rootItems).toHaveLength(1);
    expect(getItemLabel(rootItems[0])).toContain('HIGH');
    const labels = rootItems.map((item) => getItemLabel(item));
    expect(labels.some((l) => l.includes('CRITICAL'))).toBe(false);
    expect(labels.some((l) => l.includes('MEDIUM'))).toBe(false);
    expect(labels.some((l) => l.includes('LOW'))).toBe(false);
    expect(labels.some((l) => l.includes('INFO'))).toBe(false);
  });

  it('getChildren(groupHeader) returns correct finding children', async () => {
    const provider = new FindingsPanelProvider();
    const report = makeReport([
      { ruleId: 'CRIT-1', severity: 'CRITICAL', title: 'Crit 1' },
      { ruleId: 'CRIT-2', severity: 'CRITICAL', title: 'Crit 2' },
    ]);

    provider.updateReport(report);
    const rootItems = (await provider.getChildren()) as FindingsTreeItem[];
    const critGroup = rootItems[0];

    const children = (await provider.getChildren(critGroup)) as FindingsTreeItem[];
    expect(children).toHaveLength(2);
    expect(getItemLabel(children[0])).toContain('CRIT-1');
    expect(getItemLabel(children[1])).toContain('CRIT-2');
  });

  it('finding child label is truncated to 60 chars for long titles', async () => {
    const provider = new FindingsPanelProvider();
    const longTitle = 'A'.repeat(100);
    const ruleId = 'RULE-TEST';
    const report = makeReport([{ ruleId, severity: 'HIGH', title: longTitle }]);

    provider.updateReport(report);
    const rootItems = (await provider.getChildren()) as FindingsTreeItem[];
    const children = (await provider.getChildren(rootItems[0])) as FindingsTreeItem[];

    expect(children).toHaveLength(1);
    const child = children[0];
    const childLabel = getItemLabel(child);
    expect(childLabel).toContain(ruleId);
    expect(childLabel.length).toBeLessThanOrEqual(60 + ruleId.length);
  });

  it("null report shows 'No scan results' placeholder", async () => {
    const provider = new FindingsPanelProvider();
    provider.updateReport(null);

    const items = (await provider.getChildren()) as FindingsTreeItem[];
    expect(items).toHaveLength(1);
    expect(getItemLabel(items[0])).toBe('No scan results');
  });

  it("zero-findings report shows 'No findings' placeholder", async () => {
    const provider = new FindingsPanelProvider();
    const report = makeReport([]);
    provider.updateReport(report);

    const items = (await provider.getChildren()) as FindingsTreeItem[];
    expect(items).toHaveLength(1);
    expect(getItemLabel(items[0])).toBe('No findings');
  });

  it('second updateReport call resets previous grouping', async () => {
    const provider = new FindingsPanelProvider();
    const report1 = makeReport([
      { severity: 'CRITICAL' },
      { severity: 'CRITICAL' },
      { severity: 'CRITICAL' },
    ]);
    provider.updateReport(report1);

    let items = (await provider.getChildren()) as FindingsTreeItem[];
    expect(items).toHaveLength(1);
    expect(getItemLabel(items[0])).toContain('CRITICAL (3)');

    const report2 = makeReport([{ severity: 'HIGH' }, { severity: 'HIGH' }]);
    provider.updateReport(report2);

    items = (await provider.getChildren()) as FindingsTreeItem[];
    expect(items).toHaveLength(1);
    expect(getItemLabel(items[0])).toBe('HIGH (2)');
    expect(getItemLabel(items[0])).not.toContain('CRITICAL');
  });
});
