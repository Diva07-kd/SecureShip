import { describe, it, expect } from 'vitest';
import { AstScopeFinder } from '../src/ast-scope.js';

describe('AstScopeFinder Unit Suite', () => {
  it('extracts JavaScript/TypeScript function declaration', async () => {
    const code = `
import { db } from './db';

export function executeQuery(userId: string) {
  const q = "SELECT * FROM users WHERE id = " + userId;
  return db.query(q);
}

export const other = 1;
`;
    const res = await AstScopeFinder.findEnclosingScope(code, 'src/query.ts', 5, 5);
    expect(res.scopeName).toContain('executeQuery');
    expect(res.sliceText).toContain('function executeQuery');
    expect(res.startLine).toBe(4);
    expect(res.endLine).toBe(7);
  });

  it('extracts arrow function assigned to variable', async () => {
    const code = `
const handleRequest = (req, res) => {
  const input = req.body.data;
  eval(input);
};
`;
    const res = await AstScopeFinder.findEnclosingScope(code, 'src/handler.js', 4, 4);
    expect(res.scopeName).toContain('handleRequest');
    expect(res.sliceText).toContain('handleRequest');
  });

  it('extracts Python function definition', async () => {
    const pyCode = `
import os

def run_command(cmd):
    os.system(cmd)
    return True
`;
    const res = await AstScopeFinder.findEnclosingScope(pyCode, 'app.py', 5, 5);
    expect(res.scopeName).toContain('run_command');
    expect(res.sliceText).toContain('def run_command');
  });

  it('extracts Terraform HCL resource block', async () => {
    const tfCode = `
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`;
    const res = await AstScopeFinder.findEnclosingScope(tfCode, 'main.tf', 4, 4);
    expect(res.scopeName).toBe('resource.aws_s3_bucket.b');
    expect(res.sliceText).toContain('resource "aws_s3_bucket"');
    expect(res.startLine).toBe(2);
    expect(res.endLine).toBe(5);
  });

  it('falls back to bounded line window for unsupported formats or global scope', async () => {
    const genericCode = Array.from({ length: 50 }, (_, i) => `line ${i + 1}`).join('\n');
    const res = await AstScopeFinder.findEnclosingScope(genericCode, 'data.txt', 25, 25, 5);
    expect(res.scopeName).toBe('line-window');
    expect(res.startLine).toBe(20);
    expect(res.endLine).toBe(30);
  });
});
