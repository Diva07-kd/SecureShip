import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { SlicerDenylist } from '../src/denylist.js';

describe('SlicerDenylist Unit Suite (A4, A11)', () => {
  let tempRoot: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-denylist-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {}
  });

  it('correctly matches sensitive files against denylist (positive and negative tests per pattern) (R11)', () => {
    // 1. .env*
    expect(SlicerDenylist.isDenylisted('.env')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.env.local')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.env.production')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.envrc')).toBe(true);
    expect(SlicerDenylist.isDenylisted('environment.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('dotenv.ts')).toBe(false);

    // 2. *.pem
    expect(SlicerDenylist.isDenylisted('certs/server.pem')).toBe(true);
    expect(SlicerDenylist.isDenylisted('client.PEM')).toBe(true);
    expect(SlicerDenylist.isDenylisted('pem-parser.ts')).toBe(false);

    // 3. *.key
    expect(SlicerDenylist.isDenylisted('certs/private.key')).toBe(true);
    expect(SlicerDenylist.isDenylisted('jwt.KEY')).toBe(true);
    expect(SlicerDenylist.isDenylisted('src/keyboard.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('key_generator.ts')).toBe(false);

    // 4. id_rsa*
    expect(SlicerDenylist.isDenylisted('keys/id_rsa')).toBe(true);
    expect(SlicerDenylist.isDenylisted('keys/id_rsa.pub')).toBe(true);
    expect(SlicerDenylist.isDenylisted('keys/id_rsa_backup')).toBe(true);
    expect(SlicerDenylist.isDenylisted('paid_rsa.ts')).toBe(false);

    // 5. *.p12
    expect(SlicerDenylist.isDenylisted('certs/cert.p12')).toBe(true);
    expect(SlicerDenylist.isDenylisted('p12_extractor.ts')).toBe(false);

    // 6. *.pfx
    expect(SlicerDenylist.isDenylisted('certs/cert.pfx')).toBe(true);
    expect(SlicerDenylist.isDenylisted('pfx_converter.ts')).toBe(false);

    // 7. credentials*
    expect(SlicerDenylist.isDenylisted('credentials.json')).toBe(true);
    expect(SlicerDenylist.isDenylisted('credentials.txt')).toBe(true);
    expect(SlicerDenylist.isDenylisted('credentials_ci.yml')).toBe(true);
    expect(SlicerDenylist.isDenylisted('credentials')).toBe(true);
    expect(SlicerDenylist.isDenylisted('user_credentials.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('get_credentials.js')).toBe(false);

    // 8. secrets*
    expect(SlicerDenylist.isDenylisted('secrets.yaml')).toBe(true);
    expect(SlicerDenylist.isDenylisted('secrets.json')).toBe(true);
    expect(SlicerDenylist.isDenylisted('secrets_env.sh')).toBe(true);
    expect(SlicerDenylist.isDenylisted('secrets')).toBe(true);
    expect(SlicerDenylist.isDenylisted('app_secrets.ts')).toBe(false);

    // 9. *.kdbx
    expect(SlicerDenylist.isDenylisted('vault.kdbx')).toBe(true);
    expect(SlicerDenylist.isDenylisted('passwords.KDBX')).toBe(true);
    expect(SlicerDenylist.isDenylisted('kdbx_reader.ts')).toBe(false);

    // 10. .npmrc
    expect(SlicerDenylist.isDenylisted('.npmrc')).toBe(true);
    expect(SlicerDenylist.isDenylisted('npmrc.txt')).toBe(false);

    // 11. .pypirc
    expect(SlicerDenylist.isDenylisted('.pypirc')).toBe(true);
    expect(SlicerDenylist.isDenylisted('pypirc.txt')).toBe(false);

    // 12. .netrc
    expect(SlicerDenylist.isDenylisted('.netrc')).toBe(true);
    expect(SlicerDenylist.isDenylisted('netrc.conf')).toBe(false);

    // 13. terraform.tfstate*
    expect(SlicerDenylist.isDenylisted('terraform.tfstate')).toBe(true);
    expect(SlicerDenylist.isDenylisted('terraform.tfstate.backup')).toBe(true);
    expect(SlicerDenylist.isDenylisted('env.terraform.tfstate.d')).toBe(true);
    expect(SlicerDenylist.isDenylisted('terraform.tf')).toBe(false);
    expect(SlicerDenylist.isDenylisted('state.ts')).toBe(false);

    // 14. .aws/
    expect(SlicerDenylist.isDenylisted('.aws/credentials')).toBe(true);
    expect(SlicerDenylist.isDenylisted('home/.aws/config')).toBe(true);
    expect(SlicerDenylist.isDenylisted('aws-sdk.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('aws/lambda.ts')).toBe(false);

    // 15. .ssh/
    expect(SlicerDenylist.isDenylisted('.ssh/known_hosts')).toBe(true);
    expect(SlicerDenylist.isDenylisted('user/.ssh/authorized_keys')).toBe(true);
    expect(SlicerDenylist.isDenylisted('ssh-client.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('ssh/tunnel.ts')).toBe(false);

    // Extras: id_ed25519, .git, .secureship, certs, keystores
    expect(SlicerDenylist.isDenylisted('id_ed25519')).toBe(true);
    expect(SlicerDenylist.isDenylisted('id_ed25519.pub')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.git/config')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.secureship/cache.json')).toBe(true);
    expect(SlicerDenylist.isDenylisted('server.crt')).toBe(true);
    expect(SlicerDenylist.isDenylisted('app.keystore')).toBe(true);
    expect(SlicerDenylist.isDenylisted('app.jks')).toBe(true);

    // Normal files allowed
    expect(SlicerDenylist.isDenylisted('src/app.ts')).toBe(false);
    expect(SlicerDenylist.isDenylisted('package.json')).toBe(false);
    expect(SlicerDenylist.isDenylisted('')).toBe(false);
  });

  it('verifies paths within root and rejects path traversals (A11)', () => {
    const inside = path.join(tempRoot, 'src', 'index.ts');
    expect(SlicerDenylist.isWithinRoot(tempRoot, inside)).toBe(true);
    expect(SlicerDenylist.isWithinRoot(tempRoot, tempRoot)).toBe(true);

    const outside = path.join(tempRoot, '..', 'escape.ts');
    expect(SlicerDenylist.isWithinRoot(tempRoot, outside)).toBe(false);

    // Relative path inside
    expect(SlicerDenylist.isWithinRoot(tempRoot, 'src/util.ts')).toBe(true);
    expect(SlicerDenylist.isWithinRoot(tempRoot, '../outside.ts')).toBe(false);
  });

  it('converts paths to root-relative POSIX format', () => {
    const absPath = path.join(tempRoot, 'src', 'components', 'Button.tsx');
    const rel = SlicerDenylist.toRootRelativePosix(tempRoot, absPath);
    expect(rel).toBe('src/components/Button.tsx');
    expect(rel).not.toContain('\\');

    // Root itself returns '.'
    expect(SlicerDenylist.toRootRelativePosix(tempRoot, tempRoot)).toBe('.');
  });

  it('jails paths inside workspace root and rejects escapes', () => {
    expect(SlicerDenylist.jailPath(tempRoot, 'src/app.ts')).toBe('src/app.ts');
    expect(SlicerDenylist.jailPath(tempRoot, '../escape.ts')).toBeNull();
  });
});
