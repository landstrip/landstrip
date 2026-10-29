import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractDomainsFromCommand,
  extractCandidatePaths,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
  canonicalizePath,
  decodeLandstripTrap,
} from '@landstrip/landstrip-api/shared';

test('extractDomainsFromCommand extracts unique domains from URLs in commands', () => {
  assert.deepEqual(extractDomainsFromCommand(''), []);
  assert.deepEqual(extractDomainsFromCommand(null), []);
  assert.deepEqual(
    extractDomainsFromCommand(
      'curl -s https://api.github.com/repos/org/repo and http://example.com:8080/path',
    ),
    ['api.github.com', 'example.com'],
  );
  assert.deepEqual(
    extractDomainsFromCommand(
      'git clone https://github.com/landstrip/landstrip.git && curl https://github.com/releases',
    ),
    ['github.com'],
  );
});

test('extractCandidatePaths extracts candidate file paths from commands', () => {
  assert.deepEqual(extractCandidatePaths(''), []);
  assert.deepEqual(extractCandidatePaths(null), []);
  const candidates = extractCandidatePaths(
    'cat /workspace/data ./local.txt ~/secret.txt -rf "C:\\path\\file.txt"',
  );
  assert.ok(candidates.includes('/workspace/data'));
  assert.ok(candidates.includes('./local.txt'));
  assert.ok(candidates.includes('~/secret.txt'));
  assert.ok(candidates.includes('C:\\path\\file.txt'));
  assert.ok(!candidates.includes('-rf'));
});

test('extractNativeDeniedPath parses various native shell and tool permission denials', () => {
  const cwd = '/workspace/test';
  assert.equal(
    extractNativeDeniedPath('bash: line 1: /workspace/test/shadow: Permission denied', cwd),
    canonicalizePath('/workspace/test/shadow', cwd),
  );
  assert.equal(
    extractNativeDeniedPath('/bin/sh: /workspace/test/secret: Operation not permitted', cwd),
    canonicalizePath('/workspace/test/secret', cwd),
  );
  assert.equal(
    extractNativeDeniedPath("cat: './secret.txt': Permission denied", cwd),
    canonicalizePath('/workspace/test/secret.txt', cwd),
  );
  assert.equal(
    extractNativeDeniedPath("ls: cannot open directory '/workspace/root': Permission denied", cwd),
    canonicalizePath('/workspace/root', cwd),
  );
  assert.equal(extractNativeDeniedPath('echo Hello World', cwd), null);
});

test('extractNativeWriteDeniedPath parses write and creation denials', () => {
  const cwd = '/workspace/test';
  assert.equal(
    extractNativeWriteDeniedPath(
      "touch: cannot touch '/workspace/test/passwd': Permission denied",
      cwd,
    ),
    canonicalizePath('/workspace/test/passwd', cwd),
  );
  assert.equal(
    extractNativeWriteDeniedPath(
      "mkdir: cannot create directory '/workspace/test/dir': Permission denied",
      cwd,
    ),
    canonicalizePath('/workspace/test/dir', cwd),
  );
  assert.equal(
    extractNativeWriteDeniedPath(
      "sed: couldn't open temporary file /workspace/test/sed1234: Permission denied",
      cwd,
    ),
    canonicalizePath('/workspace/test/sed1234', cwd),
  );
  assert.equal(
    extractNativeWriteDeniedPath('cat: /workspace/test/hosts: Permission denied', cwd),
    null,
  );
});

test('extractDeniedPath resolves structured traps, native errors, and candidate command paths', () => {
  const cwd = '/workspace/test';

  // Structured trap
  const trapOutput =
    '{"kind":"filesystem","code":"FILESYSTEM_DENIED","query_id":"0","path":"/opt/data","requested_path":"/opt/data","operation":"read","state":"denial","syscall":"openat","errno":"EACCES","flags":[],"reason":"deny_match","suggested_grant":{"allowRead":"/opt/data"},"process":{"pid":1,"exe":null,"cwd":null},"mechanism":"seccomp"}';
  assert.equal(extractDeniedPath(trapOutput, { cwd }), canonicalizePath('/opt/data', cwd));

  // Native denial
  const nativeOutput = 'cat: /workspace/test/hosts: Permission denied';
  assert.equal(
    extractDeniedPath(nativeOutput, { cwd }),
    canonicalizePath('/workspace/test/hosts', cwd),
  );

  // Command fallback when internal trap occurred
  const internalTrap = '{"kind":"internal","code":"INTERNAL_ERROR","message":"Access denied"}';
  assert.equal(
    extractDeniedPath(internalTrap, { cwd, command: 'cat /workspace/test/secret.key' }),
    canonicalizePath('/workspace/test/secret.key', cwd),
  );

  // Unrelated output
  assert.equal(extractDeniedPath('command completed successfully', { cwd }), null);
});

test('decodeLandstripTrap aligns mechanisms and policy error codes with error.rs', () => {
  assert.deepEqual(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'SANDBOX_SETUP_FAILED',
      mechanism: 'namespace',
      message: 'unshare failed',
    }),
    {
      kind: 'internal',
      code: 'SANDBOX_SETUP_FAILED',
      mechanism: 'namespace',
      message: 'unshare failed',
    },
  );
  assert.deepEqual(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'POLICY_INVALID_MACH_LOOKUP',
      message: 'wildcard mach lookup',
    }),
    {
      kind: 'internal',
      code: 'POLICY_INVALID_MACH_LOOKUP',
      message: 'wildcard mach lookup',
    },
  );
  assert.equal(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'POLICY_TCP_BIND_UNSUPPORTED',
      message: 'retired',
    }),
    null,
  );
  assert.equal(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'POLICY_DENY_WRITE_SYMLINK_ANCESTOR',
      message: 'retired',
    }),
    null,
  );
});
