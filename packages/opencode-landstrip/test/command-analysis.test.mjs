import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractDomainsFromCommand,
  extractCandidatePaths,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
  canonicalizePath,
  controlResponseStanza,
  createDarwinLogTag,
  decodeLandstripTrap,
  parseLandstripTraps,
  parseSeatbeltDenials,
  parseTrapStanza,
  querySeatbeltDenials,
  serializeTrapStanza,
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
  const trapOutput = serializeTrapStanza({
    kind: 'filesystem',
    code: 'FILESYSTEM_DENIED',
    state: 'info',
    operation: 'read',
    path: '/opt/data',
    syscall: 'openat',
    errno: 'EACCES',
    reason: 'deny_match',
    mechanism: 'kvm',
    pid: 1,
  });
  assert.equal(extractDeniedPath(trapOutput, { cwd }), canonicalizePath('/opt/data', cwd));
  // Native denial
  const nativeOutput = 'cat: /workspace/test/hosts: Permission denied';
  assert.equal(
    extractDeniedPath(nativeOutput, { cwd }),
    canonicalizePath('/workspace/test/hosts', cwd),
  );

  // Command fallback when internal trap occurred
  const internalTrap = 'kind=internal\ncode=INTERNAL_ERROR\nmessage=Access denied\n\n';
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
      code: 'SANDBOX_SETUP_FAILED',
      mechanism: 'kvm',
      message: '/dev/kvm is not available',
    }),
    {
      kind: 'internal',
      code: 'SANDBOX_SETUP_FAILED',
      mechanism: 'kvm',
      message: '/dev/kvm is not available',
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
  assert.deepEqual(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'POLICY_GLOB_TOO_LONG',
      message: 'glob pattern exceeds limit',
    }),
    {
      kind: 'internal',
      code: 'POLICY_GLOB_TOO_LONG',
      message: 'glob pattern exceeds limit',
    },
  );
  assert.deepEqual(
    decodeLandstripTrap({
      kind: 'internal',
      code: 'POLICY_SELECTOR_LIMIT',
      message: 'too many selectors',
    }),
    {
      kind: 'internal',
      code: 'POLICY_SELECTOR_LIMIT',
      message: 'too many selectors',
    },
  );
});

test('stanza wire format round-trips escaped values, omitted fields, and replies', () => {
  const queryStanza = serializeTrapStanza({
    kind: 'filesystem',
    code: 'FILESYSTEM_DENIED',
    state: 'query',
    query_id: '42',
    operation: 'write',
    path: '/tmp/dir\\name\nline2.txt',
    requested_path: './rel.txt',
    syscall: 'openat',
    errno: 'EACCES',
    flags: ['O_WRONLY', 'O_CREAT'],
    reason: 'allow_miss',
    mechanism: 'kvm',
    pid: 412,
    exe: '/usr/bin/touch',
  });
  assert.ok(queryStanza.endsWith('\n\n'));
  assert.ok(!queryStanza.includes('\ncwd='));
  assert.deepEqual(parseTrapStanza(queryStanza), {
    kind: 'filesystem',
    code: 'FILESYSTEM_DENIED',
    state: 'query',
    query_id: '42',
    operation: 'write',
    path: '/tmp/dir\\name\nline2.txt',
    requested_path: './rel.txt',
    syscall: 'openat',
    errno: 'EACCES',
    flags: ['O_WRONLY', 'O_CREAT'],
    reason: 'allow_miss',
    mechanism: 'kvm',
    pid: 412,
    exe: '/usr/bin/touch',
  });

  const mixedStderr = [
    'cat: /etc/shadow: Permission denied',
    queryStanza.trimEnd(),
    '',
    'kind=usage\ncode=USAGE_ERROR\nmessage=missing -- COMMAND\\nhint=run --help\n',
  ].join('\n');
  const parsed = parseLandstripTraps(mixedStderr);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].kind, 'filesystem');
  assert.deepEqual(parsed[1], {
    kind: 'usage',
    code: 'USAGE_ERROR',
    message: 'missing -- COMMAND\nhint=run --help',
  });

  assert.equal(controlResponseStanza('42', 'allow'), 'query_id=42\naction=allow\n\n');
  assert.throws(() => controlResponseStanza('0', 'allow'), TypeError);

  const seccompQuery = serializeTrapStanza({
    kind: 'filesystem',
    code: 'FILESYSTEM_DENIED',
    state: 'query',
    query_id: '7',
    operation: 'read',
    path: '/etc/hosts',
    syscall: 'openat',
    errno: 'EACCES',
    reason: 'allow_miss',
    mechanism: 'seccomp',
    pid: 99,
  });
  assert.equal(parseTrapStanza(seccompQuery)?.mechanism, 'seccomp');

  const landlockFailure = serializeTrapStanza({
    kind: 'internal',
    code: 'SANDBOX_SETUP_FAILED',
    mechanism: 'landlock',
    message: 'landlock ABI unsupported',
  });
  assert.deepEqual(parseTrapStanza(landlockFailure), {
    kind: 'internal',
    code: 'SANDBOX_SETUP_FAILED',
    mechanism: 'landlock',
    message: 'landlock ABI unsupported',
  });
});

test('createDarwinLogTag and querySeatbeltDenials correlate macOS Seatbelt log output', async () => {
  const cwd = '/workspace/test';
  const tag = createDarwinLogTag('opencode-landstrip');
  assert.match(tag, /^opencode-landstrip-[0-9a-f]{12}$/);

  const rawLines = [
    `Sandbox: cat(402) deny(1) file-read-data /workspace/test/secret.pem [${tag}]`,
    'Sandbox: cat(403) deny(1) file-read-data /workspace/test/ignored.pem [other-tag]',
  ].join('\n');
  assert.deepEqual(parseSeatbeltDenials(rawLines, { logTag: tag, cwd }), [
    {
      kind: 'filesystem',
      operation: 'read',
      path: canonicalizePath('/workspace/test/secret.pem', cwd),
      action: 'file-read-data',
    },
  ]);

  const queried = await querySeatbeltDenials(tag, {
    cwd,
    runLogShow: async () => rawLines,
  });
  assert.equal(queried.length, 1);
  assert.equal(queried[0].kind, 'filesystem');
  assert.equal(queried[0].operation, 'read');
});
