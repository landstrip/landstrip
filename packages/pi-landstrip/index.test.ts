// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { matchesPattern, readAllowed, sessionScopeFor, shouldPromptForWrite } from './index.ts';

// The broker resolves relative policy entries (notably ".") against the command
// `cwd` that landstrip uses as its policy base. Regression guard: before the fix
// these resolved against the extension process's own `process.cwd()`, so a write
// inside the project was wrongly judged outside allowWrite whenever pi was
// launched from a different directory. Every project path below is deliberately
// NOT process.cwd(), so a process.cwd()-based resolution would fail these.
const PROJECT = '/proj/workspace';

describe('matchesPattern "." resolves against the command cwd', () => {
  it('matches a path inside the cwd', () => {
    expect(matchesPattern(`${PROJECT}/src/file.ts`, ['.'], PROJECT)).toBe(true);
  });

  it('matches the cwd itself', () => {
    expect(matchesPattern(PROJECT, ['.'], PROJECT)).toBe(true);
  });

  it('does not match a path outside the cwd', () => {
    expect(matchesPattern('/other/place/file.ts', ['.'], PROJECT)).toBe(false);
  });

  it('is independent of process.cwd()', () => {
    // process.cwd() is the repo root here, never PROJECT.
    expect(process.cwd()).not.toBe(PROJECT);
    expect(matchesPattern(`${PROJECT}/x`, ['.'], PROJECT)).toBe(true);
    expect(matchesPattern(`${process.cwd()}/x`, ['.'], PROJECT)).toBe(false);
  });
});

describe('matchesPattern other entry shapes', () => {
  it('expands ~ against the home directory regardless of cwd', () => {
    expect(matchesPattern(join(homedir(), '.gitconfig'), ['~/.gitconfig'], PROJECT)).toBe(true);
  });

  it('honours absolute entries regardless of cwd', () => {
    expect(matchesPattern('/dev/null', ['/dev/null'], PROJECT)).toBe(true);
  });

  it('matches globs', () => {
    expect(matchesPattern(`${PROJECT}/a/b/.env`, ['**/.env'], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/a/b/key.pem`, ['**/*.pem'], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/a/b/file.ts`, ['**/.env'], PROJECT)).toBe(false);
  });

  // A single '*' must stop at '/', like landstrip's own matcher, so an
  // allow-glob cannot reach a deeper path the operator did not intend.
  it('a single * does not cross a directory separator', () => {
    expect(matchesPattern(`${PROJECT}/srv/a/pub`, [`${PROJECT}/srv/*/pub`], PROJECT)).toBe(true);
    expect(matchesPattern(`${PROJECT}/srv/a/deep/pub`, [`${PROJECT}/srv/*/pub`], PROJECT)).toBe(
      false,
    );
    // '**' still spans directories.
    expect(matchesPattern(`${PROJECT}/srv/a/deep/pub`, [`${PROJECT}/srv/**/pub`], PROJECT)).toBe(
      true,
    );
  });
});

describe('shouldPromptForWrite', () => {
  it('does not prompt for a path inside an allowWrite "." root', () => {
    expect(shouldPromptForWrite(`${PROJECT}/out.txt`, ['.'], PROJECT)).toBe(false);
  });

  it('prompts for a path outside allowWrite', () => {
    expect(shouldPromptForWrite('/other/out.txt', ['.'], PROJECT)).toBe(true);
  });

  it('prompts when allowWrite is empty', () => {
    expect(shouldPromptForWrite(`${PROJECT}/out.txt`, [], PROJECT)).toBe(true);
  });
});

describe('sessionScopeFor', () => {
  const HOME = homedir();
  const PROJECT = join(HOME, 'work', 'proj');

  it('widens a home file to the immediate child of $HOME', () => {
    expect(sessionScopeFor(join(HOME, '.cargo', 'registry', 'foo.rs'), PROJECT)).toBe(
      join(HOME, '.cargo'),
    );
  });

  it('widens deep home paths to the same top-level directory', () => {
    const scope = sessionScopeFor(join(HOME, '.cargo', 'a', 'b', 'c.rs'), PROJECT);
    expect(scope).toBe(join(HOME, '.cargo'));
  });

  it('does not widen a file sitting directly in $HOME (would over-broaden)', () => {
    const file = join(HOME, '.netrc');
    expect(sessionScopeFor(file, PROJECT)).toBe(file);
  });

  it('widens a path outside $HOME to its containing directory', () => {
    expect(sessionScopeFor('/etc/ssl/certs/ca.pem', '/srv/app')).toBe('/etc/ssl/certs');
  });

  it('widens a project path (outside home) to the project root', () => {
    expect(sessionScopeFor('/srv/app/src/deep/mod.ts', '/srv/app')).toBe('/srv/app');
  });
});

describe('readAllowed', () => {
  const HOME = homedir();
  const cwd = join(HOME, 'work', 'proj');
  const DENY = ['/Users', '/home'];

  it('blocks a home path that is not in allowRead (broad deny wins)', () => {
    expect(readAllowed(join(HOME, '.cache', 'x'), ['.'], DENY, cwd)).toBe(false);
  });

  it('allows a granted home scope even though denyRead lists /home', () => {
    const allow = ['.', join(HOME, '.cache')];
    expect(readAllowed(join(HOME, '.cache', 'puu', 'd', 'f'), allow, DENY, cwd)).toBe(true);
  });

  it('keeps a narrow deny carve-out beating a broad allow', () => {
    expect(readAllowed(join(HOME, '.ssh', 'id'), [HOME], [join(HOME, '.ssh')], cwd)).toBe(false);
  });

  it('lets the most specific grant override a narrow deny', () => {
    const deny = [join(HOME, '.ssh')];
    expect(
      readAllowed(join(HOME, '.ssh', 'config'), [join(HOME, '.ssh', 'config')], deny, cwd),
    ).toBe(true);
  });

  it('denies when nothing in allowRead matches', () => {
    expect(readAllowed('/etc/passwd', ['.'], DENY, cwd)).toBe(false);
  });
});

import { existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { writeEnvFile } from './index.ts';

describe('writeEnvFile', () => {
  it('writes export statements for each env var', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar', BAZ: 'qux' }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).toContain("export BAZ='qux'");
  });

  it('skips undefined values', () => {
    const env: NodeJS.ProcessEnv = { FOO: 'bar', SKIP: undefined };
    const { dir, path } = writeEnvFile(env, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).not.toContain('SKIP');
  });

  it('escapes single quotes in values', () => {
    const { dir, path } = writeEnvFile({ QUOTED: "it's a test" }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export QUOTED='it'\\''s a test'");
  });

  it('skips names the shell cannot export', () => {
    const env: NodeJS.ProcessEnv = { FOO: 'bar', 'BASH_FUNC_greet%%': '() { echo hi; }' };
    const { dir, path } = writeEnvFile(env, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).not.toContain('BASH_FUNC_greet');
  });

  it('adds proxy vars when proxyPort is provided', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar' }, 8080);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).toContain("export FOO='bar'");
    expect(content).toContain("export HTTP_PROXY='http://127.0.0.1:8080'");
    expect(content).toContain("export NO_PROXY=''");
  });

  it('does not add proxy vars when proxyPort is null', () => {
    const { dir, path } = writeEnvFile({ FOO: 'bar' }, null);
    const content = readFileSync(path, 'utf-8');
    rmSync(dir, { recursive: true, force: true });
    expect(content).not.toContain('HTTP_PROXY');
  });

  it('creates the file under tmpdir', () => {
    const { dir, path } = writeEnvFile({}, null);
    expect(dir).toContain(tmpdir());
    expect(existsSync(path)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });
});

import {
  controlResponseLine,
  domainMatchesAny,
  formatLandstripTraps,
  isQueryTrap,
  parseTrapLine,
} from './index.ts';

describe('domainMatchesAny', () => {
  it('matches exact and wildcard patterns', () => {
    expect(domainMatchesAny('github.com', ['github.com'])).toBe(true);
    expect(domainMatchesAny('api.github.com', ['*.github.com'])).toBe(true);
    expect(domainMatchesAny('evil.com', ['github.com'])).toBe(false);
  });

  // A trailing-dot FQDN resolves to the same host, so it must not slip past a
  // deny entry written without the dot.
  it('normalizes a trailing dot before matching', () => {
    expect(domainMatchesAny('pastebin.com.', ['pastebin.com'])).toBe(true);
    expect(domainMatchesAny('api.github.com.', ['*.github.com'])).toBe(true);
  });
});

const FS_TRAP = {
  kind: 'filesystem',
  code: 'FILESYSTEM_DENIED',
  state: 'query',
  query_id: '7',
  operation: 'read',
  path: '/etc/passwd',
  requested_path: '/etc/passwd',
  syscall: 'openat',
  errno: 'EACCES',
  flags: ['O_RDONLY'],
  reason: 'allow_miss',
  suggested_grant: { allowRead: '/etc/passwd' },
  process: { pid: 42, exe: '/bin/cat', cwd: '/proj' },
  mechanism: 'seccomp',
};

const NET_TRAP = {
  kind: 'network',
  code: 'NETWORK_DENIED',
  state: 'query',
  query_id: '9',
  operation: 'connect',
  target: '140.82.121.4:22',
  syscall: 'connect',
  errno: 'EACCES',
  mechanism: 'seccomp',
  process: { pid: 42, exe: '/usr/bin/ssh', cwd: '/proj' },
};

const line = (trap: object): string => JSON.stringify(trap);

describe('parseTrapLine', () => {
  it('parses a filesystem query trap', () => {
    const trap = parseTrapLine(line(FS_TRAP));
    expect(trap).toMatchObject({ kind: 'filesystem', operation: 'read', path: '/etc/passwd' });
    expect(trap?.kind === 'filesystem' && trap.query_id).toBe('7');
  });

  // landstrip 0.16 sent query_id as a JSON number. Answering such a trap with a
  // numeric id leaves the child's syscall suspended, so a numeric id must not
  // parse at all rather than reach the handshake.
  it('rejects a numeric query_id', () => {
    expect(parseTrapLine(line({ ...FS_TRAP, query_id: 7 }))).toBeNull();
    expect(parseTrapLine(line({ ...NET_TRAP, query_id: 9 }))).toBeNull();
  });

  it('parses launch, usage and internal traps', () => {
    expect(
      parseTrapLine(
        line({ kind: 'launch', code: 'LAUNCH_FAILED', program: 'nope', message: 'not found' }),
      ),
    ).toMatchObject({ kind: 'launch', program: 'nope', message: 'not found' });
    expect(
      parseTrapLine(line({ kind: 'usage', code: 'USAGE_ERROR', message: 'bad flag' })),
    ).toMatchObject({ kind: 'usage', message: 'bad flag' });
    expect(
      parseTrapLine(line({ kind: 'internal', code: 'POLICY_PARSE_FAILED', message: 'bad json' })),
    ).toMatchObject({ kind: 'internal', code: 'POLICY_PARSE_FAILED' });
  });

  it('ignores non-JSON lines and unknown kinds', () => {
    expect(parseTrapLine('cat: /etc/passwd: Permission denied')).toBeNull();
    expect(parseTrapLine('')).toBeNull();
    expect(parseTrapLine(line({ kind: 'future', message: 'x' }))).toBeNull();
  });
});

describe('isQueryTrap', () => {
  it('holds for a pending filesystem or network query', () => {
    expect(isQueryTrap(parseTrapLine(line(FS_TRAP))!)).toBe(true);
    expect(isQueryTrap(parseTrapLine(line(NET_TRAP))!)).toBe(true);
  });

  it('does not hold for a terminal info trap', () => {
    const info = { ...FS_TRAP, state: 'info', query_id: '0' };
    expect(isQueryTrap(parseTrapLine(line(info))!)).toBe(false);
  });

  it('does not hold for a failure trap', () => {
    const usage = parseTrapLine(line({ kind: 'usage', code: 'USAGE_ERROR', message: 'bad flag' }));
    expect(isQueryTrap(usage!)).toBe(false);
  });
});

describe('controlResponseLine', () => {
  it('serializes query_id as a string', () => {
    expect(controlResponseLine('7', 'allow')).toBe('{"query_id":"7","action":"allow"}\n');
    expect(controlResponseLine('7', 'deny')).toBe('{"query_id":"7","action":"deny"}\n');
  });
});

describe('formatLandstripTraps', () => {
  it('renders a filesystem denial with its resolved path', () => {
    expect(formatLandstripTraps([parseTrapLine(line(FS_TRAP))!])).toBe(
      'landstrip: filesystem read denied: /etc/passwd (seccomp)',
    );
  });

  it('renders a launch failure with its message', () => {
    const trap = parseTrapLine(
      line({ kind: 'launch', code: 'LAUNCH_FAILED', program: 'nope', message: 'not found' }),
    );
    expect(formatLandstripTraps([trap!])).toBe('landstrip: launch failed: nope: not found');
  });

  it('renders an internal failure by its code, with the mechanism when present', () => {
    const policy = parseTrapLine(
      line({ kind: 'internal', code: 'POLICY_PARSE_FAILED', message: 'bad json' }),
    );
    expect(formatLandstripTraps([policy!])).toBe('landstrip: POLICY_PARSE_FAILED: bad json');

    const setup = parseTrapLine(
      line({
        kind: 'internal',
        code: 'SANDBOX_SETUP_FAILED',
        mechanism: 'landlock',
        message: 'no ABI',
      }),
    );
    expect(formatLandstripTraps([setup!])).toBe(
      'landstrip: SANDBOX_SETUP_FAILED (landlock): no ABI',
    );
  });
});
