// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { matchesPattern, sessionScopeFor, shouldPromptForWrite } from './index.ts';

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
