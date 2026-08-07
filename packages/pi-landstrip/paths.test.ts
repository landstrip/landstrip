// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { expect, test } from 'vitest';

import {
  expandHomePattern,
  isInside,
  isPathBearingTool,
  isProtectedPath,
  isReadOnlyTool,
  matchesDeniedPath,
  matchesProtectedPath,
  resolveInputPath,
} from './paths.ts';

test('expandHomePattern expands ~ to home directory', () => {
  const home = homedir();
  expect(expandHomePattern('~')).toBe(home);
  expect(expandHomePattern('~/foo')).toBe(join(home, 'foo'));
});

test('expandHomePattern expands $HOME and ${HOME}', () => {
  const home = homedir();
  expect(expandHomePattern('$HOME')).toBe(home);
  expect(expandHomePattern('${HOME}')).toBe(home);
  expect(expandHomePattern('$HOME/foo')).toBe(join(home, 'foo'));
});

test('expandHomePattern leaves absolute paths unchanged', () => {
  expect(expandHomePattern('/etc/passwd')).toBe('/etc/passwd');
});

test('isPathBearingTool identifies file tools', () => {
  expect(isPathBearingTool('read')).toBe(true);
  expect(isPathBearingTool('write')).toBe(true);
  expect(isPathBearingTool('edit')).toBe(true);
  expect(isPathBearingTool('grep')).toBe(true);
  expect(isPathBearingTool('find')).toBe(true);
  expect(isPathBearingTool('ls')).toBe(true);
  expect(isPathBearingTool('bash')).toBe(false);
  expect(isPathBearingTool('task')).toBe(false);
});

test('isReadOnlyTool identifies read-only tools', () => {
  expect(isReadOnlyTool('read')).toBe(true);
  expect(isReadOnlyTool('grep')).toBe(true);
  expect(isReadOnlyTool('find')).toBe(true);
  expect(isReadOnlyTool('ls')).toBe(true);
  expect(isReadOnlyTool('write')).toBe(false);
  expect(isReadOnlyTool('edit')).toBe(false);
});

test('resolveInputPath resolves relative paths against cwd', () => {
  const cwd = '/tmp/project';
  expect(resolveInputPath(cwd, 'src/app.ts')).toBe(resolve(cwd, 'src/app.ts'));
  expect(resolveInputPath(cwd, '/etc/passwd')).toBe('/etc/passwd');
  expect(resolveInputPath(cwd, undefined)).toBeUndefined();
  expect(resolveInputPath(cwd, 123)).toBeUndefined();
});

test('isInside detects paths within a directory', () => {
  expect(isInside('/tmp/project/src/app.ts', '/tmp/project')).toBe(true);
  expect(isInside('/tmp/project', '/tmp/project')).toBe(false);
  expect(isInside('/etc/passwd', '/tmp/project')).toBe(false);
  expect(isInside('/tmp/other/foo', '/tmp/project')).toBe(false);
});

test('matchesDeniedPath matches glob patterns', () => {
  const home = homedir();
  const patterns = ['*.env', `${home}/.ssh/*`, '/etc/*'];
  expect(matchesDeniedPath(`${home}/.env`, patterns)).toBe(true);
  expect(matchesDeniedPath(`${home}/.ssh/id_rsa`, patterns)).toBe(true);
  expect(matchesDeniedPath('/etc/passwd', patterns)).toBe(true);
  expect(matchesDeniedPath('/tmp/project/src/app.ts', patterns)).toBe(false);
});

test('matchesDeniedPath matches **/id_rsa at any depth', () => {
  expect(matchesDeniedPath('/home/user/.ssh/id_rsa', ['**/id_rsa'])).toBe(true);
  expect(matchesDeniedPath('/tmp/project/.ssh/id_rsa', ['**/id_rsa'])).toBe(true);
  expect(matchesDeniedPath('/tmp/project/src/app.ts', ['**/id_rsa'])).toBe(false);
});

test('matchesProtectedPath matches exact and prefix', () => {
  const protectedPaths = ['.git', '.husky', '.pi'];
  expect(matchesProtectedPath('.git', protectedPaths)).toBe(true);
  expect(matchesProtectedPath('.git/hooks/pre-commit', protectedPaths)).toBe(true);
  expect(matchesProtectedPath('.husky/pre-commit', protectedPaths)).toBe(true);
  expect(matchesProtectedPath('src/app.ts', protectedPaths)).toBe(false);
  expect(matchesProtectedPath('.gitignore', protectedPaths)).toBe(false);
});

test('isProtectedPath detects in-CWD protected paths', () => {
  const cwd = '/tmp/project';
  const protectedPaths = ['.git', '.husky', '.gitignore'];
  expect(isProtectedPath('/tmp/project/.git/hooks/pre-commit', cwd, protectedPaths)).toBe(true);
  expect(isProtectedPath('/tmp/project/.husky/pre-commit', cwd, protectedPaths)).toBe(true);
  expect(isProtectedPath('/tmp/project/.gitignore', cwd, protectedPaths)).toBe(true);
  expect(isProtectedPath('/tmp/project/src/app.ts', cwd, protectedPaths)).toBe(false);
});