// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { homedir } from 'node:os';
import { resolve } from 'node:path';

import { expect, test } from 'vitest';

import { deterministicHardDeny, isRootHomeOrSystemPath } from './hard-deny.ts';

const HOME = homedir();

test('blocks shell profile writes via write tool', () => {
  const reason = deterministicHardDeny('write', { path: resolve(HOME, '.bashrc') }, '/tmp/project');
  expect(reason).toMatch(/shell profile/);
});

test('blocks shell profile writes via edit tool', () => {
  const reason = deterministicHardDeny('edit', { path: resolve(HOME, '.zshrc') }, '/tmp/project');
  expect(reason).toMatch(/shell profile/);
});

test('blocks authorized_keys writes', () => {
  const reason = deterministicHardDeny(
    'write',
    { path: resolve(HOME, '.ssh/authorized_keys') },
    '/tmp/project',
  );
  expect(reason).toMatch(/authorized_keys/);
});

test('blocks TLS verification weakening in bash', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'curl -k https://example.com' },
    '/tmp/project',
  );
  expect(reason).toMatch(/certificate|TLS/);
});

test('blocks GIT_SSL_NO_VERIFY', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'GIT_SSL_NO_VERIFY=true git clone https://example.com/repo' },
    '/tmp/project',
  );
  expect(reason).toMatch(/TLS/);
});

test('blocks git config sslverify false', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'git config --global http.sslVerify false' },
    '/tmp/project',
  );
  expect(reason).toMatch(/TLS/);
});

test('blocks crontab modification', () => {
  const reason = deterministicHardDeny('bash', { command: 'crontab -e' }, '/tmp/project');
  expect(reason).toMatch(/persistence/);
});

test('allows crontab -l (read-only)', () => {
  const reason = deterministicHardDeny('bash', { command: 'crontab -l' }, '/tmp/project');
  expect(reason).toBeUndefined();
});

test('blocks systemctl enable', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'systemctl enable nginx' },
    '/tmp/project',
  );
  expect(reason).toMatch(/persistence/);
});

test('blocks recursive rm of home directory', () => {
  const reason = deterministicHardDeny('bash', { command: `rm -rf ${HOME}` }, '/tmp/project');
  expect(reason).toMatch(/home|root|system/);
});

test('blocks recursive rm of /etc', () => {
  const reason = deterministicHardDeny('bash', { command: 'rm -rf /etc' }, '/tmp/project');
  expect(reason).toMatch(/home|root|system/);
});

test('allows recursive rm of project directory', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'rm -rf /tmp/project/node_modules' },
    '/tmp/project',
  );
  expect(reason).toBeUndefined();
});

test('blocks chmod on /etc', () => {
  const reason = deterministicHardDeny('bash', { command: 'chmod 777 /etc/passwd' }, '/tmp/project');
  expect(reason).toMatch(/system.*permission/);
});

test('blocks safety-control file modification via tee', () => {
  const reason = deterministicHardDeny(
    'bash',
    { command: 'echo "{}" | tee ~/.pi/agent/sandbox.json' },
    '/tmp/project',
  );
  expect(reason).toMatch(/safety-control/);
});

test('allows safe bash commands', () => {
  expect(deterministicHardDeny('bash', { command: 'npm test' }, '/tmp/project')).toBeUndefined();
  expect(deterministicHardDeny('bash', { command: 'git status' }, '/tmp/project')).toBeUndefined();
  expect(
    deterministicHardDeny('bash', { command: 'echo hello' }, '/tmp/project'),
  ).toBeUndefined();
});

test('allows safe write operations', () => {
  expect(
    deterministicHardDeny('write', { path: '/tmp/project/src/app.ts' }, '/tmp/project'),
  ).toBeUndefined();
  expect(
    deterministicHardDeny('edit', { path: '/tmp/project/README.md' }, '/tmp/project'),
  ).toBeUndefined();
});

test('isRootHomeOrSystemPath identifies system roots', () => {
  expect(isRootHomeOrSystemPath('/', HOME)).toBe(true);
  expect(isRootHomeOrSystemPath(HOME, HOME)).toBe(true);
  expect(isRootHomeOrSystemPath('/etc', HOME)).toBe(true);
  expect(isRootHomeOrSystemPath('/usr', HOME)).toBe(true);
  expect(isRootHomeOrSystemPath('/usr/bin', HOME)).toBe(true);
});

test('isRootHomeOrSystemPath exempts home subtree', () => {
  expect(isRootHomeOrSystemPath(`${HOME}/.cache`, HOME)).toBe(false);
  expect(isRootHomeOrSystemPath(`${HOME}/projects/foo`, HOME)).toBe(false);
});

test('isRootHomeOrSystemPath exempts /var/home for Silverblue distros', () => {
  const silverblueHome = '/var/home/user';
  expect(isRootHomeOrSystemPath(`${silverblueHome}/.cache`, silverblueHome)).toBe(false);
  expect(isRootHomeOrSystemPath(silverblueHome, silverblueHome)).toBe(true);
});