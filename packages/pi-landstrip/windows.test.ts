// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type ChildProcess, execFile } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, parse } from 'node:path';
import { promisify } from 'node:util';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { getShellConfig } from '@earendil-works/pi-coding-agent';
import { binaryPath } from '@landstrip/landstrip';
import { expect, it } from 'vitest';

import { createLandstripIntegration } from './index.ts';
import { temporaryDirectory } from './test-util.ts';

const execFileAsync = promisify(execFile);
const windowsIt = it.runIf(process.platform === 'win32');

interface ProcessResult {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

function gitBash(): string {
  const shell = join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'bin', 'bash.exe');
  expect(existsSync(shell), `Git Bash was not found at ${shell}`).toBe(true);
  return shell;
}

function filesystemPolicy(directory: string, readPaths: string[] = []) {
  return {
    denyRead: [parse(directory).root],
    allowRead: [directory, ...readPaths],
    allowWrite: [directory],
    denyWrite: [],
  };
}

function collect(child: ChildProcess): Promise<ProcessResult> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let error: Error | undefined;
    child.stdout?.on('data', (data: Buffer) => (stdout += data.toString()));
    child.stderr?.on('data', (data: Buffer) => (stderr += data.toString()));
    child.once('error', (cause) => (error = cause));
    child.once('close', (code) => resolve({ code, stdout, stderr, error }));
  });
}

async function integrationFor(cwd: string) {
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void> | void) | undefined;
  const pi = {
    registerFlag() {},
    registerCommand() {},
    registerTool() {},
    getFlag: () => false,
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
  } as unknown as ExtensionAPI;
  const ctx = {
    cwd,
    hasUI: false,
    mode: 'rpc',
    isProjectTrusted: () => true,
    sessionManager: { getSessionId: () => 'windows-e2e' },
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext;
  const integration = createLandstripIntegration({ registerBashTool: false });
  integration.register(pi);
  await sessionStart?.({}, ctx);
  return { ctx, integration };
}

async function runPolicy(
  directory: string,
  policy: object,
  command: string,
  args: string[],
): Promise<ProcessResult> {
  const policyPath = join(directory, 'policy.json');
  writeFileSync(policyPath, JSON.stringify(policy));
  try {
    const result = await execFileAsync(binaryPath(), ['-p', policyPath, command, ...args], {
      cwd: directory,
      timeout: 20_000,
      windowsHide: true,
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (cause) {
    const error = cause as Error & { code?: number; stdout?: string; stderr?: string };
    return {
      code: typeof error.code === 'number' ? error.code : null,
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? '',
      error,
    };
  }
}

windowsIt(
  'runs Pi-selected Git Bash in a deep standard AppContainer workspace',
  async () => {
    const root = temporaryDirectory('pi-landstrip-windows-');
    const workspace = join(root, 'work', 'project', 'deep');
    mkdirSync(join(workspace, '.pi'), { recursive: true });
    writeFileSync(join(workspace, 'input.txt'), 'allowed');
    writeFileSync(join(root, 'work', 'secret.txt'), 'secret');
    writeFileSync(
      join(workspace, '.pi', 'sandbox.json'),
      JSON.stringify({ windows: { appContainerMode: 'standard', allowLoopback: false } }),
    );

    const { shell, args } = getShellConfig(gitBash());
    const { ctx, integration } = await integrationFor(workspace);
    const launch = await integration.prepareProcess({
      command: shell,
      args: [...args, 'cat input.txt && printf written > output.txt && cat output.txt'],
      cwd: workspace,
      ctx,
    });
    try {
      const child = launch.spawn(launch.command, launch.args, {
        cwd: launch.cwd,
        env: launch.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const result = await collect(child as ChildProcess);

      expect(result.error?.message ?? '').not.toContain('ENOTSUP');
      expect(result.code, result.stderr).toBe(0);
      expect(result.stdout).toContain('allowed');
      expect(result.stdout).toContain('written');

      const denied = await integration.prepareProcess({
        command: shell,
        args: [...args, 'cat ../../secret.txt'],
        cwd: workspace,
        ctx,
      });
      try {
        const deniedResult = await collect(
          denied.spawn(denied.command, denied.args, {
            cwd: denied.cwd,
            env: denied.env,
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true,
          }) as ChildProcess,
        );
        expect(deniedResult.code).not.toBe(0);
        expect(deniedResult.stdout).not.toContain('secret');
        expect(deniedResult.stderr).toMatch(/Access is denied|Permission denied/i);
      } finally {
        await denied.dispose();
      }
    } finally {
      await launch.dispose();
    }
  },
  30_000,
);

windowsIt('does not silently downgrade LPAC when Git Bash cannot start', async () => {
  const directory = temporaryDirectory('landstrip-windows-lpac-');
  const { shell, args } = getShellConfig(gitBash());
  const result = await runPolicy(
    directory,
    {
      network: { allowNetwork: false },
      filesystem: filesystemPolicy(directory, [dirname(dirname(shell))]),
      windows: { appContainerMode: 'lpac', allowLoopback: false },
    },
    shell,
    [...args, 'echo unexpected-lpac-success'],
  );
  expect(result.code).not.toBe(0);
  expect(result.stdout).not.toContain('unexpected-lpac-success');
});

windowsIt('keeps loopback blocked unless its explicit exemption is enabled', async () => {
  const directory = temporaryDirectory('landstrip-windows-loopback-');
  const server = createServer((_request, response) => response.end('loopback-ok'));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('test server has no TCP address');
  const script = `fetch('http://127.0.0.1:${address.port}', { signal: AbortSignal.timeout(3000) }).then(async response => process.stdout.write(await response.text()))`;
  const policy = (allowLoopback: boolean) => ({
    network: { allowNetwork: false },
    filesystem: filesystemPolicy(directory, [process.execPath]),
    windows: { appContainerMode: 'standard', allowLoopback },
  });

  try {
    const blocked = await runPolicy(directory, policy(false), process.execPath, ['-e', script]);
    expect(blocked.code).not.toBe(0);
    expect(blocked.stdout).not.toContain('loopback-ok');

    const allowed = await runPolicy(directory, policy(true), process.execPath, ['-e', script]);
    expect(allowed.code, allowed.stderr).toBe(0);
    expect(allowed.stdout).toBe('loopback-ok');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
