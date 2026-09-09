// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, expect, test, vi } from 'vitest';

import {
  createLandstripIntegration,
  type LandstripIntegration,
  type LandstripRpcWorkerOptions,
} from './index.ts';
import { SubagentRuntime } from './subagents.ts';
import { temporaryDirectory } from './test-util.ts';
const secret = 'AUTH_SECRET_SENTINEL';
const selected = {
  provider: 'github-copilot',
  id: 'selected',
  baseUrl: 'https://api.githubcopilot.com',
};
const unrelated = { provider: 'other', id: 'other', baseUrl: 'https://unrelated.example' };

function fixture(baseUrl: string) {
  const cwd = temporaryDirectory('pi-landstrip-endpoint-');
  const sessionDir = join(cwd, 'session');
  mkdirSync(sessionDir);
  const getProviderAuth = vi.fn(async () => ({
    auth: { baseUrl, apiKey: secret, headers: { Authorization: secret } },
    env: { SECRET_ENV: secret },
    source: secret,
  }));
  const notify = vi.fn();
  const appendEntry = vi.fn();
  const emit = vi.fn();
  const prepare = vi.fn(async (_options: LandstripRpcWorkerOptions) => {
    throw new Error('fixture prepared');
  });
  const ctx = {
    cwd,
    mode: 'rpc',
    hasUI: true,
    model: unrelated,
    modelRegistry: {
      getAll: () => [selected, unrelated],
      isUsingOAuth: (model: { provider: string }) => model.provider === selected.provider,
      getProviderAuth,
    },
    sessionManager: { getSessionId: () => 'endpoint-session' },
    ui: { notify },
  } as unknown as ExtensionContext;
  const runtime = new SubagentRuntime(
    {
      getActiveTools: () => ['read'],
      getThinkingLevel: () => 'off',
      appendEntry,
    } as unknown as ExtensionAPI,
    { prepareRpcWorker: prepare, emit } as unknown as LandstripIntegration,
  ) as unknown as {
    runTask(
      task: unknown,
      agent: unknown,
      prompt: string,
      catalog: unknown,
      ctx: ExtensionContext,
      signal: AbortSignal,
      update: () => void,
    ): Promise<string>;
  };
  const agent = {
    name: 'test',
    description: 'Test',
    prompt: 'Test.',
    mode: 'subagent',
    hidden: false,
    permissions: [],
    providerOptions: {},
    model: `${selected.provider}/${selected.id}` as string | undefined,
  };
  const task = {
    id: 'endpoint-task',
    agent: 'test',
    depth: 1,
    sessionDir,
    state: 'queued',
    error: undefined,
  };
  const run = (signal = new AbortController().signal) =>
    runtime.runTask(task, agent, 'Test.', { permissions: [] }, ctx, signal, () => {});
  const output = () =>
    JSON.stringify({
      task,
      entries: appendEntry.mock.calls,
      events: emit.mock.calls,
      notifications: notify.mock.calls,
    });
  return { cwd, ctx, prepare, run, output };
}

async function workerOutput(
  launch: Awaited<ReturnType<LandstripIntegration['prepareRpcWorker']>>,
  timeout?: number,
) {
  const child = launch.spawn(launch.command, launch.args, {}) as ChildProcessWithoutNullStreams;
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const timer =
    timeout === undefined ? undefined : setTimeout(() => child.kill('SIGKILL'), timeout);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    return { code, stdout, stderr };
  } finally {
    clearTimeout(timer);
  }
}

afterEach(() => vi.unstubAllEnvs());

const sandboxTest = test.runIf(['linux', 'darwin', 'win32'].includes(process.platform));
const workerTimeout = process.platform === 'win32' ? 60_000 : 12_000;
const testTimeout = process.platform === 'win32' ? 240_000 : 30_000;
sandboxTest.each([false, true])(
  'real worker endpoint grant respects explicit denial: %s',
  async (denied) => {
    const agentDir = temporaryDirectory('pi-landstrip-endpoint-agent-');
    vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
    const authPath = join(agentDir, 'auth.json');
    writeFileSync(authPath, 'parent-auth-secret');
    writeFileSync(
      join(agentDir, 'sandbox.json'),
      JSON.stringify({
        enabled: true,
        network: { allowedDomains: [], deniedDomains: denied ? ['127.0.0.1'] : [] },
        filesystem: { allowRead: [authPath], allowWrite: [agentDir, authPath] },
      }),
    );
    let requests = 0;
    const server = createServer((_request, response) => {
      requests += 1;
      response.end('effective-endpoint-ok');
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === 'string')
        throw new Error('Missing fixture server address');
      const baseUrl = `http://127.0.0.1:${address.port}/v1`;
      const f = fixture(baseUrl);
      const prompts = vi.fn(async () => undefined);
      f.ctx.ui.select = prompts;
      f.ctx.ui.custom = prompts as ExtensionContext['ui']['custom'];
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: f.cwd });
      f.prepare.mockImplementation(async (options) => {
        expect(options.domains).toEqual(['api.githubcopilot.com', 'api.github.com', '127.0.0.1']);
        expect(options.protectedPaths).toEqual(
          expect.arrayContaining([authPath, `${authPath}.lock`]),
        );
        const launch = await integration.prepareRpcWorker({
          ...options,
          command: process.execPath,
          args: [
            '--input-type=module',
            '-e',
            `
          import http from 'node:http';
          import { readFileSync, openSync, closeSync, mkdirSync } from 'node:fs';
          for (const access of [
            () => readFileSync(${JSON.stringify(authPath)}),
            () => closeSync(openSync(${JSON.stringify(authPath)}, 'a')),
            () => mkdirSync(${JSON.stringify(`${authPath}.lock`)}),
          ]) {
            let denied = false;
            try { access(); } catch (error) {
              if (!['EACCES', 'EPERM'].includes(error.code)) throw error;
              denied = true;
            }
            if (!denied) throw new Error('Parent auth access permitted');
          }
          const proxy = new URL(process.env.HTTP_PROXY);
          const authorization = Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64');
          http.get({ hostname: proxy.hostname, port: proxy.port, path: ${JSON.stringify(baseUrl)}, headers: { 'Proxy-Authorization': 'Basic ' + authorization } }, response => {
            let body = '';
            response.on('data', chunk => body += chunk);
            response.on('end', () => console.log(JSON.stringify({ status: response.statusCode, body })));
          }).on('error', () => { process.exitCode = 1; });
        `,
          ],
          env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            WINDIR: process.env.WINDIR,
            TMPDIR: options.env.TMPDIR,
            TMP: options.env.TMP,
            TEMP: options.env.TEMP,
          },
        });
        try {
          expect(integration.getContext(f.ctx).sandbox).toBe('enabled');
          const { code, stdout, stderr } = await workerOutput(launch, workerTimeout);
          expect({ code, stderr }).toEqual({ code: 0, stderr: '' });
          const response = JSON.parse(stdout);
          expect(response.status).toBe(denied ? 403 : 200);
          if (!denied) expect(response.body).toBe('effective-endpoint-ok');
          expect(requests).toBe(denied ? 0 : 1);
          expect(prompts).not.toHaveBeenCalled();
        } finally {
          await launch.dispose();
        }
        throw new Error('fixture prepared');
      });
      await expect(f.run()).rejects.toThrow('fixture prepared');
      expect(f.output()).not.toContain(secret);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
  testTimeout,
);
