// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { copyFileSync, cpSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import type { Model } from '@earendil-works/pi-ai';
import { expect, test } from 'vitest';

import { RpcProcess } from './rpc-process.ts';
import { resolvePiPackage } from './subagents.ts';
import { temporaryDirectory } from './test-util.ts';
import { serveWorkerAuth } from './worker-auth-channel.ts';
import { workerEnvironment } from './worker-environment.ts';

// Authenticated workers use inherited Unix file descriptors, not Windows pipes.
test.runIf(process.platform !== 'win32')(
  'packaged authenticated worker uses host Pi peers outside the installation tree',
  async () => {
    const root = temporaryDirectory('pi-landstrip-auth-startup-');
    const agentDir = join(root, 'agent');
    mkdirSync(agentDir);
    const workerEntry = join(root, 'worker-auth-entry.js');
    copyFileSync(new URL('./dist/worker-auth-entry.js', import.meta.url), workerEntry);
    writeFileSync(join(root, 'package.json'), JSON.stringify({ type: 'module' }));
    // Copy only the worker's declared runtime dependency; no Pi peers or symlinks.
    const require = createRequire(import.meta.url);
    cpSync(dirname(require.resolve('undici/package.json')), join(root, 'node_modules', 'undici'), {
      recursive: true,
    });
    const workerRequire = createRequire(workerEntry);
    for (const peer of ['@earendil-works/pi-ai', '@earendil-works/pi-coding-agent']) {
      for (const path of workerRequire.resolve.paths(peer) ?? []) {
        expect(existsSync(join(path, peer, 'package.json'))).toBe(false);
      }
    }
    const host = resolvePiPackage();
    if (!host) throw new Error('Cannot resolve host Pi for worker startup test');

    const requests: { url?: string; authorization?: string }[] = [];
    const server = createServer((request, response) => {
      requests.push({ url: request.url, authorization: request.headers.authorization });
      request.resume();
      response.writeHead(200, { 'Content-Type': 'text/event-stream' });
      response.end(
        `data: ${JSON.stringify({
          id: 'smoke',
          object: 'chat.completion.chunk',
          model: 'smoke',
          choices: [
            { index: 0, delta: { role: 'assistant', content: 'worker-ok' }, finish_reason: null },
          ],
        })}\n\ndata: ${JSON.stringify({
          id: 'smoke',
          object: 'chat.completion.chunk',
          model: 'smoke',
          choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
        })}\n\ndata: [DONE]\n\n`,
      );
    });
    let rpc: RpcProcess | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      });
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('Missing test server port');
      const model: Model<'openai-completions'> = {
        id: 'smoke',
        name: 'Smoke',
        provider: 'landstrip-test',
        api: 'openai-completions',
        baseUrl: `http://127.0.0.1:${address.port}/v1`,
        reasoning: false,
        input: ['text'],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 8192,
        maxTokens: 128,
      };
      let authRequests = 0;
      rpc = new RpcProcess({
        command: process.execPath,
        args: [
          '--experimental-import-meta-resolve',
          workerEntry,
          host.cliEntry,
          '--mode',
          'rpc',
          '--offline',
          '--no-session',
          '--no-extensions',
          '--no-skills',
          '--no-prompt-templates',
          '--no-themes',
          '--no-context-files',
          '--no-tools',
          '--provider',
          model.provider,
          '--model',
          `${model.provider}/${model.id}`,
          '--thinking',
          'off',
          '--system-prompt',
          'Reply briefly.',
        ],
        cwd: root,
        env: {
          ...workerEnvironment(process.env),
          PI_CODING_AGENT_DIR: agentDir,
          NO_PROXY: '127.0.0.1',
        },
        onAuthPipe: (pipe) =>
          serveWorkerAuth(pipe, async () => {
            authRequests += 1;
            return { model, auth: { auth: { apiKey: 'worker-auth-sentinel' } } };
          }),
        requestTimeoutMs: 20_000,
        settleTimeoutMs: 20_000,
      });
      await rpc.start();
      expect(await rpc.request('get_state')).toMatchObject({
        model: { id: model.id, provider: model.provider },
      });
      await rpc.prompt('Hello');
      expect(await rpc.getLastAssistantText()).toBe('worker-ok');
      expect(authRequests).toBeGreaterThan(1);
      expect(requests).toEqual([
        { url: '/v1/chat/completions', authorization: 'Bearer worker-auth-sentinel' },
      ]);
    } finally {
      try {
        await rpc?.stop();
      } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
  },
  60_000,
);
