// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, parse } from 'node:path';
import { fileURLToPath } from 'node:url';

import { binaryPath } from '@landstrip/landstrip-api';
import { expect, it } from 'vitest';

import { RpcProcess } from './rpc-process.ts';

it.runIf(['linux', 'darwin', 'win32'].includes(process.platform))(
  'starts a real Pi RPC worker inside Landstrip',
  async () => {
    const root = mkdtempSync(join(tmpdir(), 'pi-landstrip-rpc-'));
    const agentDir = join(root, 'agent');
    mkdirSync(agentDir);
    writeFileSync(join(agentDir, 'settings.json'), JSON.stringify({ packages: [] }));
    const policyPath = join(root, 'policy.json');
    writeFileSync(
      policyPath,
      JSON.stringify({
        network: { allowNetwork: false },
        filesystem: {
          denyRead: process.platform === 'win32' ? [parse(root).root] : [],
          allowRead:
            process.platform === 'win32'
              ? [process.cwd(), root, process.execPath]
              : [process.cwd()],
          allowWrite: [root],
          denyWrite: [],
        },
        windows: { appContainerMode: 'standard', allowLoopback: false },
      }),
    );
    const packageDir = dirname(fileURLToPath(import.meta.url));
    const piEntry = fileURLToPath(import.meta.resolve('@earendil-works/pi-coding-agent'));
    const piCli = join(dirname(piEntry), 'cli.js');
    const workerConfig = Buffer.from(
      JSON.stringify({
        rules: [],
        task: { id: 'native-test', description: 'Native test', depth: 0 },
        taskEnabled: false,
      }),
    ).toString('base64url');
    // Windows AppContainer setup and teardown propagate ACLs through the package tree.
    const rpc = new RpcProcess({
      command: binaryPath(),
      args: [
        'run',
        '-p',
        policyPath,
        '--',
        process.execPath,
        piCli,
        '--mode',
        'rpc',
        '--no-session',
        '--no-approve',
        '--offline',
        '--extension',
        join(packageDir, 'index.ts'),
        '--tools',
        'read',
      ],
      cwd: root,
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: agentDir,
        PI_LANDSTRIP_WORKER: workerConfig,
        PI_OFFLINE: '1',
        JITI_FS_CACHE: 'false',
      },
      requestTimeoutMs: 60_000,
      stopTimeoutMs: process.platform === 'win32' ? 60_000 : 1_000,
    });
    try {
      await rpc.start();
      const state = await rpc.request<{ sessionId: string }>('get_state');
      expect(state.sessionId).toBeTruthy();
    } finally {
      await rpc.stop();
      rmSync(root, { recursive: true, force: true });
    }
  },
  process.platform === 'win32' ? 130_000 : 75_000,
);
