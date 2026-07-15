// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { binaryPath } from '@landstrip/landstrip';
import { describe, expect, it, vi } from 'vitest';

import { RpcProcess, type RpcChildProcess, type RpcRecord } from './rpc-process.ts';

class FakeChild extends EventEmitter implements RpcChildProcess {
  public readonly stdin = new PassThrough();
  public readonly stdout = new PassThrough();
  public readonly stderr = new PassThrough();
  public exitCode: number | null = null;
  public signalCode: NodeJS.Signals | null = null;
  public readonly signals: Array<NodeJS.Signals | number | undefined> = [];

  public kill(signal?: NodeJS.Signals | number): boolean {
    this.signals.push(signal);
    return true;
  }

  public launch(): void {
    this.emit('spawn');
  }

  public exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.exitCode = code;
    this.signalCode = signal;
    this.emit('exit', code, signal);
  }
}

function harness(options: Record<string, unknown> = {}) {
  const child = new FakeChild();
  const process = new RpcProcess({
    command: 'custom-pi',
    args: ['rpc', '--flag'],
    spawn: (command, args, spawnOptions) => {
      expect(command).toBe('custom-pi');
      expect(args).toEqual(['rpc', '--flag']);
      expect(spawnOptions.stdio).toEqual(['pipe', 'pipe', 'pipe']);
      queueMicrotask(() => child.launch());
      return child;
    },
    requestTimeoutMs: 100,
    settleTimeoutMs: 100,
    stopTimeoutMs: 5,
    killTimeoutMs: 5,
    ...options,
  });
  const commands: RpcRecord[] = [];
  const inputChunks: string[] = [];
  let input = '';
  child.stdin.on('data', (chunk: Buffer) => {
    inputChunks.push(chunk.toString());
    input += chunk.toString();
    while (input.includes('\n')) {
      const newline = input.indexOf('\n');
      commands.push(JSON.parse(input.slice(0, newline)) as RpcRecord);
      input = input.slice(newline + 1);
    }
  });
  return { child, process, commands, inputChunks };
}

async function started(options: Record<string, unknown> = {}) {
  const value = harness(options);
  await value.process.start();
  return value;
}

function respond(child: FakeChild, command: RpcRecord, data?: unknown): void {
  child.stdout.write(
    `${JSON.stringify({
      type: 'response',
      id: command.id,
      command: command.type,
      success: true,
      ...(data === undefined ? {} : { data }),
    })}\n`,
  );
}

describe('RpcProcess', () => {
  it('correlates concurrent responses by ID', async () => {
    const { child, process, commands } = await started();
    const first = process.request<{ value: number }>('first');
    const second = process.request<{ value: number }>('second');
    await vi.waitFor(() => expect(commands).toHaveLength(2));
    expect(commands[0]?.id).not.toBe(commands[1]?.id);

    respond(child, commands[1], { value: 2 });
    respond(child, commands[0], { value: 1 });
    await expect(first).resolves.toEqual({ value: 1 });
    await expect(second).resolves.toEqual({ value: 2 });
  });

  it('uses only LF framing and accepts CRLF and split UTF-8 chunks', async () => {
    const { child, process, commands, inputChunks } = await started();
    const events: RpcRecord[] = [];
    process.onEvent((event) => events.push(event));
    const request = process.request('framing');
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    expect(inputChunks.join('')).toMatch(/\n$/);
    expect(inputChunks.join('')).not.toContain('\r\n');
    respond(child, commands[0]);
    await request;
    const separator = 'before\u2028middle\u2029after';
    const record = Buffer.from(`${JSON.stringify({ type: 'message', text: separator })}\r\n`);
    const split = record.indexOf(Buffer.from('middle')) + 2;
    child.stdout.write(record.subarray(0, split));
    child.stdout.write(record.subarray(split));

    await vi.waitFor(() => expect(events).toHaveLength(1));
    expect(events[0]?.text).toBe(separator);
  });

  it('accepts valid RPC frames larger than one MiB', async () => {
    const { child, process } = await started();
    const events: RpcRecord[] = [];
    process.onEvent((event) => events.push(event));
    const text = 'x'.repeat(1024 * 1024);

    child.stdout.write(`${JSON.stringify({ type: 'message', text })}\n`);

    await vi.waitFor(() => expect(events).toHaveLength(1));
    expect(events[0]?.text).toBe(text);
  });

  it('waits for prompt acceptance and agent_settled', async () => {
    const { child, process, commands } = await started();
    let completed = false;
    const prompt = process.prompt('Do work').then(() => {
      completed = true;
    });
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    respond(child, commands[0]);
    await Promise.resolve();
    expect(completed).toBe(false);
    child.stdout.write('{"type":"agent_settled"}\n');
    await prompt;
    expect(completed).toBe(true);
  });

  it('serializes concurrent prompts so one settled event completes one prompt', async () => {
    const { child, process, commands } = await started();
    const first = process.prompt('First');
    const second = process.prompt('Second');
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    respond(child, commands[0]);
    child.stdout.write('{"type":"agent_settled"}\n');
    await first;

    await vi.waitFor(() => expect(commands).toHaveLength(2));
    respond(child, commands[1]);
    child.stdout.write('{"type":"agent_settled"}\n');
    await second;
  });

  it('handles extension UI requests and retrieves assistant text', async () => {
    const callback = vi.fn(async () => ({ confirmed: true }) as const);
    const { child, process, commands } = await started({ onExtensionUiRequest: callback });
    child.stdout.write(
      '{"type":"extension_ui_request","id":"ui-1","method":"confirm","title":"Run?"}\n',
    );
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    expect(commands[0]).toEqual({
      type: 'extension_ui_response',
      id: 'ui-1',
      confirmed: true,
    });

    const text = process.getLastAssistantText();
    await vi.waitFor(() => expect(commands).toHaveLength(2));
    respond(child, commands[1], { text: 'Finished' });
    await expect(text).resolves.toBe('Finished');
  });

  it('cancels interactive UI requests when no callback is configured', async () => {
    const { child, commands } = await started();
    child.stdout.write(
      '{"type":"extension_ui_request","id":"ui-1","method":"input","title":"Value?"}\n',
    );

    await vi.waitFor(() => expect(commands).toHaveLength(1));
    expect(commands[0]).toEqual({
      type: 'extension_ui_response',
      id: 'ui-1',
      cancelled: true,
    });
  });

  it('handles stdin errors without crashing and rejects pending requests', async () => {
    const { child, process, commands } = await started();
    const errors: Error[] = [];
    process.onError((error) => errors.push(error));
    const pending = process.request('work');
    await vi.waitFor(() => expect(commands).toHaveLength(1));

    child.stdin.emit('error', new Error('write EPIPE'));

    await expect(pending).rejects.toThrow('RPC stdin error: write EPIPE');
    expect(errors[0]?.message).toContain('RPC stdin error: write EPIPE');
  });

  it('rejects oversized unterminated stdout frames', async () => {
    const { child, process } = await started({ stdoutFrameLimitBytes: 16 });
    const errors: Error[] = [];
    process.onError((error) => errors.push(error));

    child.stdout.write('x'.repeat(17));

    await vi.waitFor(() => expect(errors).toHaveLength(1));
    await expect(process.request('work')).rejects.toThrow('RPC stdout frame exceeds 16 bytes');
  });

  it('bounds stderr and rejects requests when the child exits', async () => {
    const { child, process, commands } = await started({ stderrLimitBytes: 5 });
    child.stderr.write('123456789');
    await vi.waitFor(() => expect(process.getStderr()).toBe('56789'));
    const pending = process.request('work');
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    child.exit(7);
    await expect(pending).rejects.toThrow('code 7. Stderr: 56789');
  });

  it('ignores stray non-JSON stdout without rejecting pending work', async () => {
    const { child, process, commands } = await started();
    const errors: Error[] = [];
    process.onError((error) => errors.push(error));
    const pending = process.request('work');
    await vi.waitFor(() => expect(commands).toHaveLength(1));
    child.stdout.write('not-json\n');
    child.stdout.write('{"unstructured":true}\n');
    respond(child, commands[0]);
    await expect(pending).resolves.toBeUndefined();
    expect(errors).toEqual([]);
  });

  it('aborts before graceful shutdown and escalates signals', async () => {
    const { child, process, commands } = await started();
    const stopping = process.stop();
    await vi.waitFor(() => expect(commands[0]?.type).toBe('abort'));
    respond(child, commands[0]);
    await vi.waitFor(() => expect(child.signals).toEqual(['SIGTERM', 'SIGKILL']));
    child.exit(null, 'SIGKILL');
    await stopping;
  });

  it('ignores late events from a stopped child after restart', async () => {
    const first = new FakeChild();
    const second = new FakeChild();
    const children = [first, second];
    const secondCommands: RpcRecord[] = [];
    second.stdin.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().trim().split('\n')) {
        if (line) secondCommands.push(JSON.parse(line) as RpcRecord);
      }
    });
    const process = new RpcProcess({
      command: 'custom-pi',
      spawn: () => {
        const child = children.shift();
        if (!child) throw new Error('unexpected spawn');
        queueMicrotask(() => child.launch());
        return child;
      },
      requestTimeoutMs: 100,
      stopTimeoutMs: 1,
      killTimeoutMs: 1,
    });
    await process.start();
    await process.stop();
    await process.start();
    const pending = process.request('work');
    await vi.waitFor(() => expect(secondCommands).toHaveLength(1));

    first.exit(1);
    respond(second, secondCommands[0]);

    await expect(pending).resolves.toBeUndefined();
  });
});

it.runIf(process.platform === 'linux' || process.platform === 'darwin')(
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
        filesystem: { denyRead: [], allowRead: [], allowWrite: [root], denyWrite: [] },
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
    const rpc = new RpcProcess({
      command: binaryPath(),
      args: [
        '-p',
        policyPath,
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
      requestTimeoutMs: 20_000,
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
  30_000,
);
