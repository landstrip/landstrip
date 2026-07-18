// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { expect, test, vi } from 'vitest';

import {
  contextFromEnvironment,
  encodeLandstripContext,
  LANDSTRIP_CONTEXT_ENV,
  publishLandstripRuntime,
  type PiLandstripRuntimeV1,
  useLandstrip,
} from './api.ts';
import { createLandstripIntegration } from './index.ts';
import { temporaryDirectory } from './test-util.ts';

function extensionApi(): ExtensionAPI {
  const handlers = new Map<string, Set<(data: unknown) => void>>();
  return {
    events: {
      emit(channel: string, data: unknown) {
        for (const handler of handlers.get(channel) ?? []) handler(data);
      },
      on(channel: string, handler: (data: unknown) => void) {
        const channelHandlers = handlers.get(channel) ?? new Set();
        channelHandlers.add(handler);
        handlers.set(channel, channelHandlers);
        return () => channelHandlers.delete(handler);
      },
    },
  } as unknown as ExtensionAPI;
}

function runtime(): PiLandstripRuntimeV1 {
  return createLandstripIntegration({ registerBashTool: false });
}

test('discovers the runtime regardless of extension load order', () => {
  const beforePi = extensionApi();
  const beforeRuntime = runtime();
  const before = vi.fn();
  const disposeBefore = useLandstrip(beforePi, before);
  const unpublishBefore = publishLandstripRuntime(beforePi, beforeRuntime);
  expect(before).toHaveBeenCalledOnce();
  expect(before).toHaveBeenCalledWith(beforeRuntime);

  const afterPi = extensionApi();
  const afterRuntime = runtime();
  const unpublishAfter = publishLandstripRuntime(afterPi, afterRuntime);
  const after = vi.fn();
  const disposeAfter = useLandstrip(afterPi, after);
  expect(after).toHaveBeenCalledOnce();
  expect(after).toHaveBeenCalledWith(afterRuntime);

  disposeBefore();
  unpublishBefore();
  disposeAfter();
  unpublishAfter();
});

test('republishes the runtime when a new session starts', async () => {
  const pi = extensionApi();
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void> | void) | undefined;
  let sessionShutdown: (() => void) | undefined;
  Object.assign(pi, {
    registerFlag() {},
    registerCommand() {},
    registerTool() {},
    getFlag: () => true,
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
      if (event === 'session_shutdown') sessionShutdown = handler as typeof sessionShutdown;
    },
  });
  const integration = createLandstripIntegration({ registerBashTool: false });
  integration.register(pi);
  sessionShutdown?.();

  const discovered = vi.fn();
  const dispose = useLandstrip(pi, discovered);
  expect(discovered).not.toHaveBeenCalled();
  await sessionStart?.({}, {
    cwd: process.cwd(),
    hasUI: true,
    sessionManager: { getSessionId: () => 'next-session' },
    ui: { notify() {}, setStatus() {} },
  } as unknown as ExtensionContext);
  expect(discovered).toHaveBeenCalledWith(integration);
  dispose();
});

test('encodes and validates public subagent context', () => {
  const context = {
    version: 1,
    host: 'pi',
    role: 'subagent',
    sandbox: 'enabled',
    cwd: '/workspace',
    taskId: 'task-1',
    parentTaskId: 'task-0',
    agent: 'review',
    depth: 2,
  } as const;

  expect(
    contextFromEnvironment({ [LANDSTRIP_CONTEXT_ENV]: encodeLandstripContext(context) }),
  ).toEqual(context);
  expect(contextFromEnvironment({ [LANDSTRIP_CONTEXT_ENV]: 'invalid' })).toBeUndefined();
  expect(
    contextFromEnvironment({
      [LANDSTRIP_CONTEXT_ENV]: Buffer.from(JSON.stringify({ ...context, version: 2 })).toString(
        'base64url',
      ),
    }),
  ).toBeUndefined();
});

test('validates, deduplicates, and disposes worker extensions', () => {
  const directory = temporaryDirectory('pi-landstrip-api-');
  const entry = join(directory, 'extension.ts');
  writeFileSync(entry, 'export default function () {}\n');
  const integration = createLandstripIntegration({ registerBashTool: false });

  const disposeFirst = integration.registerWorkerExtension({
    id: 'test-extension',
    entry: pathToFileURL(entry).href,
  });
  const disposeSecond = integration.registerWorkerExtension({ id: 'test-extension', entry });
  expect(integration.getWorkerExtensions()).toEqual([{ id: 'test-extension', entry }]);

  disposeFirst();
  expect(integration.getWorkerExtensions()).toHaveLength(1);
  disposeSecond();
  expect(integration.getWorkerExtensions()).toEqual([]);
  expect(() =>
    integration.registerWorkerExtension({ id: 'relative', entry: 'extension.ts' }),
  ).toThrow('absolute path or file URL');
});

test('prepares generic processes with optional environment and path allowances', async () => {
  const controller = new AbortController();
  controller.abort();
  const integration = createLandstripIntegration({ registerBashTool: false });

  await expect(
    integration.prepareProcess({
      command: process.execPath,
      args: ['--version'],
      cwd: process.cwd(),
      ctx: {} as never,
      signal: controller.signal,
    }),
  ).rejects.toThrow('Task cancelled');
});

test('dispatches typed lifecycle events without letting listeners break the runtime', () => {
  const integration = createLandstripIntegration({ registerBashTool: false });
  const context = integration.getContext();
  const events: string[] = [];
  integration.on('subagent.start', (event) => events.push(event.context.role));
  integration.on('subagent.start', () => {
    throw new Error('listener failure');
  });

  const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  integration.emit({ type: 'subagent.start', context: { ...context, role: 'subagent' } });
  expect(events).toEqual(['subagent']);
  expect(error).toHaveBeenCalledWith('pi-landstrip: lifecycle listener failed: listener failure');
  error.mockRestore();
});
