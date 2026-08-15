// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { realpathSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { expect, test, vi } from 'vitest';

import {
  contextFromEnvironment,
  encodeLandstripContext,
  LANDSTRIP_CONTEXT_ENV,
  provideLandstripPermissionAsk,
  provideLandstripShell,
  publishLandstripRuntime,
  type PiLandstripRuntimeV2,
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

function runtime(): PiLandstripRuntimeV2 {
  return createLandstripIntegration({ registerBashTool: false });
}

function shellProvider(id: string) {
  return {
    id,
    prepare() {
      return { executable: 'shell', args: [], launcherEnv: {} };
    },
  };
}

function permissionAskProvider(id: string) {
  return {
    id,
    decide: vi.fn(async () => ({ decision: 'allow' as const })),
  };
}

function permissionAskRequest() {
  return {
    context: {
      version: 2,
      host: 'pi',
      role: 'primary',
      sandbox: 'enabled',
      cwd: '/workspace',
      depth: 0,
    } as const,
    toolName: 'bash',
    input: { command: 'git status' },
    permissions: [{ permission: 'bash', resource: 'git status' }],
  };
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

test('registers shell providers regardless of extension load order', () => {
  for (const providerFirst of [true, false]) {
    const pi = extensionApi();
    const landstrip = runtime();
    const provider = shellProvider(`nu-${providerFirst}`);
    let stopProvider: (() => void) | undefined;
    let stopRuntime: (() => void) | undefined;

    if (providerFirst) stopProvider = provideLandstripShell(pi, provider);
    stopRuntime = publishLandstripRuntime(pi, landstrip);
    if (!providerFirst) stopProvider = provideLandstripShell(pi, provider);

    expect(() => landstrip.registerShellProvider(shellProvider('other'))).toThrow(
      `Shell provider "${provider.id}" is already registered`,
    );
    stopProvider?.();
    const stopReplacement = landstrip.registerShellProvider(shellProvider('other'));
    stopReplacement();
    stopRuntime?.();
  }
});

test('keeps the current shell provider when replacement registration fails', () => {
  const pi = extensionApi();
  const firstRuntime = runtime();
  const secondRuntime = runtime();
  const stopProvider = provideLandstripShell(pi, shellProvider('nu'));
  const stopFirstRuntime = publishLandstripRuntime(pi, firstRuntime);
  const stopBlocker = secondRuntime.registerShellProvider(shellProvider('blocker'));

  expect(() => publishLandstripRuntime(pi, secondRuntime)).toThrow(
    'Shell provider "blocker" is already registered',
  );
  expect(() => firstRuntime.registerShellProvider(shellProvider('other'))).toThrow(
    'Shell provider "nu" is already registered',
  );

  stopProvider();
  const stopReplacement = firstRuntime.registerShellProvider(shellProvider('other'));
  stopReplacement();
  stopBlocker();
  stopFirstRuntime();
});

test('rejects invalid and conflicting shell provider registrations', () => {
  const landstrip = runtime();
  expect(() => landstrip.registerShellProvider(shellProvider(''))).toThrow('must not be empty');
  expect(() => landstrip.registerShellProvider(shellProvider('posix'))).toThrow('is reserved');

  const stop = landstrip.registerShellProvider(shellProvider('nu'));
  expect(() => landstrip.registerShellProvider(shellProvider('fish'))).toThrow(
    'Shell provider "nu" is already registered',
  );
  stop();
  stop();
  const stopFish = landstrip.registerShellProvider(shellProvider('fish'));
  stopFish();
});

test('registers permission ask providers regardless of extension load order', async () => {
  for (const providerFirst of [true, false]) {
    const pi = extensionApi();
    const landstrip = createLandstripIntegration({ registerBashTool: false });
    const provider = permissionAskProvider(`review-${providerFirst}`);
    let stopProvider: (() => void) | undefined;

    if (providerFirst) stopProvider = provideLandstripPermissionAsk(pi, provider);
    const stopRuntime = publishLandstripRuntime(pi, landstrip);
    if (!providerFirst) stopProvider = provideLandstripPermissionAsk(pi, provider);

    await expect(landstrip.resolvePermissionAsk(permissionAskRequest())).resolves.toEqual({
      decision: 'allow',
    });
    expect(provider.decide).toHaveBeenCalledWith(permissionAskRequest());
    stopProvider?.();
    await expect(landstrip.resolvePermissionAsk(permissionAskRequest())).resolves.toEqual({
      decision: 'abstain',
    });
    stopRuntime();
  }
});

test('rejects invalid and conflicting permission ask providers', () => {
  const landstrip = createLandstripIntegration({ registerBashTool: false });
  expect(() => landstrip.registerPermissionAskProvider(permissionAskProvider(''))).toThrow(
    'must not be empty',
  );

  const stop = landstrip.registerPermissionAskProvider(permissionAskProvider('review'));
  expect(() => landstrip.registerPermissionAskProvider(permissionAskProvider('other'))).toThrow(
    'Permission ask provider "review" is already registered',
  );
  stop();
  stop();
  const stopOther = landstrip.registerPermissionAskProvider(permissionAskProvider('other'));
  stopOther();
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
    version: 2,
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
      [LANDSTRIP_CONTEXT_ENV]: Buffer.from(JSON.stringify({ ...context, version: 1 })).toString(
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
  expect(integration.getWorkerExtensions()).toEqual([
    { id: 'test-extension', entry: realpathSync(entry) },
  ]);

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
