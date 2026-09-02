// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  type ExtensionAPI,
  type ExtensionContext,
  initTheme,
  SessionManager,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { visibleWidth } from '@earendil-works/pi-tui';
import { expect, test, vi } from 'vitest';

import { loadAgentCatalog } from './agents.ts';
import { contextFromEnvironment, LANDSTRIP_CONTEXT_ENV } from './api.ts';
import type { LandstripIntegration } from './index.ts';
import {
  boundTaskOutput,
  isSupportedPiVersion,
  registerSubagentWorker,
  renderTaskResult,
  renderTaskTree,
  resolvePiPackage,
  SubagentRuntime,
} from './subagents.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';
import { PermissionPromptCoordinator } from './util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-tasks-');
}

test('propagates registered extensions and public context to workers', async () => {
  const cwd = temporaryDirectory();
  const sessionDir = join(cwd, 'session');
  const extensionEntry = join(cwd, 'extension.ts');
  mkdirSync(sessionDir, { recursive: true });
  writeFileSync(extensionEntry, 'export default function () {}\n');
  let prepared:
    | {
        args: readonly string[];
        env: NodeJS.ProcessEnv;
        readPaths: readonly string[];
        writePaths: readonly string[];
        domains?: readonly string[];
      }
    | undefined;
  const integration = {
    getWorkerExtensions: () => [{ id: 'test', entry: extensionEntry }],
    getContext: () => ({
      version: 2,
      host: 'pi',
      role: 'primary',
      sandbox: 'enabled',
      cwd,
      sessionId: 'root-session',
      depth: 0,
    }),
    async prepareRpcWorker(options: typeof prepared) {
      prepared = options;
      throw new Error('stop after preparation');
    },
  } as unknown as LandstripIntegration;
  const pi = {
    getActiveTools: () => ['read', 'bash', 'custom_inspect'],
    getThinkingLevel: () => 'medium',
  } as unknown as ExtensionAPI;
  const runtime = new SubagentRuntime(pi, integration);
  const privateRuntime = runtime as unknown as {
    piInvocation(): { command: string; args: string[] };
    validatePiInvocation(): void;
    defaultWorker(
      task: unknown,
      agent: unknown,
      rules: unknown,
      ctx: ExtensionContext,
      signal: AbortSignal,
      onRequest: () => Promise<undefined>,
    ): Promise<unknown>;
  };
  privateRuntime.piInvocation = () => ({ command: process.execPath, args: ['pi.js'] });
  privateRuntime.validatePiInvocation = () => undefined;
  const ctx = {
    cwd,
    model: { provider: 'test', id: 'model', baseUrl: 'https://api.test.example/v1' },
    modelRegistry: {
      getAll: () => [
        { provider: 'other', id: 'provider-model', baseUrl: 'https://api.other.example' },
        { provider: 'local', id: 'local-model', baseUrl: 'http://[0:0:0:0:0:0:0:1]:11434/v1' },
        { provider: 'invalid', id: 'invalid-model', baseUrl: 'not a url' },
      ],
    },
    ui: { notify() {} },
    sessionManager: { getSessionId: () => 'root-session' },
  } as unknown as ExtensionContext;

  await expect(
    privateRuntime.defaultWorker(
      {
        id: 'task-1',
        description: 'Review',
        depth: 2,
        parentTaskId: 'task-0',
        parentSessionId: 'root-session',
        agent: 'review',
        state: 'running',
        background: false,
        sessionDir,
      },
      {
        name: 'review',
        prompt: 'Review.',
        mode: 'subagent',
        hidden: false,
        permissions: [],
        providerOptions: {},
        model: 'other/provider-model',
      },
      [
        { permission: '*', pattern: '*', action: 'allow' },
        { permission: '*', pattern: '*', action: 'deny' },
        { permission: 'read', pattern: '*', action: 'allow' },
      ],
      ctx,
      new AbortController().signal,
      async () => undefined,
    ),
  ).rejects.toThrow('stop after preparation');

  expect(prepared?.args).toContain(extensionEntry);
  expect(prepared?.readPaths).toContain(extensionEntry);
  expect(prepared?.readPaths).toContain(cwd);
  expect(prepared?.readPaths.some((path) => path.endsWith('landstrip.json'))).toBe(true);
  expect(prepared?.domains).toEqual(['api.other.example']);
  expect(prepared?.writePaths.some((path) => path.endsWith('auth.json'))).toBe(true);
  expect(prepared?.writePaths.some((path) => path.endsWith('auth.json.lock'))).toBe(true);
  expect(prepared?.writePaths.some((path) => path.endsWith('settings.json.lock'))).toBe(true);
  const toolsIndex = prepared?.args.indexOf('--tools') ?? -1;
  expect(prepared?.args[toolsIndex + 1]).toBe('read');
  const context = contextFromEnvironment({
    [LANDSTRIP_CONTEXT_ENV]: prepared?.env[LANDSTRIP_CONTEXT_ENV],
  });
  expect(context).toMatchObject({
    role: 'subagent',
    sandbox: 'enabled',
    taskId: 'task-1',
    parentTaskId: 'task-0',
    agent: 'review',
    depth: 2,
  });
  expect(context).not.toHaveProperty('rules');
});

test('renders task result envelopes', () => {
  expect(renderTaskResult('task-1', 'completed', 'Result text')).toBe(
    '<task id="task-1" state="completed">\n<task_result>\nResult text\n</task_result>\n</task>',
  );
  expect(renderTaskResult('task-2', 'error', 'Failure')).toContain('<task_error>\nFailure');
  expect(renderTaskResult('task-3', 'queued', 'Waiting')).toContain('state="queued"');
});

test('bounds task output and preserves the full artifact', () => {
  const directory = temporaryDirectory();
  const artifactPath = join(directory, 'output.txt');
  const output = 'start🙂'.repeat(100) + 'finished';
  const bounded = boundTaskOutput(output, artifactPath, 256);

  expect(Buffer.byteLength(bounded)).toBeLessThanOrEqual(256);
  expect(bounded).toContain(`[Task output truncated; full output: ${artifactPath}]`);
  expect(bounded).toContain('start');
  expect(bounded).toContain('finished');
  expect(bounded).not.toContain('�');
  expect(readFileSync(artifactPath, 'utf8')).toBe(output);
});

test('renders nested tasks as a tree', () => {
  expect(
    renderTaskTree([
      {
        id: 'parent-task',
        agent: 'general',
        description: 'Coordinate work',
        state: 'running',
      },
      {
        id: 'first-child',
        parentTaskId: 'parent-task',
        agent: 'explore',
        description: 'Inspect frontend',
        state: 'completed',
      },
      {
        id: 'second-child',
        parentTaskId: 'parent-task',
        agent: 'general',
        description: 'Implement graph',
        state: 'queued',
      },
      {
        id: 'grandchild-task',
        parentTaskId: 'second-child',
        agent: 'explore',
        description: 'Check API',
        state: 'error',
      },
      {
        id: 'other-root',
        agent: 'general',
        description: 'Independent work',
        state: 'cancelled',
      },
    ]),
  ).toBe(
    [
      '├─ running     @general  Coordinate work  parent-t',
      '│  ├─ completed   @explore  Inspect frontend  first-ch',
      '│  └─ queued      @general  Implement graph  second-c',
      '│     └─ error       @explore  Check API  grandchi',
      '└─ cancelled   @general  Independent work  other-ro',
    ].join('\n'),
  );
});

test('renders active task progress without completed siblings', () => {
  type WidgetFactory = (
    tui: unknown,
    theme: {
      fg: (_color: string, value: string) => string;
      bold: (value: string) => string;
    },
  ) => { render(width: number): string[] };

  let widget: WidgetFactory | undefined;
  let cleared = false;
  const pi = {
    getActiveTools: () => ['task'],
    setActiveTools() {},
  } as unknown as ExtensionAPI;
  const runtime = new SubagentRuntime(pi, {} as LandstripIntegration);
  runtime.setMaxSubagents(4);
  const privateRuntime = runtime as unknown as {
    tasks: Map<string, unknown>;
    updateTaskWidget(ctx: ExtensionContext): void;
  };
  const root = {
    id: 'root',
    parentSessionId: 'parent',
    agent: 'general',
    description: 'Coordinate work',
    depth: 0,
    state: 'completed',
  };
  const completedSibling = {
    id: 'completed-sibling',
    parentSessionId: 'parent',
    parentTaskId: root.id,
    agent: 'scout',
    description: 'Old completed work',
    depth: 1,
    state: 'completed',
  };
  const runningTask = {
    id: 'running-child',
    parentSessionId: 'parent',
    parentTaskId: root.id,
    agent: 'review',
    description: 'Inspect implementation',
    depth: 1,
    state: 'running',
    currentTool: 'read',
    toolCalls: 3,
    retryAttempt: 2,
    startedAt: Date.now() - 5_000,
    usage: { input: 1_200, output: 345, cacheRead: 400, cacheWrite: 50, cost: 0.01234, turns: 2 },
  };
  const queuedTask = {
    id: 'queued-root',
    parentSessionId: 'parent',
    agent: 'general',
    description: 'Waiting task',
    depth: 0,
    state: 'queued',
  };
  const failedSibling = {
    id: 'failed-sibling',
    parentSessionId: 'parent',
    parentTaskId: root.id,
    agent: 'scout',
    description: 'Old failed work',
    depth: 1,
    state: 'error',
  };
  for (const task of [root, completedSibling, runningTask, queuedTask, failedSibling]) {
    privateRuntime.tasks.set(task.id, task);
  }

  const ctx = {
    hasUI: true,
    mode: 'tui',
    ui: {
      setWidget(_key: string, value: unknown) {
        if (typeof value === 'function') widget = value as WidgetFactory;
        if (value === undefined) cleared = true;
      },
    },
  } as unknown as ExtensionContext;
  const theme = {
    fg: (_color: string, value: string) => value,
    bold: (value: string) => value,
  };

  privateRuntime.updateTaskWidget(ctx);
  const text = widget?.(undefined, theme).render(120).join('\n') ?? '';
  expect(text).toContain('Subagents  1/4 running · 1 queued');
  expect(text).toContain('Coordinate work');
  expect(text).toContain('@review  Inspect implementation');
  expect(text).toContain('→ read · 3 calls');
  expect(text).toContain('1.5k tok $0.0123');
  expect(text).toMatch(/5\.\ds/);
  expect(text).toContain('retry 2');
  expect(text).toContain('@general  Waiting task  ·  waiting for slot');
  expect(text).not.toContain('Old completed work');
  expect(text).not.toContain('Old failed work');

  runningTask.description = `Inspect ${'implementation '.repeat(12)}`;
  privateRuntime.updateTaskWidget(ctx);
  const longDescription = widget?.(undefined, theme).render(120).join('\n') ?? '';
  expect(longDescription).toContain('1.5k tok $0.0123');

  const overflowTasks = Array.from({ length: 10 }, (_, index) => ({
    id: `queued-${index}`,
    parentSessionId: 'parent',
    agent: 'general',
    description: `Queued task ${index}`,
    depth: 0,
    state: 'queued',
  }));
  for (const task of overflowTasks) privateRuntime.tasks.set(task.id, task);
  privateRuntime.updateTaskWidget(ctx);
  const overflow = widget?.(undefined, theme).render(120).join('\n') ?? '';
  expect(overflow).toContain('Subagents  1/4 running · 11 queued');
  expect(overflow).toContain('… 5 more');

  const narrow = widget?.(undefined, theme).render(36) ?? [];
  expect(narrow.every((line) => visibleWidth(line) <= 36)).toBe(true);
  expect(narrow.join('\n')).toContain('@review');

  runningTask.state = 'completed';
  queuedTask.state = 'completed';
  for (const task of overflowTasks) task.state = 'completed';
  cleared = false;
  privateRuntime.updateTaskWidget(ctx);
  expect(cleared).toBe(true);
});

test('serializes agent and sandbox prompts through one presenter', async () => {
  const prompts = new PermissionPromptCoordinator();
  const runtime = new SubagentRuntime(
    {} as ExtensionAPI,
    {} as LandstripIntegration,
    undefined,
    undefined,
    prompts,
  );
  const broker = (
    runtime as unknown as {
      broker: {
        ask(
          ctx: ExtensionContext,
          task: string,
          permission: string,
          resource: string,
        ): Promise<void>;
      };
    }
  ).broker;
  const select = vi.fn(async () => 'Allow once');
  const ctx = { hasUI: true, ui: { select } } as unknown as ExtensionContext;
  const sandboxStarted = vi.fn();
  let finishSandbox = (): void => {};
  const sandboxPending = new Promise<void>((resolve) => {
    finishSandbox = resolve;
  });
  const sandbox = prompts.resolve(
    () => undefined,
    async () => {
      sandboxStarted();
      await sandboxPending;
      return true;
    },
  );
  await vi.waitFor(() => expect(sandboxStarted).toHaveBeenCalledOnce());

  const agent = broker.ask(ctx, '@build', 'bash', 'git status');
  await Promise.resolve();
  expect(select).not.toHaveBeenCalled();

  finishSandbox();
  await expect(Promise.all([sandbox, agent])).resolves.toEqual([true, undefined]);
  expect(select).toHaveBeenCalledOnce();
});

test('uses permission ask providers before headless fallback', async () => {
  const resolvePermissionAsk = vi
    .fn()
    .mockResolvedValueOnce({ decision: 'allow' })
    .mockRejectedValueOnce(new Error('review unavailable'))
    .mockResolvedValueOnce({ decision: 'deny', reason: 'Unsafe command' });
  const runtime = new SubagentRuntime(
    {} as ExtensionAPI,
    { resolvePermissionAsk } as unknown as LandstripIntegration,
  );
  const broker = (
    runtime as unknown as {
      broker: {
        ask(
          ctx: ExtensionContext,
          task: string,
          permission: string,
          resource: string,
          signal: AbortSignal | undefined,
          details: Record<string, unknown>,
        ): Promise<void>;
      };
    }
  ).broker;
  const ctx = { hasUI: false } as ExtensionContext;
  const details = {
    context: {
      version: 2,
      host: 'pi',
      role: 'primary',
      sandbox: 'enabled',
      cwd: '/workspace',
      depth: 0,
    },
    toolName: 'bash',
    input: { command: 'git status' },
  };

  await expect(broker.ask(ctx, '@build', 'bash', 'git status', undefined, details)).resolves.toBe(
    undefined,
  );
  expect(resolvePermissionAsk).toHaveBeenLastCalledWith({
    ...details,
    permissions: [{ permission: 'bash', resource: 'git status' }],
    signal: expect.any(AbortSignal),
  });

  const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  await expect(broker.ask(ctx, '@build', 'bash', 'git status', undefined, details)).rejects.toThrow(
    'Permission required: bash git status',
  );
  expect(error).toHaveBeenCalledWith(
    'pi-landstrip: permission ask provider failed: review unavailable',
  );
  await expect(broker.ask(ctx, '@build', 'bash', 'git status', undefined, details)).rejects.toThrow(
    'Unsafe command',
  );
  error.mockRestore();
});

test('selects a primary agent and applies its prompt', async () => {
  let sessionStart:
    | ((event: { type: 'session_start' }, ctx: ExtensionContext) => Promise<void> | void)
    | undefined;
  let beforeAgentStart:
    | ((
        event: { systemPrompt: string },
        ctx: ExtensionContext,
      ) => Promise<{ systemPrompt?: string } | void> | { systemPrompt?: string } | void)
    | undefined;
  let toolCall:
    | ((
        event: { toolName: string; input: Record<string, unknown> },
        ctx: ExtensionContext,
      ) => Promise<{ block?: boolean; reason?: string } | void>)
    | undefined;
  let cycleShortcut:
    | {
        key: string;
        handler: (ctx: ExtensionContext) => Promise<void> | void;
      }
    | undefined;
  const entries: Array<{ type: string; data: unknown }> = [];
  const statuses: string[] = [];
  const selections: string[] = [];
  const selectedModels: string[] = [];
  const thinkingLevels: string[] = [];
  const notifications: string[] = [];
  let idle = true;
  const planModel = { provider: 'anthropic', id: 'claude-plan' };
  const pi = {
    registerTool() {},
    registerCommand() {},
    registerShortcut(
      key: string,
      options: { handler: (ctx: ExtensionContext) => Promise<void> | void },
    ) {
      cycleShortcut = { key, handler: options.handler };
    },
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
      if (event === 'before_agent_start') {
        beforeAgentStart = handler as typeof beforeAgentStart;
      }
      if (event === 'tool_call') toolCall = handler as typeof toolCall;
    },
    getActiveTools: () => ['read', 'bash'],
    setActiveTools() {},
    async setModel(model: { provider: string; id: string }) {
      selectedModels.push(`${model.provider}/${model.id}`);
      return true;
    },
    setThinkingLevel(level: string) {
      thinkingLevels.push(level);
    },
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  const cwd = temporaryDirectory();
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    model: { provider: 'anthropic', id: 'claude-build' },
    modelRegistry: { getAll: () => [planModel] },
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      async select(title: string) {
        selections.push(title);
        return 'Allow once';
      },
      setStatus(_key: string, value: string) {
        statuses.push(value);
      },
      setWidget() {},
      theme: { fg: (_color: string, value: string) => value },
    },
    isIdle: () => idle,
    sessionManager: {
      getBranch: () => [],
      getSessionId: () => 'parent',
    },
  } as unknown as ExtensionContext;
  const authorizeFilesystemToolAccess = vi.fn(
    async (..._args: Parameters<LandstripIntegration['authorizeFilesystemToolAccess']>) => ({
      allowed: true,
      prompted: true,
    }),
  );
  const resolvePermissionAsk = vi.fn(async () => ({ decision: 'abstain' as const }));
  const integration = {
    createTools: () => [],
    authorizeFilesystemToolAccess,
    resolvePermissionAsk,
  } as unknown as LandstripIntegration;
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        toolFilesystemPolicy: 'sandbox',
        agent: {
          plan: {
            model: 'anthropic/claude-plan',
            variant: 'high',
            permission: { edit: { '*': 'ask', 'secrets/**': 'deny' } },
          },
        },
      },
    }),
  );
  const runtime = new SubagentRuntime(pi, integration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();

  await sessionStart?.({ type: 'session_start' }, ctx);
  expect(statuses.at(-1)).toBe('\x1b[32m@build\x1b[39m');
  expect(selectedModels).toEqual([]);
  expect(thinkingLevels).toEqual([]);
  expect(await runtime.selectPrimaryAgent('plan', ctx)).toBe(true);
  expect(entries.at(-1)).toEqual({ type: 'landstrip.primary-agent', data: { name: 'plan' } });
  expect(statuses.at(-1)).toBe('\x1b[33m@plan\x1b[39m');
  expect(selectedModels).toEqual(['anthropic/claude-plan']);
  expect(thinkingLevels).toEqual(['high']);

  const result = await beforeAgentStart?.({ systemPrompt: 'Base prompt' }, ctx);
  expect(result?.systemPrompt).toContain(
    'Analyze the request and produce a clear plan before making changes.',
  );
  await expect(
    toolCall?.({ toolName: 'bash', input: { command: 'git status' } }, ctx),
  ).resolves.toBe(undefined);
  expect(selections).toEqual(['@plan: permission required\nbash: git status']);
  expect(resolvePermissionAsk).toHaveBeenCalledWith(
    expect.objectContaining({
      context: expect.objectContaining({ role: 'primary', agent: 'plan' }),
      toolName: 'bash',
      input: { command: 'git status' },
      permissions: [{ permission: 'bash', resource: 'git status' }],
    }),
  );
  await expect(
    toolCall?.(
      {
        toolName: 'apply_patch',
        input: {
          patchText:
            '*** Begin Patch\n*** Update File: src/one.ts\n*** Move to: src/two.ts\n*** End Patch',
        },
      },
      ctx,
    ),
  ).resolves.toBe(undefined);
  expect(authorizeFilesystemToolAccess).toHaveBeenCalledOnce();
  expect(authorizeFilesystemToolAccess.mock.calls[0]?.[1]).toEqual([
    { operation: 'write', path: 'src/one.ts' },
    { operation: 'write', path: 'src/two.ts' },
  ]);
  expect(authorizeFilesystemToolAccess.mock.calls[0]?.[2]).toMatchObject({
    authorizationNote: 'Approval also authorizes @plan tool dispatch for this call.',
  });
  expect(selections).toHaveLength(1);
  authorizeFilesystemToolAccess.mockRejectedValueOnce(new Error('corrupt sandbox policy'));
  await expect(
    toolCall?.({ toolName: 'write', input: { path: 'src/error.ts' } }, ctx),
  ).resolves.toEqual({
    block: true,
    reason: 'Filesystem policy error: corrupt sandbox policy',
  });
  await expect(
    toolCall?.(
      {
        toolName: 'apply_patch',
        input: { patchText: '*** Begin Patch\n*** Update File: secrets/token\n*** End Patch' },
      },
      ctx,
    ),
  ).resolves.toMatchObject({ block: true, reason: expect.stringContaining('secrets/token') });
  await expect(
    toolCall?.({ toolName: 'edit', input: { path: 'tmp/../secrets/token' } }, ctx),
  ).resolves.toMatchObject({ block: true, reason: expect.stringContaining('secrets/token') });

  expect(cycleShortcut?.key).toBe('ctrl+shift+a');
  await cycleShortcut?.handler(ctx);
  expect(runtime.getPrimaryAgent()?.name).toBe('build');
  expect(entries.at(-1)).toEqual({ type: 'landstrip.primary-agent', data: { name: 'build' } });
  await cycleShortcut?.handler(ctx);
  expect(runtime.getPrimaryAgent()?.name).toBe('plan');
  expect(entries.at(-1)).toEqual({ type: 'landstrip.primary-agent', data: { name: 'plan' } });

  const entryCount = entries.length;
  idle = false;
  await cycleShortcut?.handler(ctx);
  expect(runtime.getPrimaryAgent()?.name).toBe('plan');
  expect(entries).toHaveLength(entryCount);
  expect(notifications.at(-1)).toBe('Cannot switch primary agents while an agent run is active');
});

test('restores a primary agent model and thinking variant', async () => {
  let sessionStart:
    | ((event: { type: 'session_start' }, ctx: ExtensionContext) => Promise<void> | void)
    | undefined;
  const selectedModels: string[] = [];
  const thinkingLevels: string[] = [];
  const entries: Array<{ type: string; data: unknown }> = [];
  const planModel = { provider: 'anthropic', id: 'claude-plan' };
  const pi = {
    registerTool() {},
    registerCommand() {},
    registerShortcut() {},
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
    getActiveTools: () => ['read', 'bash'],
    setActiveTools() {},
    async setModel(model: { provider: string; id: string }) {
      selectedModels.push(`${model.provider}/${model.id}`);
      return true;
    },
    setThinkingLevel(level: string) {
      thinkingLevels.push(level);
    },
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          plan: { model: 'anthropic/claude-plan', variant: 'xhigh' },
        },
      },
    }),
  );
  const runtime = new SubagentRuntime(
    pi,
    { createTools: () => [] } as unknown as LandstripIntegration,
    undefined,
    (projectCwd) => loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();
  const ctx = {
    cwd: temporaryDirectory(),
    hasUI: false,
    mode: 'json',
    model: { provider: 'anthropic', id: 'claude-build' },
    modelRegistry: { getAll: () => [planModel] },
    ui: { notify() {}, setWidget() {} },
    sessionManager: {
      getBranch: () => [
        {
          type: 'custom',
          customType: 'landstrip.primary-agent',
          data: { name: 'plan' },
        },
      ],
      getSessionId: () => 'parent',
    },
  } as unknown as ExtensionContext;

  await sessionStart?.({ type: 'session_start' }, ctx);

  expect(runtime.getPrimaryAgent()?.name).toBe('plan');
  expect(selectedModels).toEqual(['anthropic/claude-plan']);
  expect(thinkingLevels).toEqual(['xhigh']);
  expect(entries).toEqual([]);
});

test('retains the current primary agent when model activation fails', async () => {
  let sessionStart:
    | ((event: { type: 'session_start' }, ctx: ExtensionContext) => Promise<void> | void)
    | undefined;
  let cyclePrimaryAgent: ((ctx: ExtensionContext) => Promise<void> | void) | undefined;
  const entries: Array<{ type: string; data: unknown }> = [];
  const notifications: string[] = [];
  const lockedModel = { provider: 'anthropic', id: 'locked-model' };
  const pi = {
    registerTool() {},
    registerCommand() {},
    registerShortcut(
      _key: string,
      options: { handler: (ctx: ExtensionContext) => Promise<void> | void },
    ) {
      cyclePrimaryAgent = options.handler;
    },
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
    getActiveTools: () => ['read', 'bash'],
    setActiveTools() {},
    async setModel() {
      return false;
    },
    setThinkingLevel() {},
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          plan: { model: 'anthropic/missing-model' },
          locked: { mode: 'primary', model: 'anthropic/locked-model' },
        },
      },
    }),
  );
  const runtime = new SubagentRuntime(
    pi,
    { createTools: () => [] } as unknown as LandstripIntegration,
    undefined,
    (projectCwd) => loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();
  const ctx = {
    cwd: temporaryDirectory(),
    hasUI: false,
    mode: 'json',
    model: { provider: 'anthropic', id: 'claude-build' },
    modelRegistry: { getAll: () => [lockedModel] },
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      setWidget() {},
    },
    sessionManager: { getBranch: () => [], getSessionId: () => 'parent' },
    isIdle: () => true,
  } as unknown as ExtensionContext;

  await sessionStart?.({ type: 'session_start' }, ctx);
  await cyclePrimaryAgent?.(ctx);
  expect(runtime.getPrimaryAgent()?.name).toBe('build');
  expect(entries).toEqual([]);
  expect(await runtime.selectPrimaryAgent('plan', ctx)).toBe(false);

  expect(runtime.getPrimaryAgent()?.name).toBe('build');
  expect(entries).toEqual([]);
  expect(notifications).toContain(
    'Model not found for primary agent plan: anthropic/missing-model',
  );
  expect(notifications).toContain(
    'No authentication configured for primary agent locked model: anthropic/locked-model',
  );
});

test('registers task without spawning a worker process', async () => {
  let taskTool: ToolDefinition | undefined;
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void>) | undefined;
  let activeTools = ['read', 'bash'];
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on(event: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void>) {
      if (event === 'session_start') sessionStart = handler;
    },
    getActiveTools: () => activeTools,
    setActiveTools(tools: string[]) {
      activeTools = tools;
    },
  } as unknown as ExtensionAPI;
  const integration = { createTools: () => [] } as unknown as LandstripIntegration;
  const piAgentDir = temporaryDirectory();
  new SubagentRuntime(pi, integration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  expect(taskTool?.name).toBe('task');

  const cwd = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  const warnings: string[] = [];
  const ctx = {
    cwd,
    hasUI: true,
    ui: {
      notify: (message: string) => warnings.push(message),
      setStatus() {},
      setWidget() {},
    },
    sessionManager: {
      getBranch: () => [],
      getSessionId: () => 'parent',
    },
  } as unknown as ExtensionContext;
  await sessionStart?.({ type: 'session_start' }, ctx);
  expect(activeTools).toContain('task');
  await expect(
    taskTool?.execute(
      'call-1',
      {
        description: 'Unknown agent',
        prompt: 'Do the work',
        subagent_type: 'missing',
      },
      undefined,
      undefined,
      ctx,
    ),
  ).rejects.toThrow('Unknown subagent: missing');
  expect(warnings).toEqual([]);
});

test('lists hidden agents in the task tool description', () => {
  let taskTool: ToolDefinition | undefined;
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration, undefined, () => ({
    maxSubagents: 1,
    toolFilesystemPolicy: 'host',
    agents: new Map([
      [
        'visible',
        {
          name: 'visible',
          source: 'local' as const,
          description: 'Visible agent',
          prompt: 'Visible.',
          mode: 'subagent' as const,
          hidden: false,
          disabled: false,
          permissions: [],
          providerOptions: {},
        },
      ],
      [
        'advisor',
        {
          name: 'advisor',
          source: 'local' as const,
          description: 'Hidden advisor',
          prompt: 'Advise.',
          mode: 'subagent' as const,
          hidden: true,
          disabled: false,
          permissions: [],
          providerOptions: {},
        },
      ],
      [
        'disabled',
        {
          name: 'disabled',
          source: 'local' as const,
          description: 'Disabled agent',
          prompt: 'Disabled.',
          mode: 'subagent' as const,
          hidden: false,
          disabled: true,
          permissions: [],
          providerOptions: {},
        },
      ],
    ]),
    permissions: [],
    diagnostics: [],
  })).register();

  expect(taskTool?.description).toContain('visible: Visible agent');
  expect(taskTool?.description).toContain('advisor: Hidden advisor');
  expect(taskTool?.description).not.toContain('disabled: Disabled agent');
});

test('removes the task tool when maxSubagents is zero', async () => {
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void>) | undefined;
  let activeTools = ['read', 'task'];
  const pi = {
    registerTool() {},
    registerCommand() {},
    registerShortcut() {},
    on(event: string, handler: (event: unknown, ctx: ExtensionContext) => Promise<void>) {
      if (event === 'session_start') sessionStart = handler;
    },
    getActiveTools: () => activeTools,
    setActiveTools(tools: string[]) {
      activeTools = tools;
    },
  } as unknown as ExtensionAPI;
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 0 } }),
  );
  new SubagentRuntime(pi, {} as LandstripIntegration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: true,
    ui: { notify() {}, setStatus() {}, setWidget() {} },
    sessionManager: { getBranch: () => [], getSessionId: () => 'parent' },
  } as unknown as ExtensionContext;

  await sessionStart?.({ type: 'session_start' }, ctx);
  expect(activeTools).toEqual(['read']);
});

test('updates task availability without promoting queued work at zero', async () => {
  let activeTools = ['read', 'task'];
  const pi = {
    registerTool() {},
    on() {},
    getActiveTools: () => activeTools,
    setActiveTools(tools: string[]) {
      activeTools = tools;
    },
  } as unknown as ExtensionAPI;
  const runtime = new SubagentRuntime(pi, {} as LandstripIntegration);

  runtime.setMaxSubagents(0);
  expect(runtime.getMaxSubagents()).toBe(0);
  expect(activeTools).toEqual(['read']);

  runtime.setMaxSubagents(1);
  const semaphore = (
    runtime as unknown as {
      semaphore: { acquire(): Promise<() => void> };
    }
  ).semaphore;
  const releaseRunning = await semaphore.acquire();
  let promoted = false;
  const queued = semaphore.acquire().then((release) => {
    promoted = true;
    return release;
  });
  runtime.setMaxSubagents(0);
  releaseRunning();
  await Promise.resolve();
  expect(promoted).toBe(false);
  runtime.setMaxSubagents(1);
  const releaseQueued = await queued;
  expect(promoted).toBe(true);
  releaseQueued();

  runtime.setMaxSubagents(3);
  expect(runtime.getMaxSubagents()).toBe(3);
  expect(activeTools).toEqual(['read', 'task']);
  expect(() => runtime.setMaxSubagents(17)).toThrow('integer from 0 to 16');
});

test('runs a foreground task in an injected RPC worker', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          review: {
            description: 'Review code',
            mode: 'subagent',
            prompt: 'Review carefully.',
            permission: { bash: 'ask' },
          },
        },
      },
    }),
  );

  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const sentMessages: unknown[] = [];
  const widgets: unknown[] = [];
  const dialogTitles: string[] = [];
  let releaseSelect = (): void => {};
  const selectPending = new Promise<void>((resolve) => {
    releaseSelect = resolve;
  });
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry(customType: string, data: unknown) {
      parentManager.appendCustomEntry(customType, data);
    },
    sendMessage(message: unknown) {
      sentMessages.push(message);
    },
  } as unknown as ExtensionAPI;
  const resolvePermissionAsk = vi.fn(async () => ({ decision: 'allow' as const }));
  const integration = {
    createTools: () => [],
    resolvePermissionAsk,
  } as unknown as LandstripIntegration;
  let createdAgent: string | undefined;
  let emit: ((event: Record<string, unknown>) => void) | undefined;
  const onUpdate = vi.fn();
  let forwardRequest: ((request: Record<string, unknown>) => Promise<unknown>) | undefined;
  const fakeRpc = {
    onEvent(listener: (event: Record<string, unknown>) => void) {
      emit = listener;
      return () => {};
    },
    async prompt(promptText: string) {
      if (promptText === 'Fail.' || promptText === 'Retry.') {
        emit?.({
          type: 'message_end',
          message: {
            role: 'assistant',
            stopReason: 'error',
            errorMessage: 'Quota reached',
          },
        });
        if (promptText === 'Fail.') return;
        emit?.({
          type: 'message_end',
          message: { role: 'assistant', stopReason: 'stop' },
        });
        return;
      }
      emit?.({ type: 'tool_execution_start', toolCallId: 'tool-1', toolName: 'read' });
      emit?.({
        type: 'message_update',
        assistantMessageEvent: { type: 'text_delta', delta: 'Review' },
      });
      emit?.({ type: 'tool_execution_end', toolCallId: 'tool-1', toolName: 'read' });
      emit?.({
        type: 'message_update',
        assistantMessageEvent: { type: 'text_delta', delta: 'ed.' },
      });
      emit?.({ type: 'message_end', message: { role: 'user', content: 'ignored' } });
      emit?.({
        type: 'message_end',
        message: {
          role: 'assistant',
          usage: {
            input: -1,
            output: 1,
            cacheRead: 0,
            cacheWrite: 0,
            cost: { total: 1 },
          },
        },
      });
      emit?.({
        type: 'message_end',
        message: {
          role: 'assistant',
          usage: {
            input: 1_200,
            output: 300,
            cacheRead: 400,
            cacheWrite: 0,
            cost: { total: 0.01234 },
          },
        },
      });
      emit?.({
        type: 'message_end',
        message: {
          role: 'assistant',
          usage: {
            input: 800,
            output: 45,
            cacheRead: 100,
            cacheWrite: 50,
            cost: { total: 0.002 },
          },
        },
      });
      const invalidPermission = (await forwardRequest?.({
        method: 'input',
        title: 'pi-landstrip:control:v1',
        placeholder: JSON.stringify({
          type: 'permission',
          permission: 'bash',
          resource: 'git status',
          toolName: 'bash',
          toolInput: { command: 'git diff' },
        }),
      })) as { value: string };
      expect(JSON.parse(invalidPermission.value)).toEqual({
        ok: false,
        error: 'Invalid permission request',
      });
      await forwardRequest?.({
        method: 'input',
        title: 'pi-landstrip:control:v1',
        placeholder: JSON.stringify({
          type: 'permission',
          permission: 'bash',
          resource: 'git status',
          toolName: 'bash',
          toolInput: { command: 'git status' },
        }),
      });
      const selectRequest = forwardRequest?.({
        method: 'select',
        title: 'Choose item',
        options: ['one'],
      });
      const confirmRequest = forwardRequest?.({
        method: 'confirm',
        title: 'Confirm action',
        message: 'Proceed?',
      });
      await vi.waitFor(() => {
        expect(dialogTitles).toHaveLength(1);
        expect(dialogTitles[0]).toContain('\nChoose item');
      });
      releaseSelect();
      await Promise.all([selectRequest, confirmRequest]);
      await forwardRequest?.({ method: 'input', title: 'Enter value', placeholder: 'value' });
      await forwardRequest?.({ method: 'editor', title: 'Edit value', prefill: 'value' });
    },
    async getLastAssistantText() {
      return 'Reviewed.\nline 2\nline 3\nline 4';
    },
    async request() {},
    async abort() {},
    async stop() {},
  };
  const createWorker = async (
    _task: unknown,
    agent: { name: string },
    _rules: unknown,
    _ctx: unknown,
    _signal: AbortSignal,
    onRequest: (request: Record<string, unknown>) => Promise<unknown>,
  ) => {
    createdAgent = agent.name;
    forwardRequest = onRequest;
    return { rpc: fakeRpc, async dispose() {} };
  };
  new SubagentRuntime(pi, integration, createWorker as never, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    model: undefined,
    modelRegistry: { authStorage: {} },
    ui: {
      notify() {},
      async select(title: string) {
        dialogTitles.push(title);
        await selectPending;
        return 'one';
      },
      async confirm(title: string) {
        dialogTitles.push(title);
        return true;
      },
      async input(title: string) {
        dialogTitles.push(title);
        return 'value';
      },
      async editor(title: string) {
        dialogTitles.push(title);
        return 'value';
      },
      setWidget(_key: string, value: unknown) {
        widgets.push(value);
      },
    },
  } as unknown as ExtensionContext;

  const result = await taskTool?.execute(
    'call-1',
    {
      description: 'Review implementation',
      prompt: 'Review this implementation.',
      subagent_type: 'review',
    },
    undefined,
    onUpdate,
    ctx,
  );
  expect(result?.content[0]).toMatchObject({ type: 'text' });
  expect(result?.content[0]?.type === 'text' ? result.content[0].text : '').toContain('Reviewed.');
  expect(
    onUpdate.mock.calls.map(
      ([update]) => (update as { content: Array<{ type: string; text: string }> }).content[0]?.text,
    ),
  ).toEqual(['Running read', 'Review', 'Review', 'Reviewed.', 'Reviewed.', 'Reviewed.']);
  expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({
    details: { currentTool: 'read', toolCalls: 1, state: 'running' },
  });
  expect(result?.details).toMatchObject({
    description: 'Review implementation',
    state: 'completed',
    toolCalls: 1,
    output: 'Reviewed.\nline 2\nline 3\nline 4',
    usage: {
      input: 2_000,
      output: 345,
      cacheRead: 500,
      cacheWrite: 50,
      cost: 0.01434,
      turns: 2,
    },
  });
  expect(resolvePermissionAsk).toHaveBeenCalledWith(
    expect.objectContaining({
      context: expect.objectContaining({
        role: 'subagent',
        agent: 'review',
        taskId: expect.any(String),
      }),
      taskDescription: 'Review implementation',
      toolName: 'bash',
      input: { command: 'git status' },
      permissions: [{ permission: 'bash', resource: 'git status' }],
    }),
  );
  expect(resolvePermissionAsk).toHaveBeenCalledOnce();
  initTheme('dark', false);
  const theme = {
    fg: (_color: string, value: string) => value,
    bold: (value: string) => value,
  };
  const callLines = taskTool
    ?.renderCall?.(
      {
        description: 'Review implementation',
        prompt: 'Review this implementation.',
        subagent_type: 'review',
        background: true,
      },
      theme as never,
      {} as never,
    )
    .render(100);
  expect(callLines?.join('\n')).toContain('Agent (background) — Review implementation');

  const collapsedLines = taskTool
    ?.renderResult?.(
      result as never,
      { expanded: false, isPartial: false },
      theme as never,
      {} as never,
    )
    .render(100);
  expect(collapsedLines?.join('\n')).toContain('completed');
  expect(collapsedLines?.join('\n')).toContain('1 tool call');
  expect(collapsedLines?.join('\n')).toContain('2 turns in:2.0k out:345 R500 W50 $0.0143');
  expect(collapsedLines?.join('\n')).not.toContain('line 4');

  const expandedLines = taskTool
    ?.renderResult?.(
      result as never,
      { expanded: true, isPartial: false },
      theme as never,
      {} as never,
    )
    .render(100);
  expect(expandedLines?.join('\n')).toContain('line 4');
  expect(createdAgent).toBe('review');
  expect(sentMessages).toEqual([]);
  expect(dialogTitles).toHaveLength(4);
  for (const title of dialogTitles) {
    expect(title).toMatch(/^@review · Review implementation · [0-9a-f]{8}\n/);
  }
  expect(dialogTitles).toEqual(
    expect.arrayContaining([
      expect.stringContaining('\nChoose item'),
      expect.stringContaining('\nConfirm action'),
      expect.stringContaining('\nEnter value'),
      expect.stringContaining('\nEdit value'),
    ]),
  );
  const widget = widgets.find((value) => typeof value === 'function') as
    | ((
        tui: unknown,
        theme: { fg: (_color: string, value: string) => string; bold: (value: string) => string },
      ) => { render(width: number): string[] })
    | undefined;
  const lines = widget?.(undefined, {
    fg: (_color, value) => value,
    bold: (value) => value,
  }).render(80);
  expect(lines?.join('\n')).toContain('Subagents  0 running · 1 queued');
  expect(lines?.join('\n')).toContain('@review  Review implementation');
  expect(widgets.at(-1)).toBeUndefined();

  await expect(
    taskTool?.execute(
      'call-retry',
      {
        description: 'Retry review',
        prompt: 'Retry.',
        subagent_type: 'review',
      },
      undefined,
      undefined,
      ctx,
    ),
  ).resolves.toBeDefined();

  await expect(
    taskTool?.execute(
      'call-2',
      {
        description: 'Fail review',
        prompt: 'Fail.',
        subagent_type: 'review',
      },
      undefined,
      undefined,
      ctx,
    ),
  ).rejects.toThrow('Quota reached');
});

test('inspects and navigates persisted child sessions without switching sessions', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  writeFileSync(
    join(agentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        maxSubagents: 1,
        agent: {
          'global-review': {
            description: 'Global review',
            prompt: 'Review globally.',
            mode: 'subagent',
          },
          notes: {
            description: 'JSON notes',
            prompt: 'Take notes.',
          },
        },
      },
    }),
  );
  mkdirSync(join(agentDir, 'agents'), { recursive: true });
  writeFileSync(
    join(agentDir, 'agents', 'helper.md'),
    '---\ndescription: Markdown helper\n---\nHelp.\n',
  );
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          review: {
            description: 'Review code',
            prompt: 'Review.',
            mode: 'subagent',
          },
        },
      },
    }),
  );
  const parentManager = SessionManager.create(cwd, join(cwd, 'parent-sessions'));
  const childManager = SessionManager.create(cwd, join(cwd, 'child-sessions'));
  childManager.appendMessage({
    role: 'user',
    content: 'Inspect this child session.',
    timestamp: Date.now(),
  });
  childManager.appendMessage({
    role: 'assistant',
    content: [{ type: 'text', text: 'Child response.' }],
    api: 'anthropic-messages',
    provider: 'test',
    model: 'test',
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason: 'stop',
    timestamp: Date.now(),
  } as never);
  for (let index = 1; index <= 40; index += 1) {
    childManager.appendMessage({
      role: 'user',
      content: `Task log entry ${index}`,
      timestamp: Date.now(),
    });
  }
  parentManager.appendCustomEntry('landstrip.task', {
    version: 1,
    id: 'task-12345678',
    parentSessionId: parentManager.getSessionId(),
    sessionDir: childManager.getSessionDir(),
    sessionFile: childManager.getSessionFile(),
    agent: 'review',
    description: 'Inspect child',
    depth: 1,
    state: 'completed',
    output: 'Done',
    toolCalls: 2,
    usage: { input: 2_000, output: 345, cacheRead: 500, cacheWrite: 50, cost: 0.01434, turns: 2 },
    startedAt: 1,
    finishedAt: 1001,
  });
  parentManager.appendCustomEntry('landstrip.task', {
    version: 1,
    id: 'task-87654321',
    parentSessionId: parentManager.getSessionId(),
    agent: 'review',
    description: 'Failed child',
    depth: 1,
    state: 'error',
    error: 'Child failed visibly',
  });

  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void>) | undefined;
  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  const commandNames: string[] = [];
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      commandNames.push(name);
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
    getActiveTools: () => ['task'],
    setActiveTools() {},
    sendMessage() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  let sandboxGlobal = true;
  let sandboxProject: boolean | undefined;
  const integration = {
    sandboxCallbacks: {
      load: (_cwd: string, includeProject: boolean) => ({
        global: sandboxGlobal,
        project: includeProject ? sandboxProject : undefined,
      }),
      async setEnabled(_ctx: ExtensionContext, enabled: boolean, scope: 'global' | 'project') {
        if (scope === 'global') sandboxGlobal = enabled;
        else sandboxProject = enabled;
      },
      async clearProject() {
        sandboxProject = undefined;
      },
    },
  } as unknown as LandstripIntegration;
  const runtime = new SubagentRuntime(pi, integration);
  runtime.register();
  const bolded: string[] = [];
  const theme = {
    fg: (_color: string, value: string) => value,
    bold: (value: string) => {
      bolded.push(value);
      return value;
    },
  };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      async editor(_title: string, prefill = '') {
        const snippet = JSON.parse(prefill);
        const configured = snippet.landstrip?.agent ?? snippet.agent;
        const name = Object.keys(configured)[0];
        configured[name].description = `Edited ${name}`;
        return `${JSON.stringify(snippet, null, 2)}\n`;
      },
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  await sessionStart?.({}, ctx);
  const steer = vi.fn(async () => {});
  const privateRuntime = runtime as unknown as {
    tasks: Map<string, { state: string }>;
    running: Map<string, { rpc: { steer: typeof steer }; promise: Promise<string> }>;
  };
  privateRuntime.tasks.get('task-12345678')!.state = 'running';
  privateRuntime.running.set('task-12345678', {
    rpc: { steer },
    promise: new Promise<string>(() => {}),
  });
  expect(commandNames).toEqual(['landstrip']);
  const running = command?.('agents', ctx);
  const agents = component?.render(96).join('\n') ?? '';
  expect(agents).toContain('Overview  [Primary]  Subagent  Tasks  Log  Settings  Help');
  expect(agents).toContain('@build');
  expect(agents).toContain('@plan');
  expect(agents).not.toContain('@general');
  expect(agents).not.toContain('@notes');
  expect(agents).not.toContain('@helper');
  expect(agents).not.toContain('@review');
  const primaryHeader = agents
    .split('\n')
    .find((line) => line.includes('Agent') && line.includes('Runtime'));
  expect(primaryHeader).not.toContain('Primary');
  expect(primaryHeader).not.toMatch(/\bMode\b/);
  expect(agents).toMatch(/@build.*★ primary/);
  expect(bolded.some((value) => value.includes('@build'))).toBe(true);
  expect(agents).not.toContain('Tab next tab');

  component?.handleInput('e');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.build.description).toBe('Edited build');
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('x');
  expect(component?.render(96).join('\n')).toContain('Delete @build?');
  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).not.toContain('Delete @build?');
  expect(
    JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8')).landstrip.agent.build,
  ).toBeDefined();
  component?.handleInput('x');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.build).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(/@build\s+current model/);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('\t');
  const subagents = component?.render(96).join('\n') ?? '';
  expect(subagents).toContain('Primary  [Subagent]  Tasks  Log  Settings  Help');
  expect(subagents).toContain('@explore');
  expect(subagents).toContain('@general');
  expect(subagents).toContain('@review');
  expect(subagents).toContain('@notes');
  expect(subagents).toContain('@helper');
  expect(subagents).not.toContain('@build');
  expect(subagents).not.toContain('@plan');
  const subagentHeader = subagents
    .split('\n')
    .find((line) => line.includes('Agent') && line.includes('Runtime'));
  expect(subagentHeader).not.toContain('Primary');
  expect(subagentHeader).not.toMatch(/\bMode\b/);

  component?.handleInput(' ');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.explore.disable).toBe(true);
    expect(component?.render(96).join('\n')).toMatch(/@explore.*disabled/);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('i');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.explore).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(/@explore.*inherited on/);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('\x1b[B');
  component?.handleInput('\x1b[B');
  component?.handleInput('x');
  expect(component?.render(96).join('\n')).not.toContain('Delete @global-review?');
  component?.handleInput('e');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent['global-review'].description).toBe('Edited global-review');
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('\x1b[A');
  component?.handleInput('\x1b[A');

  component?.handleInput('\t');
  const tasks = component?.render(96).join('\n') ?? '';
  expect(tasks).toContain('[Tasks]');
  expect(tasks).not.toContain('Tasks 2');
  expect(tasks).toContain('task-123');
  expect(tasks).toContain('Failed child');
  expect(tasks).not.toContain('Latest activity');
  expect(tasks).not.toContain('Task log entry 40');
  expect(tasks).not.toContain('2 tool calls · 1.0s');
  expect(component?.render(96).every((line) => visibleWidth(line) <= 96)).toBe(true);

  const narrowTasks = component?.render(80).join('\n') ?? '';
  expect(narrowTasks).toContain('[Tasks]');
  expect(narrowTasks).toContain('task-123');
  expect(component?.render(80).every((line) => visibleWidth(line) <= 80)).toBe(true);

  component?.handleInput('\x1b[B');
  expect(component?.render(96).join('\n')).toContain('Failed child');
  component?.handleInput('\x1b[A');
  expect(component?.render(96).join('\n')).toContain('task-123');
  component?.handleInput('\r');
  const logs = component?.render(96).join('\n') ?? '';
  expect(logs).toContain('[Log]');
  expect(logs).toContain('Follow: on');
  expect(logs).toContain('Task log entry 40');
  expect(logs).toContain('27–42 of 42');
  expect(logs).not.toContain('Inspect this child session.');
  expect(logs).toContain('2 tool calls · 1.0s');
  expect(logs).toContain('2 turns in:2.0k out:345 R500 W50 $0.0143');
  expect(logs).toContain('Enter steer  ·  F follow  ·  Esc tasks');
  component?.handleInput('\r');
  expect(component?.render(96).join('\n')).toContain('Steer ›');
  component?.handleInput('x');
  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).toContain('Enter steer  ·  F follow  ·  Esc tasks');
  component?.handleInput('\r');
  component?.handleInput('\x1b[200~Check tests first🧪\x1b[201~');
  expect(component?.render(96).join('\n')).toContain('Steer › Check tests first🧪');
  component?.handleInput('\x7f');
  expect(component?.render(96).join('\n')).not.toContain('🧪');
  component?.handleInput('\r');
  await vi.waitFor(() => expect(steer).toHaveBeenCalledWith('Check tests first'));
  component?.handleInput('\x1b[A');
  expect(component?.render(96).join('\n')).toBe(logs);
  component?.handleInput('\x1b[C');
  expect(component?.render(96).join('\n')).toBe(logs);
  component?.handleInput('\x1b[D');
  expect(component?.render(96).join('\n')).toBe(logs);

  childManager.appendMessage({
    role: 'user',
    content: 'Task log entry 41',
    timestamp: Date.now(),
  });
  const followed = component?.render(96).join('\n') ?? '';
  expect(followed).toContain('Task log entry 41');
  expect(followed).toContain('28–43 of 43');

  component?.handleInput('f');
  expect(component?.render(96).join('\n')).toContain('Follow: off');
  component?.handleInput('\x1b[H');
  expect(component?.render(96).join('\n')).toContain('1–16 of 43');
  expect(component?.render(96).join('\n')).toContain('Inspect this child session.');

  childManager.appendMessage({
    role: 'user',
    content: 'Task log entry 42',
    timestamp: Date.now(),
  });
  const anchored = component?.render(96).join('\n') ?? '';
  expect(anchored).toContain('1–16 of 44');
  expect(anchored).not.toContain('Task log entry 42');

  component?.handleInput('\x1b[B');
  expect(component?.render(96).join('\n')).toContain('2–17 of 44');
  component?.handleInput('\x1b[A');
  expect(component?.render(96).join('\n')).toContain('1–16 of 44');
  component?.handleInput('\x1b[6~');
  expect(component?.render(96).join('\n')).toContain('17–32 of 44');
  component?.handleInput('\x1b[5~');
  expect(component?.render(96).join('\n')).toContain('1–16 of 44');
  component?.handleInput('\x1b[F');
  const ended = component?.render(96).join('\n') ?? '';
  expect(ended).toContain('29–44 of 44');
  expect(ended).toContain('Task log entry 42');
  expect(ended).toContain('Follow: off');

  component?.handleInput('\x1b[H');
  component?.handleInput('f');
  const resumed = component?.render(96).join('\n') ?? '';
  expect(resumed).toContain('Follow: on');
  expect(resumed).toContain('29–44 of 44');
  expect(resumed).toContain('Task log entry 42');

  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).toContain('[Tasks]');
  component?.handleInput('\x1b[B');
  component?.handleInput(' ');
  const selectedTask = component?.render(96).join('\n') ?? '';
  expect(selectedTask).toContain('1 selected');
  expect(selectedTask).toContain('✓');
  component?.handleInput('x');
  expect(component?.render(96).join('\n')).toContain('Delete task-876?');
  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).toContain('Failed child');
  component?.handleInput('x');
  expect(component?.render(96).join('\n')).toContain('Delete task-876?');
  component?.handleInput('\r');
  const afterTaskDelete = component?.render(96).join('\n') ?? '';
  expect(afterTaskDelete).not.toContain('Failed child');
  expect(afterTaskDelete).not.toContain('1 selected');
  component?.handleInput('\t');
  expect(component?.render(96).join('\n')).toContain('[Log]');
  component?.handleInput('\t');

  const projectSettings = component?.render(96).join('\n') ?? '';
  expect(projectSettings).toContain('Log  [Settings]  Help');
  // Unset project values render the effective Global one.
  expect(projectSettings).toMatch(/Maximum Subagents\s+1 \(global\)/);
  expect(projectSettings).toMatch(/Filesystem Tool Policy\s+host \(global\)/);
  expect(projectSettings).not.toContain('sandboxEnabled');

  component?.handleInput('\r');
  component?.handleInput('2');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBe(2);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  // The editor pre-fills the current project value, so backspace clears the 2.
  expect(component?.render(96).join('\n')).toMatch(/Maximum Subagents\s+2/);
  component?.handleInput('\r');
  component?.handleInput('\x7f');
  component?.handleInput('3');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBe(3);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  // Submitting an empty editor clears the project override.
  component?.handleInput('\r');
  component?.handleInput('\x7f');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBeUndefined();
    expect(settings.landstrip.agent.review).toBeDefined();
    expect(component?.render(96).join('\n')).toMatch(/Maximum Subagents\s+1 \(global\)/);
  });

  // Rejected input leaves the stored value untouched.
  component?.handleInput('\r');
  component?.handleInput('9');
  component?.handleInput('9');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(/Maximum Subagents\s+1 \(global\)/);
  });

  component?.handleInput('\x1b[B');
  component?.handleInput('\r');
  const policyChoices = component?.render(96).join('\n') ?? '';
  expect(policyChoices).toContain('Use Global (host)');
  expect(policyChoices).toContain('Resolve paths inside the sandbox');
  // inherit / host / sandbox, pre-selected on the inherited entry.
  component?.handleInput('\x1b[B');
  component?.handleInput('\x1b[B');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.toolFilesystemPolicy).toBe('sandbox');
    expect(component?.render(96).join('\n')).toMatch(/Filesystem Tool Policy\s+sandbox/);
  });
  component?.handleInput('\r');
  component?.handleInput('\x1b[A');
  component?.handleInput('\x1b[A');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.toolFilesystemPolicy).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(/Filesystem Tool Policy\s+host \(global\)/);
  });

  component?.handleInput('\t');

  const help = component?.render(96).join('\n') ?? '';
  expect(help).toContain('Tasks  Log  Settings  [Help]');
  expect(help).toMatch(/Shortcut\s+Description/);
  expect(help).toMatch(/X\s+Delete selected agent or task sessions/);
  expect(help).toMatch(/Space\s+Toggle agent enabled or select task/);
  expect(help).toMatch(/Backspace\s+Open parent task/);
  expect(help).toMatch(/F\s+Toggle task log follow/);
  expect(help).toMatch(/Page Up \/ Down\s+Scroll task output by page/);
  expect(help).toMatch(/Home \/ End\s+Jump to task output boundary/);
  expect(help).toMatch(/Enter\s+Activate: set primary, open log, steer, confirm/);

  component?.handleInput('\t');
  await vi.waitFor(() => {
    expect(component?.render(96).join('\n')).toContain('[Overview]  Primary');
  });
  const sandboxPane = component?.render(96).join('\n') ?? '';
  expect(sandboxPane).toContain('[Overview]  Primary');
  expect(sandboxPane).toContain('Sandbox settings are unavailable.');
  expect(sandboxPane).not.toContain('maxSubagents');

  component?.handleInput('\x1b');
  await running;

  const direct = command?.('task-123', ctx);
  expect(component?.render(96).join('\n')).toContain('[Log]');
  expect(component?.render(96).join('\n')).toContain('Follow: on');
  finishCustom?.();
  await direct;
  vi.unstubAllEnvs();
});

test('refuses to open a project setting editor when the project is untrusted', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  writeFileSync(
    join(agentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 1 } }),
  );
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(join(cwd, '.pi', 'settings.json'), JSON.stringify({ landstrip: {} }));

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const warnings: string[] = [];
  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => false,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify(message: string, level: string) {
        if (level === 'warning') warnings.push(message);
      },
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = command?.('settings', ctx);
  expect(component?.render(96).join('\n')).toContain('Log  [Settings]  Help');

  component?.handleInput('\r');
  expect(warnings).toEqual(['Project settings require a trusted project']);
  // The editor never opened, so the row still shows the inherited Global value.
  expect(component?.render(96).join('\n')).toMatch(/Maximum Subagents\s+1 \(global\)/);
  const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
  expect(settings.landstrip.maxSubagents).toBeUndefined();

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('narrows the agent list to a typed query and restores it on escape', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  writeFileSync(
    join(agentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          alpha: { description: 'A', prompt: 'Work.', mode: 'subagent' },
          beta: { description: 'B', prompt: 'Work.', mode: 'subagent' },
          gamma: { description: 'G', prompt: 'Work.', mode: 'subagent' },
        },
      },
    }),
  );

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = command?.('subagent', ctx);
  expect(component?.render(96).join('\n')).toContain('@beta');

  component?.handleInput('/');
  component?.handleInput('g');
  component?.handleInput('a');
  const filtered = component?.render(96).join('\n') ?? '';
  // gamma matches g-a in order; the built-in general does too, beta does not.
  expect(filtered).toContain('Filter ga');
  expect(filtered).toContain('@gamma');
  expect(filtered).not.toContain('@beta');
  expect(filtered).not.toContain('@alpha');

  // While the query is open the letters spell it out rather than firing E or X.
  component?.handleInput('e');
  expect(component?.render(96).join('\n')).toContain('Filter gae');
  component?.handleInput('\x7f');
  expect(component?.render(96).join('\n')).toContain('Filter ga');

  // Enter keeps the query but hands the letter keys back to the actions.
  component?.handleInput('\r');
  const kept = component?.render(96).join('\n') ?? '';
  expect(kept).toContain('Filter ga');
  expect(kept).toContain('Esc clear filter');

  // Esc clears the query instead of closing the dialog, so the full list returns.
  component?.handleInput('\x1b');
  const restored = component?.render(96).join('\n') ?? '';
  expect(restored).not.toContain('Filter');
  expect(restored).toContain('@beta');
  expect(restored).toContain('@alpha');

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('offers X delete only for an agent the project can actually delete', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  writeFileSync(
    join(agentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: { global0: { description: 'Global', prompt: 'Work.', mode: 'subagent' } },
      },
    }),
  );
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { local0: { description: 'Local', prompt: 'Work.', mode: 'subagent' } } },
    }),
  );

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = command?.('subagent', ctx);
  // Sorted: explore, general, global0, local0, scout. Selection starts on the first.
  const onBuiltIn = component?.render(96).join('\n') ?? '';
  expect(onBuiltIn).toContain('\u203a @explore');
  expect(onBuiltIn).not.toContain('X delete');

  component?.handleInput('\x1b[B');
  component?.handleInput('\x1b[B');
  const onGlobal = component?.render(96).join('\n') ?? '';
  // global0 lives in the global config, so deleting it from this project is not offered.
  expect(onGlobal).toContain('\u203a @global0');
  expect(onGlobal).not.toContain('X delete');

  component?.handleInput('\x1b[B');
  const onLocal = component?.render(96).join('\n') ?? '';
  // local0 is declared in the project config, so deleting it here is real.
  expect(onLocal).toContain('\u203a @local0');
  expect(onLocal).toContain('X delete');

  // Toggling global0 writes it into the project config, which makes it deletable.
  // The hint has to notice, so the cache must be rebuilt when agents reload.
  component?.handleInput('\x1b[A');
  component?.handleInput(' ');
  await vi.waitFor(() => {
    const view = component?.render(96).join('\n') ?? '';
    expect(view).toContain('\u203a @global0');
    expect(view).toContain('X delete');
  });

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('reports the hidden remainder when an agent list is longer than the window', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const agent = Object.fromEntries(
    Array.from({ length: 10 }, (_unused, index) => [
      `sub${index}`,
      { description: `Agent ${index}`, prompt: 'Work.', mode: 'subagent' },
    ]),
  );
  writeFileSync(join(agentDir, 'settings.json'), JSON.stringify({ landstrip: { agent } }));
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(join(cwd, '.pi', 'settings.json'), JSON.stringify({ landstrip: {} }));

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  // 10 configured agents plus the three built-ins.
  const running = command?.('subagent', ctx);
  const top = component?.render(96).join('\n') ?? '';
  expect(top).toContain('1\u20137 of 13');
  expect(top).toContain('@sub0');
  expect(top).not.toContain('@sub9');

  for (let press = 0; press < 12; press += 1) component?.handleInput('\x1b[B');
  const bottom = component?.render(96).join('\n') ?? '';
  // The window follows the cursor, so the last agent is on screen and the count is honest.
  expect(bottom).toContain('7\u201313 of 13');
  expect(bottom).toContain('@sub9');
  expect(bottom).not.toContain('@sub0 ');

  // The tab advertises the keys it binds, minus the ones this selection ignores.
  // These agents come from the global config, so X would only warn and is not offered.
  expect(bottom).toContain('Space toggle enabled  ·  E edit  ·  / filter  ·  Esc close');
  expect(bottom).not.toContain('X delete');
  expect(bottom).not.toContain('inherit global');
  expect(bottom).not.toContain('set primary');

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('gives a tall terminal a taller agent window', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  const agent = Object.fromEntries(
    Array.from({ length: 10 }, (_unused, index) => [
      `sub${index}`,
      { description: `Agent ${index}`, prompt: 'Work.', mode: 'subagent' },
    ]),
  );
  writeFileSync(join(agentDir, 'settings.json'), JSON.stringify({ landstrip: { agent } }));

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const terminal = { rows: 24 };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {}, terminal }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = command?.('subagent', ctx);
  // 24 rows leaves no room beyond the floor: 7 of the 13 agents, remainder reported.
  const small = component?.render(96).join('\n') ?? '';
  expect(small).toContain('1–7 of 13');

  // 50 rows gives the overlay 35, and 35 minus the chrome fits all 13 agents.
  terminal.rows = 50;
  const tall = component?.render(96).join('\n') ?? '';
  expect(tall).not.toContain('of 13');
  expect(tall).toContain('@sub0');
  expect(tall).toContain('@sub9');

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('advertises only the keys an untrusted project can use', async () => {
  const cwd = temporaryDirectory();
  const agentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
  writeFileSync(join(agentDir, 'settings.json'), JSON.stringify({ landstrip: {} }));

  let command: ((args: string, ctx: ExtensionContext) => Promise<void>) | undefined;
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'landstrip') command = definition.handler;
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => ['task'],
    setActiveTools() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration).register();

  const theme = { fg: (_color: string, value: string) => value, bold: (value: string) => value };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => false,
    sessionManager: SessionManager.create(cwd, join(cwd, 'sessions')),
    ui: {
      notify() {},
      setStatus() {},
      setWidget() {},
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
      ) {
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory({ requestRender() {} }, theme, undefined, resolve);
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = command?.('subagent', ctx);
  const view = component?.render(96).join('\n') ?? '';
  // Every mutating key notifies and does nothing here, so none of them are offered.
  expect(view).toContain('Esc close');
  expect(view).not.toContain('toggle enabled');
  expect(view).not.toContain('E edit');
  expect(view).not.toContain('X delete');

  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});

test('cancels worker startup promptly and disposes a worker created afterward', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  let resolveWorker: ((worker: unknown) => void) | undefined;
  const workerPromise = new Promise((resolve) => {
    resolveWorker = resolve;
  });
  const createWorker = vi.fn(() => workerPromise);
  new SubagentRuntime(pi, {} as LandstripIntegration, createWorker as never, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;
  const controller = new AbortController();
  const execution = taskTool?.execute(
    'call-1',
    { description: 'Review code', prompt: 'Review.', subagent_type: 'review' },
    controller.signal,
    undefined,
    ctx,
  );
  await vi.waitFor(() => expect(createWorker).toHaveBeenCalledOnce());

  controller.abort();
  await expect(execution).rejects.toThrow('Task cancelled');

  const stop = vi.fn(async () => {});
  const dispose = vi.fn(async () => {});
  resolveWorker?.({ rpc: { stop }, dispose });
  await vi.waitFor(() => expect(dispose).toHaveBeenCalledOnce());
  expect(stop).toHaveBeenCalledOnce();
});

test('sends messages queued during worker startup once RPC is available', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry() {},
    sendMessage() {},
  } as unknown as ExtensionAPI;
  let resolveWorker: ((worker: unknown) => void) | undefined;
  const workerPromise = new Promise((resolve) => {
    resolveWorker = resolve;
  });
  const createWorker = vi.fn(() => workerPromise);
  const request = vi.fn(async () => {});
  const steer = vi.fn(async () => {});
  const fakeRpc = {
    onEvent: () => () => {},
    async prompt() {},
    async getLastAssistantText() {
      return 'Reviewed.';
    },
    request,
    steer,
    async abort() {},
    async stop() {},
  };
  const runtime = new SubagentRuntime(
    pi,
    {} as LandstripIntegration,
    createWorker as never,
    (projectCwd) => loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();
  const ctx = {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;

  const started = await taskTool?.execute(
    'call-1',
    {
      description: 'Review code',
      prompt: 'Start review.',
      subagent_type: 'review',
      background: true,
    },
    undefined,
    undefined,
    ctx,
  );
  expect(started?.details).toMatchObject({ state: 'queued' });
  expect(started?.content[0]).toMatchObject({
    type: 'text',
    text: expect.stringContaining('state="queued"'),
  });
  const taskId = (started?.details as { taskId?: string } | undefined)?.taskId;
  expect(taskId).toBeTruthy();
  await taskTool?.execute(
    'call-2',
    {
      description: 'Continue review',
      prompt: 'Also inspect tests.',
      subagent_type: 'review',
      task_id: taskId,
      background: true,
    },
    undefined,
    undefined,
    ctx,
  );
  expect(request).not.toHaveBeenCalled();
  (runtime as unknown as { pendingSteers: Map<string, string[]> }).pendingSteers.set(taskId!, [
    'Focus on tests first.',
  ]);
  expect(steer).not.toHaveBeenCalled();

  resolveWorker?.({ rpc: fakeRpc, async dispose() {} });
  await vi.waitFor(() =>
    expect(request).toHaveBeenCalledWith('follow_up', { message: 'Also inspect tests.' }),
  );
  await vi.waitFor(() => expect(steer).toHaveBeenCalledWith('Focus on tests first.'));
});

test('records a running foreground task when continued in background', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const entries: Array<Record<string, unknown>> = [];
  const sendMessage = vi.fn();
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry(_customType: string, data: Record<string, unknown>) {
      entries.push(data);
    },
    sendMessage,
  } as unknown as ExtensionAPI;
  let resolveWorker: ((worker: unknown) => void) | undefined;
  const workerPromise = new Promise((resolve) => {
    resolveWorker = resolve;
  });
  const createWorker = vi.fn(() => workerPromise);
  const request = vi.fn(async () => {});
  const fakeRpc = {
    onEvent: () => () => {},
    async prompt() {},
    async getLastAssistantText() {
      return 'Reviewed.';
    },
    request,
    async abort() {},
    async stop() {},
  };
  new SubagentRuntime(pi, {} as LandstripIntegration, createWorker as never, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;

  const foreground = taskTool?.execute(
    'call-1',
    { description: 'Review code', prompt: 'Start review.', subagent_type: 'review' },
    undefined,
    undefined,
    ctx,
  );
  await vi.waitFor(() => expect(createWorker).toHaveBeenCalledOnce());
  const taskId = entries.find((entry) => typeof entry.id === 'string')?.id as string;
  const background = await taskTool?.execute(
    'call-2',
    {
      description: 'Continue review',
      prompt: 'Also inspect tests.',
      subagent_type: 'review',
      task_id: taskId,
      background: true,
    },
    undefined,
    undefined,
    ctx,
  );

  expect(background?.details).toMatchObject({ taskId, state: 'running' });
  expect(entries.some((entry) => entry.id === taskId && entry.background === true)).toBe(true);
  resolveWorker?.({ rpc: fakeRpc, async dispose() {} });
  await expect(foreground).resolves.toBeDefined();
  expect(sendMessage).not.toHaveBeenCalled();
});

test('delivers a completed task when it is continued in background', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const sendMessage = vi.fn();
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry() {},
    sendMessage,
  } as unknown as ExtensionAPI;
  let completeContinuation: (() => void) | undefined;
  const continuation = new Promise<void>((resolve) => {
    completeContinuation = resolve;
  });
  let workerCount = 0;
  const createWorker = vi.fn(async () => {
    const worker = workerCount++;
    let emit: ((event: Record<string, unknown>) => void) | undefined;
    return {
      rpc: {
        onEvent(listener: (event: Record<string, unknown>) => void) {
          emit = listener;
          return () => {};
        },
        async prompt() {
          emit?.({
            type: 'message_end',
            message: {
              role: 'assistant',
              usage: {
                input: worker === 0 ? 100 : 200,
                output: worker === 0 ? 10 : 20,
                cacheRead: 0,
                cacheWrite: 0,
                cost: { total: worker === 0 ? 0.01 : 0.02 },
              },
            },
          });
          if (worker === 1) await continuation;
        },
        async getLastAssistantText() {
          return worker === 0 ? 'First result.' : 'Continued result.';
        },
        async request() {},
        async abort() {},
        async stop() {},
      },
      async dispose() {},
    };
  });
  const runtime = new SubagentRuntime(
    pi,
    {} as LandstripIntegration,
    createWorker as never,
    (projectCwd) => loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();
  (runtime as unknown as { activeSessionId?: string }).activeSessionId =
    parentManager.getSessionId();
  const ctx = {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;

  const first = await taskTool?.execute(
    'call-1',
    { description: 'Review code', prompt: 'Review.', subagent_type: 'review' },
    undefined,
    undefined,
    ctx,
  );
  const taskId = (first?.details as { taskId?: string } | undefined)?.taskId;
  expect(taskId).toBeTruthy();
  expect(sendMessage).not.toHaveBeenCalled();

  const second = await taskTool?.execute(
    'call-2',
    {
      description: 'Continue review',
      prompt: 'Continue.',
      subagent_type: 'review',
      task_id: taskId,
      background: true,
    },
    undefined,
    undefined,
    ctx,
  );
  expect(second?.details).toMatchObject({ taskId, state: 'queued' });
  await vi.waitFor(() => expect(createWorker).toHaveBeenCalledTimes(2));
  completeContinuation?.();

  await vi.waitFor(() => expect(sendMessage).toHaveBeenCalledOnce());
  expect(sendMessage.mock.calls[0]?.[0]).toMatchObject({
    content: expect.stringContaining('Continued result.'),
  });
  const continuedTask = (
    runtime as unknown as {
      tasks: Map<string, { usage?: Record<string, number> }>;
    }
  ).tasks.get(taskId!);
  expect(continuedTask?.usage).toEqual({
    input: 300,
    output: 30,
    cacheRead: 0,
    cacheWrite: 0,
    cost: 0.03,
    turns: 2,
  });
});

test('rejects an unknown continuation ID instead of creating a new task', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 4 } }),
  );
  writeFileSync(
    join(cwd, '.pi', 'settings.json'),
    JSON.stringify({
      landstrip: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;

  await expect(
    taskTool?.execute(
      'call-1',
      {
        description: 'Continue review',
        prompt: 'Continue.',
        subagent_type: 'review',
        task_id: 'missing',
      },
      undefined,
      undefined,
      ctx,
    ),
  ).rejects.toThrow('Unknown task: missing');
});

test('worker mode removes tools denied for every resource', () => {
  let activeTools = ['read', 'bash', 'custom_inspect'];
  let sessionStart: (() => void) | undefined;
  let beforeAgentStart: (() => void) | undefined;
  const pi = {
    on(event: string, handler: () => void) {
      if (event === 'session_start') sessionStart = handler;
      if (event === 'before_agent_start') beforeAgentStart = handler;
    },
    getActiveTools: () => activeTools,
    setActiveTools(tools: string[]) {
      activeTools = tools;
    },
  } as unknown as ExtensionAPI;
  registerSubagentWorker(pi, {
    rules: [
      { permission: '*', pattern: '*', action: 'allow' },
      { permission: '*', pattern: '*', action: 'deny' },
      { permission: 'read', pattern: '*', action: 'allow' },
      { permission: 'bash', pattern: 'git status', action: 'allow' },
    ],
    task: { id: 'parent', description: 'Parent', depth: 0 },
    taskEnabled: false,
  });

  sessionStart?.();
  expect(activeTools).toEqual(['read', 'bash']);

  activeTools.push('late_custom');
  beforeAgentStart?.();
  expect(activeTools).toEqual(['read', 'bash']);
});

test('worker mode enforces permissions and sends nested tasks over reserved UI input', async () => {
  const cwd = temporaryDirectory();
  mkdirSync(join(cwd, 'secrets'));
  symlinkSync(join(cwd, 'secrets'), join(cwd, 'alias'), 'junction');
  symlinkSync(join(cwd, 'secrets', 'future'), join(cwd, 'dangling'), 'junction');
  let taskTool: ToolDefinition | undefined;
  let toolCall:
    | ((event: Record<string, unknown>, ctx: ExtensionContext) => Promise<unknown>)
    | undefined;
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    on(event: string, handler: typeof toolCall) {
      if (event === 'tool_call') toolCall = handler;
    },
  } as unknown as ExtensionAPI;
  registerSubagentWorker(pi, {
    rules: [
      { permission: 'edit', pattern: '*', action: 'allow' },
      { permission: 'edit', pattern: 'file.ts', action: 'deny' },
      { permission: 'edit', pattern: 'secrets/**', action: 'deny' },
    ],
    task: { id: 'parent', description: 'Parent', depth: 0 },
    taskEnabled: true,
  });
  const requests: Array<{ title: string; placeholder?: string }> = [];
  const ctx = {
    cwd,
    ui: {
      async input(title: string, placeholder?: string) {
        requests.push({ title, placeholder });
        return JSON.stringify({
          ok: true,
          value: 'nested result',
          task: { taskId: 'child-task', state: 'running', agent: 'general' },
        });
      },
    },
  } as unknown as ExtensionContext;

  await expect(
    toolCall?.({ toolName: 'write', input: { path: 'file.ts' } }, ctx),
  ).resolves.toMatchObject({ block: true });

  await expect(
    toolCall?.({ toolName: 'write', input: { path: 'alias/token.txt' } }, ctx),
  ).resolves.toMatchObject({ block: true });

  await expect(
    toolCall?.({ toolName: 'write', input: { path: 'dangling/token.txt' } }, ctx),
  ).resolves.toMatchObject({ block: true });
  await expect(
    toolCall?.(
      {
        toolName: 'apply_patch',
        input: {
          patchText:
            '*** Begin Patch\n*** Update File: secrets/token.txt\n@@\n-old\n+new\n*** End Patch',
        },
      },
      ctx,
    ),
  ).resolves.toMatchObject({ block: true });
  const result = await taskTool?.execute(
    'nested-1',
    { description: 'Nested work', prompt: 'Work.', subagent_type: 'general' },
    undefined,
    undefined,
    ctx,
  );
  expect(result?.content[0]).toEqual({ type: 'text', text: 'nested result' });
  expect(result?.details).toEqual({ taskId: 'child-task', state: 'running', agent: 'general' });
  expect(requests[0]?.title).toBe('pi-landstrip:control:v1');
  expect(JSON.parse(requests[0]?.placeholder ?? '{}')).toMatchObject({ type: 'task' });
});

test('hands a foreground scheduler permit to a nested task at capacity one', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({ landstrip: { maxSubagents: 1 } }),
  );

  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
    registerShortcut() {},
    on() {},
    appendEntry() {},
    sendMessage() {},
  } as unknown as ExtensionAPI;
  let workerCount = 0;
  let nestedResponse: { value?: string } | undefined;
  const createWorker = vi.fn(
    async (
      _task: unknown,
      _agent: unknown,
      _rules: unknown,
      _ctx: unknown,
      _signal: AbortSignal,
      onRequest: (request: {
        method: 'input';
        title: string;
        placeholder: string;
      }) => Promise<{ value?: string }>,
    ) => {
      const workerNumber = ++workerCount;
      return {
        rpc: {
          onEvent: () => () => {},
          async prompt() {
            if (workerNumber !== 1) return;
            nestedResponse = await onRequest({
              method: 'input',
              title: 'pi-landstrip:control:v1',
              placeholder: JSON.stringify({
                type: 'task',
                input: {
                  description: 'Nested work',
                  prompt: 'Complete nested work.',
                  subagent_type: 'general',
                },
              }),
            });
          },
          async getLastAssistantText() {
            return workerNumber === 1 ? 'Parent complete.' : 'Child complete.';
          },
          async request() {},
          async abort() {},
          async stop() {},
        },
        async dispose() {},
      };
    },
  );
  new SubagentRuntime(
    pi,
    { createTools: () => [] } as unknown as LandstripIntegration,
    createWorker as never,
    (projectCwd) => loadAgentCatalog(projectCwd, piAgentDir),
  ).register();
  const ctx = {
    cwd,
    hasUI: false,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: parentManager,
    model: undefined,
    modelRegistry: { authStorage: {} },
    ui: { notify() {}, setWidget() {} },
  } as unknown as ExtensionContext;

  const result = await taskTool?.execute(
    'parent-call',
    {
      description: 'Parent work',
      prompt: 'Delegate nested work.',
      subagent_type: 'general',
    },
    undefined,
    undefined,
    ctx,
  );

  expect(workerCount).toBe(2);
  expect(result?.content[0]).toMatchObject({
    type: 'text',
    text: expect.stringContaining('Parent complete.'),
  });
  expect(JSON.parse(nestedResponse?.value ?? '{}')).toMatchObject({
    ok: true,
    value: expect.stringContaining('Child complete.'),
  });
});

test('semaphore enforces the configured scheduler-permit capacity', async () => {
  const runtime = new SubagentRuntime({} as ExtensionAPI, {} as LandstripIntegration);
  const semaphore = (
    runtime as unknown as {
      semaphore: { acquire(): Promise<() => void>; tryAcquire(): (() => void) | undefined };
    }
  ).semaphore;
  const release = await semaphore.acquire();

  expect(semaphore.tryAcquire()).toBeUndefined();
  release();

  const nextRelease = semaphore.tryAcquire();
  expect(nextRelease).toBeTypeOf('function');
  nextRelease?.();
});

test('restores a transferred scheduler permit after the admission limit drops to zero', async () => {
  const runtime = new SubagentRuntime({} as ExtensionAPI, {} as LandstripIntegration);
  const internals = runtime as unknown as {
    semaphore: { acquire(): Promise<() => void>; setLimit(limit: number): void };
    leases: Map<string, { release?: () => void }>;
    releaseLease(taskId: string): boolean;
    restoreLease(taskId: string): void;
  };
  internals.leases.set('parent', { release: await internals.semaphore.acquire() });

  expect(internals.releaseLease('parent')).toBe(true);
  internals.semaphore.setLimit(0);
  internals.restoreLease('parent');

  expect(internals.leases.get('parent')?.release).toBeTypeOf('function');
  internals.leases.get('parent')?.release?.();
});

test('does not deliver old background results into a new session', async () => {
  const sendMessage = vi.fn();
  const runtime = new SubagentRuntime(
    { sendMessage } as unknown as ExtensionAPI,
    {} as LandstripIntegration,
  );
  const internals = runtime as unknown as {
    activeSessionId?: string;
    deliverBackground(task: Record<string, unknown>, content: string): Promise<boolean>;
  };
  internals.activeSessionId = 'new-session';

  await expect(
    internals.deliverBackground(
      {
        id: 'task',
        parentSessionId: 'old-session',
        agent: 'general',
        description: 'Old work',
        depth: 0,
        state: 'completed',
      },
      'old result',
    ),
  ).resolves.toBe(false);
  expect(sendMessage).not.toHaveBeenCalled();
});

test('classifies supported Pi versions', () => {
  expect(isSupportedPiVersion([0, 82, 0])).toBe(true);
  expect(isSupportedPiVersion([0, 82, 1])).toBe(true);
  expect(isSupportedPiVersion([0, 90, 0])).toBe(true);
  expect(isSupportedPiVersion([1, 2, 3])).toBe(true);
  expect(isSupportedPiVersion([26, 4, 0])).toBe(true);
  expect(isSupportedPiVersion([0, 81, 99])).toBe(false);
  expect(isSupportedPiVersion([0, 80, 6])).toBe(false);
  expect(isSupportedPiVersion([0, 80, 5])).toBe(false);
  expect(isSupportedPiVersion([0, 79, 99])).toBe(false);
  expect(isSupportedPiVersion([0, 82])).toBe(false);
  expect(isSupportedPiVersion([0, 82, Number.NaN])).toBe(false);
  expect(isSupportedPiVersion([-1, 0, 0])).toBe(false);
});

test('resolves the running Pi package from the extension location', () => {
  const pkg = resolvePiPackage();
  expect(pkg).toBeDefined();
  if (!pkg) return;
  expect(pkg.version).toHaveLength(3);
  expect(pkg.version.every((part) => Number.isInteger(part))).toBe(true);
  expect(isSupportedPiVersion(pkg.version)).toBe(true);
  expect(existsSync(pkg.cliEntry)).toBe(true);
});

test('cleans up orphan subagent session files for the current cwd at startup', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', piAgentDir);

  const orphanDirCurrentCwd = join(
    piAgentDir,
    'sessions',
    'pi-landstrip',
    'orphan-parent-current',
    'task-1',
  );
  mkdirSync(orphanDirCurrentCwd, { recursive: true });
  writeFileSync(
    join(orphanDirCurrentCwd, 'session.jsonl'),
    JSON.stringify({ type: 'header', version: 1, cwd }) + '\n',
  );

  const orphanDirOtherCwd = join(
    piAgentDir,
    'sessions',
    'pi-landstrip',
    'orphan-parent-other',
    'task-2',
  );
  mkdirSync(orphanDirOtherCwd, { recursive: true });
  writeFileSync(
    join(orphanDirOtherCwd, 'session.jsonl'),
    JSON.stringify({ type: 'header', version: 1, cwd: '/some/other/cwd' }) + '\n',
  );

  const orphanDirPrefixCollision = join(
    piAgentDir,
    'sessions',
    'pi-landstrip',
    'orphan-parent-prefix-collision',
    'task-3',
  );
  mkdirSync(orphanDirPrefixCollision, { recursive: true });
  const encodedCwd = `--${cwd.replace(/^[/\\]/, '').replace(/[/\\:]/g, '-')}--`;
  writeFileSync(
    join(orphanDirPrefixCollision, 'task.json'),
    JSON.stringify({
      parentSessionFile: join(piAgentDir, 'sessions', `${encodedCwd}-sibling`, 'session.jsonl'),
    }),
  );

  let sessionStartHandler: ((event: unknown, ctx: unknown) => Promise<void>) | undefined;
  const pi = {
    registerTool() {},
    registerCommand() {},
    registerShortcut() {},
    on(event: string, handler: (event: unknown, ctx: unknown) => Promise<void>) {
      if (event === 'session_start') sessionStartHandler = handler;
    },
    getActiveTools() {
      return [];
    },
    setActiveTools() {},
  } as unknown as ExtensionAPI;

  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const runtime = new SubagentRuntime(pi, {} as LandstripIntegration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();

  const ctx = {
    cwd,
    hasUI: false,
    mode: 'tui',
    isProjectTrusted: () => true,
    sessionManager: parentManager,
  };

  await sessionStartHandler?.({ type: 'session_start' }, ctx);

  expect(existsSync(join(piAgentDir, 'sessions', 'pi-landstrip', 'orphan-parent-current'))).toBe(
    false,
  );
  expect(existsSync(join(piAgentDir, 'sessions', 'pi-landstrip', 'orphan-parent-other'))).toBe(
    true,
  );
  expect(
    existsSync(join(piAgentDir, 'sessions', 'pi-landstrip', 'orphan-parent-prefix-collision')),
  ).toBe(true);
});

test('renders sandbox state in the settings pane and toggles it', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  vi.stubEnv('PI_CODING_AGENT_DIR', piAgentDir);
  const handlers = new Map<string, (args: string, ctx: ExtensionContext) => Promise<void>>();
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      handlers.set(name, definition.handler);
    },
    registerShortcut() {},
    on() {},
    getActiveTools: () => [],
    setActiveTools() {},
  } as unknown as ExtensionAPI;

  let enabled = true;
  const setEnabledCalls: Array<{ enabled: boolean; scope: string }> = [];
  const integration = {
    sandboxCallbacks: {
      load: () => ({ global: enabled }),
      async setEnabled(_ctx: ExtensionContext, next: boolean, scope: string) {
        enabled = next;
        setEnabledCalls.push({ enabled: next, scope });
      },
      async clearProject() {},
      overview: () => ({
        enabled,
        running: enabled,
        noSandboxFlag: false,
        networkMode: 'proxied',
        shellReadMode: 'host',
        readRuleScope: 'Workers only',
        changeScope: 'project',
        paths: {
          global: '/global/sandbox.json',
          project: '/project/sandbox.json',
          binary: '/bin/landstrip',
        },
        config: {
          enabled,
          shell: { readAccess: 'host' },
          network: {
            allowNetwork: false,
            allowLocalBinding: false,
            allowAllUnixSockets: false,
            allowUnixSockets: [],
            allowedDomains: ['example.com'],
            deniedDomains: [],
          },
          filesystem: {
            denyRead: ['~/.ssh'],
            allowRead: [],
            allowWrite: ['.'],
            denyWrite: ['**/.env'],
          },
          windows: { appContainerMode: 'lpac', allowLoopback: false },
        },
        sessionDomains: [],
        sessionReadPaths: [],
        sessionWritePaths: [],
      }),
    },
  } as unknown as LandstripIntegration;
  new SubagentRuntime(pi, integration).register();

  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let overlayOptions: unknown;
  let finishCustom: (() => void) | undefined;
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    isProjectTrusted: () => true,
    ui: {
      notify() {},
      async confirm() {
        return true;
      },
      custom(
        factory: (tui: unknown, theme: unknown, kb: unknown, done: () => void) => typeof component,
        options: unknown,
      ) {
        overlayOptions = options;
        return new Promise<void>((resolve) => {
          finishCustom = resolve;
          component = factory(
            { requestRender() {} },
            { fg: (_color: string, value: string) => value, bold: (value: string) => value },
            undefined,
            resolve,
          );
        });
      },
    },
  } as unknown as ExtensionContext;

  const running = handlers.get('landstrip')?.('', ctx);
  expect(overlayOptions).toMatchObject({
    overlay: true,
    overlayOptions: { anchor: 'bottom-center', width: '100%' },
  });
  const pane = component?.render(96).join('\n') ?? '';
  expect(pane).toContain('[Overview]  Primary');
  expect(pane).toContain('Active');
  expect(pane).toContain('proxied');
  expect(pane).toContain('example.com');
  expect(pane).toContain('/project/sandbox.json');
  expect(pane).toContain('Enter disable in project');
  expect(pane).not.toMatch(/[╭╮╰╯│]/);

  component?.handleInput('\r');
  expect(component?.render(96).join('\n')).toContain('Disable the sandbox?');
  expect(setEnabledCalls).toEqual([]);
  component?.handleInput('\r');
  await vi.waitFor(() => {
    expect(setEnabledCalls).toEqual([{ enabled: false, scope: 'project' }]);
    expect(component?.render(96).join('\n')).toContain('Enter enable in project');
  });
  expect(component?.render(96).join('\n')).toContain('Disabled by configuration');

  component?.handleInput('\x1b');
  finishCustom?.();
  await running;
  vi.unstubAllEnvs();
});
