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
      }
    | undefined;
  const integration = {
    getWorkerExtensions: () => [{ id: 'test', entry: extensionEntry }],
    getContext: () => ({
      version: 1,
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
    getActiveTools: () => ['read', 'bash'],
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
    model: { provider: 'test', id: 'model' },
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
      },
      [],
      ctx,
      new AbortController().signal,
      async () => undefined,
    ),
  ).rejects.toThrow('stop after preparation');

  expect(prepared?.args).toContain(extensionEntry);
  expect(prepared?.readPaths).toContain(extensionEntry);
  expect(prepared?.readPaths).toContain(cwd);
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
  const integration = { createTools: () => [] } as unknown as LandstripIntegration;
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'settings.json'),
    JSON.stringify({
      landstrip: {
        agent: {
          plan: {
            model: 'anthropic/claude-plan',
            variant: 'high',
            permission: { edit: { '*': 'allow', 'secrets/**': 'deny' } },
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

test('updates task availability when maxSubagents changes', () => {
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
  const integration = { createTools: () => [] } as unknown as LandstripIntegration;
  let createdAgent: string | undefined;
  let emit: ((event: Record<string, unknown>) => void) | undefined;
  const onUpdate = vi.fn();
  let forwardRequest: ((request: Record<string, unknown>) => Promise<unknown>) | undefined;
  const fakeRpc = {
    onEvent(listener: (event: Record<string, unknown>) => void) {
      emit = listener;
      return () => {};
    },
    async prompt() {
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
      await forwardRequest?.({ method: 'select', title: 'Choose item', options: ['one'] });
      await forwardRequest?.({ method: 'confirm', title: 'Confirm action', message: 'Proceed?' });
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
  ).toEqual(['Running read', 'Review', 'Review', 'Reviewed.']);
  expect(onUpdate.mock.calls[0]?.[0]).toMatchObject({
    details: { currentTool: 'read', toolCalls: 1, state: 'running' },
  });
  expect(result?.details).toMatchObject({
    description: 'Review implementation',
    state: 'completed',
    toolCalls: 1,
    output: 'Reviewed.\nline 2\nline 3\nline 4',
  });
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
  expect(lines?.join('\n')).toContain('Subagents  1 active');
  expect(lines?.join('\n')).toContain('@review  Review implementation');
  expect(widgets.at(-1)).toBeUndefined();
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
        },
      },
    }),
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
      if (name === 'agents') command = definition.handler;
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
  new SubagentRuntime(pi, integration).register();
  const theme = {
    fg: (_color: string, value: string) => value,
    bold: (value: string) => value,
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
  expect(commandNames).toEqual(['agents']);
  const running = command?.('', ctx);
  const agents = component?.render(96).join('\n') ?? '';
  expect(agents).toContain('[Agents]  Tasks  Settings  ·  Scope: Project');
  expect(agents).toContain('@build');
  expect(agents).toMatch(/@build\s+primary\s+built-in/);
  expect(agents).toMatch(/@general\s+subagent\s+built-in/);
  expect(agents).toMatch(/@review\s+subagent\s+local/);
  expect(agents).toContain('Tab next tab');

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
  component?.handleInput('y');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.build).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(/@build\s+primary\s+built-in/);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('\x1b[B');
  component?.handleInput(' ');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.explore.disable).toBe(true);
    expect(component?.render(96).join('\n')).toMatch(/@explore\s+subagent\s+local.*disabled/);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('i');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.agent.explore).toBeUndefined();
    expect(component?.render(96).join('\n')).toMatch(
      /@explore\s+subagent\s+built-in.*inherited on/,
    );
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('\x1b[A');

  component?.handleInput('\x1b[B');
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
  component?.handleInput('\x1b[A');

  component?.handleInput('s');
  const globalAgents = component?.render(96).join('\n') ?? '';
  expect(globalAgents).toContain('[Agents]  Tasks  Settings  ·  Scope: Global');
  expect(globalAgents).toMatch(/@review\s+subagent\s+local.*unavailable/);
  component?.handleInput('s');

  component?.handleInput('\t');
  const tasks = component?.render(96).join('\n') ?? '';
  expect(tasks).toContain('[Tasks]');
  expect(tasks).not.toContain('Tasks 2');
  expect(tasks).toContain('task-123');
  expect(tasks).toContain('Failed child');
  component?.handleInput('\x1b[D');
  expect(component?.render(96).join('\n')).toContain('[Tasks]');
  component?.handleInput('\x1b[C');
  expect(component?.render(96).join('\n')).toContain('[Tasks]');
  component?.handleInput('\r');
  const detail = component?.render(96).join('\n') ?? '';
  expect(detail).toContain('Inspect this child session.');
  expect(detail).toContain('Esc task list');
  component?.handleInput('\x1b[C');
  expect(component?.render(96).join('\n')).toBe(detail);
  component?.handleInput('\x1b[D');
  expect(component?.render(96).join('\n')).toBe(detail);
  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).toContain('[Tasks]');
  component?.handleInput('\t');

  const projectSettings = component?.render(96).join('\n') ?? '';
  expect(projectSettings).toContain('[Settings]');
  expect(projectSettings).toContain('[ - ] Maximum subagents');
  expect(projectSettings).toContain('[ - ] Sandbox enabled');

  component?.handleInput('\x1b[B');
  component?.handleInput(' ');
  expect(component?.render(96).join('\n')).toContain('[ off ] Sandbox enabled');
  component?.handleInput('\t');
  expect(component?.render(96).join('\n')).toContain('[Settings]');
  expect(component?.render(96).join('\n')).toContain('[ off ] Sandbox enabled');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    expect(sandboxProject).toBe(false);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });
  component?.handleInput('\x1b[A');

  component?.handleInput('s');
  expect(component?.render(96).join('\n')).toContain('Scope: Global');
  expect(component?.render(96).join('\n')).toContain('[ 1 ] Maximum subagents');
  component?.handleInput('+');
  expect(component?.render(96).join('\n')).toContain('[ 2 ] Maximum subagents');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(agentDir, 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBe(2);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('s');
  expect(component?.render(96).join('\n')).toContain('Scope: Project');
  component?.handleInput('3');
  expect(component?.render(96).join('\n')).toContain('[ 3 ] Maximum subagents');
  component?.handleInput('r');
  expect(component?.render(96).join('\n')).toContain('[ - ] Maximum subagents');
  component?.handleInput('3');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBe(3);
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('i');
  expect(component?.render(96).join('\n')).toContain('[ - ] Maximum subagents');
  component?.handleInput('\r');
  await vi.waitFor(() => {
    const settings = JSON.parse(readFileSync(join(cwd, '.pi', 'settings.json'), 'utf8'));
    expect(settings.landstrip.maxSubagents).toBeUndefined();
    expect(settings.landstrip.agent.review).toBeDefined();
    expect(component?.render(96).join('\n')).not.toContain('Saving…');
  });

  component?.handleInput('\t');
  const cycledAgents = component?.render(96).join('\n') ?? '';
  expect(cycledAgents).toContain('[Agents]  Tasks  Settings  ·  Scope: Project');
  expect(cycledAgents).toContain('Tab next tab');
  finishCustom?.();
  await running;

  const direct = command?.('task-123', ctx);
  expect(component?.render(96).join('\n')).toContain('Inspect this child session.');
  finishCustom?.();
  await direct;
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

test('sends a continuation queued during worker startup once RPC is available', async () => {
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

  resolveWorker?.({ rpc: fakeRpc, async dispose() {} });
  await vi.waitFor(() =>
    expect(request).toHaveBeenCalledWith('follow_up', { message: 'Also inspect tests.' }),
  );
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
    return {
      rpc: {
        onEvent: () => () => {},
        async prompt() {
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
