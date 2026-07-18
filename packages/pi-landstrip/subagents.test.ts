// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  type ExtensionAPI,
  type ExtensionContext,
  initTheme,
  SessionManager,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { afterEach, expect, test, vi } from 'vitest';

import { loadAgentCatalog } from './agents.ts';
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

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const path = mkdtempSync(join(tmpdir(), 'pi-landstrip-tasks-'));
  temporaryDirectories.push(path);
  return path;
}

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

test('renders OpenCode-compatible task result envelopes', () => {
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
  const entries: Array<{ type: string; data: unknown }> = [];
  const statuses: string[] = [];
  const selections: string[] = [];
  const pi = {
    registerTool() {},
    registerCommand() {},
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
      if (event === 'before_agent_start') {
        beforeAgentStart = handler as typeof beforeAgentStart;
      }
      if (event === 'tool_call') toolCall = handler as typeof toolCall;
    },
    getActiveTools: () => ['read', 'bash'],
    setActiveTools() {},
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
  } as unknown as ExtensionAPI;
  const cwd = temporaryDirectory();
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    ui: {
      notify() {},
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
    sessionManager: {
      getBranch: () => [],
      getSessionId: () => 'parent',
    },
  } as unknown as ExtensionContext;
  const integration = { createTools: () => [] } as unknown as LandstripIntegration;
  const piAgentDir = temporaryDirectory();
  writeFileSync(
    join(piAgentDir, 'subagents.json'),
    JSON.stringify({
      subagents: {
        agent: { plan: { permission: { edit: { '*': 'allow', 'secrets/**': 'deny' } } } },
      },
    }),
  );
  const runtime = new SubagentRuntime(pi, integration, undefined, (projectCwd) =>
    loadAgentCatalog(projectCwd, piAgentDir),
  );
  runtime.register();

  await sessionStart?.({ type: 'session_start' }, ctx);
  expect(statuses.at(-1)).toBe('@build');
  expect(runtime.selectPrimaryAgent('plan', ctx)).toBe(true);
  expect(entries.at(-1)).toEqual({ type: 'landstrip.primary-agent', data: { name: 'plan' } });
  expect(statuses.at(-1)).toBe('@plan');

  const result = await beforeAgentStart?.({ systemPrompt: 'Base prompt' }, ctx);
  expect(result?.systemPrompt).toContain('Base prompt\n\nWork in plan mode.');
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
  writeFileSync(join(cwd, '.pi', 'subagents.json'), JSON.stringify({ maxSubagents: 4 }));
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

test('removes the task tool when maxSubagents is zero', async () => {
  let sessionStart: ((event: unknown, ctx: ExtensionContext) => Promise<void>) | undefined;
  let activeTools = ['read', 'task'];
  const pi = {
    registerTool() {},
    registerCommand() {},
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
  writeFileSync(join(piAgentDir, 'subagents.json'), JSON.stringify({ maxSubagents: 0 }));
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
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: {
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
  expect(callLines?.join('\n')).toContain('Agent Task (background) — Review implementation');

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
  let component: { render(width: number): string[]; handleInput(data: string): void } | undefined;
  let finishCustom: (() => void) | undefined;
  const pi = {
    registerTool() {},
    registerCommand(
      name: string,
      definition: { handler: (args: string, ctx: ExtensionContext) => Promise<void> },
    ) {
      if (name === 'subagents') command = definition.handler;
    },
    on(event: string, handler: unknown) {
      if (event === 'session_start') sessionStart = handler as typeof sessionStart;
    },
    getActiveTools: () => ['task'],
    setActiveTools() {},
    sendMessage() {},
    appendEntry() {},
  } as unknown as ExtensionAPI;
  new SubagentRuntime(pi, {} as LandstripIntegration, undefined, () => ({
    maxSubagents: 1,
    agents: new Map(),
    permissions: [],
    warnings: [],
    diagnostics: [],
  })).register();
  const theme = {
    fg: (_color: string, value: string) => value,
    bold: (value: string) => value,
  };
  const ctx = {
    cwd,
    hasUI: true,
    mode: 'tui',
    sessionManager: parentManager,
    ui: {
      notify() {},
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

  await sessionStart?.({}, ctx);
  const running = command?.('', ctx);
  expect(component?.render(96).join('\n')).toContain('Subagent Sessions');
  expect(component?.render(96).join('\n')).toContain('task-123');
  expect(component?.render(96).join('\n')).toContain('Failed child');
  component?.handleInput('\r');
  const detail = component?.render(96).join('\n');
  expect(detail).toContain('Inspect this child session.');
  expect(detail).toContain('Parent p/backspace  Prev ←  Next →');
  component?.handleInput('\x1b[C');
  expect(component?.render(96).join('\n')).toContain('Child failed visibly');
  component?.handleInput('\x1b[D');
  expect(component?.render(96).join('\n')).toContain('Inspect child');
  component?.handleInput('\x1b');
  expect(component?.render(96).join('\n')).toContain('Subagent Sessions');
  finishCustom?.();
  await running;
});

test('cancels worker startup promptly and disposes a worker created afterward', async () => {
  const cwd = temporaryDirectory();
  const piAgentDir = temporaryDirectory();
  mkdirSync(join(cwd, '.pi'), { recursive: true });
  writeFileSync(
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
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
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
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
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
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
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
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
    join(cwd, '.pi', 'subagents.json'),
    JSON.stringify({
      maxSubagents: 4,
      subagents: { agent: { review: { mode: 'subagent', prompt: 'Review.' } } },
    }),
  );
  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
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
  writeFileSync(join(cwd, '.pi', 'subagents.json'), JSON.stringify({ maxSubagents: 1 }));

  let taskTool: ToolDefinition | undefined;
  const parentManager = SessionManager.create(cwd, join(cwd, 'sessions'));
  const pi = {
    registerTool(tool: ToolDefinition) {
      taskTool = tool;
    },
    registerCommand() {},
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
  expect(isSupportedPiVersion([0, 80, 6])).toBe(true);
  expect(isSupportedPiVersion([0, 80, 7])).toBe(true);
  expect(isSupportedPiVersion([0, 80, 99])).toBe(true);
  expect(isSupportedPiVersion([0, 80, 5])).toBe(false);
  expect(isSupportedPiVersion([0, 79, 99])).toBe(false);
  expect(isSupportedPiVersion([0, 81, 0])).toBe(false);
  expect(isSupportedPiVersion([1, 2, 3])).toBe(false);
  expect(isSupportedPiVersion([26, 4, 0])).toBe(false);
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
