// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, onTestFinished, test, vi } from 'vitest';

import type { AgentCatalog } from './agents.ts';
import {
  getLandstripSandboxArgumentCompletions,
  getLandstripSubagentsArgumentCompletions,
  matchingTasksById,
} from './commands.ts';
import {
  createLandstripIntegration,
  type LandstripBashInput,
  type LandstripIntegration,
} from './index.ts';
import type { RpcProcess } from './rpc-process.ts';
import { SubagentRuntime, type SubagentTaskRecord, type TasksToolInput } from './subagents.ts';

afterEach(() => {
  vi.unstubAllEnvs();
});

function createMockExtensionAPI() {
  const tools = new Map<string, any>();
  const shortcuts = new Map<string, any>();
  const commands = new Map<string, any>();
  const listeners = new Map<string, Array<(...args: any[]) => any>>();
  const messages: any[] = [];
  const entries: any[] = [];
  let activeTools: string[] = ['bash', 'task', 'tasks'];

  const api: Partial<ExtensionAPI> = {
    registerTool(tool: any) {
      tools.set(tool.name, tool);
    },
    registerShortcut(key: string, options: any) {
      shortcuts.set(key, options);
    },
    registerCommand(name: string, options: any) {
      commands.set(name, options);
    },
    on(event: string, handler: (...args: any[]) => any) {
      const list = listeners.get(event) ?? [];
      list.push(handler);
      listeners.set(event, list);
      return () => {
        const idx = list.indexOf(handler);
        if (idx !== -1) list.splice(idx, 1);
      };
    },
    sendMessage(message: any, options?: any) {
      messages.push({ message, options });
    },
    appendEntry(customType: string, data: any) {
      entries.push({ customType, data });
    },
    getActiveTools() {
      return [...activeTools];
    },
    setActiveTools(next: string[]) {
      activeTools = [...next];
    },
  };

  return {
    api: api as ExtensionAPI,
    tools,
    shortcuts,
    commands,
    listeners,
    messages,
    entries,
  };
}

function createMockExtensionContext(dir: string): ExtensionContext {
  const sessionEntries: any[] = [];
  return {
    cwd: dir,
    hasUI: false,
    sessionManager: {
      getSessionId: () => 'test-session-123',
      getSessionFile: () => join(dir, 'session.json'),
      getBranch: () => sessionEntries,
      appendCustomEntry: (_type: string, data: any) => {
        sessionEntries.push({ type: 'custom', customType: 'landstrip.task', data });
      },
    } as any,
    ui: {
      notify: vi.fn(),
      setWidget: vi.fn(),
      custom: vi.fn(),
    } as any,
  } as unknown as ExtensionContext;
}

describe('Task Cancellation vs Deletion Lifecycle', () => {
  test('cancelTasks transitions active tasks to cancelled without deleting them', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      let aborted = false;

      const integration: LandstripIntegration = {
        ...createLandstripIntegration({ registerBashTool: false, cwd: root }),
        runSandboxedCommand: async (_cmd, _cwd, options) => {
          options.signal?.addEventListener('abort', () => {
            aborted = true;
          });
          return new Promise((resolve) => {
            options.signal?.addEventListener('abort', () => {
              resolve({ exitCode: null });
            });
          });
        },
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();

      const ctx = createMockExtensionContext(root);
      // Initialize active session
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const launchResult = await runtime.runBackgroundShellTask(
        { command: 'sleep 60', name: 'long-sleep' },
        ctx,
      );

      const taskId = launchResult.details.taskId;
      expect(taskId).toBeDefined();

      const tasksBefore = runtime.getTasks();
      const task = tasksBefore.find((t) => t.id === taskId);
      expect(task).toBeDefined();
      expect(task?.state).toBe('running');

      const count = await runtime.cancelTasks([taskId], ctx);
      expect(count).toBe(1);
      expect(aborted).toBe(true);

      const tasksAfter = runtime.getTasks();
      const cancelledTask = tasksAfter.find((t) => t.id === taskId);
      expect(cancelledTask).toBeDefined();
      expect(cancelledTask?.state).toBe('cancelled');
      expect(cancelledTask?.deleted).toBeUndefined();

      // Deleting removes the task completely
      const delCount = runtime.deleteTasks([taskId], ctx);
      expect(delCount).toBe(1);
      const tasksFinal = runtime.getTasks();
      expect(tasksFinal.find((t) => t.id === taskId)).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('cancelTasks recursively cascades to child subagent tasks', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();
      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      // Populate mock parent and child tasks
      const parentTask: SubagentTaskRecord = {
        version: 1,
        id: 'parent-task-1',
        agent: 'architect',
        description: 'parent task',
        parentSessionId: 'test-session-123',
        depth: 0,
        state: 'running',
        startedAt: Date.now(),
      };
      const childTask: SubagentTaskRecord = {
        version: 1,
        id: 'child-task-1',
        parentTaskId: 'parent-task-1',
        agent: 'developer',
        description: 'child task',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'running',
        startedAt: Date.now(),
      };

      (runtime as any).tasks.set(parentTask.id, parentTask);
      (runtime as any).tasks.set(childTask.id, childTask);

      const cancelledCount = await runtime.cancelTasks(['parent-task-1'], ctx);
      expect(cancelledCount).toBe(2);
      expect(parentTask.state).toBe('cancelled');
      expect(childTask.state).toBe('cancelled');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('Tasks Tool (list, inspect, cancel)', () => {
  test('tasks tool executes list, inspect, and cancel operations', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration: LandstripIntegration = {
        ...createLandstripIntegration({ registerBashTool: false, cwd: root }),
        runSandboxedCommand: async (_cmd, _cwd, options) => {
          options.onData?.(Buffer.from('hello from background command\n'));
          return { exitCode: 0 };
        },
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();
      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const tasksTool = mockApi.tools.get('tasks');
      expect(tasksTool).toBeDefined();

      // Launch a background shell task
      const launched = await runtime.runBackgroundShellTask(
        { command: 'echo test', name: 'echo-test' },
        ctx,
      );
      const taskId = launched.details.taskId;

      // 1. List
      const listResult = await tasksTool.execute(
        'call-1',
        { action: 'list' } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(listResult.content[0].text).toContain(taskId);
      expect(listResult.details.count).toBe(1);

      // 2. Inspect with prefix
      const inspectResult = await tasksTool.execute(
        'call-2',
        { action: 'inspect', task_id: taskId.slice(0, 8) } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(inspectResult.content[0].text).toContain('echo test');

      // 3. Cancel with prefix
      const cancelResult = await tasksTool.execute(
        'call-3',
        { action: 'cancel', task_id: taskId.slice(0, 8) } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(cancelResult.content[0].text).toContain('Cancelled task');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('matchingTasksById prefix matching helper', () => {
  test('matches exact ID first and falls back to unambiguous prefix', () => {
    const tasks = [
      { id: 'abcdef123456', agent: 'bash', state: 'running' },
      { id: 'abc999888777', agent: 'bash', state: 'running' },
      { id: 'xyz123456789', agent: 'bash', state: 'running' },
    ];

    expect(matchingTasksById(tasks, 'abcdef123456')).toEqual([tasks[0]]);
    expect(matchingTasksById(tasks, 'abcdef')).toEqual([tasks[0]]);
    expect(matchingTasksById(tasks, 'abc')).toEqual([tasks[0], tasks[1]]);
    expect(matchingTasksById(tasks, 'xyz')).toEqual([tasks[2]]);
    expect(matchingTasksById(tasks, 'nonexistent')).toEqual([]);
  });
});

describe('Sandboxed Background Process Execution in Bash Tool', () => {
  test('bash tool routes background executions to SubagentRuntime', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      let capturedCommand = '';

      const integration = createLandstripIntegration({ registerBashTool: true, cwd: root });
      integration.runSandboxedCommand = async (cmd, _cwd, options) => {
        capturedCommand = cmd;
        options.onData?.(Buffer.from('streamed output data\n'));
        return { exitCode: 0 };
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const bashTool = mockApi.tools.get('bash');
      expect(bashTool).toBeDefined();

      const input: LandstripBashInput = {
        command: 'npm run build',
        background: true,
        name: 'build-step',
      };

      const result = await bashTool.execute(
        'call-bash-bg',
        input,
        new AbortController().signal,
        () => {},
        ctx,
      );

      expect(result.content[0].text).toContain('Command launched in background');
      expect(result.details.taskId).toBeDefined();
      expect(result.details.state).toBe('running');
      expect(result.details.description).toBe('build-step');

      // Allow background microtasks to settle
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(capturedCommand).toBe('npm run build');
      const task = runtime.getTasks().find((t) => t.id === result.details.taskId);
      expect(task).toBeDefined();
      expect(task?.state).toBe('completed');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('Landstrip Split Views (/landstrip-sandbox and /landstrip-subagents)', () => {
  test('renders dedicated Overview and Policy tabs in /landstrip-sandbox and scoped tabs in /landstrip-subagents', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      writeFileSync(
        join(root, 'sandbox.json'),
        JSON.stringify({
          enabled: true,
          filesystem: {
            denyRead: ['/secret-read'],
            denyReadAlways: ['/hard-secret-read'],
            allowRead: ['.'],
            allowWrite: ['.'],
            denyWrite: ['**/.env'],
            denyWriteAlways: ['/hard-secret-write'],
          },
        }),
      );

      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      let terminalRows = 30;
      let capturedComponent: any;
      const ctx = {
        ...createMockExtensionContext(root),
        mode: 'tui',
        hasUI: true,
        ui: {
          notify: vi.fn(),
          setWidget: vi.fn(),
          custom: vi.fn(async (factory: any) => {
            const tui = {
              get terminal() {
                return { rows: terminalRows };
              },
              requestRender: vi.fn(),
            };
            const theme = {
              fg: (_color: string, text: string) => text,
              bold: (text: string) => text,
            };
            capturedComponent = factory(tui, theme, {}, () => {});
          }),
        } as any,
      } as unknown as ExtensionContext;

      expect([...mockApi.commands.keys()].sort()).toEqual([
        'landstrip-sandbox',
        'landstrip-subagents',
      ]);
      const sandboxCommand = mockApi.commands.get('landstrip-sandbox')!;
      const subagentsCommand = mockApi.commands.get('landstrip-subagents')!;

      expect(getLandstripSandboxArgumentCompletions('').map((item) => item.value)).toEqual([
        'status',
        'policy',
        'on',
        'off',
        'help',
      ]);
      expect(
        getLandstripSubagentsArgumentCompletions('', runtime).map((item) => item.value),
      ).toEqual(['tasks', 'logs', 'subagents', 'agents', 'settings', 'help']);

      await sandboxCommand.handler('', ctx);
      expect(capturedComponent).toBeDefined();

      const initialFrame = capturedComponent.render(100).join('\n');
      expect(initialFrame).toContain('[Overview]  Policy  Help');
      expect(initialFrame).not.toContain('Subagent');
      expect(initialFrame).toContain('Read rules           8 · Workers only');
      expect(initialFrame).toContain('Write rules          9');
      expect(initialFrame).toContain('Enter disable in global');

      capturedComponent.handleInput('\r');
      const confirmFrame = capturedComponent.render(100).join('\n');
      expect(confirmFrame).toContain(
        'Disable the sandbox? Commands will run without OS isolation.',
      );
      expect(confirmFrame).toContain('Enter confirm  ·  Esc cancel');

      capturedComponent.handleInput('\x1b');
      capturedComponent.handleInput('\t');
      const policyFrame = capturedComponent.render(100).join('\n');
      expect(policyFrame).toContain('Overview  [Policy]  Help');
      expect(policyFrame).toContain('Network');
      expect(policyFrame).toContain('Filesystem');
      expect(policyFrame).toContain('/secret-read');
      expect(policyFrame).toContain('Always denied reads  /hard-secret-read');
      expect(policyFrame).toContain('**/.env');
      expect(policyFrame).toContain('Always denied writes /hard-secret-write');

      terminalRows = 20;
      const compactPolicyFrame = capturedComponent.render(100).join('\n');
      expect(compactPolicyFrame).toContain('↑ / ↓ scroll');
      capturedComponent.handleInput('\x1b[F');
      const bottomPolicyFrame = capturedComponent.render(100).join('\n');
      expect(bottomPolicyFrame).toContain('Session grants');

      terminalRows = 30;
      await subagentsCommand.handler('', ctx);
      const subagentsFrame = capturedComponent.render(100).join('\n');
      expect(subagentsFrame).toContain('[Tasks]  Log  Subagent  Primary  Settings  Help');
      expect(subagentsFrame).not.toContain('Overview');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('Foreground vs Background Task Differentiation', () => {
  test('filters tasks by mode/state and renders [bg]/[fg] badges across tools and TUI', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const baseCtx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, baseCtx);
      }

      const bgTask: SubagentTaskRecord = {
        version: 1,
        id: 'bg-task-11111111',
        kind: 'subagent',
        agent: 'explore',
        description: 'Background repo scan',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'running',
        background: true,
        toolCalls: 3,
        startedAt: Date.now() - 2000,
      };
      const fgTask: SubagentTaskRecord = {
        version: 1,
        id: 'fg-task-22222222',
        kind: 'subagent',
        agent: 'scout',
        description: 'Foreground symbol check',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'completed',
        background: false,
        toolCalls: 1,
        startedAt: Date.now() - 4000,
        finishedAt: Date.now() - 1000,
      };
      (runtime as any).tasks.set(bgTask.id, bgTask);
      (runtime as any).tasks.set(fgTask.id, fgTask);

      const tasksTool = mockApi.tools.get('tasks');
      const bgList = await tasksTool.execute(
        'call-bg',
        { action: 'list', mode: 'background', state: 'running' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      const bgEntries = JSON.parse(bgList.content[0].text);
      expect(bgEntries).toHaveLength(1);
      expect(bgEntries[0].id).toBe('bg-task-11111111');
      expect(bgEntries[0].mode).toBe('background');
      expect(bgEntries[0].background).toBe(true);
      expect(bgEntries[0].toolCalls).toBe(3);

      const fgList = await tasksTool.execute(
        'call-fg',
        { action: 'list', mode: 'foreground' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      const fgEntries = JSON.parse(fgList.content[0].text);
      expect(fgEntries).toHaveLength(1);
      expect(fgEntries[0].id).toBe('fg-task-22222222');
      expect(fgEntries[0].mode).toBe('foreground');
      expect(fgEntries[0].background).toBe(false);

      const inspectBg = await tasksTool.execute(
        'call-inspect',
        { action: 'inspect', task_id: 'bg-task-1' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      expect(inspectBg.content[0].text).toContain('Mode: background');

      const taskTool = mockApi.tools.get('task');
      const plainTheme = {
        fg: (_color: string, text: string) => text,
        bold: (text: string) => text,
      };
      const renderedResult = taskTool
        .renderResult(
          {
            content: [{ type: 'text', text: 'done' }],
            details: inspectBg.details,
          },
          { expanded: false },
          plainTheme,
        )
        .render(100)
        .join('\n');
      expect(renderedResult).toContain('[bg]');
      expect(renderedResult).toContain('↳ /landstrip-subagents bg-task- to inspect');

      let capturedComponent: any;
      const tuiCtx = {
        ...baseCtx,
        mode: 'tui',
        hasUI: true,
        ui: {
          notify: vi.fn(),
          setWidget: vi.fn(),
          custom: vi.fn(async (factory: any) => {
            const tui = { terminal: { rows: 30 }, requestRender: vi.fn() };
            capturedComponent = factory(tui, plainTheme, {}, () => {});
          }),
        } as any,
      } as unknown as ExtensionContext;

      bgTask.output = Array.from({ length: 30 }, (_, i) => `Line ${i + 1}`).join('\n');

      const subagentsCommand = mockApi.commands.get('landstrip-subagents');
      await subagentsCommand.handler('tasks', tuiCtx);
      const tasksFrame = capturedComponent.render(100).join('\n');
      expect(tasksFrame).toContain('[bg] @explore Background repo scan · 3 calls');
      expect(tasksFrame).toContain('[fg] @scout Foreground symbol check');
      expect(tasksFrame).toContain('S steer  ·  C cancel  ·  R clear finished');

      // Press S from Tasks tab to jump directly into Log tab with Steer input active
      capturedComponent.handleInput('s');
      const steerFrame = capturedComponent.render(100).join('\n');
      expect(steerFrame).toContain('@explore [bg] Background repo scan');
      expect(steerFrame).toContain('Steer ›');
      // Cancel steer input
      capturedComponent.handleInput('\x1b');

      const logFrame = capturedComponent.render(100).join('\n');
      expect(logFrame).toContain('bg-task-11111111 · background · 3 tool calls');
      expect(logFrame).toContain('Follow: on');

      // Up arrow auto-pauses follow and scrolls up without needing F first
      capturedComponent.handleInput('\x1b[A');
      const scrolledLogFrame = capturedComponent.render(100).join('\n');
      expect(scrolledLogFrame).toContain('Follow: off');

      // End key resumes follow
      capturedComponent.handleInput('\x1b[F');
      const resumedLogFrame = capturedComponent.render(100).join('\n');
      expect(resumedLogFrame).toContain('Follow: on');

      // Return to Tasks tab and press R to clear finished tasks
      capturedComponent.handleInput('\x1b');
      capturedComponent.handleInput('r');
      const clearConfirmFrame = capturedComponent.render(100).join('\n');
      expect(clearConfirmFrame).toContain('Delete fg-task-?');
      capturedComponent.handleInput('\r');
      const afterClearFrame = capturedComponent.render(100).join('\n');
      expect(afterClearFrame).not.toContain('fg-task-');
      expect(afterClearFrame).toContain('bg-task-');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('Background Subagent Lifecycle & Context Seeding', () => {
  test('supports non-blocking background lifecycle, steer, bounded inspect slicing, and parent context seeding', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: true, cwd: root });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const ctx = createMockExtensionContext(root);
      (ctx.sessionManager as any).getBranch = () => [
        {
          type: 'message',
          message: {
            role: 'user',
            content: 'We need to audit worker auth paths.',
          },
        },
        {
          type: 'message',
          message: {
            role: 'assistant',
            content: [{ type: 'text', text: 'I found worker-auth-runtime.ts.' }],
          },
        },
      ];

      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const bgTask: SubagentTaskRecord = {
        version: 1,
        id: 'bg-lifecycle-1234',
        kind: 'subagent',
        agent: 'explore',
        description: 'Audit worker auth',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'running',
        background: true,
        toolCalls: 2,
        startedAt: Date.now() - 1000,
        output: Array.from({ length: 10 }, (_, i) => `Step ${i + 1}`).join('\n'),
      };
      (runtime as any).tasks.set(bgTask.id, bgTask);

      let resolveRun!: (value: string) => void;
      const runPromise = new Promise<string>((r) => {
        resolveRun = r;
      });
      (runtime as any).runPromises.set(bgTask.id, runPromise);
      void (runtime as any).notifyWhenDone(bgTask, runPromise, ctx);

      const bashTool = mockApi.tools.get('bash');
      const taskTool = mockApi.tools.get('task');
      const tasksTool = mockApi.tools.get('tasks');
      expect(bashTool?.promptGuidelines?.join('\n')).toContain(
        'Do not sleep or poll tasks to wait',
      );
      expect(taskTool?.promptGuidelines?.join('\n')).toContain('Do not poll tasks to wait');
      expect(tasksTool?.promptGuidelines?.join('\n')).toContain('not as a waiting primitive');

      // Bounded inspect with offset + lines and active background guidance
      const slicedInspect = await tasksTool.execute(
        'call-slice',
        {
          action: 'inspect',
          task_id: 'bg-lifecycle',
          offset: 2,
          lines: 3,
        } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(slicedInspect.content[0].text).toContain('Step 3\nStep 4\nStep 5');
      expect(slicedInspect.content[0].text).toContain(
        'Next action: task is still active; do not poll inspect in a loop—end this turn and wait for the automatic completion follow-up turn.',
      );
      expect(slicedInspect.content[0].text).not.toContain('Step 1');
      expect(slicedInspect.content[0].text).not.toContain('Step 6');

      // Steer active background subagent
      const steerRes = await tasksTool.execute(
        'call-steer',
        {
          action: 'steer',
          task_id: 'bg-lifecycle',
          message: 'Focus on seccomp EACCES',
        } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(steerRes.content[0].text).toContain('Steered task bg-lifec (@explore)');
      expect((runtime as any).pendingSteers.get(bgTask.id)).toEqual(['Focus on seccomp EACCES']);

      // Automatic follow-up turn delivery when background task completes
      bgTask.state = 'completed';
      bgTask.output = 'Completed audit.';
      bgTask.finishedAt = Date.now();
      resolveRun('Completed audit.');
      await runPromise;
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(mockApi.messages).toContainEqual({
        message: expect.objectContaining({
          customType: 'landstrip.task.result',
          content: expect.stringContaining('Completed audit.'),
          details: { taskId: bgTask.id },
        }),
        options: { triggerTurn: true, deliverAs: 'followUp' },
      });
      // Verify parent context projection helper used by include_context
      const seededPrompt = (runtime as any).withParentContext('Check line 55', ctx);
      expect(seededPrompt).toContain('<parent_context>');
      expect(seededPrompt).toContain('[user]: We need to audit worker auth paths.');
      expect(seededPrompt).toContain('[assistant]: I found worker-auth-runtime.ts.');
      expect(seededPrompt).toContain('</parent_context>\n\nCheck line 55');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('primary file tools follow sandbox.json readAccess and write policy directly', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      writeFileSync(
        join(root, 'sandbox.json'),
        JSON.stringify({
          enabled: true,
          shell: { readAccess: 'host' },
          filesystem: {
            allowRead: [root],
            denyRead: [join(root, 'soft-secret.txt')],
            denyReadAlways: [join(root, 'hard-secret.txt')],
            allowWrite: [join(root, 'allowed')],
            denyWrite: [join(root, 'allowed', 'readonly.txt')],
            denyWriteAlways: [join(root, 'allowed', 'immutable.txt')],
          },
        }),
      );

      const projectDir = join(root, 'project');
      mkdirSync(projectDir, { recursive: true });
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: projectDir });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();

      const ctx = createMockExtensionContext(projectDir);
      for (const handler of mockApi.listeners.get('session_start') ?? []) {
        await handler({}, ctx);
      }

      const callTool = async (toolName: string, input: Record<string, unknown>) => {
        for (const handler of mockApi.listeners.get('tool_call') ?? []) {
          const result = await handler({ toolName, input }, ctx);
          if (result) return result;
        }
        return undefined;
      };

      expect(await callTool('read', { path: join(root, 'hard-secret.txt') })).toEqual({
        block: true,
        reason: `Read denied by sandbox policy: ${join(root, 'hard-secret.txt')}`,
      });

      if (process.platform !== 'win32') {
        expect(await callTool('read', { path: join(root, 'soft-secret.txt') })).toBeUndefined();
      }

      expect(await callTool('write', { path: join(root, 'allowed', 'ok.txt') })).toBeUndefined();
      expect(await callTool('write', { path: join(root, 'allowed', 'readonly.txt') })).toEqual({
        block: true,
        reason: 'Filesystem access requires approval',
      });
      const select = vi.fn().mockResolvedValue('Allow once');
      const uiCtx = {
        ...ctx,
        hasUI: true,
        ui: {
          ...ctx.ui,
          select,
        },
      };
      let promptResult: unknown;
      for (const handler of mockApi.listeners.get('tool_call') ?? []) {
        const result = await handler(
          { toolName: 'write', input: { path: join(root, 'allowed', 'readonly.txt') } },
          uiCtx,
        );
        if (result) {
          promptResult = result;
          break;
        }
      }
      expect(promptResult).toBeUndefined();
      expect(select).toHaveBeenCalledTimes(1);
      expect(await callTool('edit', { path: join(root, 'allowed', 'immutable.txt') })).toEqual({
        block: true,
        reason: `Write denied by sandbox policy: ${join(root, 'allowed', 'immutable.txt')}`,
      });
      expect(await callTool('write', { path: join(root, 'outside.txt') })).toEqual({
        block: true,
        reason: 'Filesystem access requires approval',
      });

      writeFileSync(
        join(root, 'sandbox.json'),
        JSON.stringify({
          enabled: true,
          shell: { readAccess: 'policy' },
          filesystem: {
            allowRead: [root],
            denyRead: [join(root, 'soft-secret.txt')],
            denyReadAlways: [join(root, 'hard-secret.txt')],
            allowWrite: [join(root, 'allowed')],
            denyWrite: [],
            denyWriteAlways: [],
          },
        }),
      );
      expect(await callTool('read', { path: join(root, 'soft-secret.txt') })).toEqual({
        block: true,
        reason: 'Filesystem access requires approval',
      });

      writeFileSync(join(root, 'sandbox.json'), JSON.stringify({ enabled: false }));
      expect(await callTool('read', { path: join(root, 'hard-secret.txt') })).toBeUndefined();
      expect(await callTool('write', { path: join(root, 'outside.txt') })).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('sandboxed bash preserves trap diagnostics with command output and never double-prompts Keep blocked', async () => {
    const rawRoot = mkdtempSync(join(tmpdir(), 'pi-landstrip-bash-test-'));
    const root = realpathSync(rawRoot);
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const projectDir = join(root, 'project');
      mkdirSync(projectDir, { recursive: true });
      writeFileSync(
        join(root, 'sandbox.json'),
        JSON.stringify({
          enabled: true,
          shell: { readAccess: 'host' },
          network: { allowNetwork: true },
          filesystem: {
            allowRead: [root],
            denyRead: [],
            denyReadAlways: [],
            allowWrite: [projectDir],
            denyWrite: ['**/*.pem'],
            denyWriteAlways: [join(projectDir, 'immutable.txt')],
          },
        }),
      );

      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: true, cwd: projectDir });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const ctx = createMockExtensionContext(projectDir);
      for (const handler of mockApi.listeners.get('session_start') ?? []) {
        await handler({}, ctx);
      }

      const bashTool = mockApi.tools.get('bash');
      expect(bashTool).toBeDefined();

      const textOf = (res: { content: Array<{ text?: string }> }) =>
        res.content.map((entry) => entry.text ?? '').join('\n');

      const hardResult = await bashTool.execute(
        'call-hard',
        { command: 'echo blocked > immutable.txt' } satisfies LandstripBashInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(hardResult.isError).toBe(true);
      const hardOutput = textOf(hardResult);
      expect(hardOutput).toMatch(/Permission denied|Access is denied/i);
      expect(hardOutput).toContain('Command exited with code');
      if (process.platform === 'linux') {
        expect(hardOutput).toContain(
          `landstrip: filesystem write denied (${join(projectDir, 'immutable.txt')})`,
        );
      }

      const headlessSoftResult = await bashTool.execute(
        'call-headless-soft',
        { command: 'echo cert > test.pem' } satisfies LandstripBashInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(headlessSoftResult.isError).toBe(true);
      const headlessSoftOutput = textOf(headlessSoftResult);
      expect(headlessSoftOutput).toMatch(/Permission denied|Access is denied/i);
      expect(headlessSoftOutput).toContain('Command exited with code');
      if (process.platform === 'linux') {
        expect(headlessSoftOutput).toContain(
          `landstrip: filesystem write denied (${join(projectDir, 'test.pem')})`,
        );
      }

      const rejectSelect = vi.fn().mockResolvedValue('Keep blocked');
      const rejectCtx = {
        ...ctx,
        hasUI: true,
        ui: {
          ...ctx.ui,
          select: rejectSelect,
        },
      };
      const rejectResult = await bashTool.execute(
        'call-reject',
        { command: 'echo cert > test.pem' } satisfies LandstripBashInput,
        new AbortController().signal,
        () => {},
        rejectCtx,
      );
      expect(rejectSelect).toHaveBeenCalledTimes(1);
      expect(rejectResult.isError).toBe(true);
      const rejectOutput = textOf(rejectResult);
      expect(rejectOutput).toMatch(/Permission denied|Access is denied/i);
      expect(rejectOutput).toContain('Command exited with code');
      if (process.platform === 'linux') {
        expect(rejectOutput).toContain(
          `landstrip: filesystem write denied (${join(projectDir, 'test.pem')})`,
        );
      }

      const allowSelect = vi.fn().mockResolvedValue('Allow once');
      const allowCtx = {
        ...ctx,
        hasUI: true,
        ui: {
          ...ctx.ui,
          select: allowSelect,
        },
      };
      const allowed = await bashTool.execute(
        'call-allow',
        { command: 'echo cert > test.pem && cat test.pem' } satisfies LandstripBashInput,
        new AbortController().signal,
        () => {},
        allowCtx,
      );
      expect(allowSelect).toHaveBeenCalledTimes(1);
      expect(allowed.isError).not.toBe(true);
      expect(textOf(allowed)).toContain('cert');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

async function createReloadHarness() {
  const root = mkdtempSync(join(homedir(), '.pi-landstrip-reload-test-'));
  vi.stubEnv('PI_CODING_AGENT_DIR', root);
  const mockApi = createMockExtensionAPI();
  const ctx = createMockExtensionContext(root);
  let maxSubagents = 1;
  const catalog: AgentCatalog = {
    agents: new Map([
      [
        'build',
        {
          name: 'build',
          source: 'global',
          prompt: 'Test agent',
          mode: 'all',
          hidden: false,
          disabled: false,
          permissions: [],
          providerOptions: {},
        },
      ],
    ]),
    permissions: [{ permission: '*', pattern: '*', action: 'allow' }],
    diagnostics: [],
    maxSubagents,
  };
  const workers = new Map<string, { finish: () => void; dispose: ReturnType<typeof vi.fn> }>();
  // Drain the current promise chain without advancing a timer or releasing a worker.
  const checkpoint = () => new Promise<void>((resolve) => setImmediate(resolve));
  const runtime = new SubagentRuntime(
    mockApi.api,
    createLandstripIntegration({ registerBashTool: false, cwd: root }),
    async (task) => {
      let finish!: () => void;
      const completed = new Promise<void>((resolve) => {
        finish = resolve;
      });
      const dispose = vi.fn(async () => {});
      workers.set(task.description, { finish, dispose });
      return {
        rpc: {
          onEvent() {},
          prompt: () => completed,
          getLastAssistantText: async () => 'Done',
          stop: async () => finish(),
        } as unknown as RpcProcess,
        dispose,
      };
    },
    () => ({ ...catalog, maxSubagents }),
  );
  onTestFinished(async () => {
    try {
      for (const listener of mockApi.listeners.get('session_shutdown') ?? []) {
        await listener({}, ctx);
      }
      for (const worker of workers.values()) expect(worker.dispose).toHaveBeenCalledTimes(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
  runtime.register();
  for (const listener of mockApi.listeners.get('session_start') ?? []) await listener({}, ctx);

  const submit = (description: string) =>
    mockApi.tools
      .get('task')
      .execute(
        description,
        { description, prompt: description, subagent_type: 'build', background: true },
        undefined,
        undefined,
        ctx,
      );
  return {
    runtime,
    workers,
    submit,
    async launch(description: string) {
      const result = await submit(description);
      await checkpoint();
      return runtime.getTasks().find((task) => task.id === result.details.taskId)!;
    },
    async finish(description: string) {
      workers.get(description)!.finish();
      await checkpoint();
    },
    async reload(limit: number) {
      maxSubagents = limit;
      // The primary-agent TUI edit/reload path calls this without restarting the session.
      await (
        runtime as unknown as { restorePrimaryAgent(ctx: ExtensionContext): Promise<void> }
      ).restorePrimaryAgent(ctx);
      await checkpoint();
      expect(runtime.getMaxSubagents()).toBe(limit);
      expect(mockApi.api.getActiveTools()).toEqual(
        limit > 0 ? ['bash', 'tasks', 'task'] : ['bash', 'tasks'],
      );
    },
  };
}

describe('Primary agent reload concurrency', () => {
  test('keeps active workers and old and new waiters on the same limit', async () => {
    const h = await createReloadHarness();
    const active = await h.launch('active');
    const queued = await h.launch('queued');
    expect([active.state, queued.state]).toEqual(['running', 'queued']);

    await h.reload(1);
    const newest = await h.launch('newest');
    expect([active.state, queued.state, newest.state]).toEqual(['running', 'queued', 'queued']);
    expect([...h.workers.keys()]).toEqual(['active']);

    await h.finish('active');
    expect([active.state, queued.state, newest.state]).toEqual(['completed', 'running', 'queued']);
    await h.finish('queued');
    expect([queued.state, newest.state]).toEqual(['completed', 'running']);
    await h.finish('newest');
    expect(newest.state).toBe('completed');
  });

  test('increases capacity for existing waiters and decreases it without forgetting active workers', async () => {
    const h = await createReloadHarness();
    const first = await h.launch('first');
    const second = await h.launch('second');
    const third = await h.launch('third');

    await h.reload(2);
    expect([first.state, second.state, third.state]).toEqual(['running', 'running', 'queued']);
    const fourth = await h.launch('fourth');
    expect(fourth.state).toBe('queued');

    await h.reload(1);
    expect([first.state, second.state, third.state, fourth.state]).toEqual([
      'running',
      'running',
      'queued',
      'queued',
    ]);
    await h.finish('first');
    expect([first.state, second.state, third.state, fourth.state]).toEqual([
      'completed',
      'running',
      'queued',
      'queued',
    ]);
    await h.finish('second');
    expect([second.state, third.state, fourth.state]).toEqual(['completed', 'running', 'queued']);
    await h.finish('third');
    expect([third.state, fourth.state]).toEqual(['completed', 'running']);
    await h.finish('fourth');
    expect(fourth.state).toBe('completed');
  });

  test('zero disables task dispatch without cancelling active workers or losing waiters', async () => {
    const h = await createReloadHarness();
    const active = await h.launch('active');
    const queued = await h.launch('queued');

    await h.reload(0);
    expect([active.state, queued.state]).toEqual(['running', 'queued']);
    await expect(h.submit('disabled')).rejects.toThrow('Subagents are disabled by maxSubagents: 0');
    expect(h.runtime.getTasks()).toHaveLength(2);
    await h.finish('active');
    expect([active.state, queued.state]).toEqual(['completed', 'queued']);
    expect([...h.workers.keys()]).toEqual(['active']);

    await h.reload(1);
    expect(queued.state).toBe('running');
    const newest = await h.launch('newest');
    expect(newest.state).toBe('queued');
    await h.finish('queued');
    expect([queued.state, newest.state]).toEqual(['completed', 'running']);
    await h.finish('newest');
    expect(newest.state).toBe('completed');
  });
});
