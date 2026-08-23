// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { expect, test } from 'vitest';

import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentCatalog } from './agents.ts';
import {
  type CommandSubagentRuntime,
  getLandstripArgumentCompletions,
  handleLandstripCommand,
  matchingTasksById,
} from './commands.ts';
import type { LandstripIntegration } from './index.ts';

function makeRuntime(overrides: Partial<CommandSubagentRuntime> = {}): CommandSubagentRuntime {
  return {
    getTasks: () => [
      { id: 'abc12345-0000', agent: 'coder', state: 'running' },
      { id: 'def67890-0000', agent: 'tester', state: 'queued' },
    ],
    getAgentCatalog: () =>
      ({
        agents: new Map([
          ['coder', { name: 'coder', hidden: false, mode: 'all', description: 'writes code' }],
          ['ghost', { name: 'ghost', hidden: true, mode: 'all' }],
        ]),
        diagnostics: [],
      }) as unknown as AgentCatalog,
    selectPrimaryAgent: async () => true,
    deleteTasks: (ids) => ids.length,
    openLandstrip: async () => {},
    primaryAgentName: () => 'coder',
    ...overrides,
  };
}

function makeCtx(notifications: string[], mode = 'print'): ExtensionContext {
  return {
    mode,
    cwd: '/tmp',
    ui: { notify: (message: string) => notifications.push(message) },
  } as unknown as ExtensionContext;
}

const ctxProvider = () => makeCtx([]);

test('completions list subcommands and live task ids for an empty prefix', () => {
  const all = getLandstripArgumentCompletions('', makeRuntime(), ctxProvider).map((i) => i.value);
  expect(all).toContain('status');
  expect(all).toContain('help');
  // A bare task id is a valid argument, so it must be completable too.
  expect(all).toContain('abc12345-0000');
});

test('subcommand completions are fuzzy and rank the best match first', () => {
  const sa = getLandstripArgumentCompletions('sa', makeRuntime(), ctxProvider).map((i) => i.value);
  expect(sa[0]).toBe('sandbox');
  expect(sa).toContain('subagents');
  // Descriptions must not participate, or every subcommand would match.
  expect(sa).not.toContain('logs');

  const tk = getLandstripArgumentCompletions('tasks k', makeRuntime(), ctxProvider);
  expect(tk.map((item) => item.value)[0]).toBe('tasks kill');
});

test('completions offer sandbox on/off and agent names', () => {
  const sandbox = getLandstripArgumentCompletions('sandbox ', makeRuntime(), ctxProvider);
  expect(sandbox.map((item) => item.value)).toEqual(['sandbox on', 'sandbox off']);
  const agents = getLandstripArgumentCompletions('agents ', makeRuntime(), ctxProvider);
  expect(agents.map((item) => item.value)).toEqual(['agents @coder']);
});

test('completions offer task ids for tasks kill and logs', () => {
  const kill = getLandstripArgumentCompletions('tasks kill ', makeRuntime(), ctxProvider);
  expect(kill.map((item) => item.value)).toEqual([
    'tasks kill abc12345-0000',
    'tasks kill def67890-0000',
  ]);
  const logs = getLandstripArgumentCompletions('logs abc', makeRuntime(), ctxProvider);
  expect(logs.map((item) => item.value)).toEqual(['logs abc12345-0000']);
  // Task ids are matched in full, not just the 8-character display label.
  const long = getLandstripArgumentCompletions('logs abc12345-0000', makeRuntime(), ctxProvider);
  expect(long.map((item) => item.value)).toEqual(['logs abc12345-0000']);
});

test('status prints a non-interactive summary', async () => {
  const notifications: string[] = [];
  const integration = {
    sandboxCallbacks: {
      overview: () => ({ enabled: true, running: true, changeScope: 'global' }),
    },
  } as unknown as LandstripIntegration;
  await handleLandstripCommand('status', makeCtx(notifications), makeRuntime(), integration);
  expect(notifications[0]).toContain('Sandbox: active');
  expect(notifications[0]).toContain('@coder');
  expect(notifications[0]).toContain('1 running, 1 queued, 2 total');
});

test('tasks kill removes tasks by id prefix', async () => {
  const notifications: string[] = [];
  const deleted: string[] = [];
  const runtime = makeRuntime({
    deleteTasks: (ids) => {
      deleted.push(...ids);
      return ids.length;
    },
  });
  await handleLandstripCommand(
    'tasks kill abc',
    makeCtx(notifications),
    runtime,
    {} as LandstripIntegration,
  );
  expect(deleted).toEqual(['abc12345-0000']);
  expect(notifications[0]).toBe('Killed 1 task');
});

test('task ID matching prefers an exact ID over ambiguous prefixes', () => {
  const tasks = [
    { id: 'abc', agent: 'coder', state: 'running' },
    { id: 'abc12345', agent: 'tester', state: 'queued' },
  ];

  expect(matchingTasksById(tasks, 'abc')).toEqual([tasks[0]]);
  expect(matchingTasksById(tasks, 'a')).toEqual(tasks);
});

test('tasks kill rejects an ambiguous ID prefix', async () => {
  const notifications: string[] = [];
  const deleted: string[] = [];
  const runtime = makeRuntime({
    getTasks: () => [
      { id: 'abc12345-0000', agent: 'coder', state: 'running' },
      { id: 'abc98765-0000', agent: 'tester', state: 'queued' },
    ],
    deleteTasks: (ids) => {
      deleted.push(...ids);
      return ids.length;
    },
  });

  await handleLandstripCommand(
    'tasks kill abc',
    makeCtx(notifications),
    runtime,
    {} as LandstripIntegration,
  );

  expect(deleted).toEqual([]);
  expect(notifications[0]).toBe('Task ID prefix abc matches 2 tasks');
});

test('help text is generated from the subcommand table', async () => {
  const notifications: string[] = [];
  await handleLandstripCommand(
    'help',
    makeCtx(notifications),
    makeRuntime(),
    {} as LandstripIntegration,
  );
  const names = getLandstripArgumentCompletions('', makeRuntime(), ctxProvider)
    .filter((item) => !item.value.includes('-'))
    .map((item) => item.value);
  for (const name of names) expect(notifications[0]).toContain(name);
});

test.each([
  ['', 'overview'],
  ['status', 'overview'],
  ['settings', 'settings'],
  ['agents', 'primary'],
  ['subagents', 'subagent'],
  ['tasks', 'tasks'],
  ['logs', 'log'],
  ['logs abc12345-0000', 'abc12345-0000'],
  ['help', 'help'],
])('%j opens the %j pane in the TUI', async (args, pane) => {
  const opened: string[] = [];
  const runtime = makeRuntime({
    openLandstrip: async (value) => {
      opened.push(value);
    },
  });
  await handleLandstripCommand(args, makeCtx([], 'tui'), runtime, {} as LandstripIntegration);
  expect(opened).toEqual([pane]);
});

test.each(['sandbox on', 'tasks list', 'tasks kill abc', 'agents @coder'])(
  '%j runs instead of opening a pane in the TUI',
  async (args) => {
    const opened: string[] = [];
    const runtime = makeRuntime({
      openLandstrip: async (value) => {
        opened.push(value);
      },
    });
    const integration = {
      sandboxCallbacks: {
        overview: () => ({ enabled: false, running: false, changeScope: 'global' }),
        setEnabled: async () => {},
      },
    } as unknown as LandstripIntegration;
    await handleLandstripCommand(args, makeCtx([], 'tui'), runtime, integration);
    expect(opened).toEqual([]);
  },
);

test('unknown subcommand errors outside the TUI', async () => {
  const notifications: string[] = [];
  await handleLandstripCommand(
    'bogus',
    makeCtx(notifications),
    makeRuntime(),
    {} as LandstripIntegration,
  );
  expect(notifications[0]).toContain('Unknown Landstrip command');
});
