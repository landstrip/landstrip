// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { expect, test } from 'vitest';

import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import type { AgentCatalog } from './agents.ts';
import {
  type CommandSubagentRuntime,
  getLandstripArgumentCompletions,
  handleLandstripCommand,
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

function makeCtx(notifications: string[]): ExtensionContext {
  return {
    mode: 'print',
    cwd: '/tmp',
    ui: { notify: (message: string) => notifications.push(message) },
  } as unknown as ExtensionContext;
}

const ctxProvider = () => makeCtx([]);

test('completions list subcommands for empty and filtered prefix', () => {
  const all = getLandstripArgumentCompletions('', makeRuntime(), ctxProvider);
  expect(all.map((item) => item.value)).toContain('status');
  const filtered = getLandstripArgumentCompletions('sa', makeRuntime(), ctxProvider);
  expect(filtered.map((item) => item.value)).toEqual(['sandbox']);
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
