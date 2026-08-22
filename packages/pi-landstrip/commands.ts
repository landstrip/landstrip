// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
} from '@earendil-works/pi-coding-agent';
import type { AutocompleteItem } from '@earendil-works/pi-tui';
import type { AgentCatalog, AgentDefinition } from './agents.ts';
import {
  isProjectTrusted,
  loadMaxSubagentsSettings,
  loadToolFilesystemPolicySettings,
} from './config.ts';
import type { LandstripIntegration } from './index.ts';

export interface CommandSubagentRuntime {
  getTasks(): TaskCommandRecord[];
  getAgentCatalog(ctx: ExtensionContext): AgentCatalog;
  selectPrimaryAgent(name: string, ctx: ExtensionContext): Promise<boolean>;
  deleteTasks(taskIds: readonly string[], ctx: ExtensionContext): number;
  openLandstrip(args: string, ctx: ExtensionContext): Promise<void>;
  primaryAgentName(): string | undefined;
}

export interface TaskCommandRecord {
  id: string;
  agent: string;
  state: string;
  description?: string;
}

const ROOT_COMMANDS: readonly AutocompleteItem[] = [
  { value: 'status', label: 'status', description: 'Inspect sandbox & agent runtime status' },
  { value: 'sandbox', label: 'sandbox', description: 'Inspect or toggle sandbox OS isolation' },
  {
    value: 'settings',
    label: 'settings',
    description: 'Manage concurrency and filesystem tool policies',
  },
  {
    value: 'agents',
    label: 'agents',
    description: 'Inspect catalog or switch active primary agent',
  },
  { value: 'subagents', label: 'subagents', description: 'Inspect configured process subagents' },
  { value: 'tasks', label: 'tasks', description: 'Inspect and manage running task sessions' },
  { value: 'logs', label: 'logs', description: 'View live logs for a task session' },
  { value: 'help', label: 'help', description: 'Show Landstrip commands and shortcuts help' },
];

export function getLandstripArgumentCompletions(
  argumentPrefix: string,
  runtime?: CommandSubagentRuntime,
  contextProvider?: () => ExtensionContext | undefined,
): AutocompleteItem[] {
  const trimmed = argumentPrefix.trimStart();
  const parts = trimmed.split(/\s+/);
  const isTypingSubcommand = parts.length <= 1 && !argumentPrefix.includes(' ');

  if (isTypingSubcommand) {
    const query = (parts[0] ?? '').toLowerCase();
    return ROOT_COMMANDS.filter((cmd) => cmd.value.startsWith(query));
  }

  const subcommand = (parts[0] ?? '').toLowerCase();
  const subQuery = (trimmed.endsWith(' ') ? '' : (parts[parts.length - 1] ?? '')).toLowerCase();

  if (subcommand === 'sandbox') {
    const options: AutocompleteItem[] = [
      { value: 'sandbox on', label: 'on', description: 'Enable OS sandbox isolation' },
      { value: 'sandbox off', label: 'off', description: 'Disable OS sandbox isolation' },
    ];
    return options.filter((opt) => opt.label.startsWith(subQuery));
  }

  if (subcommand === 'agents') {
    const ctx = contextProvider?.();
    if (!runtime || !ctx) return [];
    try {
      const catalog = runtime.getAgentCatalog(ctx);
      const cleanSub = subQuery.replace(/^@/, '');
      return [...catalog.agents.values()]
        .filter((a) => !a.hidden && a.name.toLowerCase().startsWith(cleanSub))
        .map((a: AgentDefinition) => ({
          value: `agents @${a.name}`,
          label: `@${a.name}`,
          description: a.description ?? (a.model ? `Model: ${a.model}` : 'Primary agent'),
        }));
    } catch {
      return [];
    }
  }

  if (subcommand === 'tasks') {
    const tasks = runtime?.getTasks() ?? [];
    if (parts.length >= 2 && parts[1]?.toLowerCase() === 'kill') {
      const targetQuery = trimmed.endsWith(' ') ? '' : (parts[2] ?? '').toLowerCase();
      return filterItems(taskItems(tasks, 'tasks kill '), targetQuery);
    }
    const base: AutocompleteItem[] = [
      { value: 'tasks list', label: 'list', description: 'List all task sessions' },
      { value: 'tasks kill', label: 'kill', description: 'Kill a task session by ID' },
      ...taskItems(tasks, 'tasks '),
    ];
    return filterItems(base, subQuery);
  }

  if (subcommand === 'logs') {
    return filterItems(taskItems(runtime?.getTasks() ?? [], 'logs '), subQuery);
  }

  return [];
}

function taskItems(tasks: TaskCommandRecord[], prefix: string): AutocompleteItem[] {
  return tasks.map((t) => ({
    value: `${prefix}${t.id}`,
    label: t.id.slice(0, 8),
    description: `@${t.agent} [${t.state}]`,
  }));
}

function filterItems(items: AutocompleteItem[], query: string): AutocompleteItem[] {
  return items.filter(
    (item) =>
      item.label.toLowerCase().startsWith(query) || item.value.toLowerCase().includes(query),
  );
}

export async function handleLandstripCommand(
  args: string,
  ctx: ExtensionCommandContext | ExtensionContext,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): Promise<void> {
  const trimmed = args.trim();
  const [subcommand = '', ...rest] = trimmed ? trimmed.split(/\s+/) : [];
  const normalized = subcommand.toLowerCase();
  const subArg = rest.join(' ').trim();
  const isTui = ctx.mode === 'tui';

  if (!normalized || normalized === 'status') {
    if (isTui && !subArg) {
      await runtime.openLandstrip('overview', ctx);
      return;
    }
    const projectTrusted = isProjectTrusted(ctx);
    const overview = integration.sandboxCallbacks?.overview?.(ctx.cwd, projectTrusted);
    const primary = runtime.primaryAgentName();
    const tasks = runtime.getTasks();
    const runningTasks = tasks.filter((t) => t.state === 'running').length;
    const queuedTasks = tasks.filter((t) => t.state === 'queued').length;

    const parts: string[] = [
      `Sandbox: ${overview ? (overview.enabled ? (overview.running ? 'active' : 'enabled (inactive)') : 'disabled') : 'unavailable'}`,
      `Primary agent: ${primary ? `@${primary}` : 'none'}`,
      `Tasks: ${runningTasks} running, ${queuedTasks} queued, ${tasks.length} total`,
    ];
    ctx.ui.notify(parts.join(' · '), 'info');
    return;
  }

  if (normalized === 'sandbox') {
    const action = subArg.toLowerCase();
    const callbacks = integration.sandboxCallbacks;
    const projectTrusted = isProjectTrusted(ctx);
    const overview = callbacks?.overview?.(ctx.cwd, projectTrusted);

    if (!callbacks || !overview) {
      ctx.ui.notify('Sandbox controls are unavailable', 'warning');
      return;
    }

    if (!action) {
      if (isTui) {
        await runtime.openLandstrip('overview', ctx);
        return;
      }
      ctx.ui.notify(
        `Sandbox is ${overview.enabled ? 'enabled' : 'disabled'} in ${overview.changeScope} configuration`,
        'info',
      );
      return;
    }

    if (action === 'on') {
      await callbacks.setEnabled(ctx, true, overview.changeScope);
      ctx.ui.notify(`Sandbox enabled in ${overview.changeScope} configuration`, 'info');
      return;
    }

    if (action === 'off') {
      const ui = ctx.ui as { confirm?: (title: string, body: string) => Promise<boolean> };
      if (isTui && ui.confirm) {
        const confirmed = await ui.confirm(
          'Disable sandbox?',
          `Commands will run without OS isolation.\nScope: ${overview.changeScope} configuration`,
        );
        if (!confirmed) return;
      }
      await callbacks.setEnabled(ctx, false, overview.changeScope);
      ctx.ui.notify(`Sandbox disabled in ${overview.changeScope} configuration`, 'warning');
      return;
    }

    ctx.ui.notify(`Unknown sandbox action: ${subArg}. Use on or off.`, 'error');
    return;
  }

  if (normalized === 'settings') {
    if (isTui && !subArg) {
      await runtime.openLandstrip('settings', ctx);
      return;
    }
    const projectTrusted = isProjectTrusted(ctx);
    const maxSubagents = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
    const policy = loadToolFilesystemPolicySettings(ctx.cwd, projectTrusted);
    const effectiveLimit = maxSubagents.project ?? maxSubagents.global;
    const effectivePolicy = policy.project ?? policy.global;
    ctx.ui.notify(
      `Settings: maxSubagents=${effectiveLimit} · toolFilesystemPolicy=${effectivePolicy}`,
      'info',
    );
    return;
  }

  if (normalized === 'agents') {
    if (!subArg) {
      if (isTui) {
        await runtime.openLandstrip('primary', ctx);
        return;
      }
      const catalog = runtime.getAgentCatalog(ctx);
      const agentNames = [...catalog.agents.values()]
        .filter((a) => !a.hidden)
        .map((a) => `@${a.name}`)
        .join(', ');
      ctx.ui.notify(`Available agents: ${agentNames || 'none'}`, 'info');
      return;
    }
    const targetAgent = subArg.replace(/^@/, '');
    const success = await runtime.selectPrimaryAgent(targetAgent, ctx);
    if (success) {
      ctx.ui.notify(`Primary agent switched to @${targetAgent}`, 'info');
    }
    return;
  }

  if (normalized === 'subagents') {
    if (isTui && !subArg) {
      await runtime.openLandstrip('subagent', ctx);
      return;
    }
    const catalog = runtime.getAgentCatalog(ctx);
    const subagentNames = [...catalog.agents.values()]
      .filter((a) => !a.hidden && a.mode === 'subagent')
      .map((a) => `@${a.name}`)
      .join(', ');
    ctx.ui.notify(`Subagents: ${subagentNames || 'none'}`, 'info');
    return;
  }

  if (normalized === 'tasks') {
    const [taskAction = '', taskId = ''] = subArg ? subArg.split(/\s+/) : [];
    if (taskAction === 'kill') {
      if (!taskId) {
        ctx.ui.notify('Task ID required to kill a task', 'error');
        return;
      }
      const matched = runtime.getTasks().filter((t) => t.id.startsWith(taskId));
      if (matched.length === 0) {
        ctx.ui.notify(`No task found matching ${taskId}`, 'error');
        return;
      }
      const deleted = runtime.deleteTasks(
        matched.map((t) => t.id),
        ctx,
      );
      ctx.ui.notify(`Killed ${deleted} task${deleted === 1 ? '' : 's'}`, 'info');
      return;
    }

    if (taskAction === 'list' || !isTui) {
      const allTasks = runtime.getTasks();
      if (allTasks.length === 0) {
        ctx.ui.notify('No task sessions', 'info');
        return;
      }
      const summary = allTasks
        .map((t) => `${t.id.slice(0, 8)}: @${t.agent} [${t.state}]`)
        .join('\n');
      ctx.ui.notify(summary, 'info');
      return;
    }

    await runtime.openLandstrip('tasks', ctx);
    return;
  }

  if (normalized === 'logs') {
    if (isTui) {
      await runtime.openLandstrip(subArg || 'log', ctx);
      return;
    }
    ctx.ui.notify('Task logs are available in interactive TUI mode', 'info');
    return;
  }

  if (normalized === 'help') {
    if (isTui) {
      await runtime.openLandstrip('help', ctx);
      return;
    }
    ctx.ui.notify(
      'Commands: /landstrip [status|sandbox|settings|agents|subagents|tasks|logs|help]',
      'info',
    );
    return;
  }

  if (isTui) {
    const directTask = runtime.getTasks().find((t) => t.id.startsWith(trimmed));
    await runtime.openLandstrip(directTask?.id ?? trimmed, ctx);
    return;
  }

  ctx.ui.notify(`Unknown Landstrip command: ${trimmed}. Type /landstrip help.`, 'error');
}

export function registerLandstripCommands(
  pi: ExtensionAPI,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): void {
  pi.registerCommand('landstrip', {
    description: 'Manage Landstrip sandbox, agents, tasks, and runtime settings',
    getArgumentCompletions: (prefix) =>
      getLandstripArgumentCompletions(prefix, runtime, () => integration.getExtensionContext()),
    handler: async (args, ctx) => handleLandstripCommand(args, ctx, runtime, integration),
  });
}
