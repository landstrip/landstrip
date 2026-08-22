// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
} from '@earendil-works/pi-coding-agent';
import { type AutocompleteItem, fuzzyFilter } from '@earendil-works/pi-tui';
import type { AgentCatalog } from './agents.ts';
import {
  isProjectTrusted,
  loadMaxSubagentsSettings,
  loadToolFilesystemPolicySettings,
} from './config.ts';
import type { LandstripIntegration, SandboxOverview } from './index.ts';

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

type CommandContext = ExtensionCommandContext | ExtensionContext;

interface CommandDeps {
  readonly ctx: CommandContext;
  readonly runtime: CommandSubagentRuntime;
  readonly integration: LandstripIntegration;
}

interface CompletionDeps {
  readonly runtime: CommandSubagentRuntime | undefined;
  readonly ctx: ExtensionContext | undefined;
}

/** Parsed `/landstrip` argument text. Parsed once, shared by dispatch and completion. */
interface Argv {
  /** Subcommand name, lowercased; empty when nothing was typed. */
  readonly name: string;
  readonly words: readonly string[];
  readonly rest: string;
  /** Whole argument text, trimmed. */
  readonly raw: string;
  /** True when the input ends in whitespace, i.e. a new word has begun. */
  readonly trailing: boolean;
}

/**
 * A `/landstrip` subcommand. Dispatch, completion and help are all derived from
 * this one declaration, so the three can never drift apart.
 */
interface Subcommand {
  readonly name: string;
  readonly summary: string;
  /** Pane to open in TUI mode, or undefined to fall through to {@link run}. */
  readonly pane?: (argv: Argv, deps: CommandDeps) => string | undefined;
  readonly complete?: (argv: Argv, deps: CompletionDeps) => Completion[];
  readonly run: (argv: Argv, deps: CommandDeps) => Promise<void> | void;
}

const DEFAULT_SUBCOMMAND = 'status';

function parseArgv(args: string): Argv {
  const raw = args.trim();
  const [name = '', ...words] = raw ? raw.split(/\s+/) : [];
  return {
    name: name.toLowerCase(),
    words,
    rest: words.join(' '),
    raw,
    trailing: /\s$/.test(args),
  };
}

function sandboxOverview(
  ctx: CommandContext,
  integration: LandstripIntegration,
): SandboxOverview | undefined {
  return integration.sandboxCallbacks?.overview?.(ctx.cwd, isProjectTrusted(ctx));
}

/** An {@link AutocompleteItem} that is fuzzy-matched against something other than its label. */
type Completion = AutocompleteItem & { readonly search?: string };

function taskItems(tasks: readonly TaskCommandRecord[], prefix: string): Completion[] {
  return tasks.map((task) => ({
    value: `${prefix}${task.id}`,
    label: task.id.slice(0, 8),
    description: `@${task.agent} [${task.state}]`,
    search: task.id,
  }));
}

const SUBCOMMANDS: readonly Subcommand[] = [
  {
    name: 'status',
    summary: 'Inspect sandbox & agent runtime status',
    pane: (argv) => (argv.rest ? undefined : 'overview'),
    run: (_argv, { ctx, runtime, integration }) => {
      const overview = sandboxOverview(ctx, integration);
      const sandbox = !overview
        ? 'unavailable'
        : !overview.enabled
          ? 'disabled'
          : overview.running
            ? 'active'
            : 'enabled (inactive)';
      const primary = runtime.primaryAgentName();
      const tasks = runtime.getTasks();
      const running = tasks.filter((task) => task.state === 'running').length;
      const queued = tasks.filter((task) => task.state === 'queued').length;
      ctx.ui.notify(
        [
          `Sandbox: ${sandbox}`,
          `Primary agent: ${primary ? `@${primary}` : 'none'}`,
          `Tasks: ${running} running, ${queued} queued, ${tasks.length} total`,
        ].join(' · '),
        'info',
      );
    },
  },
  {
    name: 'sandbox',
    summary: 'Inspect or toggle sandbox OS isolation',
    pane: (argv, { ctx, integration }) =>
      !argv.rest && sandboxOverview(ctx, integration) ? 'overview' : undefined,
    complete: () => [
      { value: 'sandbox on', label: 'on', description: 'Enable OS sandbox isolation' },
      { value: 'sandbox off', label: 'off', description: 'Disable OS sandbox isolation' },
    ],
    run: async (argv, { ctx, integration }) => {
      const callbacks = integration.sandboxCallbacks;
      const overview = sandboxOverview(ctx, integration);
      if (!callbacks || !overview) {
        ctx.ui.notify('Sandbox controls are unavailable', 'warning');
        return;
      }
      const scope = overview.changeScope;
      const action = argv.rest.toLowerCase();

      if (!action) {
        ctx.ui.notify(
          `Sandbox is ${overview.enabled ? 'enabled' : 'disabled'} in ${scope} configuration`,
          'info',
        );
        return;
      }
      if (action === 'on') {
        await callbacks.setEnabled(ctx, true, scope);
        ctx.ui.notify(`Sandbox enabled in ${scope} configuration`, 'info');
        return;
      }
      if (action === 'off') {
        const confirm = (ctx.ui as { confirm?: (title: string, body: string) => Promise<boolean> })
          .confirm;
        if (ctx.mode === 'tui' && confirm) {
          const confirmed = await confirm(
            'Disable sandbox?',
            `Commands will run without OS isolation.\nScope: ${scope} configuration`,
          );
          if (!confirmed) return;
        }
        await callbacks.setEnabled(ctx, false, scope);
        ctx.ui.notify(`Sandbox disabled in ${scope} configuration`, 'warning');
        return;
      }
      ctx.ui.notify(`Unknown sandbox action: ${argv.rest}. Use on or off.`, 'error');
    },
  },
  {
    name: 'settings',
    summary: 'Manage concurrency and filesystem tool policies',
    pane: (argv) => (argv.rest ? undefined : 'settings'),
    run: (_argv, { ctx }) => {
      const projectTrusted = isProjectTrusted(ctx);
      const maxSubagents = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
      const policy = loadToolFilesystemPolicySettings(ctx.cwd, projectTrusted);
      ctx.ui.notify(
        `Settings: maxSubagents=${maxSubagents.project ?? maxSubagents.global} · toolFilesystemPolicy=${policy.project ?? policy.global}`,
        'info',
      );
    },
  },
  {
    name: 'agents',
    summary: 'Inspect catalog or switch active primary agent',
    pane: (argv) => (argv.rest ? undefined : 'primary'),
    complete: (_argv, { runtime, ctx }) => {
      if (!runtime || !ctx) return [];
      try {
        return visibleAgents(runtime.getAgentCatalog(ctx)).map((agent) => ({
          value: `agents @${agent.name}`,
          label: `@${agent.name}`,
          description:
            agent.description ?? (agent.model ? `Model: ${agent.model}` : 'Primary agent'),
        }));
      } catch {
        return [];
      }
    },
    run: async (argv, { ctx, runtime }) => {
      if (!argv.rest) {
        const names = visibleAgents(runtime.getAgentCatalog(ctx))
          .map((agent) => `@${agent.name}`)
          .join(', ');
        ctx.ui.notify(`Available agents: ${names || 'none'}`, 'info');
        return;
      }
      const target = argv.rest.replace(/^@/, '');
      if (await runtime.selectPrimaryAgent(target, ctx)) {
        ctx.ui.notify(`Primary agent switched to @${target}`, 'info');
      }
    },
  },
  {
    name: 'subagents',
    summary: 'Inspect configured process subagents',
    pane: (argv) => (argv.rest ? undefined : 'subagent'),
    run: (_argv, { ctx, runtime }) => {
      const names = visibleAgents(runtime.getAgentCatalog(ctx))
        .filter((agent) => agent.mode === 'subagent')
        .map((agent) => `@${agent.name}`)
        .join(', ');
      ctx.ui.notify(`Subagents: ${names || 'none'}`, 'info');
    },
  },
  {
    name: 'tasks',
    summary: 'Inspect and manage running task sessions',
    pane: (argv) => (argv.words[0] === 'kill' || argv.words[0] === 'list' ? undefined : 'tasks'),
    complete: (argv, { runtime }) => {
      const tasks = runtime?.getTasks() ?? [];
      if (argv.words[0]?.toLowerCase() === 'kill') return taskItems(tasks, 'tasks kill ');
      return [
        { value: 'tasks list', label: 'list', description: 'List all task sessions' },
        { value: 'tasks kill', label: 'kill', description: 'Kill a task session by ID' },
        ...taskItems(tasks, 'tasks '),
      ];
    },
    run: (argv, { ctx, runtime }) => {
      const [action = '', taskId = ''] = argv.words;
      if (action === 'kill') {
        if (!taskId) {
          ctx.ui.notify('Task ID required to kill a task', 'error');
          return;
        }
        const matched = runtime.getTasks().filter((task) => task.id.startsWith(taskId));
        if (matched.length === 0) {
          ctx.ui.notify(`No task found matching ${taskId}`, 'error');
          return;
        }
        const deleted = runtime.deleteTasks(
          matched.map((task) => task.id),
          ctx,
        );
        ctx.ui.notify(`Killed ${deleted} task${deleted === 1 ? '' : 's'}`, 'info');
        return;
      }
      const tasks = runtime.getTasks();
      if (tasks.length === 0) {
        ctx.ui.notify('No task sessions', 'info');
        return;
      }
      ctx.ui.notify(
        tasks.map((task) => `${task.id.slice(0, 8)}: @${task.agent} [${task.state}]`).join('\n'),
        'info',
      );
    },
  },
  {
    name: 'logs',
    summary: 'View live logs for a task session',
    pane: (argv) => argv.rest || 'log',
    complete: (_argv, { runtime }) => taskItems(runtime?.getTasks() ?? [], 'logs '),
    run: (_argv, { ctx }) => {
      ctx.ui.notify('Task logs are available in interactive TUI mode', 'info');
    },
  },
  {
    name: 'help',
    summary: 'Show Landstrip commands and shortcuts help',
    pane: () => 'help',
    run: (_argv, { ctx }) => {
      ctx.ui.notify(
        `Commands: /landstrip [${SUBCOMMANDS.map((command) => command.name).join('|')}]`,
        'info',
      );
    },
  },
];

function visibleAgents(catalog: AgentCatalog) {
  return [...catalog.agents.values()].filter((agent) => !agent.hidden);
}

/** Descriptions are prose and would dilute matching, so only the typed text counts. */
function itemText(item: Completion): string {
  return item.search ?? item.label;
}

export function getLandstripArgumentCompletions(
  argumentPrefix: string,
  runtime?: CommandSubagentRuntime,
  contextProvider?: () => ExtensionContext | undefined,
): AutocompleteItem[] {
  const argv = parseArgv(argumentPrefix);
  const deps: CompletionDeps = { runtime, ctx: contextProvider?.() };

  if (argv.words.length === 0 && !argv.trailing) {
    const roots: Completion[] = [
      ...SUBCOMMANDS.map((command) => ({
        value: command.name,
        label: command.name,
        description: command.summary,
      })),
      ...taskItems(runtime?.getTasks() ?? [], ''),
    ];
    return fuzzyFilter(roots, argv.name, itemText);
  }

  const command = SUBCOMMANDS.find((candidate) => candidate.name === argv.name);
  const items = command?.complete?.(argv, deps) ?? [];
  return fuzzyFilter(items, argv.trailing ? '' : (argv.words.at(-1) ?? ''), itemText);
}

export async function handleLandstripCommand(
  args: string,
  ctx: CommandContext,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): Promise<void> {
  const argv = parseArgv(args);
  const deps: CommandDeps = { ctx, runtime, integration };
  const command = SUBCOMMANDS.find(
    (candidate) => candidate.name === (argv.name || DEFAULT_SUBCOMMAND),
  );

  if (!command) {
    if (ctx.mode === 'tui') {
      const directTask = runtime.getTasks().find((task) => task.id.startsWith(argv.raw));
      await runtime.openLandstrip(directTask?.id ?? argv.raw, ctx);
      return;
    }
    ctx.ui.notify(`Unknown Landstrip command: ${argv.raw}. Type /landstrip help.`, 'error');
    return;
  }

  if (ctx.mode === 'tui') {
    const pane = command.pane?.(argv, deps);
    if (pane !== undefined) {
      await runtime.openLandstrip(pane, ctx);
      return;
    }
  }

  await command.run(argv, deps);
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
