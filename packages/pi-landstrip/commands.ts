// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
} from '@earendil-works/pi-coding-agent';
import { type AutocompleteItem, fuzzyFilter } from '@earendil-works/pi-tui';
import type { AgentCatalog } from './agents.ts';
import { isProjectTrusted, loadMaxSubagentsSettings } from './config.ts';
import type { LandstripIntegration } from './index.ts';

export interface CommandSubagentRuntime {
  getTasks(): TaskCommandRecord[];
  getAgentCatalog(ctx: ExtensionContext): AgentCatalog;
  selectPrimaryAgent(name: string, ctx: ExtensionContext): Promise<boolean>;
  cancelTasks(taskIds: readonly string[], ctx: ExtensionContext): Promise<number>;
  deleteTasks(taskIds: readonly string[], ctx: ExtensionContext): number;
  openLandstrip(args: string, ctx: ExtensionContext, scope: 'sandbox' | 'subagents'): Promise<void>;
  primaryAgentName(): string | undefined;
}

export interface TaskCommandRecord {
  id: string;
  agent: string;
  state: string;
  kind?: 'subagent' | 'command';
  command?: string;
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

/** Parsed slash-command argument text. Parsed once, shared by dispatch and completion. */
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
 * A Landstrip slash-command subcommand. Dispatch, completion and help are all derived from
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

/** An {@link AutocompleteItem} that is fuzzy-matched against something other than its label. */
type Completion = AutocompleteItem & { readonly search?: string };

function taskItems(tasks: readonly TaskCommandRecord[], prefix: string): Completion[] {
  return tasks.map((task) => {
    const label = task.kind === 'command' || task.agent === 'bash' ? '$ bash' : `@${task.agent}`;
    return {
      value: `${prefix}${task.id}`,
      label: task.id.slice(0, 8),
      description: `${label} [${task.state}]`,
      search: task.id,
    };
  });
}

export function matchingTasksById<T extends { id: string }>(
  tasks: readonly T[],
  taskId: string,
): T[] {
  const exact = tasks.find((task) => task.id === taskId);
  return exact ? [exact] : tasks.filter((task) => task.id.startsWith(taskId));
}

async function runSandboxToggle(action: string, { ctx, integration }: CommandDeps): Promise<void> {
  const callbacks = integration.sandboxCallbacks;
  const overview = integration.sandboxCallbacks?.overview?.(ctx.cwd, isProjectTrusted(ctx));
  if (!callbacks || !overview) {
    ctx.ui.notify('Sandbox controls are unavailable', 'warning');
    return;
  }
  const scope = overview.changeScope;
  const normalized = action.toLowerCase();

  if (!normalized) {
    ctx.ui.notify(
      `Sandbox is ${overview.enabled ? 'enabled' : 'disabled'} in ${scope} configuration`,
      'info',
    );
    return;
  }
  if (normalized === 'on') {
    await callbacks.setEnabled(ctx, true, scope);
    ctx.ui.notify(`Sandbox enabled in ${scope} configuration`, 'info');
    return;
  }
  if (normalized === 'off') {
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
  ctx.ui.notify(`Unknown sandbox action: ${action}. Use on or off.`, 'error');
}

const statusSubcommand: Subcommand = {
  name: 'status',
  summary: 'Inspect sandbox & agent runtime status',
  pane: (argv) => (argv.rest ? undefined : 'overview'),
  run: (_argv, { ctx, runtime, integration }) => {
    const overview = integration.sandboxCallbacks?.overview?.(ctx.cwd, isProjectTrusted(ctx));
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
};

const policySubcommand: Subcommand = {
  name: 'policy',
  summary: 'Inspect network, filesystem, and session policy rules',
  pane: (argv, { ctx, integration }) =>
    !argv.rest && integration.sandboxCallbacks?.overview?.(ctx.cwd, isProjectTrusted(ctx))
      ? 'policy'
      : undefined,
  run: (_argv, { ctx, integration }) => {
    const overview = integration.sandboxCallbacks?.overview?.(ctx.cwd, isProjectTrusted(ctx));
    if (!overview) {
      ctx.ui.notify('Sandbox policy is unavailable', 'warning');
      return;
    }
    const readCount =
      overview.config.filesystem.denyRead.length +
      overview.config.filesystem.denyReadAlways.length +
      overview.config.filesystem.allowRead.length;
    const writeCount =
      overview.config.filesystem.allowWrite.length +
      overview.config.filesystem.denyWrite.length +
      overview.config.filesystem.denyWriteAlways.length;
    const grantCount =
      overview.sessionDomains.length +
      overview.sessionReadPaths.length +
      overview.sessionWritePaths.length;
    ctx.ui.notify(
      [
        `Network: ${overview.networkMode}`,
        `Read rules: ${readCount} (${overview.readRuleScope})`,
        `Write rules: ${writeCount}`,
        `Session grants: ${grantCount}`,
      ].join(' · '),
      'info',
    );
  },
};

const settingsSubcommand: Subcommand = {
  name: 'settings',
  summary: 'Manage subagent concurrency settings',
  pane: (argv) => (argv.rest ? undefined : 'settings'),
  run: (_argv, { ctx }) => {
    const projectTrusted = isProjectTrusted(ctx);
    const maxSubagents = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
    ctx.ui.notify(`Settings: maxSubagents=${maxSubagents.project ?? maxSubagents.global}`, 'info');
  },
};

const agentsSubcommand: Subcommand = {
  name: 'agents',
  summary: 'Inspect catalog or switch active primary agent',
  pane: (argv) => (argv.rest ? undefined : 'primary'),
  complete: (_argv, { runtime, ctx }) => {
    if (!runtime || !ctx) return [];
    try {
      return [...runtime.getAgentCatalog(ctx).agents.values()]
        .filter((agent) => !agent.hidden)
        .map((agent) => ({
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
      const names = [...runtime.getAgentCatalog(ctx).agents.values()]
        .filter((agent) => !agent.hidden)
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
};

const subagentsSubcommand: Subcommand = {
  name: 'subagents',
  summary: 'Inspect configured process subagents',
  pane: (argv) => (argv.rest ? undefined : 'subagent'),
  run: (_argv, { ctx, runtime }) => {
    const names = [...runtime.getAgentCatalog(ctx).agents.values()]
      .filter((agent) => !agent.hidden)
      .filter((agent) => agent.mode === 'subagent')
      .map((agent) => `@${agent.name}`)
      .join(', ');
    ctx.ui.notify(`Subagents: ${names || 'none'}`, 'info');
  },
};

const tasksSubcommand: Subcommand = {
  name: 'tasks',
  summary: 'Inspect and manage running task sessions',
  pane: (argv) => {
    const first = argv.words[0]?.toLowerCase() ?? '';
    if (['cancel', 'delete'].includes(first)) return undefined;
    if (first === 'inspect' && argv.words[1]) return argv.words[1];
    if (first && first !== 'list') return first;
    return 'tasks';
  },
  complete: (argv, { runtime }) => {
    const tasks = runtime?.getTasks() ?? [];
    const action = argv.words[0]?.toLowerCase();
    if (action === 'cancel') return taskItems(tasks, 'tasks cancel ');
    if (action === 'delete') return taskItems(tasks, 'tasks delete ');
    if (action === 'inspect') return taskItems(tasks, 'tasks inspect ');
    return [
      { value: 'tasks cancel', label: 'cancel', description: 'Cancel an active task session' },
      { value: 'tasks delete', label: 'delete', description: 'Delete a task session by ID' },
      { value: 'tasks inspect', label: 'inspect', description: 'Inspect a task session in TUI' },
      ...taskItems(tasks, 'tasks '),
    ];
  },
  run: async (argv, { ctx, runtime }) => {
    const [rawAction = '', rawTaskId = ''] = argv.words;
    let action = rawAction.toLowerCase();
    let taskId = rawTaskId;
    if (!['cancel', 'delete', 'inspect', 'list'].includes(action) && action) {
      const matched = matchingTasksById(runtime.getTasks(), action);
      if (matched.length > 0) {
        action = 'inspect';
        taskId = matched[0]!.id;
      }
    }
    if (action === 'cancel') {
      if (!taskId) {
        ctx.ui.notify('Task ID required to cancel a task', 'error');
        return;
      }
      const matched = matchingTasksById(runtime.getTasks(), taskId);
      if (matched.length === 0) {
        ctx.ui.notify(`No task found matching ${taskId}`, 'error');
        return;
      }
      if (matched.length > 1) {
        ctx.ui.notify(`Task ID prefix ${taskId} matches ${matched.length} tasks`, 'error');
        return;
      }
      const cancelled = await runtime.cancelTasks([matched[0]!.id], ctx);
      ctx.ui.notify(`Cancelled ${cancelled} task${cancelled === 1 ? '' : 's'}`, 'info');
      return;
    }
    if (action === 'delete') {
      if (!taskId) {
        ctx.ui.notify('Task ID required to delete a task', 'error');
        return;
      }
      const matched = matchingTasksById(runtime.getTasks(), taskId);
      if (matched.length === 0) {
        ctx.ui.notify(`No task found matching ${taskId}`, 'error');
        return;
      }
      if (matched.length > 1) {
        ctx.ui.notify(`Task ID prefix ${taskId} matches ${matched.length} tasks`, 'error');
        return;
      }
      const deleted = runtime.deleteTasks([matched[0]!.id], ctx);
      ctx.ui.notify(`Deleted ${deleted} task${deleted === 1 ? '' : 's'}`, 'info');
      return;
    }
    if (action === 'inspect' && taskId) {
      const matched = matchingTasksById(runtime.getTasks(), taskId);
      if (matched.length === 1) {
        await runtime.openLandstrip(matched[0]!.id, ctx, 'subagents');
        return;
      }
    }
    await runtime.openLandstrip('tasks', ctx, 'subagents');
  },
};

const logsSubcommand: Subcommand = {
  name: 'logs',
  summary: 'View live logs for a task session',
  pane: (argv) => argv.rest || 'log',
  complete: (_argv, { runtime }) => taskItems(runtime?.getTasks() ?? [], 'logs '),
  run: (_argv, { ctx }) => {
    ctx.ui.notify('Task logs are available in interactive TUI mode', 'info');
  },
};

const SANDBOX_SUBCOMMANDS: readonly Subcommand[] = [
  statusSubcommand,
  policySubcommand,
  {
    name: 'on',
    summary: 'Enable OS sandbox isolation',
    run: async (_argv, deps) => runSandboxToggle('on', deps),
  },
  {
    name: 'off',
    summary: 'Disable OS sandbox isolation',
    run: async (_argv, deps) => runSandboxToggle('off', deps),
  },
  {
    name: 'help',
    summary: 'Show Landstrip sandbox commands and shortcuts',
    pane: () => 'help',
    run: (_argv, { ctx }) => {
      ctx.ui.notify(
        `Commands: /landstrip-sandbox [${SANDBOX_SUBCOMMANDS.map((command) => command.name).join('|')}]`,
        'info',
      );
    },
  },
];

const SUBAGENTS_SUBCOMMANDS: readonly Subcommand[] = [
  tasksSubcommand,
  logsSubcommand,
  subagentsSubcommand,
  agentsSubcommand,
  settingsSubcommand,
  {
    name: 'help',
    summary: 'Show Landstrip subagents commands and shortcuts',
    pane: () => 'help',
    run: (_argv, { ctx }) => {
      ctx.ui.notify(
        `Commands: /landstrip-subagents [${SUBAGENTS_SUBCOMMANDS.map((command) => command.name).join('|')}]`,
        'info',
      );
    },
  },
];

function itemText(item: Completion): string {
  return item.search ?? item.label;
}

function getCompletionsForTable(
  commands: readonly Subcommand[],
  includeRootTasks: boolean,
  argumentPrefix: string,
  runtime?: CommandSubagentRuntime,
  contextProvider?: () => ExtensionContext | undefined,
): AutocompleteItem[] {
  const argv = parseArgv(argumentPrefix);
  const deps: CompletionDeps = { runtime, ctx: contextProvider?.() };

  if (argv.words.length === 0 && !argv.trailing) {
    const roots: Completion[] = [
      ...commands.map((command) => ({
        value: command.name,
        label: command.name,
        description: command.summary,
      })),
      ...(includeRootTasks ? taskItems(runtime?.getTasks() ?? [], '') : []),
    ];
    return fuzzyFilter(roots, argv.name, itemText);
  }

  const command = commands.find((candidate) => candidate.name === argv.name);
  const items = command?.complete?.(argv, deps) ?? [];
  return fuzzyFilter(items, argv.trailing ? '' : (argv.words.at(-1) ?? ''), itemText);
}

export function getLandstripSandboxArgumentCompletions(
  argumentPrefix: string,
  runtime?: CommandSubagentRuntime,
  contextProvider?: () => ExtensionContext | undefined,
): AutocompleteItem[] {
  return getCompletionsForTable(
    SANDBOX_SUBCOMMANDS,
    false,
    argumentPrefix,
    runtime,
    contextProvider,
  );
}

export function getLandstripSubagentsArgumentCompletions(
  argumentPrefix: string,
  runtime?: CommandSubagentRuntime,
  contextProvider?: () => ExtensionContext | undefined,
): AutocompleteItem[] {
  return getCompletionsForTable(
    SUBAGENTS_SUBCOMMANDS,
    true,
    argumentPrefix,
    runtime,
    contextProvider,
  );
}

async function dispatchCommandTable(
  commands: readonly Subcommand[],
  defaultName: string,
  commandLabel: string,
  scope: 'sandbox' | 'subagents',
  args: string,
  ctx: CommandContext,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): Promise<void> {
  const argv = parseArgv(args);
  const deps: CommandDeps = { ctx, runtime, integration };
  const command = commands.find((candidate) => candidate.name === (argv.name || defaultName));

  if (!command) {
    if (ctx.mode === 'tui' && scope !== 'sandbox') {
      await runtime.openLandstrip(argv.raw, ctx, scope);
      return;
    }
    ctx.ui.notify(`Unknown Landstrip command: ${argv.raw}. Type /${commandLabel} help.`, 'error');
    return;
  }

  if (ctx.mode === 'tui') {
    const pane = command.pane?.(argv, deps);
    if (pane !== undefined) {
      await runtime.openLandstrip(pane, ctx, scope);
      return;
    }
  }

  await command.run(argv, deps);
}

export async function handleLandstripSandboxCommand(
  args: string,
  ctx: CommandContext,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): Promise<void> {
  await dispatchCommandTable(
    SANDBOX_SUBCOMMANDS,
    'status',
    'landstrip-sandbox',
    'sandbox',
    args,
    ctx,
    runtime,
    integration,
  );
}

export async function handleLandstripSubagentsCommand(
  args: string,
  ctx: CommandContext,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): Promise<void> {
  await dispatchCommandTable(
    SUBAGENTS_SUBCOMMANDS,
    'tasks',
    'landstrip-subagents',
    'subagents',
    args,
    ctx,
    runtime,
    integration,
  );
}

export function registerLandstripCommands(
  pi: ExtensionAPI,
  runtime: CommandSubagentRuntime,
  integration: LandstripIntegration,
): void {
  pi.registerCommand('landstrip-sandbox', {
    description: 'Inspect and configure Landstrip OS sandbox status and policy',
    getArgumentCompletions: (prefix) =>
      getLandstripSandboxArgumentCompletions(prefix, runtime, () =>
        integration.getExtensionContext(),
      ),
    handler: async (args, ctx) => handleLandstripSandboxCommand(args, ctx, runtime, integration),
  });
  pi.registerCommand('landstrip-subagents', {
    description: 'Manage Landstrip subagents, primary agents, tasks, logs, and settings',
    getArgumentCompletions: (prefix) =>
      getLandstripSubagentsArgumentCompletions(prefix, runtime, () =>
        integration.getExtensionContext(),
      ),
    handler: async (args, ctx) => handleLandstripSubagentsCommand(args, ctx, runtime, integration),
  });
}
