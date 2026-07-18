// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  type ExtensionAPI,
  type ExtensionContext,
  getAgentDir,
  keyHint,
  SessionManager,
  type Theme,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { matchesKey, Text, truncateToWidth } from '@earendil-works/pi-tui';
import { Type } from 'typebox';

import {
  type AgentCatalog,
  type AgentDefinition,
  availablePrimaryAgents,
  availableSubagents,
  loadAgentCatalog,
  mergePermissionRules,
  permissionDecision,
  type PermissionRules,
} from './agents.ts';
import { MAX_SUBAGENTS } from './config.ts';
import type { LandstripIntegration, LandstripRpcWorkerLaunch } from './index.ts';
import { type ExtensionUiRequest, type ExtensionUiResult, RpcProcess } from './rpc-process.ts';

const TASK_ENTRY = 'landstrip.task';
const TASK_WIDGET = 'landstrip.subagents';
const PRIMARY_AGENT_ENTRY = 'landstrip.primary-agent';
const WORKER_ENV = 'PI_LANDSTRIP_WORKER';
const CONTROL_TITLE = 'pi-landstrip:control:v1';
const MAX_DEPTH = 3;
const packageDir = dirname(fileURLToPath(import.meta.url));
const MAX_TASK_OUTPUT_BYTES = 64 * 1024;
const INSPECTOR_BODY_LINES = 16;
interface PiPackage {
  readonly cliEntry: string;
  readonly version: readonly [number, number, number];
}

const SUPPORTED_PI_MAJOR = 0;
const SUPPORTED_PI_MINOR = 80;
const MIN_SUPPORTED_PI_PATCH = 6;

let cachedPiPackage: PiPackage | undefined;
let piPackageResolved = false;

export function isSupportedPiVersion(version: readonly number[]): boolean {
  const [major, minor = -1, patch = -1] = version;
  return (
    Number.isInteger(major) &&
    major === SUPPORTED_PI_MAJOR &&
    minor === SUPPORTED_PI_MINOR &&
    patch >= MIN_SUPPORTED_PI_PATCH
  );
}

// Resolve the Pi package used by this extension import. Reading its
// `package.json` instead of spawning `pi --version` avoids depending on
// `process.argv[1]`, which is not the Pi CLI entry when Pi runs as an embedded
// or extension host and would otherwise report the Node version instead.
export function resolvePiPackage(): PiPackage | undefined {
  if (piPackageResolved) return cachedPiPackage;
  piPackageResolved = true;

  try {
    const entry = fileURLToPath(import.meta.resolve('@earendil-works/pi-coding-agent'));
    let dir = dirname(entry);
    for (;;) {
      const pkgPath = join(dir, 'package.json');
      if (existsSync(pkgPath)) {
        const pkg = readPiPackage(pkgPath);
        if (pkg) return pkg;
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // Fall back to package discovery for runtimes without import.meta.resolve.
  }

  let dir = packageDir;
  for (;;) {
    const pkgPath = join(dir, 'node_modules', '@earendil-works', 'pi-coding-agent', 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = readPiPackage(pkgPath);
      if (pkg) return pkg;
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

function readPiPackage(pkgPath: string): PiPackage | undefined {
  try {
    const value: unknown = JSON.parse(readFileSync(pkgPath, 'utf8'));
    if (
      !isRecord(value) ||
      value.name !== '@earendil-works/pi-coding-agent' ||
      typeof value.version !== 'string'
    ) {
      return undefined;
    }
    const parts = value.version.split('.').map(Number);
    if (parts.length < 3 || !parts.slice(0, 3).every((n) => Number.isInteger(n))) return undefined;
    const binFile =
      typeof value.bin === 'string'
        ? value.bin
        : isRecord(value.bin) && typeof value.bin.pi === 'string'
          ? value.bin.pi
          : undefined;
    if (!binFile) return undefined;
    const cliEntry = join(dirname(pkgPath), binFile);
    if (!existsSync(cliEntry)) return undefined;
    cachedPiPackage = { cliEntry, version: parts.slice(0, 3) as [number, number, number] };
    return cachedPiPackage;
  } catch {
    return undefined;
  }
}

const taskParameters = Type.Object({
  description: Type.String({ description: 'A short 3-5 word description of the task' }),
  prompt: Type.String({ description: 'The complete task for the subagent' }),
  subagent_type: Type.String({ description: 'The configured subagent name' }),
  task_id: Type.Optional(Type.String({ description: 'An existing task ID to continue' })),
  command: Type.Optional(Type.String({ description: 'The command that originated this task' })),
  background: Type.Optional(Type.Boolean({ description: 'Run without blocking the parent task' })),
});

interface TaskInput {
  description: string;
  prompt: string;
  subagent_type: string;
  task_id?: string;
  command?: string;
  background?: boolean;
}

type TaskState = 'queued' | 'running' | 'completed' | 'error' | 'cancelled' | 'interrupted';
const TASK_STATES = new Set<TaskState>([
  'queued',
  'running',
  'completed',
  'error',
  'cancelled',
  'interrupted',
]);

interface TaskRecord {
  version?: 1;
  id: string;
  parentSessionId: string;
  parentTaskId?: string;
  parentSessionFile?: string;
  sessionDir?: string;
  sessionFile?: string;
  agent: string;
  description: string;
  depth: number;
  state: TaskState;
  output?: string;
  error?: string;
  outputFile?: string;
  errorFile?: string;
  delivered?: boolean;
  background?: boolean;
  currentTool?: string;
  toolCalls?: number;
  retryAttempt?: number;
  startedAt?: number;
  finishedAt?: number;
}

export interface SubagentTaskView {
  readonly id: string;
  readonly parentTaskId?: string;
  readonly agent: string;
  readonly description: string;
  readonly state: 'queued' | 'running' | 'completed' | 'error' | 'cancelled' | 'interrupted';
}

interface TaskDetails {
  taskId: string;
  state: TaskState;
  agent: string;
  description?: string;
  background?: boolean;
  currentTool?: string;
  toolCalls?: number;
  retryAttempt?: number;
  startedAt?: number;
  finishedAt?: number;
  output?: string;
  error?: string;
}

function taskDetails(task: TaskRecord, state: TaskState = task.state): TaskDetails {
  return {
    taskId: task.id,
    state,
    agent: task.agent,
    description: task.description,
    background: task.background,
    currentTool: task.currentTool,
    toolCalls: task.toolCalls,
    retryAttempt: task.retryAttempt,
    startedAt: task.startedAt,
    finishedAt: task.finishedAt,
    output: task.output,
    error: task.error,
  };
}

function taskDuration(details: TaskDetails): string | undefined {
  if (details.startedAt === undefined) return undefined;
  const end = details.finishedAt ?? Date.now();
  const seconds = Math.max(0, end - details.startedAt) / 1000;
  return seconds < 10 ? `${seconds.toFixed(1)}s` : `${Math.round(seconds)}s`;
}

function taskOutput(details: TaskDetails, fallback: string): string {
  return details.error ?? details.output ?? fallback;
}

function workerDialogTitle(task: TaskRecord, title: string): string {
  return `@${task.agent} · ${task.description} · ${task.id.slice(0, 8)}\n${title}`;
}

function messageContentText(message: unknown): string {
  if (!isRecord(message)) return '';
  const content = message.content;
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content
    .map((part) => {
      if (!isRecord(part)) return '';
      if (part.type === 'text' && typeof part.text === 'string') return part.text;
      if (part.type === 'toolCall' && typeof part.name === 'string') return `→ ${part.name}`;
      return '';
    })
    .filter(Boolean)
    .join('\n');
}

function taskTranscript(task: TaskRecord): string[] {
  if (!task.sessionFile || !existsSync(task.sessionFile)) {
    const fallback = task.error ?? task.output ?? 'Child session is not available yet.';
    return fallback.split('\n');
  }
  try {
    const session = SessionManager.open(task.sessionFile, task.sessionDir);
    const lines: string[] = [];
    for (const entry of session.buildContextEntries()) {
      if (entry.type !== 'message') continue;
      const message = entry.message as unknown;
      if (!isRecord(message) || typeof message.role !== 'string') continue;
      const content = messageContentText(message);
      if (!content) continue;
      const role =
        message.role === 'toolResult' && typeof message.toolName === 'string'
          ? `tool:${message.toolName}`
          : message.role;
      lines.push(`${role}: ${content}`);
    }
    return lines.length > 0 ? lines : ['Child session has no messages yet.'];
  } catch (error) {
    return [
      `Could not read child session: ${error instanceof Error ? error.message : String(error)}`,
    ];
  }
}

interface RunningTask {
  rpc: RpcProcess;
  promise: Promise<string>;
}

interface TaskLease {
  release?: () => void;
}

interface WorkerConfig {
  readonly rules: PermissionRules;
  readonly task: Pick<TaskRecord, 'id' | 'description' | 'depth'>;
  readonly taskEnabled: boolean;
  readonly steps?: number;
}

interface ControlRequest {
  readonly type: 'permission' | 'task';
  readonly permission?: string;
  readonly resource?: string;
  readonly input?: TaskInput;
}

interface ControlResponse {
  readonly ok: boolean;
  readonly value?: string;
  readonly task?: TaskDetails;
  readonly error?: string;
}

interface WorkerHandle {
  readonly rpc: RpcProcess;
  dispose(): Promise<void>;
}

type CatalogLoader = typeof loadAgentCatalog;
type WorkerFactory = (
  task: TaskRecord,
  agent: AgentDefinition,
  rules: PermissionRules,
  ctx: ExtensionContext,
  signal: AbortSignal,
  onRequest: (request: ExtensionUiRequest) => Promise<ExtensionUiResult>,
) => Promise<WorkerHandle>;

function isProjectTrusted(ctx: ExtensionContext): boolean {
  const trustContext = ctx as ExtensionContext & { isProjectTrusted?: () => boolean };
  return trustContext.isProjectTrusted?.() ?? false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function dependencyRoot(path: string): string | undefined {
  const marker = `${sep}node_modules${sep}`;
  const index = path.lastIndexOf(marker);
  return index < 0 ? undefined : path.slice(0, index + marker.length - 1);
}

function agentBootstrapPaths(agentDir: string): string[] {
  return [
    'settings.json',
    'models.json',
    'auth.json',
    'trust.json',
    'AGENTS.md',
    'SYSTEM.md',
    'APPEND_SYSTEM.md',
    'extensions',
    'skills',
    'prompts',
    'themes',
    'tools',
    'bin',
    'npm',
    'git',
  ].map((path) => join(agentDir, path));
}

class Semaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];

  constructor(private limit: number) {}

  setLimit(limit: number): void {
    this.limit = limit;
    while (this.active < this.limit && this.waiters.length > 0) this.waiters.shift()?.();
  }

  tryAcquire(): (() => void) | undefined {
    if (this.active >= this.limit) return undefined;
    this.active += 1;
    return () => this.release();
  }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new Error('Task cancelled');
    if (this.active < this.limit) {
      this.active += 1;
      return () => this.release();
    }
    await new Promise<void>((resolve, reject) => {
      const abort = () => {
        const index = this.waiters.indexOf(start);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error('Task cancelled'));
      };
      const start = () => {
        signal?.removeEventListener('abort', abort);
        this.active += 1;
        resolve();
      };
      this.waiters.push(start);
      signal?.addEventListener('abort', abort, { once: true });
    });
    return () => this.release();
  }

  private release(): void {
    this.active -= 1;
    this.waiters.shift()?.();
  }
}

class PermissionBroker {
  private tail = Promise.resolve();
  private readonly grants = new Set<string>();

  async ask(
    ctx: ExtensionContext,
    task: string,
    permission: string,
    resource: string,
    signal?: AbortSignal,
  ): Promise<void> {
    const key = `${permission}\u0000${resource}`;
    if (this.grants.has(key)) return;
    if (!ctx.hasUI) throw new Error(`Permission required: ${permission} ${resource}`);
    let release: (() => void) | undefined;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    if (signal) {
      let abort: (() => void) | undefined;
      try {
        await Promise.race([
          previous,
          new Promise<never>((_resolve, reject) => {
            abort = () => reject(new Error('Permission request cancelled'));
            signal.addEventListener('abort', abort, { once: true });
          }),
        ]);
      } catch (error) {
        void previous.finally(() => release?.());
        throw error;
      } finally {
        if (abort) signal.removeEventListener('abort', abort);
      }
    } else {
      await previous;
    }
    try {
      if (this.grants.has(key)) return;
      if (signal?.aborted) throw new Error('Permission request cancelled');
      const choice = await ctx.ui.select(
        `${task}: permission required\n${permission}: ${resource}`,
        ['Allow once', 'Allow for this session', 'Reject'],
        { signal },
      );
      if (choice === 'Allow for this session') this.grants.add(key);
      if (choice !== 'Allow once' && choice !== 'Allow for this session') {
        throw new Error(`Permission denied: ${permission} ${resource}`);
      }
    } finally {
      release?.();
    }
  }

  reset(): void {
    this.grants.clear();
    this.tail = Promise.resolve();
  }
}

export function renderTaskResult(
  id: string,
  state: 'queued' | 'running' | 'completed' | 'error',
  value: string,
): string {
  const tag = state === 'error' ? 'task_error' : 'task_result';
  return `<task id="${id}" state="${state}">\n<${tag}>\n${value}\n</${tag}>\n</task>`;
}

function utf8Slice(value: string, maxBytes: number, fromEnd: boolean): string {
  if (maxBytes <= 0) return '';
  let low = 0;
  let high = value.length;
  while (low < high) {
    const length = Math.ceil((low + high) / 2);
    const candidate = fromEnd ? value.slice(value.length - length) : value.slice(0, length);
    if (Buffer.byteLength(candidate) <= maxBytes) low = length;
    else high = length - 1;
  }
  let result = fromEnd ? value.slice(value.length - low) : value.slice(0, low);
  if (fromEnd && /^[\uDC00-\uDFFF]/.test(result)) result = result.slice(1);
  if (!fromEnd && /[\uD800-\uDBFF]$/.test(result)) result = result.slice(0, -1);
  return result;
}

export function boundTaskOutput(
  value: string,
  artifactPath: string,
  maxBytes = MAX_TASK_OUTPUT_BYTES,
): string {
  if (Buffer.byteLength(value) <= maxBytes) return value;
  writeFileSync(artifactPath, value, 'utf8');
  const marker = `\n\n[Task output truncated; full output: ${artifactPath}]\n\n`;
  const contentBytes = Math.max(0, maxBytes - Buffer.byteLength(marker));
  const headBytes = Math.ceil(contentBytes / 2);
  const tailBytes = Math.floor(contentBytes / 2);
  return `${utf8Slice(value, headBytes, false)}${marker}${utf8Slice(value, tailBytes, true)}`;
}

function taskTreeLines(
  tasks: readonly SubagentTaskView[],
  renderTask: (task: SubagentTaskView) => string,
): string[] {
  const taskIds = new Set(tasks.map((task) => task.id));
  const children = new Map<string, SubagentTaskView[]>();
  const roots: SubagentTaskView[] = [];

  for (const task of tasks) {
    if (!task.parentTaskId || !taskIds.has(task.parentTaskId)) {
      roots.push(task);
      continue;
    }
    const siblings = children.get(task.parentTaskId) ?? [];
    siblings.push(task);
    children.set(task.parentTaskId, siblings);
  }

  const lines: string[] = [];
  const visit = (task: SubagentTaskView, prefix: string, connector: string): void => {
    lines.push(`${prefix}${connector}${renderTask(task)}`);
    const descendants = children.get(task.id) ?? [];
    for (const [index, child] of descendants.entries()) {
      const last = index === descendants.length - 1;
      visit(child, `${prefix}${connector === '├─ ' ? '│  ' : '   '}`, last ? '└─ ' : '├─ ');
    }
  };

  for (const [index, root] of roots.entries()) {
    visit(root, '', index === roots.length - 1 ? '└─ ' : '├─ ');
  }
  return lines;
}

export function renderTaskTree(tasks: readonly SubagentTaskView[]): string {
  return taskTreeLines(
    tasks,
    (task) =>
      `${task.state.padEnd(11)} @${task.agent}  ${task.description}  ${task.id.slice(0, 8)}`,
  ).join('\n');
}

function taskState(theme: Theme, task: SubagentTaskView): string {
  switch (task.state) {
    case 'completed':
      return `${theme.fg('success', '●')} ${theme.fg('success', 'completed')}`;
    case 'running':
      return `${theme.fg('accent', '●')} ${theme.fg('accent', 'running')}`;
    case 'queued':
      return `${theme.fg('warning', '○')} ${theme.fg('warning', 'queued')}`;
    case 'cancelled':
      return `${theme.fg('muted', '●')} ${theme.fg('muted', 'cancelled')}`;
    case 'interrupted':
      return `${theme.fg('warning', '●')} ${theme.fg('warning', 'interrupted')}`;
    case 'error':
      return `${theme.fg('error', '●')} ${theme.fg('error', 'error')}`;
  }
}

function permissionName(tool: string): string {
  if (tool === 'write' || tool === 'apply_patch') return 'edit';
  if (tool === 'find') return 'glob';
  if (tool === 'ls') return 'list';
  return tool;
}

function canonicalPermissionPath(path: string, seen = new Set<string>()): string {
  const missing: string[] = [];
  let existing = path;
  while (true) {
    try {
      const stat = lstatSync(existing);
      if (stat.isSymbolicLink()) {
        if (seen.has(existing)) return path;
        seen.add(existing);
        const target = resolve(dirname(existing), readlinkSync(existing), ...missing);
        return canonicalPermissionPath(target, seen);
      }
      break;
    } catch {
      const parent = dirname(existing);
      if (parent === existing) return path;
      missing.unshift(basename(existing));
      existing = parent;
    }
  }
  try {
    return resolve(realpathSync(existing), ...missing);
  } catch {
    return path;
  }
}

function permissionResource(tool: string, input: Record<string, unknown>, cwd: string): string {
  if (tool === 'bash' && typeof input.command === 'string') return input.command;
  if (tool === 'task' && typeof input.subagent_type === 'string') return input.subagent_type;
  if ((tool === 'grep' || tool === 'find') && typeof input.pattern === 'string') {
    return input.pattern;
  }
  if (typeof input.path !== 'string') return '*';
  const projectRoot = canonicalPermissionPath(resolve(cwd));
  const absolutePath = canonicalPermissionPath(resolve(cwd, input.path));
  const projectPath = relative(projectRoot, absolutePath);
  if (
    projectPath &&
    !isAbsolute(projectPath) &&
    !projectPath.startsWith(`..${sep}`) &&
    projectPath !== '..'
  ) {
    return projectPath.split(sep).join('/');
  }
  return absolutePath.split(sep).join('/');
}

function permissionResources(tool: string, input: Record<string, unknown>, cwd: string): string[] {
  if (tool !== 'apply_patch' || typeof input.patchText !== 'string') {
    return [permissionResource(tool, input, cwd)];
  }
  const paths = [...input.patchText.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)].map(
    (match) => match[1].trim(),
  );
  paths.push(
    ...[...input.patchText.matchAll(/^\*\*\* Move to: (.+)$/gm)].map((match) => match[1].trim()),
  );
  return paths.length > 0
    ? [...new Set(paths.map((path) => permissionResource('edit', { path }, cwd)))]
    : ['*'];
}

function parseWorkerConfig(): WorkerConfig | undefined {
  const encoded = process.env[WORKER_ENV];
  if (!encoded) return undefined;
  try {
    const value: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!isRecord(value) || !Array.isArray(value.rules) || !isRecord(value.task)) {
      throw new Error('invalid shape');
    }
    return value as unknown as WorkerConfig;
  } catch (error) {
    throw new Error(
      `Invalid ${WORKER_ENV}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function parseControlResponse(value: string | undefined): ControlResponse {
  if (value === undefined) throw new Error('Supervisor cancelled the request');
  const response: unknown = JSON.parse(value);
  if (!isRecord(response) || typeof response.ok !== 'boolean') {
    throw new Error('Invalid supervisor response');
  }
  if (!response.ok) {
    throw new Error(typeof response.error === 'string' ? response.error : 'Request failed');
  }
  if (response.value !== undefined && typeof response.value !== 'string') {
    throw new Error('Invalid supervisor response value');
  }
  if (
    response.task !== undefined &&
    (!isRecord(response.task) ||
      typeof response.task.taskId !== 'string' ||
      typeof response.task.state !== 'string' ||
      !TASK_STATES.has(response.task.state as TaskState) ||
      typeof response.task.agent !== 'string')
  ) {
    throw new Error('Invalid supervisor task response');
  }
  return response as unknown as ControlResponse;
}

/** Register the constrained half of this extension inside an RPC worker. */
export function registerSubagentWorker(pi: ExtensionAPI, config: WorkerConfig): void {
  pi.on('session_start', () => {
    delete process.env[WORKER_ENV];
  });
  pi.on('tool_call', async (event, ctx) => {
    // Nested task requests are validated by the root scheduler after transport.
    if (event.toolName === 'task') return;
    const permission = permissionName(event.toolName);
    const input = isRecord(event.input) ? event.input : {};
    for (const resource of permissionResources(event.toolName, input, ctx.cwd)) {
      const decision = permissionDecision(config.rules, permission, resource);
      if (decision === 'deny') {
        return { block: true, reason: `Permission denied: ${permission} ${resource}` };
      }
      if (decision !== 'ask') continue;
      const value = await ctx.ui.input(
        CONTROL_TITLE,
        JSON.stringify({ type: 'permission', permission, resource } satisfies ControlRequest),
        { signal: ctx.signal },
      );
      try {
        parseControlResponse(value);
      } catch (error) {
        return { block: true, reason: error instanceof Error ? error.message : String(error) };
      }
    }
  });

  if (config.taskEnabled) {
    pi.registerTool({
      name: 'task',
      label: 'Task',
      description: 'Delegate work to a process-backed subagent managed by the root supervisor.',
      parameters: taskParameters,
      executionMode: 'parallel',
      async execute(_id, input, signal, _onUpdate, ctx) {
        const value = await ctx.ui.input(
          CONTROL_TITLE,
          JSON.stringify({ type: 'task', input } satisfies ControlRequest),
          { signal },
        );
        const response = parseControlResponse(value);
        const text = response.value ?? '';
        return {
          content: [{ type: 'text', text }],
          details: response.task ?? {
            taskId: input.task_id ?? '',
            state: input.background ? 'queued' : 'completed',
            agent: input.subagent_type,
          },
        };
      },
    });
  }

  if (config.steps) {
    const maxTurns = config.steps;
    let turns = 0;
    pi.on('turn_end', (_event, ctx) => {
      turns += 1;
      if (turns >= maxTurns) ctx.abort();
    });
  }
}

export function workerConfigFromEnvironment(): WorkerConfig | undefined {
  return parseWorkerConfig();
}

export class SubagentRuntime {
  private semaphore = new Semaphore(1);
  private readonly broker = new PermissionBroker();
  private readonly tasks = new Map<string, TaskRecord>();
  private readonly running = new Map<string, RunningTask>();
  private readonly runPromises = new Map<string, Promise<string>>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly leases = new Map<string, TaskLease>();
  private readonly foregroundClaims = new Map<string, number>();
  private readonly pendingPrompts = new Map<string, string[]>();
  private primaryAgent: AgentDefinition | undefined;
  private primaryRules: PermissionRules | undefined;
  private primaryConfigurationError = false;
  private maxSubagents = 0;
  private shuttingDown = false;
  private activeSessionId: string | undefined;

  constructor(
    private readonly pi: ExtensionAPI,
    private readonly integration: LandstripIntegration,
    private readonly createWorker: WorkerFactory = (...args) => this.defaultWorker(...args),
    private readonly loadCatalog: CatalogLoader = loadAgentCatalog,
  ) {}

  register(): void {
    this.pi.registerTool(this.createTaskTool());
    this.pi.registerCommand('subagents', {
      description: 'Inspect and navigate subagent sessions',
      handler: async (args, ctx) => this.openTaskInspector(args, ctx),
    });
    this.pi.on('session_start', async (_event, ctx) => {
      this.activeSessionId = undefined;
      await this.dispose();
      this.shuttingDown = false;
      this.activeSessionId = ctx.sessionManager.getSessionId();
      this.broker.reset();
      this.restore(ctx);
      this.restorePrimaryAgent(ctx);
      const activeTools = this.pi.getActiveTools();
      const withoutTask = activeTools.filter((tool) => tool !== 'task');
      const nextTools = this.maxSubagents > 0 ? [...withoutTask, 'task'] : withoutTask;
      if (nextTools.join('\0') !== activeTools.join('\0')) this.pi.setActiveTools(nextTools);
    });
    this.pi.on('session_before_switch', async (_event, ctx) => {
      this.activeSessionId = undefined;
      if (ctx.hasUI) ctx.ui.setWidget(TASK_WIDGET, undefined);
      await this.dispose();
    });
    this.pi.on('session_shutdown', async (_event, ctx) => {
      this.activeSessionId = undefined;
      if (ctx.hasUI) ctx.ui.setWidget(TASK_WIDGET, undefined);
      await this.dispose();
    });
    this.pi.on('before_agent_start', (event) => {
      if (!this.primaryAgent?.prompt) return;
      return { systemPrompt: `${event.systemPrompt}\n\n${this.primaryAgent.prompt}` };
    });
    this.pi.on('tool_call', async (event, ctx) => {
      if (this.primaryConfigurationError) {
        return { block: true, reason: 'Invalid primary agent configuration' };
      }
      if (!this.primaryAgent || !this.primaryRules || event.toolName === 'task') return;
      const permission = permissionName(event.toolName);
      for (const resource of permissionResources(event.toolName, event.input, ctx.cwd)) {
        const decision = permissionDecision(this.primaryRules, permission, resource);
        if (decision === 'deny') {
          return {
            block: true,
            reason: `Permission denied by @${this.primaryAgent.name}: ${permission} ${resource}`,
          };
        }
        if (decision === 'ask') {
          try {
            await this.broker.ask(
              ctx,
              `@${this.primaryAgent.name}`,
              permission,
              resource,
              ctx.signal,
            );
          } catch (error) {
            return { block: true, reason: error instanceof Error ? error.message : String(error) };
          }
        }
      }
    });
  }

  getAgentCatalog(ctx: ExtensionContext): AgentCatalog {
    return this.loadCatalog(ctx.cwd, getAgentDir(), isProjectTrusted(ctx));
  }

  getPrimaryAgent(): AgentDefinition | undefined {
    return this.primaryAgent;
  }

  getMaxSubagents(): number {
    return this.maxSubagents;
  }

  setMaxSubagents(maxSubagents: number): void {
    if (!Number.isInteger(maxSubagents) || maxSubagents < 0 || maxSubagents > MAX_SUBAGENTS) {
      throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
    }
    this.maxSubagents = maxSubagents;
    this.semaphore.setLimit(Math.max(1, maxSubagents));
    const activeTools = this.pi.getActiveTools();
    const withoutTask = activeTools.filter((tool) => tool !== 'task');
    const nextTools = maxSubagents > 0 ? [...withoutTask, 'task'] : withoutTask;
    if (nextTools.join('\0') !== activeTools.join('\0')) this.pi.setActiveTools(nextTools);
  }

  private async openTaskInspector(args: string, ctx: ExtensionContext): Promise<void> {
    if (ctx.mode !== 'tui') {
      ctx.ui.notify('Subagent inspection is available in TUI mode', 'warning');
      return;
    }
    const tasks = [...this.tasks.values()];
    if (tasks.length === 0) {
      ctx.ui.notify('No subagent sessions in this session', 'info');
      return;
    }

    const requested = args.trim();
    let selected = requested
      ? tasks.findIndex((task) => task.id === requested || task.id.startsWith(requested))
      : 0;
    if (selected < 0) {
      ctx.ui.notify(`Unknown subagent task: ${requested}`, 'error');
      return;
    }
    let detail = requested.length > 0;
    let scroll = 0;

    await ctx.ui.custom<void>(
      (tui, theme, _keybindings, done) => ({
        render: (width: number) => {
          const fit = (line: string) => truncateToWidth(line, Math.max(1, width));
          if (!detail) {
            const start = Math.max(0, Math.min(selected - 6, tasks.length - 12));
            const shown = tasks.slice(start, start + 12);
            const lines = [theme.fg('accent', theme.bold('Subagent sessions'))];
            for (const [offset, task] of shown.entries()) {
              const index = start + offset;
              const cursor = index === selected ? theme.fg('accent', '›') : ' ';
              const indent = '  '.repeat(Math.max(0, task.depth - 1));
              lines.push(
                `${cursor} ${indent}${taskState(theme, task)} ${theme.fg('accent', `@${task.agent}`)} ${theme.fg('text', task.description)} ${theme.fg('dim', task.id.slice(0, 8))}`,
              );
            }
            lines.push('', theme.fg('dim', '↑↓ select  enter inspect  esc close'));
            return lines.map(fit);
          }

          const task = tasks[selected];
          if (!task) return [];
          const siblings = tasks.filter(
            (candidate) => candidate.parentTaskId === task.parentTaskId,
          );
          const siblingIndex = siblings.findIndex((candidate) => candidate.id === task.id);
          const transcript = taskTranscript(task).flatMap((line) => line.split('\n'));
          const maxScroll = Math.max(0, transcript.length - INSPECTOR_BODY_LINES);
          scroll = Math.min(scroll, maxScroll);
          const shown = transcript.slice(scroll, scroll + INSPECTOR_BODY_LINES);
          const duration = taskDuration(taskDetails(task));
          const metrics = [
            task.id,
            `${siblingIndex + 1} of ${siblings.length}`,
            task.toolCalls === undefined
              ? undefined
              : `${task.toolCalls} tool call${task.toolCalls === 1 ? '' : 's'}`,
            duration,
          ].filter(Boolean);
          const lines = [
            `${theme.fg('accent', theme.bold(`@${task.agent}`))} ${theme.fg('text', task.description)}`,
            `${taskState(theme, task)} ${theme.fg('dim', metrics.join(' · '))}`,
            '',
            ...shown.map((line) => theme.fg('toolOutput', line)),
          ];
          while (lines.length < INSPECTOR_BODY_LINES + 3) lines.push('');
          if (transcript.length > INSPECTOR_BODY_LINES) {
            lines.push(
              theme.fg('dim', `${scroll + 1}-${scroll + shown.length} of ${transcript.length}`),
            );
          }
          lines.push(
            theme.fg('dim', 'Parent p/backspace  Prev ←  Next →  ↑↓ scroll  r refresh  esc back'),
          );
          return lines.map(fit);
        },
        handleInput: (data: string) => {
          if (!detail) {
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) done();
            else if (matchesKey(data, 'up')) selected = Math.max(0, selected - 1);
            else if (matchesKey(data, 'down')) selected = Math.min(tasks.length - 1, selected + 1);
            else if (matchesKey(data, 'return')) {
              detail = true;
              scroll = 0;
            } else return;
            tui.requestRender();
            return;
          }

          const task = tasks[selected];
          if (!task) return;
          if (matchesKey(data, 'escape')) {
            detail = false;
            scroll = 0;
          } else if (matchesKey(data, 'ctrl+c')) {
            done();
          } else if (matchesKey(data, 'up')) {
            scroll = Math.max(0, scroll - 1);
          } else if (matchesKey(data, 'down')) {
            scroll += 1;
          } else if (data === 'p' || matchesKey(data, 'backspace')) {
            const parentIndex = task.parentTaskId
              ? tasks.findIndex((candidate) => candidate.id === task.parentTaskId)
              : -1;
            if (parentIndex >= 0) selected = parentIndex;
            else detail = false;
            scroll = 0;
          } else if (matchesKey(data, 'left') || matchesKey(data, 'right')) {
            const siblings = tasks.filter(
              (candidate) => candidate.parentTaskId === task.parentTaskId,
            );
            const siblingIndex = siblings.findIndex((candidate) => candidate.id === task.id);
            const offset = matchesKey(data, 'left') ? -1 : 1;
            const sibling = siblings[siblingIndex + offset];
            if (sibling) selected = tasks.indexOf(sibling);
            scroll = 0;
          } else if (data !== 'r') return;
          tui.requestRender();
        },
        invalidate() {},
      }),
      { overlay: true, overlayOptions: { anchor: 'center', width: 96, margin: 2 } },
    );
  }

  selectPrimaryAgent(name: string, ctx: ExtensionContext): boolean {
    const catalog = this.getAgentCatalog(ctx);
    for (const warning of catalog.warnings) ctx.ui.notify(warning, 'warning');
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) return false;
    const agent = availablePrimaryAgents(catalog).find((candidate) => candidate.name === name);
    if (!agent) {
      ctx.ui.notify(`Unknown primary agent: ${name}`, 'error');
      return false;
    }
    this.activatePrimaryAgent(agent, catalog, ctx, true);
    return true;
  }

  private createTaskTool(
    parentTask?: TaskRecord,
    callerRules?: PermissionRules,
    boundCtx?: ExtensionContext,
  ): ToolDefinition<typeof taskParameters, TaskDetails> {
    const cwd = boundCtx?.cwd ?? process.cwd();
    const catalog = this.loadCatalog(
      cwd,
      getAgentDir(),
      boundCtx ? isProjectTrusted(boundCtx) : false,
    );
    const agents = availableSubagents(catalog).filter(
      (agent) =>
        !agent.hidden &&
        permissionDecision(callerRules ?? catalog.permissions, 'task', agent.name) !== 'deny',
    );
    const descriptions = agents
      .map((agent) => `${agent.name}: ${agent.description ?? 'No description'}`)
      .join('\n');
    return {
      name: 'task',
      label: 'Task',
      description:
        'Delegate a task to a sandboxed Pi RPC process.' +
        (descriptions ? `\n\nAvailable subagents:\n${descriptions}` : ''),
      parameters: taskParameters,
      executionMode: 'parallel',
      renderCall: (input, theme) => {
        const background = input.background ? theme.fg('muted', ' (background)') : '';
        const description = input.description?.trim() || '...';
        const agent = input.subagent_type?.trim() || '...';
        const title = theme.fg('toolTitle', theme.bold('Agent Task'));
        return new Text(
          `${title}${background}${theme.fg('muted', ' — ')}${theme.fg('text', description)}\n` +
            theme.fg('dim', `  @${agent}`),
          0,
          0,
        );
      },
      execute: async (_toolCallId, input, signal, onUpdate, callCtx) => {
        const result = await this.execute(
          input,
          boundCtx ?? callCtx,
          signal,
          parentTask,
          callerRules,
          (text, updatedTask) =>
            onUpdate?.({
              content: [{ type: 'text', text }],
              details: updatedTask
                ? taskDetails(updatedTask)
                : {
                    taskId: input.task_id ?? '',
                    state: 'running',
                    agent: input.subagent_type,
                    description: input.description,
                    background: input.background,
                  },
            }),
        );
        return {
          content: [{ type: 'text', text: result.text }],
          details: taskDetails(result.task, result.state),
        };
      },
      renderResult: (result, { expanded }, theme) => {
        const details = result.details;
        const fallback = result.content.find((item) => item.type === 'text')?.text ?? '(no output)';
        if (!details) return new Text(fallback, 0, 0);

        const stateView: SubagentTaskView = {
          id: details.taskId,
          agent: details.agent,
          description: details.description ?? '',
          state: details.state,
        };
        let text = taskState(theme, stateView);
        if (details.currentTool) text += theme.fg('muted', `  → ${details.currentTool}`);
        if (details.retryAttempt) text += theme.fg('warning', `  retry ${details.retryAttempt}`);

        const metrics: string[] = [];
        if (details.toolCalls !== undefined) {
          metrics.push(`${details.toolCalls} tool call${details.toolCalls === 1 ? '' : 's'}`);
        }
        const duration = taskDuration(details);
        if (duration) metrics.push(duration);
        if (metrics.length > 0) text += `\n${theme.fg('dim', metrics.join(' · '))}`;

        const output = taskOutput(details, '');
        if (output) {
          const lines = output.trimEnd().split('\n');
          const shown = expanded ? lines : lines.slice(0, 3);
          text += `\n${theme.fg(details.state === 'error' ? 'error' : 'toolOutput', shown.join('\n'))}`;
          if (!expanded && lines.length > shown.length) {
            text += `\n${theme.fg('muted', `… ${keyHint('app.tools.expand', 'to expand')}`)}`;
          }
        }
        text += `\n${theme.fg('dim', `↳ /subagents ${details.taskId.slice(0, 8)} to inspect`)}`;
        return new Text(text, 0, 0);
      },
    };
  }

  private async execute(
    input: TaskInput,
    ctx: ExtensionContext,
    signal: AbortSignal | undefined,
    parentTask: TaskRecord | undefined,
    callerRules: PermissionRules | undefined,
    update: (text: string, task?: TaskRecord) => void,
  ): Promise<{ task: TaskRecord; text: string; state: TaskState }> {
    if (!input.prompt.trim()) throw new Error('Task prompt cannot be empty');
    const catalog = this.loadCatalog(ctx.cwd, getAgentDir(), isProjectTrusted(ctx));
    for (const warning of catalog.warnings) ctx.ui.notify(warning, 'warning');
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) {
      throw new Error(`Invalid agent configuration:\n${catalog.diagnostics.join('\n')}`);
    }
    if (catalog.maxSubagents === 0) throw new Error('Subagents are disabled by maxSubagents: 0');
    const agent = catalog.agents.get(input.subagent_type);
    if (!agent || agent.mode === 'primary')
      throw new Error(`Unknown subagent: ${input.subagent_type}`);
    const rules = callerRules ?? catalog.permissions;
    const taskPermission = permissionDecision(rules, 'task', agent.name);
    if (taskPermission === 'deny') throw new Error(`Task permission denied for ${agent.name}`);
    if (taskPermission === 'ask') {
      await this.broker.ask(ctx, input.description, 'task', agent.name, signal);
    }

    const depth = (parentTask?.depth ?? -1) + 1;
    if (depth > MAX_DEPTH) throw new Error(`Maximum subagent depth (${MAX_DEPTH}) exceeded`);
    let task: TaskRecord;
    if (input.task_id) {
      const continued = this.tasks.get(input.task_id);
      if (!continued) throw new Error(`Unknown task: ${input.task_id}`);
      task = continued;
      if (task.parentSessionId !== ctx.sessionManager.getSessionId()) {
        throw new Error(`Task ${task.id} does not belong to this session`);
      }
      if (task.parentTaskId !== parentTask?.id) {
        throw new Error(`Task ${task.id} does not belong to this parent task`);
      }
      if (task.agent !== agent.name) {
        throw new Error(`Task ${task.id} belongs to agent ${task.agent}, not ${agent.name}`);
      }
      if (
        !this.running.has(task.id) &&
        (!task.sessionDir || !existsSync(task.sessionDir)) &&
        (!task.sessionFile || !existsSync(task.sessionFile))
      ) {
        throw new Error(`Task ${task.id} session is unavailable`);
      }
    } else {
      task = this.createRecord(input, ctx, parentTask, agent, depth);
    }

    const existingRun = this.runPromises.get(task.id);

    if (input.task_id) task.delivered = false;
    if (existingRun) {
      const controller = this.controllers.get(task.id);
      let rejectCancelled: ((error: Error) => void) | undefined;
      const cancelled = new Promise<never>((_resolve, reject) => {
        rejectCancelled = reject;
      });
      const abort = () => {
        controller?.abort();
        rejectCancelled?.(new Error('Task cancelled'));
      };
      const waitFor = <T>(promise: Promise<T>): Promise<T> =>
        signal && !input.background ? Promise.race([promise, cancelled]) : promise;
      if (!input.background && signal?.aborted) {
        controller?.abort();
        throw new Error('Task cancelled');
      }
      if (!input.background) signal?.addEventListener('abort', abort, { once: true });
      try {
        const running = this.running.get(task.id);
        if (running) {
          await waitFor(running.rpc.request('follow_up', { message: input.prompt }));
        } else {
          const prompts = this.pendingPrompts.get(task.id) ?? [];
          prompts.push(input.prompt);
          this.pendingPrompts.set(task.id, prompts);
        }
        if (input.background) {
          if (!task.background) {
            task.background = true;
            this.persist(task);
            void this.notifyWhenDone(task, existingRun, ctx);
          }
          const state = task.state === 'queued' ? 'queued' : 'running';
          const status = state === 'queued' ? 'Background task queued' : 'Background task updated';
          return { task, text: renderTaskResult(task.id, state, status), state };
        }
        this.claimForeground(task.id);
        try {
          const output = await waitFor(existingRun);
          task.delivered = true;
          this.persist(task);
          return { task, text: renderTaskResult(task.id, 'completed', output), state: 'completed' };
        } finally {
          this.releaseForeground(task.id);
        }
      } finally {
        signal?.removeEventListener('abort', abort);
      }
    }

    task.state = 'queued';
    task.delivered = false;
    task.background = input.background === true;
    task.output = undefined;
    task.error = undefined;
    task.currentTool = undefined;
    task.toolCalls = 0;
    task.retryAttempt = undefined;
    task.startedAt = undefined;
    task.finishedAt = undefined;
    this.persist(task);
    this.updateTaskWidget(ctx);

    const controller = new AbortController();
    this.controllers.set(task.id, controller);
    const abort = () => controller.abort();
    if (!input.background && signal?.aborted) controller.abort();
    if (!input.background) signal?.addEventListener('abort', abort, { once: true });
    if (!input.background) this.claimForeground(task.id);
    const run = this.runTask(task, agent, input.prompt, catalog, ctx, controller.signal, (text) =>
      update(text, task),
    );
    this.runPromises.set(task.id, run);
    void run
      .catch(() => undefined)
      .finally(() => {
        this.runPromises.delete(task.id);
        this.controllers.delete(task.id);
        signal?.removeEventListener('abort', abort);
      });
    if (input.background) {
      task.background = true;
      this.persist(task);
      void this.notifyWhenDone(task, run, ctx);
      return {
        task,
        text: renderTaskResult(task.id, 'queued', 'Background task queued'),
        state: 'queued',
      };
    }
    try {
      const output = await run;
      task.delivered = true;
      this.persist(task);
      return { task, text: renderTaskResult(task.id, 'completed', output), state: 'completed' };
    } finally {
      this.releaseForeground(task.id);
    }
  }

  private createRecord(
    input: TaskInput,
    ctx: ExtensionContext,
    parentTask: TaskRecord | undefined,
    agent: AgentDefinition,
    depth: number,
  ): TaskRecord {
    const parentSession = parentTask?.sessionFile ?? ctx.sessionManager.getSessionFile();
    const id = randomUUID();
    const sessionDir = join(
      getAgentDir(),
      'sessions',
      'pi-landstrip',
      ctx.sessionManager.getSessionId(),
      id,
    );
    mkdirSync(sessionDir, { recursive: true });
    const task: TaskRecord = {
      version: 1,
      id,
      parentSessionId: ctx.sessionManager.getSessionId(),
      parentTaskId: parentTask?.id,
      parentSessionFile: parentSession,
      sessionDir,
      agent: agent.name,
      description: input.description,
      depth,
      state: 'queued',
      background: input.background === true,
    };
    this.tasks.set(task.id, task);
    this.persist(task);
    this.updateTaskWidget(ctx);
    return task;
  }

  private async runTask(
    task: TaskRecord,
    agent: AgentDefinition,
    prompt: string,
    catalog: AgentCatalog,
    ctx: ExtensionContext,
    signal: AbortSignal,
    update: (text: string) => void,
  ): Promise<string> {
    let worker: WorkerHandle | undefined;
    try {
      const release = await this.semaphore.acquire(signal);
      this.leases.set(task.id, { release });
      task.state = 'running';
      task.startedAt = Date.now();
      task.finishedAt = undefined;
      task.error = undefined;
      this.persist(task);
      this.updateTaskWidget(ctx);
      const rules = mergePermissionRules(catalog.permissions, agent.permissions);
      const workerPromise = this.createWorker(task, agent, rules, ctx, signal, (request) =>
        this.handleWorkerRequest(task, rules, ctx, request),
      );
      let rejectCancelled: ((error: Error) => void) | undefined;
      const cancelled = new Promise<never>((_resolve, reject) => {
        rejectCancelled = reject;
      });
      const abortStartup = () => rejectCancelled?.(new Error('Task cancelled'));
      signal.addEventListener('abort', abortStartup, { once: true });
      if (signal.aborted) abortStartup();
      try {
        worker = await Promise.race([workerPromise, cancelled]);
      } catch (error) {
        if (signal.aborted) {
          void workerPromise.then(
            async (lateWorker) => {
              await lateWorker.rpc.stop().catch(() => undefined);
              await lateWorker.dispose().catch(() => undefined);
            },
            () => undefined,
          );
        }
        throw error;
      } finally {
        signal.removeEventListener('abort', abortStartup);
      }
      if (signal.aborted) throw new Error('Task cancelled');
      let turns = 0;
      let streamedText = '';
      worker.rpc.onEvent((event) => {
        if (event.type === 'message_update' && isRecord(event.assistantMessageEvent)) {
          const messageEvent = event.assistantMessageEvent;
          if (messageEvent.type === 'text_delta' && typeof messageEvent.delta === 'string') {
            streamedText += messageEvent.delta;
            update(streamedText);
          }
        }
        if (event.type === 'tool_execution_start' && typeof event.toolName === 'string') {
          task.currentTool = event.toolName;
          task.toolCalls = (task.toolCalls ?? 0) + 1;
          this.persist(task);
          this.updateTaskWidget(ctx);
          update(streamedText || `Running ${event.toolName}`);
        }
        if (event.type === 'tool_execution_end') {
          task.currentTool = undefined;
          this.persist(task);
          this.updateTaskWidget(ctx);
          update(streamedText || 'Subagent running');
        }
        if (event.type === 'auto_retry_start' && typeof event.attempt === 'number') {
          task.retryAttempt = event.attempt;
          this.persist(task);
          this.updateTaskWidget(ctx);
          update(streamedText || `Retry ${event.attempt}`);
        }
        if (event.type === 'auto_retry_end') {
          task.retryAttempt = undefined;
          this.persist(task);
          this.updateTaskWidget(ctx);
          update(streamedText || 'Subagent running');
        }
        if (event.type === 'turn_end') {
          turns += 1;
          if (agent.steps && turns >= agent.steps) void worker?.rpc.abort().catch(() => undefined);
        }
      });
      const abort = () => void worker?.rpc.stop().catch(() => undefined);
      signal.addEventListener('abort', abort, { once: true });
      this.running.set(task.id, { rpc: worker.rpc, promise: Promise.resolve('') });
      try {
        const promise = worker.rpc
          .prompt(prompt)
          .then(async () => (await worker?.rpc.getLastAssistantText()) ?? '');
        this.running.set(task.id, { rpc: worker.rpc, promise });
        const pendingPrompts = this.pendingPrompts.get(task.id) ?? [];
        this.pendingPrompts.delete(task.id);
        for (const pendingPrompt of pendingPrompts) {
          await worker.rpc.request('follow_up', { message: pendingPrompt });
        }
        const output = await promise;
        if (signal.aborted) throw new Error('Task cancelled');
        task.state = 'completed';
        task.output = this.storeTaskText(task, output, 'output');
        task.currentTool = undefined;
        task.retryAttempt = undefined;
        task.finishedAt = Date.now();
        this.persist(task);
        this.updateTaskWidget(ctx);
        return task.output;
      } finally {
        signal.removeEventListener('abort', abort);
      }
    } catch (error) {
      task.state = signal.aborted ? 'cancelled' : 'error';
      const message = error instanceof Error ? error.message : String(error);
      task.error = this.storeTaskText(task, message, 'error');
      task.currentTool = undefined;
      task.retryAttempt = undefined;
      task.finishedAt = Date.now();
      this.persist(task);
      this.updateTaskWidget(ctx);
      if (task.error === message) throw error;
      throw new Error(task.error);
    } finally {
      this.running.delete(task.id);
      this.pendingPrompts.delete(task.id);
      await worker?.rpc.stop().catch(() => undefined);
      await worker?.dispose().catch(() => undefined);
      this.releaseLease(task.id);
      this.leases.delete(task.id);
    }
  }

  private async defaultWorker(
    task: TaskRecord,
    agent: AgentDefinition,
    rules: PermissionRules,
    ctx: ExtensionContext,
    signal: AbortSignal,
    onRequest: (request: ExtensionUiRequest) => Promise<ExtensionUiResult>,
  ): Promise<WorkerHandle> {
    const invocation = this.piInvocation();
    this.validatePiInvocation();
    const model = agent.model ?? (ctx.model ? `${ctx.model.provider}/${ctx.model.id}` : undefined);
    if (!model) throw new Error(`No model available for subagent ${agent.name}`);
    const thinkingLevels = new Set(['off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']);
    const thinking =
      agent.variant && thinkingLevels.has(agent.variant)
        ? agent.variant
        : this.pi.getThinkingLevel();
    if (agent.variant && !thinkingLevels.has(agent.variant)) {
      ctx.ui.notify(
        `Agent ${agent.name} uses unsupported Pi model variant: ${agent.variant}`,
        'warning',
      );
    }
    const providerOptionNames = Object.keys(agent.providerOptions);
    if (providerOptionNames.length > 0) {
      ctx.ui.notify(
        `Agent ${agent.name} options are not supported by Pi RPC mode: ${providerOptionNames.join(', ')}`,
        'warning',
      );
    }
    const taskEnabled = agent.permissions.some(
      (rule) => rule.permission === 'task' && rule.action !== 'deny',
    );
    const tools = taskEnabled
      ? [...new Set([...this.pi.getActiveTools(), 'task'])]
      : this.pi.getActiveTools().filter((tool) => tool !== 'task');
    const args = [
      ...invocation.args,
      '--mode',
      'rpc',
      '--extension',
      join(packageDir, 'index.ts'),
      ...(task.sessionFile
        ? ['--session', task.sessionFile]
        : task.sessionDir
          ? ['--session-dir', task.sessionDir]
          : []),
      '--model',
      model,
      '--thinking',
      thinking,
      '--system-prompt',
      agent.prompt,
      isProjectTrusted(ctx) ? '--approve' : '--no-approve',
      '--tools',
      tools.join(','),
    ];
    const config: WorkerConfig = { rules, task, taskEnabled, steps: agent.steps };
    const temp = mkdtempSync(join(tmpdir(), `pi-landstrip-task-${task.id}-`));
    const agentDir = getAgentDir();
    let launch: LandstripRpcWorkerLaunch | undefined;
    let rpc: RpcProcess | undefined;
    const abortWorker = () => void rpc?.stop().catch(() => undefined);
    try {
      const sessionWritePath =
        task.sessionDir ?? (task.sessionFile ? dirname(task.sessionFile) : undefined);
      if (!sessionWritePath) throw new Error('Subagent task has no session directory or file');
      const cliEntry = invocation.args[0] ?? invocation.command;
      const cliRoot = dependencyRoot(cliEntry) ?? dirname(dirname(cliEntry));
      const extensionRoot = dependencyRoot(packageDir);
      launch = await this.integration.prepareRpcWorker({
        command: invocation.command,
        args,
        cwd: ctx.cwd,
        env: {
          ...process.env,
          [WORKER_ENV]: Buffer.from(JSON.stringify(config)).toString('base64url'),
          JITI_FS_CACHE: 'false',
          TMPDIR: temp,
          TMP: temp,
          TEMP: temp,
        },
        ctx,
        readPaths: [
          ...new Set(
            [
              ctx.cwd,
              ...agentBootstrapPaths(agentDir),
              join(homedir(), '.agents', 'skills'),
              packageDir,
              join(packageDir, 'node_modules'),
              invocation.command,
              cliRoot,
              extensionRoot,
              task.sessionDir,
              task.sessionFile,
              temp,
            ].filter((path): path is string => path !== undefined),
          ),
        ],
        writePaths: [sessionWritePath, temp],
        signal,
      });
      if (signal.aborted) throw new Error('Task cancelled');
      rpc = new RpcProcess({
        command: launch.command,
        args: launch.args,
        cwd: launch.cwd,
        env: launch.env,
        spawn: launch.spawn,
        onExtensionUiRequest: onRequest,
        requestTimeoutMs: 120_000,
        settleTimeoutMs: 24 * 60 * 60 * 1000,
      });
      signal.addEventListener('abort', abortWorker, { once: true });
      if (signal.aborted) throw new Error('Task cancelled');
      await rpc.start();
      const state = await rpc.request<{ sessionFile?: string }>('get_state');
      if (state.sessionFile) {
        task.sessionFile = state.sessionFile;
        this.persist(task);
      }
      signal.removeEventListener('abort', abortWorker);
      return {
        rpc,
        async dispose() {
          try {
            await launch?.dispose();
          } finally {
            rmSync(temp, { recursive: true, force: true });
          }
        },
      };
    } catch (error) {
      signal.removeEventListener('abort', abortWorker);
      await rpc?.stop().catch(() => undefined);
      await launch?.dispose().catch(() => undefined);
      rmSync(temp, { recursive: true, force: true });
      throw error;
    }
  }

  private piInvocation(): { command: string; args: string[] } {
    const argvEntry = process.argv[1];
    if (argvEntry && /(?:^|[/\\])cli\.(?:js|mjs|cjs|ts)$/.test(argvEntry)) {
      return { command: process.execPath, args: [argvEntry] };
    }
    const pkg = resolvePiPackage();
    if (!pkg) {
      throw new Error(
        'Unable to determine the running Pi CLI entry; process-backed subagents are unavailable',
      );
    }
    return { command: process.execPath, args: [pkg.cliEntry] };
  }

  private validatePiInvocation(): void {
    const pkg = resolvePiPackage();
    if (!pkg) {
      throw new Error(
        'Unable to resolve the running Pi package; process-backed subagents are unavailable',
      );
    }
    if (!isSupportedPiVersion(pkg.version)) {
      throw new Error(
        `Process-backed subagents require Pi >=0.80.6 <0.81.0; found ${pkg.version.join('.')}`,
      );
    }
  }

  private async handleWorkerRequest(
    task: TaskRecord,
    rules: PermissionRules,
    ctx: ExtensionContext,
    request: ExtensionUiRequest,
  ): Promise<ExtensionUiResult> {
    if (request.method === 'input' && request.title === CONTROL_TITLE) {
      let response: ControlResponse;
      try {
        const control: unknown = JSON.parse(String(request.placeholder ?? ''));
        if (!isRecord(control) || (control.type !== 'permission' && control.type !== 'task')) {
          throw new Error('Invalid worker control request');
        }
        if (control.type === 'permission') {
          if (typeof control.permission !== 'string' || typeof control.resource !== 'string') {
            throw new Error('Invalid permission request');
          }
          await this.broker.ask(
            ctx,
            task.description,
            control.permission,
            control.resource,
            this.controllers.get(task.id)?.signal,
          );
          response = { ok: true };
        } else {
          if (!isRecord(control.input)) throw new Error('Invalid nested task request');
          const input = control.input as unknown as TaskInput;
          const signal = this.controllers.get(task.id)?.signal;
          const handedOff = input.background !== true && this.releaseLease(task.id);
          let result: { task: TaskRecord; text: string; state: TaskState };
          try {
            result = await this.execute(input, ctx, signal, task, rules, () => undefined);
          } finally {
            if (handedOff) await this.restoreLease(task.id, signal);
          }
          response = {
            ok: true,
            value: result.text,
            task: taskDetails(result.task, result.state),
          };
        }
      } catch (error) {
        response = { ok: false, error: error instanceof Error ? error.message : String(error) };
      }
      return { value: JSON.stringify(response) };
    }
    return this.forwardWorkerUi(ctx, task, request, this.controllers.get(task.id)?.signal);
  }

  private async forwardWorkerUi(
    ctx: ExtensionContext,
    task: TaskRecord,
    request: ExtensionUiRequest,
    signal?: AbortSignal,
  ): Promise<ExtensionUiResult> {
    if (
      request.method === 'select' &&
      typeof request.title === 'string' &&
      Array.isArray(request.options)
    ) {
      const options = request.options.filter((value): value is string => typeof value === 'string');
      const value = await ctx.ui.select(workerDialogTitle(task, request.title), options, {
        signal,
      });
      return value === undefined ? { cancelled: true } : { value };
    }
    if (request.method === 'confirm' && typeof request.title === 'string') {
      return {
        confirmed: await ctx.ui.confirm(
          workerDialogTitle(task, request.title),
          typeof request.message === 'string' ? request.message : '',
          { signal },
        ),
      };
    }
    if (request.method === 'input' && typeof request.title === 'string') {
      const value = await ctx.ui.input(
        workerDialogTitle(task, request.title),
        typeof request.placeholder === 'string' ? request.placeholder : undefined,
        { signal },
      );
      return value === undefined ? { cancelled: true } : { value };
    }
    if (request.method === 'editor' && typeof request.title === 'string') {
      const value = await ctx.ui.editor(
        workerDialogTitle(task, request.title),
        typeof request.prefill === 'string' ? request.prefill : undefined,
      );
      return value === undefined ? { cancelled: true } : { value };
    }
    if (request.method === 'notify' && typeof request.message === 'string') {
      const level =
        request.notifyType === 'warning' || request.notifyType === 'error'
          ? request.notifyType
          : 'info';
      ctx.ui.notify(request.message, level);
    }
  }

  private async notifyWhenDone(
    task: TaskRecord,
    run: Promise<string>,
    ctx: ExtensionContext,
  ): Promise<void> {
    try {
      const output = await run;
      if (this.shuttingDown || task.delivered || this.foregroundClaims.has(task.id)) return;
      const delivered = await this.deliverBackground(
        task,
        `Background task completed: ${task.description}\n\n${renderTaskResult(task.id, 'completed', output)}`,
      );
      if (!delivered) return;
      task.delivered = true;
      this.persist(task);
    } catch (error) {
      if (this.shuttingDown || task.delivered || this.foregroundClaims.has(task.id)) return;
      const message = error instanceof Error ? error.message : String(error);
      const delivered = await this.deliverBackground(
        task,
        `Background task failed: ${task.description}\n\n${renderTaskResult(task.id, 'error', message)}`,
      );
      if (!delivered) return;
      ctx.ui.notify(`Background task failed: ${task.description}`, 'error');
      task.delivered = true;
      this.persist(task);
    }
  }

  private async deliverBackground(task: TaskRecord, content: string): Promise<boolean> {
    if (this.activeSessionId !== task.parentSessionId) return false;
    const parent = task.parentTaskId ? this.running.get(task.parentTaskId) : undefined;
    if (parent) {
      try {
        await parent.rpc.request('follow_up', { message: content });
        return true;
      } catch {
        // The parent may have settled between lookup and delivery; route to root.
      }
    }
    if (this.activeSessionId !== task.parentSessionId) return false;
    this.pi.sendMessage(
      {
        customType: 'landstrip.task.result',
        content,
        display: true,
        details: { taskId: task.id },
      },
      { triggerTurn: true, deliverAs: 'followUp' },
    );
    return true;
  }

  private storeTaskText(task: TaskRecord, value: string, kind: 'output' | 'error'): string {
    if (Buffer.byteLength(value) <= MAX_TASK_OUTPUT_BYTES) return value;
    const directory = task.sessionDir ?? (task.sessionFile ? dirname(task.sessionFile) : undefined);
    if (!directory) throw new Error(`Task ${task.id} has no artifact directory`);
    mkdirSync(directory, { recursive: true });
    const artifactPath = join(directory, `${kind}.txt`);
    const bounded = boundTaskOutput(value, artifactPath);
    if (kind === 'output') task.outputFile = artifactPath;
    else task.errorFile = artifactPath;
    return bounded;
  }

  private persist(task: TaskRecord): void {
    this.pi.appendEntry(TASK_ENTRY, { ...task });
  }

  private updateTaskWidget(ctx: ExtensionContext): void {
    if (!ctx.hasUI || (ctx.mode !== undefined && ctx.mode !== 'tui')) return;

    const tasks = [...this.tasks.values()];
    const byId = new Map(tasks.map((task) => [task.id, task]));
    const rootId = (task: TaskRecord): string => {
      const seen = new Set<string>();
      let current = task;
      while (current.parentTaskId && !seen.has(current.id)) {
        seen.add(current.id);
        const parent = byId.get(current.parentTaskId);
        if (!parent) break;
        current = parent;
      }
      return current.id;
    };
    const active = tasks.filter((task) => task.state === 'queued' || task.state === 'running');
    const activeRoots = new Set(active.map(rootId));
    if (activeRoots.size === 0) {
      ctx.ui.setWidget(TASK_WIDGET, undefined);
      return;
    }
    const visible = tasks.filter((task) => activeRoots.has(rootId(task)));

    ctx.ui.setWidget(TASK_WIDGET, (_tui, theme) => ({
      render: (width: number) => {
        const header =
          theme.fg('accent', theme.bold('Subagents')) +
          theme.fg('dim', `  ${active.length} active`);
        const tree = taskTreeLines(visible, (task) => {
          const agent = theme.fg('accent', `@${task.agent}`);
          const description = theme.fg('text', task.description);
          return `${taskState(theme, task)}  ${agent}  ${description}`;
        });
        const shown = tree.slice(0, 8);
        if (tree.length > shown.length) {
          shown.push(theme.fg('dim', `   … ${tree.length - shown.length} more`));
        }
        return [header, ...shown].map((line) => truncateToWidth(line, Math.max(1, width)));
      },
      invalidate() {},
    }));
  }

  private restore(ctx: ExtensionContext): void {
    this.tasks.clear();
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type !== 'custom' || entry.customType !== TASK_ENTRY) continue;
      const task = entry.data as TaskRecord | undefined;
      if (!task?.id || task.parentSessionId !== ctx.sessionManager.getSessionId()) continue;
      this.tasks.set(task.id, {
        ...task,
        state: task.state === 'running' || task.state === 'queued' ? 'interrupted' : task.state,
      });
    }
    for (const task of this.tasks.values()) {
      if (!task.background || task.delivered) continue;
      if (task.state !== 'completed' && task.state !== 'error') continue;
      const failed = task.state === 'error';
      const value = failed ? (task.error ?? 'Task failed') : (task.output ?? '');
      const content = `Background task ${failed ? 'failed' : 'completed'}: ${task.description}\n\n${renderTaskResult(task.id, failed ? 'error' : 'completed', value)}`;
      this.pi.sendMessage(
        {
          customType: 'landstrip.task.result',
          content,
          display: true,
          details: { taskId: task.id },
        },
        { triggerTurn: true, deliverAs: 'followUp' },
      );
      task.delivered = true;
      this.persist(task);
    }
    this.updateTaskWidget(ctx);
  }

  private restorePrimaryAgent(ctx: ExtensionContext): void {
    this.primaryAgent = undefined;
    this.primaryRules = undefined;
    this.primaryConfigurationError = false;
    const catalog = this.loadCatalog(ctx.cwd, getAgentDir(), isProjectTrusted(ctx));
    for (const warning of catalog.warnings) ctx.ui.notify(warning, 'warning');
    this.maxSubagents = catalog.maxSubagents;
    this.semaphore = new Semaphore(Math.max(1, this.maxSubagents));
    if (catalog.diagnostics.length > 0) {
      this.primaryRules = [{ permission: '*', pattern: '*', action: 'deny' }];
      this.primaryConfigurationError = true;
      this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
      for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'error');
      if (ctx.hasUI) ctx.ui.setStatus('landstrip-agent', '@invalid');
      return;
    }
    let name = 'build';
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type !== 'custom' || entry.customType !== PRIMARY_AGENT_ENTRY) continue;
      const value = entry.data as { name?: unknown } | undefined;
      if (typeof value?.name === 'string') name = value.name;
    }
    const agents = availablePrimaryAgents(catalog);
    const agent = agents.find((candidate) => candidate.name === name) ?? agents[0];
    if (agent) this.activatePrimaryAgent(agent, catalog, ctx, false);
  }

  private activatePrimaryAgent(
    agent: AgentDefinition,
    catalog: AgentCatalog,
    ctx: ExtensionContext,
    persist: boolean,
  ): void {
    this.primaryAgent = agent;
    this.primaryRules = mergePermissionRules(catalog.permissions, agent.permissions);
    this.primaryConfigurationError = false;
    this.broker.reset();
    this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
    if (persist) this.pi.appendEntry(PRIMARY_AGENT_ENTRY, { name: agent.name });
    if (ctx.hasUI) {
      ctx.ui.setStatus('landstrip-agent', `@${agent.name}`);
      if (persist) ctx.ui.notify(`Primary agent: ${agent.name}`, 'info');
    }
  }

  private async dispose(): Promise<void> {
    this.shuttingDown = true;
    for (const controller of this.controllers.values()) controller.abort();
    await Promise.allSettled([...this.running.values()].map(({ rpc }) => rpc.stop()));
    await Promise.allSettled(this.runPromises.values());
    this.running.clear();
    this.runPromises.clear();
    this.controllers.clear();
    this.foregroundClaims.clear();
    this.pendingPrompts.clear();
    for (const taskId of this.leases.keys()) this.releaseLease(taskId);
    this.leases.clear();
  }

  private claimForeground(taskId: string): void {
    this.foregroundClaims.set(taskId, (this.foregroundClaims.get(taskId) ?? 0) + 1);
  }

  private releaseForeground(taskId: string): void {
    const claims = this.foregroundClaims.get(taskId) ?? 0;
    if (claims <= 1) this.foregroundClaims.delete(taskId);
    else this.foregroundClaims.set(taskId, claims - 1);
  }

  private releaseLease(taskId: string): boolean {
    const lease = this.leases.get(taskId);
    if (!lease?.release) return false;
    lease.release();
    lease.release = undefined;
    return true;
  }

  private async restoreLease(taskId: string, signal?: AbortSignal): Promise<void> {
    const lease = this.leases.get(taskId);
    if (!lease || lease.release) return;
    const release = await this.semaphore.acquire(signal);
    const current = this.leases.get(taskId);
    if (!current || current.release) {
      release();
      return;
    }
    current.release = release;
  }
}

export function registerSubagents(
  pi: ExtensionAPI,
  integration: LandstripIntegration,
): SubagentRuntime {
  const runtime = new SubagentRuntime(pi, integration);
  runtime.register();
  return runtime;
}

export function describeSubagents(catalog: AgentCatalog): string {
  return availableSubagents(catalog)
    .map((agent) => `${agent.name}: ${agent.description ?? 'No description'}`)
    .join('\n');
}
