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
import {
  matchesKey,
  Text,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
} from '@earendil-works/pi-tui';
import { Type } from 'typebox';

import { encodeLandstripContext, type LandstripContextV1, LANDSTRIP_CONTEXT_ENV } from './api.ts';
import {
  type AgentCatalog,
  type AgentDefinition,
  agentSupportsMode,
  availableAgents,
  loadAgentCatalog,
  mergePermissionRules,
  permissionAlwaysDenied,
  permissionDecision,
  type PermissionRules,
} from './agents.ts';
import {
  canDeleteProjectAgent,
  deleteProjectAgent,
  prepareProjectAgentEditor,
} from './agent-files.ts';
import { boxBottom, boxRow, boxTop, dialogKeys, dialogTabs } from './box.ts';
import {
  clearAgentDisabledForScope,
  clearMaxSubagentsConfigForScope,
  loadAgentDisabledOverrides,
  loadMaxSubagentsSettings,
  MAX_SUBAGENTS,
  setAgentDisabledForScope,
  setMaxSubagentsConfigForScope,
} from './config.ts';
import type {
  LandstripIntegration,
  LandstripRpcWorkerLaunch,
  SandboxConfigScope,
} from './index.ts';
import { type ExtensionUiRequest, type ExtensionUiResult, RpcProcess } from './rpc-process.ts';
import { AsyncQueue, colorizeAgentText, formatError, isRecord } from './util.ts';

const TASK_ENTRY = 'landstrip.task';
const TASK_WIDGET = 'landstrip.subagents';
const PRIMARY_AGENT_ENTRY = 'landstrip.primary-agent';
const WORKER_ENV = 'PI_LANDSTRIP_WORKER';
const CONTROL_TITLE = 'pi-landstrip:control:v1';
const MAX_DEPTH = 3;
const packageDir = dirname(fileURLToPath(import.meta.url));
const MAX_TASK_OUTPUT_BYTES = 64 * 1024;
const INSPECTOR_BODY_LINES = 16;
const PI_THINKING_LEVELS = new Set(['off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']);
const AGENTS_HELP_ROWS = [
  ['Tab', 'Next tab'],
  ['Shift+Tab / S', 'Switch scope in Agents or Settings'],
  ['↑ / ↓', 'Select item or scroll when follow is off'],
  ['F', 'Toggle task log follow'],
  ['Page Up / Down', 'Scroll task output by page'],
  ['Home / End', 'Jump to task output boundary'],
  ['Enter', 'Open logs, set primary, or save'],
  ['Esc', 'Back or close'],
  ['Ctrl+C', 'Close'],
  ['Space', 'Enable agent or toggle sandbox'],
  ['E', 'Edit project agent'],
  ['X', 'Delete project agent'],
  ['Y / N', 'Confirm or cancel deletion'],
  ['I', 'Use global value'],
  ['R', 'Discard setting changes'],
  ['0-9 / + / -', 'Set subagent limit'],
  ['Backspace', 'Open parent task'],
] as const;
type PiThinkingLevel = Parameters<ExtensionAPI['setThinkingLevel']>[0];

interface PiPackage {
  readonly cliEntry: string;
  readonly version: readonly [number, number, number];
}

const MIN_SUPPORTED_PI_VERSION = [0, 82, 0] as const;
let cachedPiPackage: PiPackage | undefined;
let piPackageResolved = false;

export function isSupportedPiVersion(version: readonly number[]): boolean {
  if (version.length !== 3 || !version.every((part) => Number.isInteger(part) && part >= 0)) {
    return false;
  }
  for (let i = 0; i < 3; i++) {
    const part = version[i]!;
    const min = MIN_SUPPORTED_PI_VERSION[i]!;
    if (part > min) return true;
    if (part < min) return false;
  }
  return true;
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
  description: Type.String({ description: 'Short task label (3-5 words)' }),
  prompt: Type.String({ description: 'Full instructions for the subagent' }),
  subagent_type: Type.String({ description: 'Subagent name' }),
  task_id: Type.Optional(Type.String({ description: 'Task ID to resume' })),
  command: Type.Optional(Type.String({ description: 'Originating command, if any' })),
  background: Type.Optional(
    Type.Boolean({ description: 'Return immediately and run in background' }),
  ),
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

function activeTaskRecords(tasks: readonly TaskRecord[]): TaskRecord[] {
  const byId = new Map(tasks.map((task) => [task.id, task]));
  const visibleIds = new Set<string>();

  for (const task of tasks) {
    if (task.state !== 'queued' && task.state !== 'running') continue;
    const seen = new Set<string>();
    let current: TaskRecord | undefined = task;
    while (current && !seen.has(current.id)) {
      seen.add(current.id);
      visibleIds.add(current.id);
      current = current.parentTaskId ? byId.get(current.parentTaskId) : undefined;
    }
  }

  return tasks.filter((task) => visibleIds.has(task.id));
}

function taskProgress(task: TaskRecord): string[] {
  if (task.state === 'queued') return ['waiting for slot'];
  if (task.state !== 'running') return [];

  const progress: string[] = [];
  if (task.currentTool) progress.push(`→ ${task.currentTool}`);
  if (task.toolCalls !== undefined) {
    progress.push(`${task.toolCalls} call${task.toolCalls === 1 ? '' : 's'}`);
  }
  const duration = taskDuration(taskDetails(task));
  if (duration) progress.push(duration);
  if (task.retryAttempt) progress.push(`retry ${task.retryAttempt}`);
  return progress;
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
    return [`Could not read child session: ${formatError(error)}`];
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
  private readonly queue = new AsyncQueue();
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
    const release = await this.queue.acquire(signal, 'Permission request cancelled');
    try {
      if (this.grants.has(key)) return;
      if (signal?.aborted) throw new Error('Permission request cancelled');
      const choice = await ctx.ui.select(
        `${task}: permission required\n${permission}: ${resource}`,
        ['Allow once', 'Allow for this session', 'Keep blocked'],
        { signal },
      );
      if (choice === 'Allow for this session') this.grants.add(key);
      if (choice !== 'Allow once' && choice !== 'Allow for this session') {
        throw new Error(`Permission denied: ${permission} ${resource}`);
      }
    } finally {
      release();
    }
  }

  reset(): void {
    this.grants.clear();
    this.queue.reset();
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

function permittedToolNames(tools: readonly string[], rules: PermissionRules): string[] {
  return tools.filter((tool) => !permissionAlwaysDenied(rules, permissionName(tool)));
}

function enforcePermittedTools(pi: ExtensionAPI, rules: PermissionRules): void {
  const active = pi.getActiveTools();
  const permitted = permittedToolNames(active, rules);
  if (permitted.join('\0') !== active.join('\0')) pi.setActiveTools(permitted);
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
    throw new Error(`Invalid ${WORKER_ENV}: ${formatError(error)}`);
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
    enforcePermittedTools(pi, config.rules);
  });
  pi.on('before_agent_start', () => {
    enforcePermittedTools(pi, config.rules);
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
        return { block: true, reason: formatError(error) };
      }
    }
  });

  if (config.taskEnabled) {
    pi.registerTool({
      name: 'task',
      label: 'Task',
      description: 'Delegate a task to a Pi subagent process.',
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
  private primaryAgentSwitching = false;
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
    this.pi.registerCommand('agents', {
      description: 'Manage agents, tasks, and concurrency',
      handler: async (args, ctx) => this.openAgents(args, ctx),
    });
    this.pi.registerShortcut('ctrl+shift+a', {
      description: 'Cycle to the next primary agent',
      handler: async (ctx) => this.cyclePrimaryAgent(ctx),
    });
    this.pi.on('session_start', async (_event, ctx) => {
      this.activeSessionId = undefined;
      await this.dispose();
      this.shuttingDown = false;
      this.activeSessionId = ctx.sessionManager.getSessionId();
      this.broker.reset();
      this.restore(ctx);
      await this.restorePrimaryAgent(ctx);
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
            return { block: true, reason: formatError(error) };
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

  private async openAgents(args: string, ctx: ExtensionContext): Promise<void> {
    if (ctx.mode !== 'tui') {
      ctx.ui.notify('Agent management is available in TUI mode', 'warning');
      return;
    }

    const projectTrusted = isProjectTrusted(ctx);
    let tasks = [...this.tasks.values()];
    const requested = args.trim();
    let scope: SandboxConfigScope = projectTrusted ? 'project' : 'global';
    let catalog = this.getAgentCatalog(ctx);
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    let globalCatalog = this.loadCatalog(ctx.cwd, getAgentDir(), false);
    let agents = [...catalog.agents.values()]
      .filter((agent) => !agent.hidden)
      .sort((left, right) => left.name.localeCompare(right.name));
    let disabledOverrides = loadAgentDisabledOverrides(ctx.cwd, projectTrusted);
    let maxSubagentsSettings = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
    const sandboxCallbacks = this.integration.sandboxCallbacks;
    let sandboxSettings = sandboxCallbacks?.load(ctx.cwd, projectTrusted) ?? { global: true };
    let tab: 'agents' | 'tasks' | 'logs' | 'settings' | 'help' = requested ? 'logs' : 'agents';
    let selectedAgent = Math.max(
      0,
      agents.findIndex((agent) => agent.name === this.primaryAgent?.name),
    );
    let selectedTask = requested
      ? tasks.findIndex((task) => task.id === requested || task.id.startsWith(requested))
      : 0;
    if (selectedTask < 0) {
      ctx.ui.notify(`Unknown task session: ${requested}`, 'error');
      return;
    }
    let selectedSetting = 0;
    const dirtySettings = new Set<number>();
    let saving = false;
    let editing = false;
    let confirmingDeleteAgent: string | undefined;
    let follow = requested.length > 0;
    let scroll = 0;

    const reloadAgents = (): void => {
      const selectedName = agents[selectedAgent]?.name;
      catalog = this.getAgentCatalog(ctx);
      globalCatalog = this.loadCatalog(ctx.cwd, getAgentDir(), false);
      agents = [...catalog.agents.values()]
        .filter((agent) => !agent.hidden)
        .sort((left, right) => left.name.localeCompare(right.name));
      disabledOverrides = loadAgentDisabledOverrides(ctx.cwd, projectTrusted);
      const nextSelected = selectedName
        ? agents.findIndex((agent) => agent.name === selectedName)
        : selectedAgent;
      selectedAgent = Math.max(0, Math.min(nextSelected < 0 ? 0 : nextSelected, agents.length - 1));
    };
    const reloadSettings = (): void => {
      maxSubagentsSettings = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
      sandboxSettings = sandboxCallbacks?.load(ctx.cwd, projectTrusted) ?? { global: true };
    };
    const refreshTasks = (): void => {
      const selectedId = tasks[selectedTask]?.id;
      tasks = [...this.tasks.values()];
      const nextSelected = selectedId
        ? tasks.findIndex((task) => task.id === selectedId)
        : selectedTask;
      selectedTask = Math.max(0, Math.min(nextSelected < 0 ? 0 : nextSelected, tasks.length - 1));
    };
    const refreshAgentRuntime = async (name: string): Promise<void> => {
      reloadAgents();
      if (this.primaryAgent?.name === name) {
        await this.restorePrimaryAgent(ctx);
      } else {
        this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
      }
    };
    const scopedAgent = (agent: AgentDefinition): AgentDefinition | undefined =>
      scope === 'global' ? globalCatalog.agents.get(agent.name) : agent;
    const selectedMaxSubagents = (): number =>
      scope === 'global'
        ? maxSubagentsSettings.global
        : (maxSubagentsSettings.project ?? maxSubagentsSettings.global);
    const updateSelectedMaxSubagents = (value: number): void => {
      maxSubagentsSettings =
        scope === 'global'
          ? { ...maxSubagentsSettings, global: value }
          : { ...maxSubagentsSettings, project: value };
      dirtySettings.add(0);
    };
    const selectedSandboxEnabled = (): boolean =>
      scope === 'global'
        ? sandboxSettings.global
        : (sandboxSettings.project ?? sandboxSettings.global);
    const updateSelectedSandboxEnabled = (value: boolean): void => {
      sandboxSettings =
        scope === 'global'
          ? { ...sandboxSettings, global: value }
          : { ...sandboxSettings, project: value };
      dirtySettings.add(1);
    };

    await ctx.ui.custom<void>(
      (tui, theme, _keybindings, done) => ({
        render: (width: number) => {
          const contentWidth = Math.max(1, width - 4);
          const box = (lines: string[]) => [
            boxTop(theme, width, 'Agents'),
            ...lines.map((line) => boxRow(theme, width, line)),
            boxBottom(theme, width),
          ];
          const pad = (value: string, cellWidth: number): string => {
            const clipped = truncateToWidth(value, cellWidth);
            return `${clipped}${' '.repeat(Math.max(0, cellWidth - visibleWidth(clipped)))}`;
          };
          refreshTasks();
          const tabs = `${dialogTabs(theme, ['Agents', 'Tasks', 'Logs', 'Settings', 'Help'], `${tab[0]?.toUpperCase()}${tab.slice(1)}`)}${
            tab === 'tasks' || tab === 'logs'
              ? ''
              : theme.fg('dim', `  ·  Scope: ${scope === 'project' ? 'Project' : 'Global'}`)
          }`;

          if (tab === 'agents') {
            const start = Math.max(0, Math.min(selectedAgent - 3, agents.length - 7));
            const shown = agents.slice(start, start + 7);
            const nameWidth = Math.min(
              20,
              Math.max(5, ...agents.map((agent) => visibleWidth(`@${agent.name}`))),
            );
            const primaryWidth = 7;
            const modeWidth = 8;
            const sourceWidth = 8;
            const stateWidth = 13;
            const fixedWidth =
              2 + primaryWidth + 1 + nameWidth + 1 + modeWidth + 1 + sourceWidth + 1 + stateWidth;
            const modelWidth = Math.max(10, Math.min(30, contentWidth - fixedWidth - 1));
            const lines = [
              tabs,
              '',
              theme.fg(
                'dim',
                `  ${pad('Primary', primaryWidth)} ${pad('Agent', nameWidth)} ${pad('Mode', modeWidth)} ${pad(
                  'Source',
                  sourceWidth,
                )} ${pad('Model', modelWidth)} ${pad('State', stateWidth)}`,
              ),
            ];
            for (const [offset, agent] of shown.entries()) {
              const index = start + offset;
              const selected = index === selectedAgent;
              const cursor = selected ? theme.fg('accent', '›') : ' ';
              const primary = agent.name === this.primaryAgent?.name ? 'yes' : '';
              const current = scopedAgent(agent);
              const unavailable = current === undefined;
              const scopedDisabled = current?.disabled ?? false;
              const disabled = agent.disabled;
              const deleting = confirmingDeleteAgent === agent.name;
              const inherited = scope === 'project' && !disabledOverrides.project.has(agent.name);
              const state = unavailable
                ? 'unavailable'
                : inherited
                  ? `inherited ${scopedDisabled ? 'off' : 'on'}`
                  : scopedDisabled
                    ? 'disabled'
                    : 'enabled';
              const color = deleting ? 'error' : disabled ? 'muted' : 'text';
              const plainName = pad(`@${agent.name}`, nameWidth);
              const name = deleting
                ? theme.fg('error', plainName)
                : disabled
                  ? theme.fg('muted', plainName)
                  : colorizeAgentText(agent.color, plainName, (agentColor, text) =>
                      theme.fg(agentColor as Parameters<Theme['fg']>[0], text),
                    );
              lines.push(
                `${cursor} ${theme.fg(primary ? 'success' : 'dim', pad(primary, primaryWidth))} ${name} ${theme.fg(
                  color,
                  pad(agent.mode, modeWidth),
                )} ${theme.fg(color, pad(agent.source, sourceWidth))} ${theme.fg(
                  color,
                  pad(agent.model ?? 'current model', modelWidth),
                )} ${theme.fg(
                  deleting ? 'error' : unavailable ? 'muted' : scopedDisabled ? 'warning' : color,
                  pad(state, stateWidth),
                )}`,
              );
            }
            if (agents.length === 0) lines.push(theme.fg('muted', '  No agents configured.'));

            const agent = agents[selectedAgent];
            if (agent) {
              lines.push(
                '',
                theme.fg(agent.disabled ? 'muted' : 'text', agent.description ?? 'No description'),
              );
              const details = [
                agent.variant ? `variant ${agent.variant}` : undefined,
                agent.steps ? `${agent.steps} steps` : undefined,
              ].filter(Boolean);
              if (details.length > 0) lines.push(theme.fg('dim', details.join(' · ')));
              const permissions = [...catalog.permissions, ...agent.permissions];
              lines.push(theme.fg('dim', 'Permissions'));
              if (permissions.length === 0) lines.push(`  ${theme.fg('muted', 'default: ask')}`);
              for (const rule of permissions.slice(0, 4)) {
                const color =
                  rule.action === 'deny'
                    ? 'error'
                    : rule.action === 'allow'
                      ? 'success'
                      : 'warning';
                lines.push(
                  `  ${theme.fg('text', `${rule.permission}:${rule.pattern}`)} ${theme.fg('dim', '→')} ${theme.fg(color, rule.action)}`,
                );
              }
              if (permissions.length > 4) {
                lines.push(`  ${theme.fg('muted', `… ${permissions.length - 4} more`)}`);
              }
              const unsupported = Object.keys(agent.providerOptions);
              if (agent.variant && !PI_THINKING_LEVELS.has(agent.variant)) {
                unsupported.push(`variant=${agent.variant}`);
              }
              if (unsupported.length > 0) {
                lines.push(
                  `${theme.fg('dim', 'Unsupported RPC options:')} ${theme.fg('text', unsupported.join(', '))}`,
                );
              }
            }
            if (catalog.diagnostics.length > 0) {
              lines.push(theme.fg('error', 'Catalog diagnostics'));
              for (const diagnostic of catalog.diagnostics.slice(0, 3)) {
                lines.push(`  ${theme.fg('error', diagnostic)}`);
              }
            }
            if (confirmingDeleteAgent) {
              lines.push(
                '',
                theme.fg(
                  'error',
                  `Delete @${confirmingDeleteAgent}? This removes its project file.`,
                ),
                dialogKeys(theme, [
                  ['Y', 'delete'],
                  ['N / Esc', 'cancel'],
                ]),
              );
            } else if (saving) {
              lines.push('', theme.fg('dim', 'Saving…'));
            }
            return box(lines);
          }

          if (tab === 'settings') {
            const maxSubagentsInherited =
              scope === 'project' && maxSubagentsSettings.project === undefined;
            const sandboxInherited = scope === 'project' && sandboxSettings.project === undefined;
            const rows = [
              {
                label: 'Maximum subagents',
                value: String(selectedMaxSubagents()),
                inherited: maxSubagentsInherited,
                unavailable: false,
              },
              {
                label: 'Sandbox enabled',
                value: selectedSandboxEnabled() ? 'on' : 'off',
                inherited: sandboxInherited,
                unavailable: sandboxCallbacks === undefined,
              },
            ];
            const lines = [tabs, ''];
            for (const [index, row] of rows.entries()) {
              const selected = index === selectedSetting;
              const cursor = selected ? theme.fg('accent', '›') : ' ';
              const text = `[ ${row.value} ]`;
              const value = row.inherited
                ? theme.fg('dim', text)
                : selected
                  ? theme.fg('accent', text)
                  : theme.fg(row.unavailable ? 'muted' : 'text', text);
              const label = theme.fg(row.unavailable ? 'muted' : 'text', row.label);
              const dirty = dirtySettings.has(index) ? theme.fg('warning', ' *') : '';
              lines.push(`${cursor} ${value} ${label}${dirty}`);
            }
            lines.push(
              '',
              theme.fg(
                'dim',
                selectedSetting === 0
                  ? rows[0]?.inherited
                    ? 'Sets concurrent subagents. Zero disables the task tool. Using the Global value.'
                    : 'Sets concurrent subagents. Zero disables the task tool.'
                  : rows[1]?.inherited
                    ? 'Controls OS sandboxing. Use /sandbox to inspect its policy. Using the Global value.'
                    : 'Controls OS sandboxing. Use /sandbox to inspect its policy.',
              ),
            );
            if (saving) lines.push('', theme.fg('dim', 'Saving…'));
            return box(lines);
          }

          if (tab === 'help') {
            const shortcutWidth = Math.max(
              visibleWidth('Shortcut'),
              ...AGENTS_HELP_ROWS.map(([shortcut]) => visibleWidth(shortcut)),
            );
            const descriptionWidth = Math.max(1, contentWidth - shortcutWidth - 4);
            const lines = [
              tabs,
              '',
              theme.fg('dim', `  ${pad('Shortcut', shortcutWidth)}  Description`),
              ...AGENTS_HELP_ROWS.map(
                ([shortcut, description]) =>
                  `  ${theme.fg('accent', pad(shortcut, shortcutWidth))}  ${theme.fg(
                    'text',
                    truncateToWidth(description, descriptionWidth),
                  )}`,
              ),
            ];
            return box(lines);
          }

          if (tab === 'tasks') {
            const listLines: string[] = [];
            if (tasks.length === 0) {
              listLines.push('No task sessions in this session.');
            } else {
              const start = Math.max(0, Math.min(selectedTask - 5, tasks.length - 11));
              const shown = tasks.slice(start, start + 11);
              for (const [offset, task] of shown.entries()) {
                const index = start + offset;
                const cursor = index === selectedTask ? theme.fg('accent', '›') : ' ';
                const indent = '  '.repeat(Math.max(0, task.depth - 1));
                listLines.push(
                  `${cursor} ${indent}${taskState(theme, task)} ${theme.fg('accent', `@${task.agent}`)} ${theme.fg('text', task.description)} ${theme.fg('dim', task.id.slice(0, 8))}`,
                );
              }
            }
            return box([tabs, '', ...listLines]);
          }

          const task = tasks[selectedTask];
          if (!task) return box([tabs, '', 'No task sessions in this session.']);
          const transcript = taskTranscript(task).flatMap((line) =>
            wrapTextWithAnsi(line, contentWidth),
          );
          const maxScroll = Math.max(0, transcript.length - INSPECTOR_BODY_LINES);
          scroll = follow ? maxScroll : Math.min(scroll, maxScroll);
          const shown = transcript.slice(scroll, scroll + INSPECTOR_BODY_LINES);
          const duration = taskDuration(taskDetails(task));
          const metrics = [
            task.id,
            task.toolCalls === undefined
              ? undefined
              : `${task.toolCalls} tool call${task.toolCalls === 1 ? '' : 's'}`,
            duration,
          ].filter(Boolean);
          const lines = [
            tabs,
            '',
            `${theme.fg('accent', theme.bold(`@${task.agent}`))} ${theme.fg('text', task.description)}`,
            `${taskState(theme, task)} ${theme.fg('dim', metrics.join(' · '))} ${theme.fg('dim', '·')} ${theme.fg(follow ? 'accent' : 'muted', `Follow: ${follow ? 'on' : 'off'}`)}`,
            '',
            ...shown.map((line) => theme.fg('toolOutput', line)),
          ];
          while (lines.length < INSPECTOR_BODY_LINES + 5) lines.push('');
          if (transcript.length > INSPECTOR_BODY_LINES) {
            lines.push(
              theme.fg('dim', `${scroll + 1}–${scroll + shown.length} of ${transcript.length}`),
            );
          }
          return box(lines.map((line) => truncateToWidth(line, contentWidth)));
        },
        handleInput: (data: string) => {
          if (confirmingDeleteAgent !== undefined) {
            if (matchesKey(data, 'escape') || data.toLowerCase() === 'n') {
              confirmingDeleteAgent = undefined;
              tui.requestRender();
              return;
            }
            if (data.toLowerCase() === 'y') {
              const name = confirmingDeleteAgent;
              const agent = agents.find((candidate) => candidate.name === name);
              confirmingDeleteAgent = undefined;
              if (!agent) {
                tui.requestRender();
                return;
              }
              saving = true;
              void deleteProjectAgent(ctx.cwd, agent)
                .then(async (deleted) => {
                  if (!deleted) return;
                  await refreshAgentRuntime(name);
                  ctx.ui.notify(`Deleted project agent ${name}`, 'info');
                })
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not delete agent: ${formatError(error)}`, 'error'),
                )
                .finally(() => {
                  saving = false;
                  tui.requestRender();
                });
              return;
            }
            return;
          }
          if (
            (matchesKey(data, 'shift+tab') || data.toLowerCase() === 's') &&
            (tab === 'agents' || tab === 'settings')
          ) {
            if (saving) return;
            if (dirtySettings.size > 0) {
              ctx.ui.notify('Save or discard settings changes before changing scope', 'warning');
              return;
            }
            if (!projectTrusted && scope === 'global') {
              ctx.ui.notify('Project settings require a trusted project', 'warning');
              return;
            }
            scope = scope === 'project' ? 'global' : 'project';
            editing = false;
            reloadAgents();
            reloadSettings();
            tui.requestRender();
            return;
          }
          if (matchesKey(data, 'tab')) {
            if (tab === 'settings' && dirtySettings.size > 0) {
              ctx.ui.notify(
                'Save changes with Enter or discard them with R before leaving',
                'warning',
              );
              return;
            }
            const tabs = ['agents', 'tasks', 'logs', 'settings', 'help'] as const;
            tab = tabs[(tabs.indexOf(tab) + 1) % tabs.length] ?? 'agents';
            if (tab === 'logs' && tasks.length > 0) follow = true;
            else follow = false;
            editing = false;
            scroll = 0;
            tui.requestRender();
            return;
          }

          if (tab === 'agents') {
            const agent = agents[selectedAgent];
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) {
              done();
              return;
            }
            if (matchesKey(data, 'up')) selectedAgent = Math.max(0, selectedAgent - 1);
            else if (matchesKey(data, 'down') && agents.length > 0) {
              selectedAgent = Math.min(agents.length - 1, selectedAgent + 1);
            } else if (data.toLowerCase() === 'x' && agent && !saving) {
              if (!projectTrusted || !canDeleteProjectAgent(ctx.cwd, agent)) {
                ctx.ui.notify('Only project agent files can be deleted here', 'warning');
                return;
              }
              confirmingDeleteAgent = agent.name;
              tui.requestRender();
              return;
            } else if (data.toLowerCase() === 'e' && agent && !saving) {
              if (!projectTrusted) {
                ctx.ui.notify('Agent editing requires a trusted project', 'warning');
                return;
              }
              saving = true;
              void (async () => {
                const document = prepareProjectAgentEditor(ctx.cwd, agent);
                const edited = await ctx.ui.editor(document.title, document.content);
                if (edited === undefined) return;
                await document.save(edited);
                await refreshAgentRuntime(agent.name);
                ctx.ui.notify(`Updated project agent ${agent.name}`, 'info');
              })()
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not edit agent: ${formatError(error)}`, 'error'),
                )
                .finally(() => {
                  saving = false;
                  tui.requestRender();
                });
              return;
            } else if (data === ' ' && agent && !saving) {
              const current = scopedAgent(agent);
              if (!current) {
                ctx.ui.notify('Local-only agents are unavailable in Global scope', 'warning');
                return;
              }
              const disabled = !current.disabled;
              saving = true;
              void setAgentDisabledForScope(ctx.cwd, agent.name, disabled, scope)
                .then(async () => {
                  await refreshAgentRuntime(agent.name);
                  ctx.ui.notify(
                    `${agent.name} ${disabled ? 'disabled' : 'enabled'} in ${scope} settings`,
                    'info',
                  );
                })
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not update agent: ${formatError(error)}`, 'error'),
                )
                .finally(() => {
                  saving = false;
                  tui.requestRender();
                });
              return;
            } else if (data.toLowerCase() === 'i' && scope === 'project' && agent && !saving) {
              if (!disabledOverrides.project.has(agent.name)) return;
              saving = true;
              void clearAgentDisabledForScope(ctx.cwd, agent.name, 'project')
                .then(async () => {
                  await refreshAgentRuntime(agent.name);
                  ctx.ui.notify(`${agent.name} now inherits its global state`, 'info');
                })
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not update agent: ${formatError(error)}`, 'error'),
                )
                .finally(() => {
                  saving = false;
                  tui.requestRender();
                });
              return;
            } else if (
              matchesKey(data, 'return') &&
              agent &&
              !agent.disabled &&
              agentSupportsMode(agent, 'primary')
            ) {
              void this.selectPrimaryAgent(agent.name, ctx)
                .then(() => tui.requestRender())
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not select primary agent: ${formatError(error)}`, 'error'),
                );
              return;
            } else if (matchesKey(data, 'return') && agent) {
              ctx.ui.notify(
                agent.disabled
                  ? 'Enable this agent before setting it as primary'
                  : 'This agent cannot be used as the primary agent',
                'warning',
              );
              return;
            } else return;
            tui.requestRender();
            return;
          }

          if (tab === 'settings') {
            if (saving) return;
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) {
              if (dirtySettings.size > 0) {
                ctx.ui.notify(
                  'Save changes with Enter or discard them with R before closing',
                  'warning',
                );
                return;
              }
              done();
              return;
            }
            if (data.toLowerCase() === 'r') {
              reloadSettings();
              dirtySettings.clear();
              editing = false;
              tui.requestRender();
              return;
            }
            if (matchesKey(data, 'up')) {
              selectedSetting = Math.max(0, selectedSetting - 1);
              editing = false;
            } else if (matchesKey(data, 'down')) {
              selectedSetting = Math.min(1, selectedSetting + 1);
              editing = false;
            } else if (selectedSetting === 0 && /^[0-9]$/.test(data)) {
              const value = Number(editing ? `${selectedMaxSubagents()}${data}` : data);
              if (value <= MAX_SUBAGENTS) {
                updateSelectedMaxSubagents(value);
                editing = true;
              }
            } else if (selectedSetting === 0 && (data === '+' || data === '-')) {
              updateSelectedMaxSubagents(
                Math.min(
                  MAX_SUBAGENTS,
                  Math.max(0, selectedMaxSubagents() + (data === '+' ? 1 : -1)),
                ),
              );
              editing = false;
            } else if (selectedSetting === 1 && data === ' ' && sandboxCallbacks) {
              updateSelectedSandboxEnabled(!selectedSandboxEnabled());
              editing = false;
            } else if (data === 'i' && scope === 'project') {
              if (selectedSetting === 0) {
                maxSubagentsSettings = { ...maxSubagentsSettings, project: undefined };
              } else {
                sandboxSettings = { ...sandboxSettings, project: undefined };
              }
              dirtySettings.add(selectedSetting);
              editing = false;
            } else if (matchesKey(data, 'return')) {
              const setting = selectedSetting;
              if (!dirtySettings.has(setting)) return;
              const pendingMaxSubagents = maxSubagentsSettings;
              const pendingSandbox = sandboxSettings;
              const inherited =
                scope === 'project' &&
                (setting === 0
                  ? pendingMaxSubagents.project === undefined
                  : pendingSandbox.project === undefined);
              const maxSubagents = selectedMaxSubagents();
              const sandboxEnabled = selectedSandboxEnabled();
              let save: Promise<void>;
              if (setting === 0) {
                save = inherited
                  ? clearMaxSubagentsConfigForScope(ctx.cwd, 'project')
                  : setMaxSubagentsConfigForScope(ctx.cwd, maxSubagents, scope);
              } else if (!sandboxCallbacks) {
                ctx.ui.notify('Sandbox settings are unavailable', 'warning');
                return;
              } else {
                save = inherited
                  ? sandboxCallbacks.clearProject(ctx)
                  : sandboxCallbacks.setEnabled(ctx, sandboxEnabled, scope);
              }
              saving = true;
              void save
                .then(() => {
                  dirtySettings.delete(setting);
                  const loadedMaxSubagents = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
                  const loadedSandbox = sandboxCallbacks?.load(ctx.cwd, projectTrusted) ?? {
                    global: true,
                  };
                  this.setMaxSubagents(loadedMaxSubagents.project ?? loadedMaxSubagents.global);
                  maxSubagentsSettings = dirtySettings.has(0)
                    ? pendingMaxSubagents
                    : loadedMaxSubagents;
                  sandboxSettings = dirtySettings.has(1) ? pendingSandbox : loadedSandbox;
                  editing = false;
                  ctx.ui.notify(
                    inherited
                      ? `${setting === 0 ? 'Maximum subagents' : 'Sandbox'} now uses the global value`
                      : `${setting === 0 ? 'Maximum subagents' : 'Sandbox'} updated in ${scope} settings`,
                    'info',
                  );
                })
                .catch((error: unknown) =>
                  ctx.ui.notify(`Could not save setting: ${formatError(error)}`, 'error'),
                )
                .finally(() => {
                  saving = false;
                  tui.requestRender();
                });
              return;
            } else return;
            tui.requestRender();
            return;
          }

          if (tab === 'help') {
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) done();
            return;
          }

          if (tab === 'tasks') {
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) done();
            else if (matchesKey(data, 'up')) selectedTask = Math.max(0, selectedTask - 1);
            else if (matchesKey(data, 'down') && tasks.length > 0) {
              selectedTask = Math.min(tasks.length - 1, selectedTask + 1);
            } else if (matchesKey(data, 'return') && tasks.length > 0) {
              tab = 'logs';
              follow = true;
              scroll = 0;
            } else return;
            tui.requestRender();
            return;
          }

          if (tab !== 'logs') return;

          const task = tasks[selectedTask];
          if (!task) {
            if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) done();
            return;
          }
          if (matchesKey(data, 'escape')) {
            tab = 'tasks';
            follow = false;
            scroll = 0;
          } else if (matchesKey(data, 'ctrl+c')) {
            done();
          } else if (data.toLowerCase() === 'f') {
            follow = !follow;
          } else if (!follow && matchesKey(data, 'up')) {
            scroll = Math.max(0, scroll - 1);
          } else if (!follow && matchesKey(data, 'down')) {
            scroll += 1;
          } else if (!follow && matchesKey(data, 'pageUp')) {
            scroll = Math.max(0, scroll - INSPECTOR_BODY_LINES);
          } else if (!follow && matchesKey(data, 'pageDown')) {
            scroll += INSPECTOR_BODY_LINES;
          } else if (!follow && matchesKey(data, 'home')) {
            scroll = 0;
          } else if (!follow && matchesKey(data, 'end')) {
            scroll = Number.MAX_SAFE_INTEGER;
          } else if (matchesKey(data, 'backspace')) {
            const parentIndex = task.parentTaskId
              ? tasks.findIndex((candidate) => candidate.id === task.parentTaskId)
              : -1;
            if (parentIndex >= 0) {
              selectedTask = parentIndex;
              follow = true;
            } else {
              tab = 'tasks';
              follow = false;
            }
            scroll = 0;
          } else return;
          tui.requestRender();
        },
        invalidate() {},
      }),
      { overlay: true, overlayOptions: { anchor: 'center', width: 96, margin: 2 } },
    );
  }

  async selectPrimaryAgent(name: string, ctx: ExtensionContext): Promise<boolean> {
    const catalog = this.getAgentCatalog(ctx);
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) return false;
    const agent = availableAgents(catalog).find(
      (candidate) => candidate.name === name && agentSupportsMode(candidate, 'primary'),
    );
    if (!agent) {
      ctx.ui.notify(`Unknown primary agent: ${name}`, 'error');
      return false;
    }
    return this.activatePrimaryAgent(agent, catalog, ctx, true);
  }

  private async cyclePrimaryAgent(ctx: ExtensionContext): Promise<void> {
    if (!ctx.isIdle()) {
      ctx.ui.notify('Cannot switch primary agents while an agent run is active', 'warning');
      return;
    }
    if (this.primaryAgentSwitching) {
      ctx.ui.notify('Primary agent selection is already in progress', 'warning');
      return;
    }

    const catalog = this.getAgentCatalog(ctx);
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) return;

    const agents = availableAgents(catalog).filter((agent) => agentSupportsMode(agent, 'primary'));
    if (agents.length === 0) {
      ctx.ui.notify('No primary agents are available', 'warning');
      return;
    }
    if (agents.length === 1 && agents[0]?.name === this.primaryAgent?.name) {
      ctx.ui.notify(`Only one primary agent is available: ${agents[0].name}`, 'info');
      return;
    }

    const currentIndex = agents.findIndex((agent) => agent.name === this.primaryAgent?.name);
    const nextAgent = agents[(currentIndex + 1) % agents.length]!;
    this.primaryAgentSwitching = true;
    try {
      await this.activatePrimaryAgent(nextAgent, catalog, ctx, true);
    } finally {
      this.primaryAgentSwitching = false;
    }
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
    const agents = [...catalog.agents.values()].filter(
      (agent) =>
        !agent.disabled &&
        agentSupportsMode(agent, 'subagent') &&
        permissionDecision(callerRules ?? catalog.permissions, 'task', agent.name) !== 'deny',
    );
    const descriptions = agents
      .map((agent) => `${agent.name}: ${agent.description ?? 'No description'}`)
      .join('\n');
    return {
      name: 'task',
      label: 'Task',
      description:
        'Delegate a task to a Pi subagent process.' +
        (descriptions ? `\n\nAvailable subagents:\n${descriptions}` : ''),
      parameters: taskParameters,
      executionMode: 'parallel',
      renderCall: (input, theme) => {
        const background = input.background ? theme.fg('muted', ' (background)') : '';
        const description = input.description?.trim() || '...';
        const agent = input.subagent_type?.trim() || '...';
        const title = theme.fg('toolTitle', theme.bold('Agent'));
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
        text += `\n${theme.fg('dim', `↳ /agents ${details.taskId.slice(0, 8)} to inspect`)}`;
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
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) {
      throw new Error(`Invalid agent configuration:\n${catalog.diagnostics.join('\n')}`);
    }
    if (catalog.maxSubagents === 0) throw new Error('Subagents are disabled by maxSubagents: 0');
    const agent = catalog.agents.get(input.subagent_type);
    if (!agent || agent.disabled || agent.mode === 'primary')
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
    let started = false;
    try {
      const release = await this.semaphore.acquire(signal);
      this.leases.set(task.id, { release });
      task.state = 'running';
      task.startedAt = Date.now();
      task.finishedAt = undefined;
      task.error = undefined;
      started = true;
      this.integration.emit?.({ type: 'subagent.start', context: this.taskContext(task, ctx) });
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
      const message = formatError(error);
      task.error = this.storeTaskText(task, message, 'error');
      task.currentTool = undefined;
      task.retryAttempt = undefined;
      task.finishedAt = Date.now();
      this.persist(task);
      this.updateTaskWidget(ctx);
      if (task.error === message) throw error;
      throw new Error(task.error);
    } finally {
      if (started && ['completed', 'cancelled', 'error'].includes(task.state)) {
        this.integration.emit?.({
          type: 'subagent.end',
          context: this.taskContext(task, ctx),
          status: task.state as 'completed' | 'cancelled' | 'error',
        });
      }
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
    const thinking =
      agent.variant && PI_THINKING_LEVELS.has(agent.variant)
        ? agent.variant
        : this.pi.getThinkingLevel();
    if (agent.variant && !PI_THINKING_LEVELS.has(agent.variant)) {
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
    const activeTools = taskEnabled
      ? [...new Set([...this.pi.getActiveTools(), 'task'])]
      : this.pi.getActiveTools().filter((tool) => tool !== 'task');
    const tools = permittedToolNames(activeTools, rules);
    const workerExtensions = this.integration.getWorkerExtensions?.() ?? [];
    const args = [
      ...invocation.args,
      '--mode',
      'rpc',
      '--extension',
      join(packageDir, 'index.ts'),
      ...workerExtensions.flatMap((extension) => ['--extension', extension.entry]),
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
    const publicContext = this.taskContext(task, ctx);
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
          [LANDSTRIP_CONTEXT_ENV]: encodeLandstripContext(publicContext),
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
              ...workerExtensions.flatMap((extension) => [
                extension.entry,
                dirname(extension.entry),
                dependencyRoot(extension.entry),
              ]),
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

  private taskContext(task: TaskRecord, ctx: ExtensionContext): LandstripContextV1 {
    const context = this.integration.getContext?.(ctx) ?? {
      version: 1,
      host: 'pi',
      role: 'primary',
      sandbox: 'unavailable',
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      depth: 0,
    };
    return {
      ...context,
      role: 'subagent',
      sessionId: undefined,
      taskId: task.id,
      parentTaskId: task.parentTaskId,
      agent: task.agent,
      depth: task.depth,
    };
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
        `Process-backed subagents require Pi >=0.82.0; found ${pkg.version.join('.')}`,
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
        response = { ok: false, error: formatError(error) };
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
      const message = formatError(error);
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
    const active = tasks.filter((task) => task.state === 'queued' || task.state === 'running');
    if (active.length === 0) {
      ctx.ui.setWidget(TASK_WIDGET, undefined);
      return;
    }

    const visible = activeTaskRecords(tasks);
    const byId = new Map(tasks.map((task) => [task.id, task]));
    const running = active.filter((task) => task.state === 'running').length;
    const queued = active.length - running;
    const runningSummary =
      this.maxSubagents > 0 ? `${running}/${this.maxSubagents} running` : `${running} running`;
    const summary = queued > 0 ? `${runningSummary} · ${queued} queued` : runningSummary;

    ctx.ui.setWidget(TASK_WIDGET, (_tui, theme) => ({
      render: (width: number) => {
        const header =
          theme.fg('accent', theme.bold('Subagents')) + theme.fg('dim', `  ${summary}`);
        const tree = taskTreeLines(visible, (task) => {
          const agent = theme.fg('accent', `@${task.agent}`);
          const description = theme.fg('text', task.description);
          const progress = taskProgress(byId.get(task.id)!);
          const suffix = progress.length > 0 ? theme.fg('dim', `  ·  ${progress.join(' · ')}`) : '';
          return `${taskState(theme, task)}  ${agent}  ${description}${suffix}`;
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

  private async restorePrimaryAgent(ctx: ExtensionContext): Promise<void> {
    this.primaryAgent = undefined;
    this.primaryRules = undefined;
    this.primaryConfigurationError = false;
    const catalog = this.loadCatalog(ctx.cwd, getAgentDir(), isProjectTrusted(ctx));
    this.maxSubagents = catalog.maxSubagents;
    this.semaphore = new Semaphore(Math.max(1, this.maxSubagents));
    if (catalog.diagnostics.length > 0) {
      this.invalidatePrimaryAgent(catalog, ctx);
      return;
    }
    let name = 'build';
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type !== 'custom' || entry.customType !== PRIMARY_AGENT_ENTRY) continue;
      const value = entry.data as { name?: unknown } | undefined;
      if (typeof value?.name === 'string') name = value.name;
    }
    const agents = availableAgents(catalog).filter((agent) => agentSupportsMode(agent, 'primary'));
    const agent = agents.find((candidate) => candidate.name === name) ?? agents[0];
    if (agent && !(await this.activatePrimaryAgent(agent, catalog, ctx, false))) {
      this.invalidatePrimaryAgent(catalog, ctx);
    }
  }

  private invalidatePrimaryAgent(catalog: AgentCatalog, ctx: ExtensionContext): void {
    this.primaryAgent = undefined;
    this.primaryRules = [{ permission: '*', pattern: '*', action: 'deny' }];
    this.primaryConfigurationError = true;
    this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'error');
    if (ctx.hasUI) ctx.ui.setStatus('landstrip-agent', '@invalid');
  }

  private async applyPrimaryAgentRuntime(
    agent: AgentDefinition,
    ctx: ExtensionContext,
  ): Promise<boolean> {
    if (agent.variant && !PI_THINKING_LEVELS.has(agent.variant)) {
      ctx.ui.notify(
        `Agent ${agent.name} uses unsupported Pi model variant: ${agent.variant}`,
        'error',
      );
      return false;
    }

    if (agent.model) {
      const models = ctx.modelRegistry.getAll();
      const qualified = models.filter((model) => `${model.provider}/${model.id}` === agent.model);
      const matches =
        qualified.length > 0 ? qualified : models.filter((model) => model.id === agent.model);
      if (matches.length === 0) {
        ctx.ui.notify(`Model not found for primary agent ${agent.name}: ${agent.model}`, 'error');
        return false;
      }
      if (matches.length > 1) {
        ctx.ui.notify(`Ambiguous model for primary agent ${agent.name}: ${agent.model}`, 'error');
        return false;
      }
      const model = matches[0]!;
      if (ctx.model?.provider !== model.provider || ctx.model.id !== model.id) {
        try {
          if (!(await this.pi.setModel(model))) {
            ctx.ui.notify(
              `No authentication configured for primary agent ${agent.name} model: ${agent.model}`,
              'error',
            );
            return false;
          }
        } catch (error) {
          ctx.ui.notify(
            `Could not select model for primary agent ${agent.name}: ${formatError(error)}`,
            'error',
          );
          return false;
        }
      }
    }

    if (agent.variant) this.pi.setThinkingLevel(agent.variant as PiThinkingLevel);
    return true;
  }

  private async activatePrimaryAgent(
    agent: AgentDefinition,
    catalog: AgentCatalog,
    ctx: ExtensionContext,
    persist: boolean,
  ): Promise<boolean> {
    if (!(await this.applyPrimaryAgentRuntime(agent, ctx))) return false;
    this.primaryAgent = agent;
    this.primaryRules = mergePermissionRules(catalog.permissions, agent.permissions);
    this.primaryConfigurationError = false;
    this.broker.reset();
    this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
    if (persist) this.pi.appendEntry(PRIMARY_AGENT_ENTRY, { name: agent.name });
    if (ctx.hasUI) {
      ctx.ui.setStatus('landstrip-agent', colorizeAgentText(agent.color, `@${agent.name}`));
      if (persist) ctx.ui.notify(`Primary agent: ${agent.name}`, 'info');
    }
    return true;
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
