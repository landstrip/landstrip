// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
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
  fuzzyFilter,
  matchesKey,
  Input,
  type TUI,
  type SelectItem,
  SelectList,
  type SettingItem,
  SettingsList,
  Text,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
} from '@earendil-works/pi-tui';
import { Type } from 'typebox';

import {
  encodeLandstripContext,
  type LandstripContextV2,
  LANDSTRIP_CONTEXT_ENV,
  type LandstripPermissionAskDecision,
  type LandstripPermissionAskRequest,
} from './api.ts';
import {
  type AgentCatalog,
  type AgentDefinition,
  agentSupportsMode,
  availableAgents,
  isPrimaryAgent,
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
import { dialogKeys, dialogTabs, paneRow, paneTop } from './box.ts';
import {
  type CommandSubagentRuntime,
  matchingTasksById,
  registerLandstripCommands,
} from './commands.ts';
import {
  clearAgentDisabledForScope,
  clearMaxSubagentsConfigForScope,
  clearToolFilesystemPolicyConfigForScope,
  isProjectTrusted,
  loadAgentDisabledOverrides,
  loadMaxSubagentsSettings,
  loadToolFilesystemPolicySettings,
  MAX_SUBAGENTS,
  setAgentDisabledForScope,
  setMaxSubagentsConfigForScope,
  setToolFilesystemPolicyConfigForScope,
  type ToolFilesystemPolicy,
} from './config.ts';
import type { LandstripIntegration, LandstripRpcWorkerLaunch } from './index.ts';
import { type ExtensionUiRequest, type ExtensionUiResult, RpcProcess } from './rpc-process.ts';
import {
  colorizeAgentText,
  combineAbortSignals,
  formatError,
  isRecord,
  PermissionPromptCoordinator,
} from './util.ts';

const TASK_ENTRY = 'landstrip.task';
const TASK_WIDGET = 'landstrip.subagents';
const PRIMARY_AGENT_ENTRY = 'landstrip.primary-agent';
const WORKER_ENV = 'PI_LANDSTRIP_WORKER';
const CONTROL_TITLE = 'pi-landstrip:control:v1';
const MAX_DEPTH = 3;
const packageDir = dirname(fileURLToPath(import.meta.url));
const MAX_TASK_OUTPUT_BYTES = 64 * 1024;
const INSPECTOR_BODY_LINES = 16;
/** Fewest list rows each tab shows; taller terminals get more via listRowBudget. */
const AGENT_LIST_ROWS = 7;
const TASK_LIST_ROWS = 11;
/** Must match the overlayOptions maxHeight the landstrip dialog is opened with. */
const OVERLAY_HEIGHT_RATIO = 0.7;
/** Measured rows the agents tab draws around its list: title, tabs, table header,
 * selection details with a typical permission block, and the key hints. */
const AGENT_TAB_CHROME_ROWS = 15;
/** Measured rows the tasks tab draws around its list. */
const TASK_TAB_CHROME_ROWS = 8;
/** Grow a list to fill the overlay on tall terminals, never below its floor. */
function listRowBudget(terminalRows: number | undefined, floor: number, chrome: number): number {
  if (!terminalRows) return floor;
  return Math.max(floor, Math.floor(terminalRows * OVERLAY_HEIGHT_RATIO) - chrome);
}
const PI_THINKING_LEVELS = new Set(['off', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']);
const AGENTS_HELP_ROWS = [
  ['Tab', 'Next tab'],
  ['↑ / ↓', 'Select item or scroll when follow is off'],
  ['Enter', 'Activate: set primary, open log, steer, confirm'],
  ['Esc', 'Back one level, or close from a top-level tab'],
  ['Ctrl+C', 'Close'],
  ['Space', 'Toggle agent enabled or select task'],
  ['X', 'Delete selected agent or task sessions'],
  ['E', 'Edit project agent'],
  ['I', 'Inherit global agent state'],
  ['/', 'Filter agents by name'],
  ['F', 'Toggle task log follow'],
  ['Page Up / Down', 'Scroll task output by page'],
  ['Home / End', 'Jump to task output boundary'],
  ['Backspace', 'Open parent task'],
] as const;

/** Sentinel settings value that clears the project override so Global applies. */
const INHERIT = 'inherit';

interface TaskListAction {
  readonly type: 'delete';
  readonly taskIds: string[];
}
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
// `package.json` instead of spawning `pi --version` avoids reporting the Node
// version when Pi runs as an embedded or extension host.
function findPiPackage(entry: string): PiPackage | undefined {
  let dir = dirname(realpathSync(entry));
  for (;;) {
    const pkgPath = join(dir, 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = readPiPackage(pkgPath);
      if (pkg) return pkg;
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export function resolvePiPackage(): PiPackage | undefined {
  if (piPackageResolved) return cachedPiPackage;
  piPackageResolved = true;

  const argvEntry = process.argv[1];
  if (argvEntry) {
    try {
      const pkg = findPiPackage(argvEntry);
      if (pkg) return pkg;
    } catch {
      // Fall through when the process entry is not a filesystem path.
    }
  }

  try {
    const pkg = findPiPackage(
      fileURLToPath(import.meta.resolve('@earendil-works/pi-coding-agent')),
    );
    if (pkg) return pkg;
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

/**
 * Scroll window that keeps `selected` visible and reports what is hidden, so a
 * truncated list never looks complete.
 */
function listWindow<T>(
  items: readonly T[],
  selected: number,
  rows: number,
): { shown: readonly T[]; start: number; status: string | undefined } {
  const start = Math.max(0, Math.min(selected - Math.floor(rows / 2), items.length - rows));
  const shown = items.slice(start, start + rows);
  return {
    shown,
    start,
    status:
      items.length > rows ? `${start + 1}–${start + shown.length} of ${items.length}` : undefined,
  };
}

/** Per-frame drawing context handed to each tab renderer. */
interface TabFrame {
  contentWidth: number;
  tabs: string;
  pane: (lines: string[]) => string[];
  pad: (value: string, cellWidth: number) => string;
  listValue: (values: readonly string[]) => string;
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

interface TaskUsage {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cost: number;
  turns: number;
}

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
  deleted?: boolean;
  background?: boolean;
  currentTool?: string;
  toolCalls?: number;
  retryAttempt?: number;
  usage?: TaskUsage;
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
  usage?: TaskUsage;
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
    usage: task.usage ? { ...task.usage } : undefined,
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

function usageNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isTaskUsage(value: unknown): value is TaskUsage {
  return (
    isRecord(value) &&
    usageNumber(value.input) &&
    usageNumber(value.output) &&
    usageNumber(value.cacheRead) &&
    usageNumber(value.cacheWrite) &&
    usageNumber(value.cost) &&
    usageNumber(value.turns) &&
    Number.isInteger(value.turns)
  );
}

function taskUsageFromMessage(message: unknown): TaskUsage | undefined {
  if (!isRecord(message) || message.role !== 'assistant' || !isRecord(message.usage))
    return undefined;
  const usage = message.usage;
  if (
    !usageNumber(usage.input) ||
    !usageNumber(usage.output) ||
    !usageNumber(usage.cacheRead) ||
    !usageNumber(usage.cacheWrite) ||
    !isRecord(usage.cost) ||
    !usageNumber(usage.cost.total)
  ) {
    return undefined;
  }
  return {
    input: usage.input,
    output: usage.output,
    cacheRead: usage.cacheRead,
    cacheWrite: usage.cacheWrite,
    cost: usage.cost.total,
    turns: 1,
  };
}

function addTaskUsage(current: TaskUsage | undefined, added: TaskUsage): TaskUsage {
  return {
    input: (current?.input ?? 0) + added.input,
    output: (current?.output ?? 0) + added.output,
    cacheRead: (current?.cacheRead ?? 0) + added.cacheRead,
    cacheWrite: (current?.cacheWrite ?? 0) + added.cacheWrite,
    cost: (current?.cost ?? 0) + added.cost,
    turns: (current?.turns ?? 0) + added.turns,
  };
}

function formatTokens(count: number): string {
  if (count < 1_000) return String(count);
  if (count < 10_000) return `${(count / 1_000).toFixed(1)}k`;
  if (count < 1_000_000) return `${Math.round(count / 1_000)}k`;
  if (count < 10_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  return `${Math.round(count / 1_000_000)}M`;
}

function formatTaskUsage(usage: TaskUsage | undefined): string | undefined {
  if (!usage) return undefined;
  const parts: string[] = [];
  if (usage.turns) parts.push(`${usage.turns} turn${usage.turns === 1 ? '' : 's'}`);
  if (usage.input) parts.push(`in:${formatTokens(usage.input)}`);
  if (usage.output) parts.push(`out:${formatTokens(usage.output)}`);
  if (usage.cacheRead) parts.push(`R${formatTokens(usage.cacheRead)}`);
  if (usage.cacheWrite) parts.push(`W${formatTokens(usage.cacheWrite)}`);
  if (usage.cost) parts.push(`$${usage.cost.toFixed(4)}`);
  return parts.length > 0 ? parts.join(' ') : undefined;
}

function formatTaskUsageSummary(usage: TaskUsage | undefined): string | undefined {
  if (!usage) return undefined;
  const parts: string[] = [];
  const tokens = usage.input + usage.output;
  if (tokens) parts.push(`${formatTokens(tokens)} tok`);
  if (usage.cost) parts.push(`$${usage.cost.toFixed(4)}`);
  return parts.length > 0 ? parts.join(' ') : undefined;
}

function findFilesRecursively(dir: string): string[] {
  const results: string[] = [];
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findFilesRecursively(fullPath));
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
  } catch {
    // Ignore read errors
  }
  return results;
}

function extractCwdFromSessionFile(filePath: string): string | undefined {
  try {
    const content = readFileSync(filePath, 'utf8');
    const firstNewline = content.indexOf('\n');
    const firstLine = firstNewline >= 0 ? content.slice(0, firstNewline) : content;
    if (!firstLine.trim()) return undefined;
    const header = JSON.parse(firstLine) as { cwd?: unknown };
    if (typeof header.cwd === 'string') {
      return header.cwd;
    }
  } catch {
    // Ignore parse errors
  }
  return undefined;
}

function extractCwdFromTaskJsonFile(filePath: string): {
  cwd?: string;
  parentSessionFile?: string;
} {
  try {
    const content = readFileSync(filePath, 'utf8');
    const data = JSON.parse(content) as { cwd?: unknown; parentSessionFile?: unknown };
    return {
      cwd: typeof data.cwd === 'string' ? data.cwd : undefined,
      parentSessionFile:
        typeof data.parentSessionFile === 'string' ? data.parentSessionFile : undefined,
    };
  } catch {
    return {};
  }
}

function defaultSessionDirForCwd(cwd: string, agentDir = getAgentDir()): string {
  const resolvedCwd = resolve(cwd);
  const safePath = `--${resolvedCwd.replace(/^[/\\]/, '').replace(/[/\\:]/g, '-')}--`;
  return join(agentDir, 'sessions', safePath);
}

function isSubagentSessionDirForCwd(parentSessionDir: string, targetCwd: string): boolean {
  const files = findFilesRecursively(parentSessionDir);
  if (files.length === 0) {
    return true;
  }

  const resolvedTarget = resolve(targetCwd);
  const targetSessionDir = resolve(defaultSessionDirForCwd(targetCwd));
  let hasTargetCwd = false;
  let hasOtherCwd = false;

  for (const file of files) {
    if (file.endsWith('.jsonl')) {
      const cwd = extractCwdFromSessionFile(file);
      if (cwd) {
        if (resolve(cwd) === resolvedTarget) {
          hasTargetCwd = true;
        } else {
          hasOtherCwd = true;
        }
      }
    } else if (file.endsWith('.json')) {
      const { cwd, parentSessionFile } = extractCwdFromTaskJsonFile(file);
      if (cwd) {
        if (resolve(cwd) === resolvedTarget) {
          hasTargetCwd = true;
        } else {
          hasOtherCwd = true;
        }
      } else if (parentSessionFile) {
        const resolvedParent = resolve(parentSessionFile);
        if (
          resolvedParent === targetSessionDir ||
          resolvedParent.startsWith(`${targetSessionDir}${sep}`)
        ) {
          hasTargetCwd = true;
        } else {
          hasOtherCwd = true;
        }
      }
    }
  }

  if (hasOtherCwd) return false;
  if (hasTargetCwd) return true;
  return true;
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
  const usage = formatTaskUsageSummary(task.usage);
  if (usage) progress.push(usage);
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
  readonly toolName?: string;
  readonly toolInput?: Record<string, unknown>;
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

function dependencyRoot(path: string): string | undefined {
  const marker = `${sep}node_modules${sep}`;
  const index = path.lastIndexOf(marker);
  return index < 0 ? undefined : path.slice(0, index + marker.length - 1);
}

function agentBootstrapPaths(agentDir: string): string[] {
  return [
    'settings.json',
    'landstrip.json',
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
    return this.releaseOnce();
  }

  restoreTransferred(): () => void {
    this.active += 1;
    return this.releaseOnce();
  }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new Error('Task cancelled');
    if (this.active < this.limit) {
      this.active += 1;
      return this.releaseOnce();
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
    return this.releaseOnce();
  }

  private releaseOnce(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
      if (this.active < this.limit) this.waiters.shift()?.();
    };
  }
}

type PermissionAskDetails = Omit<LandstripPermissionAskRequest, 'permissions' | 'signal'>;

type PermissionAskResolver = (
  request: LandstripPermissionAskRequest,
) => Promise<LandstripPermissionAskDecision>;

class PermissionBroker {
  private readonly grants = new Set<string>();
  private resetController = new AbortController();

  constructor(
    private readonly prompts: PermissionPromptCoordinator,
    private readonly resolveAsk: PermissionAskResolver = async () => ({ decision: 'abstain' }),
  ) {}

  async ask(
    ctx: ExtensionContext,
    task: string,
    permission: string,
    resource: string,
    signal?: AbortSignal,
    details?: PermissionAskDetails,
  ): Promise<void> {
    await this.askMany(ctx, task, [{ permission, resource }], signal, details);
  }

  async askMany(
    ctx: ExtensionContext,
    task: string,
    requests: readonly { permission: string; resource: string }[],
    signal?: AbortSignal,
    details?: PermissionAskDetails,
  ): Promise<void> {
    const unique = [
      ...new Map(
        requests.map((request) => [`${request.permission}\u0000${request.resource}`, request]),
      ).values(),
    ];
    const pending = (): typeof unique =>
      unique.filter(
        ({ permission, resource }) => !this.grants.has(`${permission}\u0000${resource}`),
      );
    if (pending().length === 0) return;

    const combined = combineAbortSignals(signal, this.resetController.signal);
    try {
      if (details) {
        let decision: LandstripPermissionAskDecision = { decision: 'abstain' };
        try {
          decision = await this.resolveWithSignal(
            { ...details, permissions: pending(), signal: combined.signal },
            combined.signal,
          );
        } catch (error) {
          if (combined.signal.aborted) throw new Error('Permission request cancelled');
          console.error(`pi-landstrip: permission ask provider failed: ${formatError(error)}`);
        }
        if (combined.signal.aborted) throw new Error('Permission request cancelled');
        if (pending().length === 0) return;
        if (decision.decision === 'allow') return;
        if (decision.decision === 'deny') {
          const request = pending()[0]!;
          throw new Error(
            decision.reason ?? `Permission denied: ${request.permission} ${request.resource}`,
          );
        }
      }

      if (!ctx.hasUI) {
        const request = pending()[0]!;
        throw new Error(`Permission required: ${request.permission} ${request.resource}`);
      }
      await this.prompts.resolve(
        () => (pending().length === 0 ? true : undefined),
        async (promptSignal) => {
          const requested = pending();
          const choice = await ctx.ui.select(
            `${task}: permission required\n${requested
              .map(({ permission, resource }) => `${permission}: ${resource}`)
              .join('\n')}`,
            ['Allow once', 'Allow for this session', 'Keep blocked'],
            { signal: promptSignal },
          );
          if (promptSignal.aborted) throw new Error('Permission request cancelled');
          if (choice === 'Allow for this session') {
            for (const { permission, resource } of requested) {
              this.grants.add(`${permission}\u0000${resource}`);
            }
          }
          if (choice !== 'Allow once' && choice !== 'Allow for this session') {
            const request = requested[0]!;
            throw new Error(`Permission denied: ${request.permission} ${request.resource}`);
          }
          return true;
        },
        combined.signal,
      );
    } finally {
      combined.dispose();
    }
  }

  reset(): void {
    const controller = this.resetController;
    this.resetController = new AbortController();
    this.grants.clear();
    controller.abort();
  }

  private async resolveWithSignal(
    request: LandstripPermissionAskRequest,
    signal: AbortSignal,
  ): Promise<LandstripPermissionAskDecision> {
    if (signal.aborted) throw new Error('Permission request cancelled');
    let abort: (() => void) | undefined;
    try {
      return await Promise.race([
        this.resolveAsk(request),
        new Promise<never>((_resolve, reject) => {
          abort = () => reject(new Error('Permission request cancelled'));
          signal.addEventListener('abort', abort, { once: true });
        }),
      ]);
    } finally {
      if (abort) signal.removeEventListener('abort', abort);
    }
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

function filesystemToolAccesses(
  tool: string,
  input: Record<string, unknown>,
  cwd: string,
): { accesses: Array<{ operation: 'read' | 'write'; path: string }>; valid: boolean } | undefined {
  if (!['read', 'write', 'edit', 'apply_patch'].includes(tool)) return undefined;
  const paths = permissionResources(tool, input, cwd);
  return {
    accesses: paths
      .filter((path) => path !== '*')
      .map((path) => ({
        operation: tool === 'read' ? 'read' : 'write',
        path,
      })),
    valid: paths.length > 0 && paths.every((path) => path !== '*'),
  };
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
  if (response.task !== undefined) {
    if (
      !isRecord(response.task) ||
      typeof response.task.taskId !== 'string' ||
      typeof response.task.state !== 'string' ||
      !TASK_STATES.has(response.task.state as TaskState) ||
      typeof response.task.agent !== 'string' ||
      (response.task.usage !== undefined && !isTaskUsage(response.task.usage))
    ) {
      throw new Error('Invalid supervisor task response');
    }
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
        JSON.stringify({
          type: 'permission',
          permission,
          resource,
          toolName: event.toolName,
          toolInput: input,
        } satisfies ControlRequest),
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

export class SubagentRuntime implements CommandSubagentRuntime {
  private semaphore = new Semaphore(1);
  private readonly broker: PermissionBroker;
  private readonly tasks = new Map<string, TaskRecord>();
  private readonly running = new Map<string, RunningTask>();
  private readonly runPromises = new Map<string, Promise<string>>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly leases = new Map<string, TaskLease>();
  private readonly foregroundClaims = new Map<string, number>();
  private readonly pendingPrompts = new Map<string, string[]>();
  private workerUiQueue: Promise<void> = Promise.resolve();
  private readonly pendingSteers = new Map<string, string[]>();
  private primaryAgent: AgentDefinition | undefined;
  private primaryRules: PermissionRules | undefined;
  private primaryConfigurationError = false;
  private maxSubagents = 0;
  private toolFilesystemPolicy: ToolFilesystemPolicy = 'host';
  private primaryAgentSwitching = false;
  private shuttingDown = false;
  private activeSessionId: string | undefined;

  constructor(
    private readonly pi: ExtensionAPI,
    private readonly integration: LandstripIntegration,
    private readonly createWorker: WorkerFactory = (...args) => this.defaultWorker(...args),
    private readonly loadCatalog: CatalogLoader = loadAgentCatalog,
    permissionPrompts = new PermissionPromptCoordinator(),
  ) {
    this.broker = new PermissionBroker(permissionPrompts, (request) => {
      const resolveAsk = this.integration.resolvePermissionAsk;
      return typeof resolveAsk === 'function'
        ? resolveAsk.call(this.integration, request)
        : Promise.resolve({ decision: 'abstain' });
    });
  }

  getTasks(): TaskRecord[] {
    return [...this.tasks.values()];
  }

  primaryAgentName(): string | undefined {
    return this.primaryAgent?.name;
  }

  register(): void {
    this.pi.registerTool(this.createTaskTool());
    registerLandstripCommands(this.pi, this, this.integration);
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
      await this.cleanupOrphanSubagentSessions(ctx);
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
      if (event.toolName === 'task') return;

      const input = isRecord(event.input) ? event.input : {};
      const permission = permissionName(event.toolName);
      const resources = permissionResources(event.toolName, input, ctx.cwd);
      const requests: Array<{ permission: string; resource: string }> = [];
      if (this.primaryAgent && this.primaryRules) {
        for (const resource of resources) {
          const decision = permissionDecision(this.primaryRules, permission, resource);
          if (decision === 'deny') {
            return {
              block: true,
              reason: `Permission denied by @${this.primaryAgent.name}: ${permission} ${resource}`,
            };
          }
          if (decision === 'ask') requests.push({ permission, resource });
        }
      }

      const filesystem = filesystemToolAccesses(event.toolName, input, ctx.cwd);
      if (this.toolFilesystemPolicy === 'sandbox' && filesystem) {
        if (!filesystem.valid) {
          return { block: true, reason: `Filesystem path unavailable for ${event.toolName}` };
        }
        try {
          const authorization = await this.integration.authorizeFilesystemToolAccess(
            ctx,
            filesystem.accesses,
            {
              signal: ctx.signal,
              authorizationNote:
                requests.length > 0 && this.primaryAgent
                  ? `Approval also authorizes @${this.primaryAgent.name} tool dispatch for this call.`
                  : undefined,
            },
          );
          if (!authorization.allowed) {
            return { block: true, reason: authorization.reason ?? 'Filesystem access denied' };
          }
          if (authorization.prompted) return;
        } catch (error) {
          return { block: true, reason: `Filesystem policy error: ${formatError(error)}` };
        }
      }

      if (requests.length > 0 && this.primaryAgent) {
        try {
          await this.broker.askMany(ctx, `@${this.primaryAgent.name}`, requests, ctx.signal, {
            context: this.permissionContext(ctx),
            toolName: event.toolName,
            input,
          });
        } catch (error) {
          return { block: true, reason: formatError(error) };
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
    this.semaphore.setLimit(maxSubagents);
    const activeTools = this.pi.getActiveTools();
    const withoutTask = activeTools.filter((tool) => tool !== 'task');
    const nextTools = maxSubagents > 0 ? [...withoutTask, 'task'] : withoutTask;
    if (nextTools.join('\0') !== activeTools.join('\0')) this.pi.setActiveTools(nextTools);
  }

  async openLandstrip(args: string, ctx: ExtensionContext): Promise<void> {
    if (ctx.mode !== 'tui') {
      ctx.ui.notify('Agent management is available in TUI mode', 'warning');
      return;
    }

    const projectTrusted = isProjectTrusted(ctx);
    let tasks = [...this.tasks.values()];
    const requested = args.trim();
    let catalog = this.getAgentCatalog(ctx);
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    let agents = [...catalog.agents.values()]
      .filter((agent) => !agent.hidden)
      .sort((left, right) => left.name.localeCompare(right.name));
    let disabledOverrides = loadAgentDisabledOverrides(ctx.cwd, projectTrusted);
    // canDeleteProjectAgent reads the project config, so the answer is cached per
    // agent reload rather than recomputed for every frame the hint row is drawn.
    const deletableAgents = new Set<string>();
    const refreshDeletableAgents = (): void => {
      deletableAgents.clear();
      if (!projectTrusted) return;
      for (const agent of agents) {
        if (canDeleteProjectAgent(ctx.cwd, agent)) deletableAgents.add(agent.name);
      }
    };
    refreshDeletableAgents();
    let overview = this.integration.sandboxCallbacks?.overview?.(ctx.cwd, projectTrusted);
    let maxSubagentsSettings = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
    let policySettings = loadToolFilesystemPolicySettings(ctx.cwd, projectTrusted);
    let settingsList: SettingsList | undefined;
    let saving = false;
    let confirmingSandboxDisable = false;

    type LandstripTab = 'overview' | 'settings' | 'primary' | 'subagent' | 'tasks' | 'log' | 'help';
    const TAB_ORDER: readonly LandstripTab[] = [
      'overview',
      'primary',
      'subagent',
      'tasks',
      'log',
      'settings',
      'help',
    ];
    const TAB_LABELS: Record<LandstripTab, string> = {
      overview: 'Overview',
      settings: 'Settings',
      primary: 'Primary',
      subagent: 'Subagent',
      tasks: 'Tasks',
      log: 'Log',
      help: 'Help',
    };

    let tab: LandstripTab = 'overview';
    let selectedTask = 0;
    let follow = false;

    if (requested === 'agents' || requested === 'primary') {
      tab = 'primary';
    } else if (requested === 'settings') {
      tab = 'settings';
    } else if (requested === 'overview' || requested === 'sandbox') {
      tab = 'overview';
    } else if (requested === 'subagent' || requested === 'subagents') {
      tab = 'subagent';
    } else if (requested === 'tasks') {
      tab = 'tasks';
    } else if (requested === 'help') {
      tab = 'help';
    } else if (requested === 'log') {
      tab = 'log';
      follow = true;
    } else if (requested) {
      const matched = matchingTasksById(tasks, requested);
      if (matched.length === 0) {
        ctx.ui.notify(`Unknown task session: ${requested}`, 'error');
        return;
      }
      if (matched.length > 1) {
        ctx.ui.notify(`Task ID prefix ${requested} matches ${matched.length} tasks`, 'error');
        return;
      }
      selectedTask = tasks.findIndex((task) => task.id === matched[0]!.id);
      tab = 'log';
      follow = true;
    }

    let agentFilter = '';
    let filteringAgents = false;
    const agentsForTab = (): AgentDefinition[] => {
      const listed = agents.filter((agent) =>
        tab === 'subagent' ? agentSupportsMode(agent, 'subagent') : isPrimaryAgent(agent),
      );
      if (!agentFilter) return listed;
      return fuzzyFilter(listed, agentFilter, (agent) => agent.name);
    };
    const setAgentFilter = (value: string): void => {
      // The match set changes under the cursor, so keep the selection in range and
      // pinned to the same agent when that agent survives the new query.
      const selectedName = agentsForTab()[selectedAgent]?.name;
      agentFilter = value;
      const listed = agentsForTab();
      const next = selectedName ? listed.findIndex((agent) => agent.name === selectedName) : 0;
      selectedAgent = Math.max(0, Math.min(next < 0 ? 0 : next, listed.length - 1));
    };
    let selectedAgent = Math.max(
      0,
      agentsForTab().findIndex((agent) => agent.name === this.primaryAgent?.name),
    );
    let confirmingDeleteAgent: string | undefined;
    let pendingTaskAction: TaskListAction | undefined;
    const selectedTaskIds = new Set<string>();
    let scroll = 0;
    let steering: Input | undefined;

    const reloadAgents = (): void => {
      const selectedName = agentsForTab()[selectedAgent]?.name;
      catalog = this.getAgentCatalog(ctx);
      agents = [...catalog.agents.values()]
        .filter((agent) => !agent.hidden)
        .sort((left, right) => left.name.localeCompare(right.name));
      disabledOverrides = loadAgentDisabledOverrides(ctx.cwd, projectTrusted);
      refreshDeletableAgents();
      const listedAgents = agentsForTab();
      const nextSelected = selectedName
        ? listedAgents.findIndex((agent) => agent.name === selectedName)
        : selectedAgent;
      selectedAgent = Math.max(
        0,
        Math.min(nextSelected < 0 ? 0 : nextSelected, listedAgents.length - 1),
      );
    };
    const refreshTasks = (): void => {
      const selectedId = tasks[selectedTask]?.id;
      tasks = [...this.tasks.values()];
      const visibleTaskIds = new Set(tasks.map((task) => task.id));
      for (const taskId of selectedTaskIds) {
        if (!visibleTaskIds.has(taskId)) selectedTaskIds.delete(taskId);
      }
      const nextSelected = selectedId
        ? tasks.findIndex((task) => task.id === selectedId)
        : selectedTask;
      selectedTask = Math.max(0, Math.min(nextSelected < 0 ? 0 : nextSelected, tasks.length - 1));
    };
    const taskTargets = (): TaskRecord[] => {
      const selected = tasks.filter((task) => selectedTaskIds.has(task.id));
      if (selected.length > 0) return selected;
      const task = tasks[selectedTask];
      return task ? [task] : [];
    };
    const refreshAgentRuntime = async (name: string): Promise<void> => {
      reloadAgents();
      if (this.primaryAgent?.name === name) {
        await this.restorePrimaryAgent(ctx);
      } else {
        this.pi.registerTool(this.createTaskTool(undefined, this.primaryRules, ctx));
      }
    };

    const buildSettingsList = (
      tui: TUI,
      theme: Theme,
      done: (result: void) => void,
    ): SettingsList => {
      if (settingsList) return settingsList;
      // Only the project scope is editable here, so an unset project value shows the
      // effective global one, matching what the runtime actually uses.
      const settingValue = (
        project: string | number | undefined,
        global: string | number,
      ): string => (project === undefined ? `${global} (global)` : String(project));

      const syncSettingsList = (): void => {
        settingsList?.updateValue(
          'maxSubagents',
          settingValue(maxSubagentsSettings.project, maxSubagentsSettings.global),
        );
        settingsList?.updateValue(
          'toolFilesystemPolicy',
          settingValue(policySettings.project, policySettings.global),
        );
      };

      const saveSetting = (id: string, value: string): void => {
        if (!projectTrusted) {
          ctx.ui.notify('Project settings require a trusted project', 'warning');
          syncSettingsList();
          return;
        }
        let save: Promise<void>;
        let notifyMessage: string;
        if (id === 'maxSubagents') {
          if (value === INHERIT || value === '') {
            save = clearMaxSubagentsConfigForScope(ctx.cwd, 'project');
            notifyMessage = 'Project maxSubagents inherits Global';
          } else {
            const parsed = Number(value);
            if (
              !/^\d+$/.test(value) ||
              !Number.isSafeInteger(parsed) ||
              parsed < 0 ||
              parsed > MAX_SUBAGENTS
            ) {
              ctx.ui.notify(`Enter a whole number between 0 and ${MAX_SUBAGENTS}`, 'error');
              syncSettingsList();
              return;
            }
            save = setMaxSubagentsConfigForScope(ctx.cwd, parsed, 'project');
            notifyMessage = `Project maxSubagents = ${parsed}`;
          }
        } else if (value === INHERIT) {
          save = clearToolFilesystemPolicyConfigForScope(ctx.cwd, 'project');
          notifyMessage = 'Project toolFilesystemPolicy inherits Global';
        } else {
          const policy: ToolFilesystemPolicy = value === 'host' ? 'host' : 'sandbox';
          save = setToolFilesystemPolicyConfigForScope(ctx.cwd, policy, 'project');
          notifyMessage = `Project toolFilesystemPolicy = ${policy}`;
        }

        saving = true;
        tui.requestRender();
        void save
          .then(() => {
            maxSubagentsSettings = loadMaxSubagentsSettings(ctx.cwd, projectTrusted);
            policySettings = loadToolFilesystemPolicySettings(ctx.cwd, projectTrusted);
            this.setMaxSubagents(maxSubagentsSettings.project ?? maxSubagentsSettings.global);
            this.toolFilesystemPolicy = policySettings.project ?? policySettings.global;
            ctx.ui.notify(notifyMessage, 'info');
          })
          .catch((error: unknown) =>
            ctx.ui.notify(`Could not save setting: ${formatError(error)}`, 'error'),
          )
          .finally(() => {
            saving = false;
            syncSettingsList();
            tui.requestRender();
          });
      };

      const items: SettingItem[] = [
        {
          id: 'maxSubagents',
          label: 'Maximum Subagents',
          currentValue: settingValue(maxSubagentsSettings.project, maxSubagentsSettings.global),
          description: 'Concurrent subagent tasks. Enter to edit, empty to inherit Global.',
          submenu: (_currentValue, doneEditing) => {
            const input = new Input();
            input.focused = true;
            // Typed rather than setValue() so the cursor lands after the prefill.
            if (maxSubagentsSettings.project !== undefined) {
              for (const char of String(maxSubagentsSettings.project)) input.handleInput(char);
            }
            input.onSubmit = (value) => doneEditing(value.trim() || INHERIT);
            input.onEscape = () => doneEditing(undefined);
            return input;
          },
        },
        {
          id: 'toolFilesystemPolicy',
          label: 'Filesystem Tool Policy',
          currentValue: settingValue(policySettings.project, policySettings.global),
          description: 'How file tools resolve paths. Enter to choose.',
          submenu: (_currentValue, doneEditing) => {
            const options: SelectItem[] = [
              {
                value: INHERIT,
                label: 'inherit',
                description: `Use Global (${policySettings.global})`,
              },
              { value: 'host', label: 'host', description: 'Resolve paths on the host' },
              {
                value: 'sandbox',
                label: 'sandbox',
                description: 'Resolve paths inside the sandbox',
              },
            ];
            const list = new SelectList(options, options.length, {
              selectedPrefix: (text) => theme.fg('accent', text),
              selectedText: (text) => theme.fg('accent', text),
              description: (text) => theme.fg('dim', text),
              scrollInfo: (text) => theme.fg('dim', text),
              noMatch: (text) => theme.fg('dim', text),
            });
            list.setSelectedIndex(
              options.findIndex((option) => option.value === (policySettings.project ?? INHERIT)),
            );
            list.onSelect = (item) => doneEditing(item.value);
            list.onCancel = () => doneEditing(undefined);
            return list;
          },
        },
      ];
      settingsList = new SettingsList(
        items,
        INSPECTOR_BODY_LINES,
        {
          label: (text, selected) => theme.fg(selected ? 'accent' : 'text', text),
          value: (text, selected) => theme.fg(selected ? 'accent' : 'dim', text),
          description: (text) => theme.fg('dim', text),
          cursor: theme.fg('accent', '› '),
          hint: (text) => theme.fg('dim', text),
        },
        saveSetting,
        () => done(undefined),
      );
      return settingsList;
    };

    return ctx.ui.custom<void>(
      (tui, theme, _keybindings, done) => {
        const renderAgentsTab = (frame: TabFrame): string[] => {
          const { tabs, pane, contentWidth, pad } = frame;
          const listedAgents = agentsForTab();
          const agentRows = listRowBudget(
            (tui as Partial<TUI>).terminal?.rows,
            AGENT_LIST_ROWS,
            AGENT_TAB_CHROME_ROWS,
          );
          const { shown, start, status } = listWindow(listedAgents, selectedAgent, agentRows);
          const nameWidth = Math.min(
            20,
            Math.max(5, ...listedAgents.map((agent) => visibleWidth(`@${agent.name}`))),
          );
          const modelWidth = Math.max(10, Math.min(24, Math.floor((contentWidth - 2) / 3)));
          const enabledWidth = 13;
          const runtimeWidth = Math.max(
            12,
            contentWidth - 2 - nameWidth - 1 - modelWidth - 1 - enabledWidth - 1,
          );
          const runtimeFor = (agent: AgentDefinition): string => {
            const parts: string[] = [];
            if (agent.name === this.primaryAgent?.name) parts.push('★ primary');
            const byState = (state: TaskState): number =>
              [...this.tasks.values()].filter(
                (task) => task.agent === agent.name && task.state === state,
              ).length;
            const running = byState('running');
            const queued = byState('queued');
            if (running > 0) parts.push(`${running} running`);
            if (queued > 0) parts.push(`${queued} queued`);
            const rules = [...catalog.permissions, ...agent.permissions].length;
            parts.push(rules > 0 ? `${rules} rules` : 'ask by default');
            return parts.length > 0 ? parts.join(' · ') : '—';
          };
          const lines = [tabs, ''];
          if (filteringAgents || agentFilter) {
            lines.push(
              `${theme.fg('accent', 'Filter')} ${agentFilter}${
                filteringAgents ? theme.fg('accent', '\u2588') : ''
              }`,
            );
          }
          lines.push(
            theme.fg(
              'dim',
              `  ${pad('Agent', nameWidth)} ${pad('Model', modelWidth)} ${pad(
                'Enabled',
                enabledWidth,
              )} ${pad('Runtime', runtimeWidth)}`,
            ),
          );
          for (const [offset, agent] of shown.entries()) {
            const index = start + offset;
            const selected = index === selectedAgent;
            const cursor = selected ? theme.fg('accent', '›') : ' ';
            const disabled = agent.disabled;
            const deleting = confirmingDeleteAgent === agent.name;
            const inherited = !disabledOverrides.project.has(agent.name);
            const enabled = inherited
              ? `inherited ${disabled ? 'off' : 'on'}`
              : disabled
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
            const runtime = runtimeFor(agent);
            const line = `${cursor} ${name} ${theme.fg(
              color,
              pad(agent.model ?? 'current model', modelWidth),
            )} ${theme.fg(
              deleting ? 'error' : disabled ? 'warning' : color,
              pad(enabled, enabledWidth),
            )} ${theme.fg(disabled ? 'muted' : 'dim', pad(runtime, runtimeWidth))}`;
            lines.push(agent.name === this.primaryAgent?.name ? theme.bold(line) : line);
          }
          if (listedAgents.length === 0) {
            lines.push(
              theme.fg(
                'muted',
                agentFilter
                  ? `  No ${tab} agents match ${agentFilter}`
                  : `  No ${tab} agents configured.`,
              ),
            );
          }
          if (status) lines.push(theme.fg('dim', `  ${status}`));

          const agent = listedAgents[selectedAgent];
          if (agent) {
            lines.push(
              '',
              theme.fg(agent.disabled ? 'muted' : 'text', agent.description ?? 'No description'),
            );
            const details = [
              agent.source,
              agent.variant ? `variant ${agent.variant}` : undefined,
              agent.steps ? `${agent.steps} steps` : undefined,
            ].filter(Boolean);
            if (details.length > 0) lines.push(theme.fg('dim', details.join(' · ')));
            const permissions = [...catalog.permissions, ...agent.permissions];
            lines.push(theme.fg('dim', 'Permissions'));
            if (permissions.length === 0) lines.push(`  ${theme.fg('muted', 'default: ask')}`);
            for (const rule of permissions.slice(0, 4)) {
              const color =
                rule.action === 'deny' ? 'error' : rule.action === 'allow' ? 'success' : 'warning';
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
              theme.fg('error', `Delete @${confirmingDeleteAgent}? This removes its project file.`),
              dialogKeys(theme, [
                ['Enter', 'confirm'],
                ['Esc', 'cancel'],
              ]),
            );
          } else if (saving) {
            lines.push('', theme.fg('dim', 'Saving…'));
          } else if (agent) {
            // Only advertise what this selection actually accepts: I is a silent
            // no-op without a project override, and Enter sets primary on that tab.
            lines.push(
              '',
              dialogKeys(theme, [
                ...(tab === 'primary' ? ([['Enter', 'set primary']] as const) : ([] as const)),
                ...(projectTrusted
                  ? ([
                      ['Space', 'toggle enabled'],
                      ['E', 'edit'],
                    ] as const)
                  : ([] as const)),
                ...(deletableAgents.has(agent.name) ? ([['X', 'delete']] as const) : ([] as const)),
                ...(projectTrusted && disabledOverrides.project.has(agent.name)
                  ? ([['I', 'inherit global']] as const)
                  : ([] as const)),
                ['/', 'filter'],
                ['Esc', agentFilter ? 'clear filter' : 'close'],
              ]),
            );
          }
          return pane(lines);
        };
        const handleAgentsInput = (data: string): void => {
          if (filteringAgents) {
            // While typing a query the letter keys spell it out instead of running
            // the actions they are bound to, so only these four keys are special.
            if (matchesKey(data, 'escape')) {
              filteringAgents = false;
              setAgentFilter('');
            } else if (matchesKey(data, 'return')) {
              filteringAgents = false;
            } else if (matchesKey(data, 'backspace')) {
              setAgentFilter(agentFilter.slice(0, -1));
            } else if (data >= ' ' && data <= '~') {
              setAgentFilter(agentFilter + data);
            }
            tui.requestRender();
            return;
          }
          const listedAgents = agentsForTab();
          const agent = listedAgents[selectedAgent];
          if (data === '/') {
            filteringAgents = true;
            tui.requestRender();
            return;
          }
          if (matchesKey(data, 'escape')) {
            if (agentFilter) {
              setAgentFilter('');
              tui.requestRender();
              return;
            }
            done(undefined);
            return;
          }
          if (matchesKey(data, 'up')) selectedAgent = Math.max(0, selectedAgent - 1);
          else if (matchesKey(data, 'down') && listedAgents.length > 0) {
            selectedAgent = Math.min(listedAgents.length - 1, selectedAgent + 1);
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
            if (!projectTrusted) {
              ctx.ui.notify('Project settings require a trusted project', 'warning');
              return;
            }
            const disabled = !agent.disabled;
            saving = true;
            void setAgentDisabledForScope(ctx.cwd, agent.name, disabled, 'project')
              .then(async () => {
                await refreshAgentRuntime(agent.name);
                ctx.ui.notify(
                  `${agent.name} ${disabled ? 'disabled' : 'enabled'} in project settings`,
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
          } else if (data.toLowerCase() === 'i' && agent && !saving) {
            if (!projectTrusted) {
              ctx.ui.notify('Project settings require a trusted project', 'warning');
              return;
            }
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
            tab === 'primary' &&
            matchesKey(data, 'return') &&
            agent &&
            !agent.disabled &&
            isPrimaryAgent(agent)
          ) {
            void this.selectPrimaryAgent(agent.name, ctx)
              .then(() => tui.requestRender())
              .catch((error: unknown) =>
                ctx.ui.notify(`Could not select primary agent: ${formatError(error)}`, 'error'),
              );
            return;
          } else if (tab === 'primary' && matchesKey(data, 'return') && agent) {
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
        };
        const renderTab: Record<LandstripTab, (frame: TabFrame) => string[]> = {
          overview: (frame) => {
            const { tabs, pane, contentWidth, listValue } = frame;
            const lines = [tabs, ''];
            if (!overview) {
              lines.push(theme.fg('muted', '  Sandbox settings are unavailable.'));
              lines.push('', dialogKeys(theme, [['Esc', 'close']]));
              return pane(lines);
            }
            const status = overview.noSandboxFlag
              ? { color: 'warning', label: 'Disabled by --no-sandbox' }
              : !overview.enabled
                ? { color: 'warning', label: 'Disabled by configuration' }
                : !overview.running
                  ? { color: 'warning', label: 'Inactive' }
                  : { color: 'success', label: 'Active' };
            const networkMode = overview.networkMode;
            const shellReadMode =
              overview.windowsMode !== undefined
                ? 'Policy (required)'
                : overview.shellReadMode === 'host'
                  ? 'Host-aligned'
                  : 'Policy';
            const changePath =
              overview.changeScope === 'project' ? overview.paths.project : overview.paths.global;
            const item = (label: string, value: string): string =>
              `  ${theme.fg('dim', label.padEnd(16))} ${value}`;
            lines.push(
              `${theme.fg(status.color as 'success' | 'warning', '●')} ${theme.fg('text', status.label)}`,
              item(
                'Configured',
                overview.enabled ? theme.fg('text', 'Enabled') : theme.fg('warning', 'Disabled'),
              ),
              item(
                'Runtime',
                overview.running ? theme.fg('success', 'Running') : theme.fg('dim', 'Not running'),
              ),
              '',
              theme.fg('accent', 'Protection'),
              item('Network', networkMode),
              item('Shell reads', shellReadMode),
              item(
                'Read rules',
                `${overview.config.filesystem.denyRead.length + overview.config.filesystem.allowRead.length} · ${overview.readRuleScope}`,
              ),
              item(
                'Write rules',
                String(
                  overview.config.filesystem.allowWrite.length +
                    overview.config.filesystem.denyWrite.length,
                ),
              ),
              item(
                'Session grants',
                String(
                  overview.sessionDomains.length +
                    overview.sessionReadPaths.length +
                    overview.sessionWritePaths.length,
                ),
              ),
              '',
              theme.fg('accent', 'Configuration'),
              item('Change scope', overview.changeScope === 'project' ? 'Project' : 'Global'),
              item('Change file', truncateToWidth(changePath, Math.max(10, contentWidth - 20))),
              item(
                'Project file',
                truncateToWidth(overview.paths.project, Math.max(10, contentWidth - 20)),
              ),
              item(
                'Global file',
                truncateToWidth(overview.paths.global, Math.max(10, contentWidth - 20)),
              ),
              item(
                'Landstrip binary',
                truncateToWidth(overview.paths.binary, Math.max(10, contentWidth - 20)),
              ),
            );
            if (overview.windowsMode !== undefined)
              lines.push(item('Windows mode', overview.windowsMode));
            lines.push(
              '',
              theme.fg('accent', 'Network'),
              item('Allowed domains', listValue(overview.config.network.allowedDomains)),
              item('Denied domains', listValue(overview.config.network.deniedDomains)),
              item(
                'Unix sockets',
                overview.config.network.allowAllUnixSockets
                  ? 'all'
                  : listValue(overview.config.network.allowUnixSockets),
              ),
              '',
              theme.fg('accent', 'Filesystem'),
              item('Shell reads', shellReadMode),
              item('Read rules for', overview.readRuleScope),
              item('Denied reads', listValue(overview.config.filesystem.denyRead)),
              item('Allowed reads', listValue(overview.config.filesystem.allowRead)),
              item('Allowed writes', listValue(overview.config.filesystem.allowWrite)),
              item('Denied writes', listValue(overview.config.filesystem.denyWrite)),
              '',
              theme.fg('accent', 'Session grants'),
              item('Domains', listValue(overview.sessionDomains)),
              item('Read paths', listValue(overview.sessionReadPaths)),
              item('Write paths', listValue(overview.sessionWritePaths)),
            );
            if (saving) lines.push('', theme.fg('dim', 'Saving…'));
            lines.push('');
            if (confirmingSandboxDisable) {
              lines.push(
                theme.fg('error', 'Disable the sandbox? Commands will run without OS isolation.'),
                dialogKeys(theme, [
                  ['Enter', 'confirm'],
                  ['Esc', 'cancel'],
                ]),
              );
            } else {
              lines.push(
                dialogKeys(theme, [
                  ['Tab', 'next tab'],
                  [
                    'Enter',
                    `${overview.enabled ? 'disable' : 'enable'} in ${overview.changeScope}`,
                  ],
                  ['Esc', 'close'],
                ]),
              );
            }
            return pane(lines);
          },
          settings: (frame) => {
            const { tabs, pane, contentWidth } = frame;
            const lines = [tabs, '', ...buildSettingsList(tui, theme, done).render(contentWidth)];
            if (saving) lines.push('', theme.fg('dim', 'Saving…'));
            return pane(lines);
          },
          primary: renderAgentsTab,
          subagent: renderAgentsTab,
          tasks: (frame) => {
            const { tabs, pane } = frame;
            const listLines: string[] = [];
            if (tasks.length === 0) {
              listLines.push('No task sessions in this session.');
            } else {
              const taskRows = listRowBudget(
                (tui as Partial<TUI>).terminal?.rows,
                TASK_LIST_ROWS,
                TASK_TAB_CHROME_ROWS,
              );
              const { shown, start, status } = listWindow(tasks, selectedTask, taskRows);
              for (const [offset, task] of shown.entries()) {
                const index = start + offset;
                const cursor = index === selectedTask ? theme.fg('accent', '›') : ' ';
                const selected = selectedTaskIds.has(task.id) ? theme.fg('accent', '✓') : ' ';
                const indent = '  '.repeat(Math.max(0, task.depth - 1));
                listLines.push(
                  `${cursor} ${selected} ${indent}${taskState(theme, task)} ${theme.fg('accent', `@${task.agent}`)} ${theme.fg('text', task.description)} ${theme.fg('dim', task.id.slice(0, 8))}`,
                );
              }
              if (status) listLines.push(theme.fg('dim', `  ${status}`));
            }
            const selectedCount = tasks.filter((task) => selectedTaskIds.has(task.id)).length;
            if (selectedCount > 0) {
              listLines.push('', theme.fg('dim', `${selectedCount} selected`));
            }
            listLines.push('');
            if (pendingTaskAction) {
              const count = pendingTaskAction.taskIds.length;
              const label =
                count === 1
                  ? `Delete ${pendingTaskAction.taskIds[0]?.slice(0, 8) ?? 'task'}?`
                  : `Delete ${count} selected task sessions?`;
              listLines.push(
                `${theme.fg('warning', label)} ${dialogKeys(theme, [
                  ['Enter', 'confirm'],
                  ['Esc', 'cancel'],
                ])}`,
              );
            } else {
              listLines.push(
                dialogKeys(theme, [
                  ['↑ / ↓', 'move'],
                  ['Space', 'select'],
                  ['Enter', 'inspect'],
                  ['X', 'delete'],
                  ['Esc', 'close'],
                ]),
              );
            }
            return pane([tabs, '', ...listLines]);
          },
          log: (frame) => {
            const { tabs, pane, contentWidth } = frame;
            const task = tasks[selectedTask];
            if (!task) return pane([tabs, '', 'No task sessions in this session.']);
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
            const usage = formatTaskUsage(task.usage);
            const lines = [
              tabs,
              '',
              `${theme.fg('accent', theme.bold(`@${task.agent}`))} ${theme.fg('text', task.description)}`,
              `${taskState(theme, task)} ${theme.fg('dim', metrics.join(' · '))} ${theme.fg('dim', '·')} ${theme.fg(follow ? 'accent' : 'muted', `Follow: ${follow ? 'on' : 'off'}`)}`,
              ...(usage ? [theme.fg('dim', usage)] : []),
              '',
              ...shown.map((line) => theme.fg('toolOutput', line)),
            ];
            while (lines.length < INSPECTOR_BODY_LINES + 5) lines.push('');
            if (transcript.length > INSPECTOR_BODY_LINES) {
              lines.push(
                theme.fg('dim', `${scroll + 1}–${scroll + shown.length} of ${transcript.length}`),
              );
            }
            if (steering) {
              const input =
                steering.render(Math.max(2, contentWidth - visibleWidth('Steer ')))[0] ?? '';
              lines.push(`${theme.fg('accent', 'Steer')} ${input.replace(/^>/, '›')}`);
            } else if (task.state === 'queued' || task.state === 'running') {
              lines.push(
                dialogKeys(theme, [
                  ['Enter', 'steer'],
                  ['F', 'follow'],
                  ['Esc', 'tasks'],
                ]),
              );
            }
            return pane(lines.map((line) => truncateToWidth(line, contentWidth)));
          },
          help: (frame) => {
            const { tabs, pane, contentWidth, pad } = frame;
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
            return pane(lines);
          },
        };
        const handleTabInput: Record<LandstripTab, (data: string) => void> = {
          overview: (data) => {
            if (confirmingSandboxDisable) {
              if (matchesKey(data, 'escape')) {
                confirmingSandboxDisable = false;
                tui.requestRender();
                return;
              }
              if (!matchesKey(data, 'return')) return;
            }
            if (matchesKey(data, 'escape')) {
              done(undefined);
              return;
            }
            if (!matchesKey(data, 'return')) return;
            const callbacks = this.integration.sandboxCallbacks;
            const current = overview;
            if (!callbacks || !current) {
              ctx.ui.notify('Sandbox settings are unavailable', 'warning');
              return;
            }
            const enabled = !current.enabled;
            if (!enabled && !confirmingSandboxDisable) {
              confirmingSandboxDisable = true;
              tui.requestRender();
              return;
            }
            confirmingSandboxDisable = false;
            saving = true;
            tui.requestRender();
            void callbacks
              .setEnabled(ctx, enabled, current.changeScope)
              .then(() => {
                overview = callbacks.overview(ctx.cwd, projectTrusted);
                if (enabled && overview.noSandboxFlag) {
                  ctx.ui.notify('Sandbox remains disabled via --no-sandbox', 'warning');
                } else {
                  ctx.ui.notify(
                    `Sandbox ${enabled ? 'enabled' : 'disabled'} in ${current.changeScope} config`,
                    'info',
                  );
                }
              })
              .catch((error: unknown) =>
                ctx.ui.notify(`Could not update config: ${formatError(error)}`, 'error'),
              )
              .finally(() => {
                saving = false;
                tui.requestRender();
              });
            return;
          },
          settings: (data) => {
            // Refuse activation up front so an untrusted project never opens an editor
            // whose result would only be rejected on save.
            if (!projectTrusted && (matchesKey(data, 'return') || data === ' ')) {
              ctx.ui.notify('Project settings require a trusted project', 'warning');
              return;
            }
            buildSettingsList(tui, theme, done).handleInput(data);
            tui.requestRender();
            return;
          },
          primary: handleAgentsInput,
          subagent: handleAgentsInput,
          tasks: (data) => {
            if (pendingTaskAction) {
              if (matchesKey(data, 'return')) {
                const taskIds = pendingTaskAction.taskIds;
                pendingTaskAction = undefined;
                const deleted = this.deleteTasks(taskIds, ctx);
                for (const taskId of taskIds) selectedTaskIds.delete(taskId);
                refreshTasks();
                if (deleted > 0) {
                  ctx.ui.notify(
                    `Deleted ${deleted} task session${deleted === 1 ? '' : 's'}`,
                    'info',
                  );
                }
                tui.requestRender();
                return;
              }
              if (matchesKey(data, 'escape')) {
                pendingTaskAction = undefined;
                tui.requestRender();
              }
              return;
            }
            if (matchesKey(data, 'escape')) done(undefined);
            else if (matchesKey(data, 'up')) selectedTask = Math.max(0, selectedTask - 1);
            else if (matchesKey(data, 'down') && tasks.length > 0) {
              selectedTask = Math.min(tasks.length - 1, selectedTask + 1);
            } else if (data === ' ') {
              const task = tasks[selectedTask];
              if (!task) return;
              if (!selectedTaskIds.delete(task.id)) selectedTaskIds.add(task.id);
            } else if (data.toLowerCase() === 'x') {
              const targets = taskTargets();
              if (targets.length === 0) return;
              pendingTaskAction = {
                type: 'delete',
                taskIds: targets.map((task) => task.id),
              };
            } else if (matchesKey(data, 'return') && tasks.length > 0) {
              tab = 'log';
              follow = true;
              scroll = 0;
            } else return;
            tui.requestRender();
            return;
          },
          log: (data) => {
            const task = tasks[selectedTask];
            if (!task) {
              if (matchesKey(data, 'escape')) done(undefined);
              return;
            }
            if (matchesKey(data, 'escape')) {
              tab = 'tasks';
              follow = false;
              scroll = 0;
            } else if (
              matchesKey(data, 'return') &&
              (task.state === 'queued' || task.state === 'running')
            ) {
              const input = new Input();
              input.focused = true;
              input.onEscape = () => {
                steering = undefined;
                tui.requestRender();
              };
              input.onSubmit = (value) => {
                const message = value.trim();
                if (!message) {
                  ctx.ui.notify('Steering message must not be empty', 'warning');
                  return;
                }
                steering = undefined;
                void (async () => {
                  const running = this.running.get(task.id);
                  if (running) {
                    await running.rpc.steer(message);
                  } else if (
                    (task.state === 'queued' || task.state === 'running') &&
                    this.runPromises.has(task.id)
                  ) {
                    const pending = this.pendingSteers.get(task.id) ?? [];
                    pending.push(message);
                    this.pendingSteers.set(task.id, pending);
                  } else {
                    throw new Error('Task is no longer active');
                  }
                  ctx.ui.notify(`Steered task ${task.id.slice(0, 8)}`, 'info');
                })()
                  .catch((error: unknown) =>
                    ctx.ui.notify(`Could not steer task: ${formatError(error)}`, 'error'),
                  )
                  .finally(() => tui.requestRender());
                tui.requestRender();
              };
              steering = input;
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
          help: (data) => {
            if (matchesKey(data, 'escape')) done(undefined);
            return;
          },
        };
        return {
          render: (width: number) => {
            const contentWidth = Math.max(1, width - 2);
            const terminalRows = (tui as Partial<TUI>).terminal?.rows;
            const paneHeight = terminalRows
              ? Math.max(1, Math.floor(terminalRows * OVERLAY_HEIGHT_RATIO))
              : undefined;
            const pane = (lines: string[]) => {
              const rows = [
                paneTop(theme, width, 'Landstrip'),
                ...lines.map((line) => paneRow(theme, width, line)),
              ];
              if (paneHeight === undefined) return rows;
              while (rows.length < paneHeight) rows.push(paneRow(theme, width));
              return rows.slice(0, paneHeight);
            };
            const pad = (value: string, cellWidth: number): string => {
              const clipped = truncateToWidth(value, cellWidth);
              return `${clipped}${' '.repeat(Math.max(0, cellWidth - visibleWidth(clipped)))}`;
            };
            const listValue = (values: readonly string[]): string => {
              const value = values.join(', ') || 'none';
              return truncateToWidth(value, Math.max(10, contentWidth - 20));
            };
            refreshTasks();
            const tabs = dialogTabs(
              theme,
              TAB_ORDER.map((key) => TAB_LABELS[key]),
              TAB_LABELS[tab],
            );
            return renderTab[tab]({ contentWidth, tabs, pane, pad, listValue });
          },
          handleInput: (data: string) => {
            if (saving) return;
            if (confirmingDeleteAgent !== undefined) {
              if (matchesKey(data, 'escape')) {
                confirmingDeleteAgent = undefined;
                tui.requestRender();
                return;
              }
              if (matchesKey(data, 'return')) {
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
            if (steering) {
              steering.handleInput(data);
              tui.requestRender();
              return;
            }
            if (matchesKey(data, 'tab')) {
              const selectedName =
                tab === 'primary' || tab === 'subagent'
                  ? agentsForTab()[selectedAgent]?.name
                  : undefined;
              const nextIndex = (TAB_ORDER.indexOf(tab) + 1) % TAB_ORDER.length;
              tab = TAB_ORDER[nextIndex]!;
              if (tab === 'primary' || tab === 'subagent') {
                const listedAgents = agentsForTab();
                const preferredName =
                  selectedName ?? (tab === 'primary' ? this.primaryAgent?.name : undefined);
                const nextSelected = preferredName
                  ? listedAgents.findIndex((agent) => agent.name === preferredName)
                  : 0;
                selectedAgent = Math.max(
                  0,
                  Math.min(nextSelected < 0 ? 0 : nextSelected, listedAgents.length - 1),
                );
              }
              if (tab === 'log' && tasks.length > 0) follow = true;
              else follow = false;
              scroll = 0;
              confirmingDeleteAgent = undefined;
              pendingTaskAction = undefined;
              confirmingSandboxDisable = false;
              settingsList = undefined;
              steering = undefined;
              reloadAgents();
              tui.requestRender();
              return;
            }

            handleTabInput[tab](data);
          },
          invalidate() {},
        };
      },
      {
        overlay: true,
        overlayOptions: { anchor: 'bottom-center', width: '100%', maxHeight: '70%' },
      },
    );
  }

  async selectPrimaryAgent(name: string, ctx: ExtensionContext): Promise<boolean> {
    const catalog = this.getAgentCatalog(ctx);
    for (const diagnostic of catalog.diagnostics) ctx.ui.notify(diagnostic, 'warning');
    if (catalog.diagnostics.length > 0) return false;
    const agent = availableAgents(catalog).find(
      (candidate) => candidate.name === name && isPrimaryAgent(candidate),
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

    const agents = availableAgents(catalog).filter(isPrimaryAgent);
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
        const usage = formatTaskUsage(details.usage);
        if (usage) metrics.push(usage);
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
      await this.broker.ask(ctx, input.description, 'task', agent.name, signal, {
        context: parentTask ? this.taskContext(parentTask, ctx) : this.permissionContext(ctx),
        toolName: 'task',
        input: { ...input },
        taskDescription: parentTask?.description,
      });
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
      let workerError: string | undefined;
      worker.rpc.onEvent((event) => {
        if (event.type === 'message_update' && isRecord(event.assistantMessageEvent)) {
          const messageEvent = event.assistantMessageEvent;
          if (messageEvent.type === 'text_delta' && typeof messageEvent.delta === 'string') {
            streamedText += messageEvent.delta;
            update(streamedText);
          }
        }
        if (event.type === 'message_end' && isRecord(event.message)) {
          if (event.message.role === 'assistant') {
            workerError =
              event.message.stopReason === 'error'
                ? typeof event.message.errorMessage === 'string'
                  ? event.message.errorMessage
                  : 'Subagent model request failed'
                : undefined;
          }
          const usage = taskUsageFromMessage(event.message);
          if (usage) {
            task.usage = addTaskUsage(task.usage, usage);
            this.persist(task);
            this.updateTaskWidget(ctx);
            update(streamedText || 'Subagent running');
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
        await Promise.resolve(); // Let the initial prompt reach RPC before queued messages.
        const pendingSteers = this.pendingSteers.get(task.id) ?? [];
        this.pendingSteers.delete(task.id);
        for (const pendingSteer of pendingSteers) await worker.rpc.steer(pendingSteer);
        const pendingPrompts = this.pendingPrompts.get(task.id) ?? [];
        this.pendingPrompts.delete(task.id);
        for (const pendingPrompt of pendingPrompts) {
          await worker.rpc.request('follow_up', { message: pendingPrompt });
        }
        const output = await promise;
        if (workerError) throw new Error(workerError);
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
      this.pendingSteers.delete(task.id);
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
      const authPath = join(agentDir, 'auth.json');
      const settingsPath = join(agentDir, 'settings.json');
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
        writePaths: [sessionWritePath, temp, authPath, `${authPath}.lock`, `${settingsPath}.lock`],
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

  private taskContext(task: TaskRecord, ctx: ExtensionContext): LandstripContextV2 {
    const context = this.integration.getContext?.(ctx) ?? {
      version: 2,
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

  private permissionContext(ctx: ExtensionContext): LandstripContextV2 {
    const context = this.integration.getContext?.(ctx) ?? {
      version: 2,
      host: 'pi',
      role: 'primary',
      sandbox: 'unavailable',
      cwd: ctx.cwd,
      sessionId: ctx.sessionManager.getSessionId(),
      depth: 0,
    };
    return { ...context, agent: this.primaryAgent?.name };
  }

  private piInvocation(): { command: string; args: string[] } {
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
          if (
            typeof control.permission !== 'string' ||
            typeof control.resource !== 'string' ||
            typeof control.toolName !== 'string' ||
            !isRecord(control.toolInput)
          ) {
            throw new Error('Invalid permission request');
          }
          const derivedPermission = permissionName(control.toolName);
          const derivedResources = permissionResources(
            control.toolName,
            control.toolInput,
            ctx.cwd,
          );
          if (
            control.permission !== derivedPermission ||
            !derivedResources.includes(control.resource) ||
            permissionDecision(rules, control.permission, control.resource) !== 'ask'
          ) {
            throw new Error('Invalid permission request');
          }
          await this.broker.ask(
            ctx,
            task.description,
            control.permission,
            control.resource,
            this.controllers.get(task.id)?.signal,
            {
              context: this.taskContext(task, ctx),
              toolName: control.toolName,
              input: control.toolInput,
              taskDescription: task.description,
            },
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
            // Reclaim the parent's transferred permit even if admission was disabled mid-task.
            if (handedOff) this.restoreLease(task.id);
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
    if (['select', 'confirm', 'input', 'editor'].includes(request.method)) {
      return this.enqueueWorkerUi(() =>
        this.forwardWorkerUi(ctx, task, request, this.controllers.get(task.id)?.signal),
      );
    }
    return this.forwardWorkerUi(ctx, task, request, this.controllers.get(task.id)?.signal);
  }

  private enqueueWorkerUi<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.workerUiQueue.then(operation);
    this.workerUiQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
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
          const state = taskState(theme, task);
          const agent = theme.fg('accent', `@${task.agent}`);
          const record = byId.get(task.id)!;
          const progress = taskProgress(record);
          const suffix = progress.length > 0 ? theme.fg('dim', `  ·  ${progress.join(' · ')}`) : '';
          const indentWidth = 3 + Math.max(0, record.depth) * 3;
          const descriptionWidth = Math.max(
            1,
            width - indentWidth - visibleWidth(`${state}  ${agent}  ${suffix}`),
          );
          const description = theme.fg('text', truncateToWidth(task.description, descriptionWidth));
          return `${state}  ${agent}  ${description}${suffix}`;
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

  deleteTasks(taskIds: readonly string[], ctx: ExtensionContext): number {
    let deleted = 0;
    for (const taskId of taskIds) {
      const task = this.tasks.get(taskId);
      if (!task) continue;
      task.deleted = true;
      task.delivered = true;
      this.controllers.get(taskId)?.abort();
      if (task.sessionDir && existsSync(task.sessionDir)) {
        rmSync(task.sessionDir, { recursive: true, force: true });
      }
      this.tasks.delete(taskId);
      this.pendingPrompts.delete(taskId);
      this.pendingSteers.delete(taskId);
      this.foregroundClaims.delete(taskId);
      this.persist(task);
      deleted += 1;
    }
    if (deleted > 0) this.updateTaskWidget(ctx);
    return deleted;
  }

  private async cleanupOrphanSubagentSessions(ctx: ExtensionContext): Promise<void> {
    try {
      const subagentBaseDir = join(getAgentDir(), 'sessions', 'pi-landstrip');
      if (!existsSync(subagentBaseDir)) return;

      const sessionFile = ctx.sessionManager.getSessionFile();
      const sessionDir = sessionFile ? dirname(sessionFile) : undefined;
      const cwdSessions = sessionDir
        ? await SessionManager.list(ctx.cwd, sessionDir).catch(() => [])
        : await SessionManager.list(ctx.cwd).catch(() => []);
      const allSessions = await SessionManager.listAll().catch(() => []);

      const existingParentSessionIds = new Set<string>();
      for (const s of cwdSessions) {
        if (s.id) existingParentSessionIds.add(s.id);
      }
      for (const s of allSessions) {
        if (s.id) existingParentSessionIds.add(s.id);
      }
      const activeId = ctx.sessionManager.getSessionId();
      if (activeId) existingParentSessionIds.add(activeId);

      const entries = readdirSync(subagentBaseDir, { withFileTypes: true });
      const targetCwd = ctx.cwd;

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const parentSessionId = entry.name;
        if (existingParentSessionIds.has(parentSessionId)) continue;

        const parentSessionDir = join(subagentBaseDir, parentSessionId);
        if (isSubagentSessionDirForCwd(parentSessionDir, targetCwd)) {
          rmSync(parentSessionDir, { recursive: true, force: true });
        }
      }
    } catch {
      // Ignore errors during orphan cleanup
    }
  }

  private restore(ctx: ExtensionContext): void {
    this.tasks.clear();
    for (const entry of ctx.sessionManager.getBranch()) {
      if (entry.type !== 'custom' || entry.customType !== TASK_ENTRY) continue;
      const task = entry.data as TaskRecord | undefined;
      if (!task?.id || task.parentSessionId !== ctx.sessionManager.getSessionId()) continue;
      if (task.deleted) {
        this.tasks.delete(task.id);
        continue;
      }
      this.tasks.set(task.id, {
        ...task,
        usage: isTaskUsage(task.usage) ? { ...task.usage } : undefined,
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
    this.toolFilesystemPolicy = catalog.toolFilesystemPolicy;
    this.semaphore = new Semaphore(this.maxSubagents);
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
    const agents = availableAgents(catalog).filter(isPrimaryAgent);
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
    this.toolFilesystemPolicy = catalog.toolFilesystemPolicy;
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
    this.broker.reset();
    for (const controller of this.controllers.values()) controller.abort();
    await Promise.allSettled([...this.running.values()].map(({ rpc }) => rpc.stop()));
    await Promise.allSettled(this.runPromises.values());
    this.running.clear();
    this.runPromises.clear();
    this.controllers.clear();
    this.foregroundClaims.clear();
    this.pendingPrompts.clear();
    this.pendingSteers.clear();
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

  private restoreLease(taskId: string): void {
    const lease = this.leases.get(taskId);
    if (!lease || lease.release) return;
    const release = this.semaphore.restoreTransferred();
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
  permissionPrompts = new PermissionPromptCoordinator(),
): SubagentRuntime {
  const runtime = new SubagentRuntime(pi, integration, undefined, undefined, permissionPrompts);
  runtime.register();
  return runtime;
}
