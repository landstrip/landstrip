// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type ChildProcess, spawn, spawnSync, type StdioOptions } from 'node:child_process';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from 'node:fs';
import { type AddressInfo, createServer, Socket as NetSocket } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { quote as quoteShell } from 'shell-quote';

import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  BashToolDetails,
  BashToolInput,
  ExtensionAPI,
  ExtensionContext,
  ExtensionToolContext,
} from '@earendil-works/pi-coding-agent';

import {
  type BashOperations,
  createBashToolDefinition,
  createLocalBashOperations,
  getShellConfig,
  SettingsManager,
  type ToolDefinition,
  withFileMutationQueue,
} from '@earendil-works/pi-coding-agent';
import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripPolicy,
  type SandboxConfig as BaseSandboxConfig,
  type SandboxConfigFile,
  type SandboxFilesystemConfig,
  type SandboxNetworkConfig,
  type SandboxShellConfig,
  type SandboxWindowsConfig,
  type ShellReadAccess,
} from '@landstrip/landstrip-api';
import {
  buildLandstripPolicy as assembleLandstripPolicy,
  allowsAllDomains,
  type LandstripQueryTrap,
  controlResponseLine,
  deepMergeSandboxConfig as deepMerge,
  domainMatchesAny,
  evaluateDomainAccess,
  formatLandstripTraps,
  isDenialTrap,
  isFilesystemTrap,
  isPathReadAllowed,
  isRecord,
  isQueryTrap,
  matchesPathPattern,
  matchesWriteDenyPattern,
  mergeArray,
  parseLandstripTraps,
  parseSandboxConfig,
  canonicalizeGlobPattern,
  canonicalizePath,
  expandPath,
  globToRegExp,
  normalizePathSeparators,
  parseTrapLine,
  pathUnderDirectory,
  sessionScopeFor,
  writeLandstripPolicyFile,
  shouldPromptForWrite,
  writeGrantScopesFor,
  readGrantScopesFor,
  normalizeBlockedPath,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractTrapBlockedPath,
} from '@landstrip/landstrip-api/shared';
import {
  type ProxyPortRange,
  createProxyCredentials,
  createProxyEnvironment,
  startFilterProxy,
} from '@landstrip/landstrip-api/proxy';

export interface SandboxConfig extends BaseSandboxConfig {
  shell: SandboxShellConfig;
  windows: SandboxWindowsConfig;
}
import {
  type LandstripContextV3,
  type LandstripEvent,
  type LandstripPermissionAskDecision,
  type LandstripPermissionAskProvider,
  type LandstripPermissionAskRequest,
  type LandstripPreparedProcess,
  type LandstripProcessOptions,
  type LandstripSandboxState,
  type LandstripShellInvocation,
  type LandstripShellPrepareOptions,
  type LandstripShellProvider,
  type LandstripSpawn,
  type LandstripWorkerExtension,
  LANDSTRIP_RUNTIME_VERSION,
  type PiLandstripRuntimeV3,
  publishLandstripRuntime,
} from './api.ts';
import type { RpcSpawn } from './rpc-process.ts';
import { WORKER_AUTH_FD } from './worker-auth-channel.ts';
import {
  registerSubagents,
  registerSubagentWorker,
  type SubagentRuntime,
  workerConfigFromEnvironment,
} from './subagents.ts';
import { Type, type Static } from 'typebox';
import { getPiConfigPaths, isProjectTrusted } from './config.ts';
import { formatError, PermissionPromptCoordinator } from './util.ts';
import { Text } from '@earendil-works/pi-tui';

export const LandstripBashSchema = Type.Object({
  command: Type.String({ description: 'Shell command to execute' }),
  timeout: Type.Optional(
    Type.Number({ description: 'Timeout in seconds (optional, no default timeout)' }),
  ),
  background: Type.Optional(
    Type.Boolean({
      description:
        'Run command asynchronously in the background and return a task ID immediately; completion automatically triggers a follow-up turn',
    }),
  ),
  name: Type.Optional(
    Type.String({
      description: 'Concise label for the background command execution',
    }),
  ),
});
export type LandstripBashInput = Static<typeof LandstripBashSchema>;

export type LandstripBashTool = ToolDefinition<typeof LandstripBashSchema, any, any>;

export type SandboxConfigScope = 'global' | 'project';

export type PolicyAudience = 'shell' | 'worker';

export function enforcesShellReadPolicy(
  shellReadAccess: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return shellReadAccess !== 'host' || platform === 'win32';
}

export function resolveProcessReadPolicy(
  audience: PolicyAudience,
  shellReadAccess: ShellReadAccess,
  denyRead: string[],
  allowRead: string[],
  platform: NodeJS.Platform = process.platform,
): Pick<SandboxFilesystemConfig, 'denyRead' | 'allowRead'> {
  if (audience === 'shell' && !enforcesShellReadPolicy(shellReadAccess, platform)) {
    return { denyRead: [], allowRead: [] };
  }
  return { denyRead, allowRead };
}

interface LandstripBashCallbacks {
  onStderr?: (data: Buffer) => void;
  onErrorFd?: (data: Buffer) => void;
  onRejectedPath?: (operation: 'read' | 'write', path: string) => void;
  promptOnBlock?: boolean;
}

interface ExecutionAllowances {
  readonly permissionPromptLabel?: string;
  // Bootstrap grants must not silently override configured read denials.
  explicitDenyRead?: {
    patterns: string[];
    globRoots: Map<string, string[]>;
    approvedPaths: string[];
  };
  readonly protectedPaths?: string[];
  readonly domains: string[];
  readonly readPaths: string[];
  readonly writePaths: string[];
  readonly targets: string[];
  rejectedTargets?: Set<string>;
}

const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);
// Grace period after the child exits for its stdio to drain before we stop
// waiting; matches pi's own bash backend so a backgrounded process cannot hang us.
const EXIT_STDIO_GRACE_MS = 100;

const packageDir = dirname(fileURLToPath(import.meta.url));
type PermissionChoice = 'abort' | 'once' | 'session' | 'project' | 'global';
type NotificationLevel = Parameters<ExtensionContext['ui']['notify']>[1];

interface PromptOption {
  label: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

function permissionOptionsFor(ctx: ExtensionContext): PromptOption[] {
  const options: PromptOption[] = [
    { label: 'Allow once', action: 'once' },
    { label: 'Allow for this session', action: 'session' },
  ];
  if (isProjectTrusted(ctx)) {
    options.push({
      label: 'Allow for this project',
      action: 'project',
      confirm: true,
      hint: 'save to .pi/sandbox.json',
    });
  }
  options.push(
    {
      label: 'Allow for all projects',
      action: 'global',
      confirm: true,
      hint: 'save to ~/.pi/agent/sandbox.json',
    },
    { label: 'Keep blocked', action: 'abort' },
  );
  return options;
}
const NETWORK_PERMISSION_OPTIONS: PromptOption[] = [
  { label: 'Allow once', action: 'once' },
  { label: 'Allow for this session', action: 'session' },
  { label: 'Keep blocked', action: 'abort' },
];

type LoadedSandboxConfig = SandboxConfig & {
  explicitDenyRead: string[];
  explicitAllowRead: string[];
};

type SandboxGrantField =
  | Extract<keyof SandboxNetworkConfig, 'allowedDomains' | 'allowUnixSockets'>
  | Extract<keyof SandboxFilesystemConfig, 'allowRead' | 'allowWrite'>;

class SandboxConfigStore {
  readonly globalPath: string;
  readonly projectPath: string;

  constructor(cwd: string) {
    const { globalPath, projectPath } = getPiConfigPaths(cwd, 'sandbox.json');
    this.globalPath = globalPath;
    this.projectPath = projectPath;
  }

  private static readOrEmpty(configPath: string): SandboxConfigFile {
    if (!existsSync(configPath)) return {};
    try {
      return parseSandboxConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
    } catch (error) {
      throw new Error(`${configPath}: ${formatError(error)}`);
    }
  }

  private static write(configPath: string, config: SandboxConfigFile): void {
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf-8');
  }

  private static appendGrant(
    config: SandboxConfigFile,
    field: SandboxGrantField,
    value: string,
  ): boolean {
    switch (field) {
      case 'allowedDomains': {
        const existing = config.network?.allowedDomains ?? [];
        if (existing.includes(value)) return false;
        config.network = {
          ...config.network,
          allowedDomains: [...existing, value],
          deniedDomains: config.network?.deniedDomains ?? [],
        };
        return true;
      }
      case 'allowUnixSockets': {
        const existing = config.network?.allowUnixSockets ?? [];
        if (existing.includes(value)) return false;
        config.network = { ...config.network, allowUnixSockets: [...existing, value] };
        return true;
      }
      case 'allowRead': {
        const existing = config.filesystem?.allowRead ?? [];
        if (existing.includes(value)) return false;
        config.filesystem = { ...config.filesystem, allowRead: [...existing, value] };
        return true;
      }
      case 'allowWrite': {
        const existing = config.filesystem?.allowWrite ?? [];
        if (existing.includes(value)) return false;
        config.filesystem = { ...config.filesystem, allowWrite: [...existing, value] };
        return true;
      }
    }
  }

  changeScope(includeProject: boolean): SandboxConfigScope {
    return includeProject ? 'project' : 'global';
  }

  load(includeProject: boolean): LoadedSandboxConfig {
    if (!existsSync(this.globalPath)) {
      mkdirSync(dirname(this.globalPath), { recursive: true });
      writeFileSync(this.globalPath, '{}\n', 'utf-8');
    }

    const globalOverrides = SandboxConfigStore.readOrEmpty(this.globalPath);
    const projectOverrides = includeProject ? SandboxConfigStore.readOrEmpty(this.projectPath) : {};
    const globalConfig = deepMerge(
      JSON.parse(readFileSync(join(packageDir, 'sandbox.json'), 'utf-8')) as SandboxConfig,
      globalOverrides,
    );

    return {
      ...deepMerge(globalConfig, projectOverrides),
      explicitDenyRead: mergeArray(
        globalOverrides.filesystem?.denyRead ?? [],
        projectOverrides.filesystem?.denyRead,
      ),
      explicitAllowRead: mergeArray(
        globalOverrides.filesystem?.allowRead ?? [],
        projectOverrides.filesystem?.allowRead,
      ),
    };
  }

  enabledSettings(includeProject: boolean): { global: boolean; project?: boolean } {
    const global = this.load(false).enabled;
    if (!includeProject || !existsSync(this.projectPath)) return { global };
    const project = SandboxConfigStore.readOrEmpty(this.projectPath).enabled;
    return { global, project };
  }

  async setEnabled(scope: SandboxConfigScope, enabled: boolean | undefined): Promise<void> {
    const path = scope === 'project' ? this.projectPath : this.globalPath;
    await withFileMutationQueue(path, async () => {
      const config = SandboxConfigStore.readOrEmpty(path);
      if (enabled === undefined) delete config.enabled;
      else config.enabled = enabled;
      SandboxConfigStore.write(path, config);
    });
  }

  async persistGrant(
    choice: Exclude<PermissionChoice, 'abort'>,
    includeProject: boolean,
    field: SandboxGrantField,
    values: readonly string[],
  ): Promise<void> {
    const configPath =
      choice === 'global'
        ? this.globalPath
        : choice === 'project' && includeProject
          ? this.projectPath
          : undefined;
    if (!configPath) return;
    try {
      for (const value of values) {
        await withFileMutationQueue(configPath, async () => {
          const config = SandboxConfigStore.readOrEmpty(configPath);
          if (!SandboxConfigStore.appendGrant(config, field, value)) return;
          SandboxConfigStore.write(configPath, config);
        });
      }
    } catch (error) {
      throw new Error(
        `Failed to save sandbox permission to "${configPath}": ${formatError(error)}`,
        {
          cause: error,
        },
      );
    }
  }
}

type GrantChoice = Exclude<PermissionChoice, 'abort'>;

class SessionGrants {
  private readonly domains: string[] = [];
  private readonly readPaths: string[] = [];
  private readonly writePaths: string[] = [];
  private readonly unixSockets: string[] = [];
  private readonly targets: string[] = [];

  private static addUnique(target: string[] | undefined, value: string): void {
    if (target && !target.includes(value)) target.push(value);
  }

  reset(): void {
    this.domains.length = 0;
    this.readPaths.length = 0;
    this.writePaths.length = 0;
    this.unixSockets.length = 0;
    this.targets.length = 0;
  }

  overview(): Pick<SandboxOverview, 'sessionDomains' | 'sessionReadPaths' | 'sessionWritePaths'> {
    return {
      sessionDomains: [...this.domains],
      sessionReadPaths: [...this.readPaths],
      sessionWritePaths: [...this.writePaths],
    };
  }

  domainOverrides(allowances?: ExecutionAllowances): string[] {
    return [...new Set([...this.domains, ...(allowances?.domains ?? [])])];
  }

  effectiveUnixSockets(base: readonly string[]): string[] {
    return [...new Set([...base, ...this.unixSockets])];
  }

  effectiveAllowRead(
    config: SandboxConfig,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): string[] {
    const paths = [
      ...new Set([
        ...config.filesystem.allowRead,
        ...this.readPaths,
        ...(allowances?.readPaths ?? []),
      ]),
    ];
    if (process.platform !== 'win32') return paths;

    return paths.filter(
      (path) => !path.startsWith('/') && (path.includes('*') || existsSync(expandPath(path, cwd))),
    );
  }

  effectiveAllowWrite(config: SandboxConfig, allowances?: ExecutionAllowances): string[] {
    const paths = [
      ...new Set([
        ...config.filesystem.allowWrite,
        ...this.writePaths,
        ...(allowances?.writePaths ?? []),
      ]),
    ];
    return process.platform === 'win32' ? paths.filter((path) => !path.startsWith('/')) : paths;
  }

  explicitAllowRead(base: string[], approvedPaths: readonly string[]): string[] {
    return mergeArray(base, [...this.readPaths, ...approvedPaths]);
  }

  hasTarget(key: string, allowances: ExecutionAllowances): boolean {
    return this.targets.includes(key) || allowances.targets.includes(key);
  }

  grantDomain(choice: GrantChoice, domain: string, allowances?: ExecutionAllowances): void {
    SessionGrants.addUnique(choice === 'once' ? allowances?.domains : this.domains, domain);
  }

  grantTarget(choice: GrantChoice, key: string, allowances: ExecutionAllowances): void {
    SessionGrants.addUnique(choice === 'once' ? allowances.targets : this.targets, key);
  }

  grantUnixSocket(
    choice: GrantChoice,
    socketPath: string,
    key: string,
    allowances?: ExecutionAllowances,
  ): void {
    if (choice === 'once') {
      SessionGrants.addUnique(allowances?.targets, key);
      return;
    }
    SessionGrants.addUnique(this.unixSockets, socketPath);
    SessionGrants.addUnique(this.targets, key);
  }

  grantRead(
    choice: GrantChoice,
    scopes: readonly string[],
    allowances?: ExecutionAllowances,
  ): void {
    const target = choice === 'once' ? allowances?.readPaths : this.readPaths;
    for (const entry of scopes) {
      SessionGrants.addUnique(target, entry);
      SessionGrants.addUnique(allowances?.explicitDenyRead?.approvedPaths, entry);
    }
  }

  grantWrite(
    choice: GrantChoice,
    scopes: readonly string[],
    allowances?: ExecutionAllowances,
  ): void {
    const target = choice === 'once' ? allowances?.writePaths : this.writePaths;
    for (const entry of scopes) {
      SessionGrants.addUnique(target, entry);
    }
  }
}

type WindowsImplementation = 'appContainer' | 'restrictedUser';

interface WindowsStatus {
  active: WindowsImplementation;
  installed: boolean;
  healthy: boolean;
  proxyPortLow?: number;
  proxyPortHigh?: number;
}

function windowsStatus(): WindowsStatus {
  const result = spawnSync(binaryPath(), ['windows', 'status'], {
    encoding: 'utf-8',
    windowsHide: true,
  });
  if (result.error) throw result.error;

  let status: WindowsStatus;
  try {
    status = JSON.parse(result.stdout) as WindowsStatus;
  } catch {
    throw new Error(result.stderr.trim() || 'Windows sandbox status check failed');
  }
  if (result.status !== 0 || status.healthy !== true) {
    throw new Error(
      result.stderr.trim() ||
        'The Windows restricted-user installation is unhealthy. Run "landstrip windows status".',
    );
  }
  return status;
}

function shouldStartProxy(config: SandboxConfig): boolean {
  if (config.network.allowNetwork) return false;
  return (
    process.platform !== 'win32' ||
    windowsStatus().active === 'restrictedUser' ||
    config.windows.allowLoopback
  );
}

function restrictedUserProxyPortRange(): ProxyPortRange | undefined {
  if (process.platform !== 'win32') return undefined;

  const status = windowsStatus();
  if (status.active === 'appContainer') return undefined;
  if (
    status.installed !== true ||
    !Number.isInteger(status.proxyPortLow) ||
    !Number.isInteger(status.proxyPortHigh) ||
    status.proxyPortLow! < 1 ||
    status.proxyPortHigh! < status.proxyPortLow!
  ) {
    throw new Error(
      'The Windows restricted-user installation is unhealthy. Run "landstrip windows status".',
    );
  }
  return { low: status.proxyPortLow!, high: status.proxyPortHigh! };
}

export function matchesPattern(
  filePath: string,
  patterns: string[],
  cwd: string,
  explicitDenyGlobRoots?: Map<string, string[]>,
): boolean {
  if (!explicitDenyGlobRoots) {
    return matchesPathPattern(filePath, patterns, cwd);
  }
  const abs = normalizePathSeparators(canonicalizePath(filePath, cwd));

  return patterns.some((pattern) => {
    const absPattern = normalizePathSeparators(canonicalizeGlobPattern(pattern, cwd));

    if (/[*?[\]]/.test(pattern)) {
      // Mirror landstrip's matcher: `**/` spans directories, `**` spans any run,
      // but a single `*` stops at `/` — so `/srv/*/pub` cannot reach
      // `/srv/a/secret/pub`. Compiling `*` to `.*` would over-match across `/`.
      const matcher = globToRegExp(absPattern);
      // Native glob matches name directory roots as well as files. Descendants
      // inherit the matched directory's rule, including paths not created yet.
      for (let candidate = abs; ;) {
        if (matcher.test(candidate)) return true;
        const parent = normalizePathSeparators(dirname(candidate));
        if (parent === candidate) break;
        candidate = parent;
      }

      // Only explicit worker denies need native glob lowering. Retain the
      // canonical roots per worker so trap queries never repeat the traversal.
      if (!explicitDenyGlobRoots) return false;
      let roots = explicitDenyGlobRoots.get(absPattern);
      if (!roots) {
        const resolvedRoots: string[] = [];
        const wildcard = absPattern.search(/[*?[\]]/);
        const base = absPattern.slice(0, absPattern.lastIndexOf('/', wildcard) + 1);
        const suffix = absPattern.slice(base.length);
        const segments = suffix.match(/(?:\[[^\]]*\]|[^/])+/g) ?? [];
        const recursive = suffix.includes('**');
        const visit = (directory: string, depth: number): void => {
          if (depth >= 40) throw new Error(`Glob traversal depth exceeded for "${pattern}"`);
          let entries;
          try {
            entries = readdirSync(directory, { withFileTypes: true });
          } catch (error) {
            if (
              isRecord(error) &&
              ['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(String(error.code))
            ) {
              return;
            }
            throw error;
          }
          for (const entry of entries) {
            const candidate = normalizePathSeparators(join(directory, entry.name));
            // Match the alias before canonicalizing: `/runtime/ali*` can lower
            // to a root such as `/opt/worker` that does not match lexically.
            if (entry.isSymbolicLink() && matcher.test(candidate)) {
              resolvedRoots.push(normalizePathSeparators(canonicalizePath(candidate, cwd)));
            }
            // Like native expansion, never descend through a symlink. Without
            // globstars, prune directories that cannot match the next segment.
            if (
              entry.isDirectory() &&
              (recursive ||
                (depth + 1 < segments.length && globToRegExp(segments[depth]!).test(entry.name)))
            ) {
              visit(candidate, depth + 1);
            }
          }
        };
        visit(base, 0);
        roots = resolvedRoots;
        explicitDenyGlobRoots.set(absPattern, roots);
      }
      return roots.some(
        (target) => abs === target || abs.startsWith(target.endsWith('/') ? target : `${target}/`),
      );
    }

    const sep = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sep);
  });
}

function readAllowed(path: string, allowRead: string[], denyRead: string[], cwd: string): boolean {
  return isPathReadAllowed(path, allowRead, denyRead, cwd);
}

function extractDeniedPathMention(
  output: string,
  cwd: string,
  denied: (path: string) => boolean,
): string | null {
  const start = /(?<=^|['"`\s=:(])(?=\/|[a-zA-Z]:[\\/])/g;
  for (const line of output.split(/\r?\n/)) {
    for (const match of line.matchAll(start)) {
      const raw = line.slice(match.index);
      const quoted = raw.match(/^([^'"`]+)['"`]/);
      const words = (quoted ? quoted[1] : raw).replace(/[.,:;)\]]+$/, '').split(' ');
      for (let count = words.length; count > 0; count -= 1) {
        const candidate = words.slice(0, count).join(' ');
        if (!existsSync(candidate)) continue;
        const path = normalizeBlockedPath(candidate, cwd);
        if (denied(path)) return path;
        break;
      }
    }
  }
  return null;
}

export function extractRetryableNativeReadDeniedPath(
  output: string,
  cwd: string,
  allowRead: string[],
  denyRead: string[],
): string | null {
  const denied = (path: string): boolean => !readAllowed(path, allowRead, denyRead, cwd);
  const path = extractNativeDeniedPath(output, cwd);
  if (path) return denied(path) ? path : null;
  return extractDeniedPathMention(output, cwd, denied);
}

function notify(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
  if (!ctx.hasUI) return;
  ctx.ui.notify(message, level);
}

function hasTuiStatus(ctx: ExtensionContext): boolean {
  if (!ctx.hasUI) return false;
  const mode = ctx.mode;
  return mode === undefined || mode === 'tui';
}

function setTuiStatus(ctx: ExtensionContext, key: string, value: string | undefined): void {
  if (!hasTuiStatus(ctx)) return;
  ctx.ui.setStatus(key, value);
}

function patchProcessGroupKill(child: ChildProcess): void {
  const kill = child.kill.bind(child);
  child.kill = (signal?: NodeJS.Signals | number): boolean => {
    if (signal === 0 || child.pid === undefined) return kill(signal);
    if (process.platform === 'win32') {
      const result = spawnSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
      if (result.status === 0) return true;
    } else {
      try {
        process.kill(-child.pid, signal);
        return true;
      } catch {
        // Fall back when the process exited before its group was signalled.
      }
    }
    return kill(signal);
  };
}

async function stopPreparedChild(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.pid === undefined || child.exitCode !== null || child.signalCode !== null) {
    return;
  }

  const waitForExit = (timeoutMs: number): Promise<void> => {
    if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
    return new Promise<void>((resolveExit) => {
      const settleTimer = setTimeout(() => {
        child.off('exit', onExit);
        resolveExit();
      }, timeoutMs);
      const onExit = (): void => {
        clearTimeout(settleTimer);
        resolveExit();
      };
      child.once('exit', onExit);
    });
  };

  if (process.platform !== 'win32') {
    child.kill('SIGTERM');
    await waitForExit(200);
    if (child.exitCode !== null || child.signalCode !== null) return;
  }

  child.kill('SIGKILL');
  await waitForExit(1_000);
}

async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
  options: PromptOption[],
  signal?: AbortSignal,
  label?: string,
): Promise<PermissionChoice> {
  if (!ctx.hasUI) return 'abort';

  const labels = options.map((option) =>
    option.hint ? `${option.label} — ${option.hint}` : option.label,
  );
  const selected = await ctx.ui.select(label ? `${label}\n${title}` : title, labels, { signal });
  if (signal?.aborted) return 'abort';
  const index = selected === undefined ? -1 : labels.indexOf(selected);
  const option = options[index];
  if (!option) return 'abort';
  if (option.confirm) {
    const confirmed = await ctx.ui.confirm(
      label ? `${label}\nSave this permission?` : 'Save this permission?',
      `${title}\n\n${option.hint ?? 'This changes persisted sandbox policy.'}`,
      { signal },
    );
    if (!confirmed || signal?.aborted) return 'abort';
  }
  return option.action;
}

function promptFilesystemBlock(
  ctx: ExtensionContext,
  operation: 'read' | 'write',
  filePath: string,
  reason?: string,
  signal?: AbortSignal,
  label?: string,
): Promise<PermissionChoice> {
  const [verb, denyField, allowField] =
    operation === 'read' ? ['Read', 'denyRead', 'allowRead'] : ['Write', 'denyWrite', 'allowWrite'];
  const title = reason
    ? `${verb} blocked: "${filePath}" is in ${denyField} (${reason})`
    : `${verb} blocked: "${filePath}" is not in ${allowField}`;
  return showPermissionPrompt(ctx, title, permissionOptionsFor(ctx), signal, label);
}

// Write the full environment to a temporary shell file.
//
// Sandboxed process reaches environment through the filesystem instead of the
// execve() argument buffer, which has a ~128 KiB cap.
export function writeEnvFile(
  env: NodeJS.ProcessEnv,
  proxyPort: number | null,
  proxyToken?: string,
): { dir: string; path: string } {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    // bash exports non-identifier names (e.g. a `BASH_FUNC_foo%%` function
    // export) that `export NAME=...` rejects; emitting one makes `source` exit
    // non-zero and the `&&`-chained command never runs. Skip what the shell
    // itself cannot set.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    lines.push(`export ${key}=${quoteShell([value])}`);
  }
  if (proxyPort !== null) {
    const proxyVars = createProxyEnvironment(proxyPort, { token: proxyToken });
    for (const [name, value] of Object.entries(proxyVars)) {
      if (value === undefined) continue;
      lines.push(`export ${name}=${quoteShell([value])}`);
    }
  }
  const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-env-'));
  const path = join(dir, 'env.sh');
  writeFileSync(path, lines.join('\n'), 'utf-8');
  return { dir, path };
}

export const POSIX_SHELL_PROVIDER_ID = 'posix';

export function createPosixShellProvider(): LandstripShellProvider {
  return {
    id: POSIX_SHELL_PROVIDER_ID,
    prepare(options: LandstripShellPrepareOptions): LandstripShellInvocation {
      if (options.signal?.aborted) throw new Error('aborted');
      const { shell, args } = getShellConfig(SettingsManager.create(options.cwd).getShellPath());
      const envFile = writeEnvFile(options.env, null);
      let disposed = false;

      return {
        executable: shell,
        args: [...args, `source ${quoteShell([envFile.path])} && ${options.command}`],
        launcherEnv: { PATH: process.env.PATH, HOME: process.env.HOME },
        readPaths: [envFile.path],
        dispose() {
          if (disposed) return;
          disposed = true;
          rmSync(envFile.dir, { recursive: true, force: true });
        },
      };
    },
  };
}

function shellEnvironment(
  env: NodeJS.ProcessEnv | undefined,
  cwd: string,
  proxyPort: number | null,
  proxyToken?: string,
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = { ...process.env, ...env, PWD: resolve(cwd) };
  return createProxyEnvironment(proxyPort, { token: proxyToken, baseEnv: result });
}

// The runner needs ProgramData and LOCALAPPDATA to set up the AppContainer
// (without them the launch fails with ERROR_ENVVAR_NOT_FOUND, os error 203),
// and the sandboxed program needs SystemRoot and its companions to start.
const WINDOWS_LAUNCHER_ENVIRONMENT = [
  'ProgramData',
  'LOCALAPPDATA',
  'SystemRoot',
  'windir',
  'ComSpec',
  'PATHEXT',
] as const;

export function createLandstripLauncherEnvironment(
  providerEnv: NodeJS.ProcessEnv,
  hostEnv: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  if (platform !== 'win32') return providerEnv;
  const result: NodeJS.ProcessEnv = { ...providerEnv };
  for (const name of WINDOWS_LAUNCHER_ENVIRONMENT) {
    const value = hostEnv[name];
    if (value !== undefined) result[name] = value;
  }
  return result;
}

export function createWindowsDenyRead(denyRead: readonly string[], volumeRoot: string): string[] {
  return [...new Set([...denyRead.filter((path) => !path.startsWith('/')), volumeRoot])];
}

/** Options for creating a landstrip sandbox integration. */
export interface LandstripIntegrationOptions {
  /** Register a sandboxed bash tool when the integration is registered. */
  readonly registerBashTool?: boolean;
  /** Working directory used when registering the default bash tool. */
  readonly cwd?: string;
  /** Subagent and background task runtime. */
  readonly subagentRuntime?: SubagentRuntime;
}

/** Filesystem access requested by a primary Pi file tool. */
export interface FilesystemToolAccess {
  readonly operation: 'read' | 'write';
  readonly path: string;
}

/** Result of applying sandbox filesystem policy before a Pi file tool runs. */
export interface FilesystemToolAuthorization {
  readonly allowed: boolean;
  readonly prompted: boolean;
  readonly reason?: string;
}

export interface FilesystemToolAuthorizationOptions {
  readonly signal?: AbortSignal;
  readonly authorizationNote?: string;
}

/** Landstrip sandbox integration hooks for Pi. */
export interface LandstripIntegration extends PiLandstripRuntimeV3 {
  /** Resolve a permission ask through the registered external provider. */
  resolvePermissionAsk(
    request: LandstripPermissionAskRequest,
  ): Promise<LandstripPermissionAskDecision>;
  /** Prepare a full Pi RPC process constrained by the effective sandbox policy. */
  prepareRpcWorker(options: LandstripRpcWorkerOptions): Promise<LandstripRpcWorkerLaunch>;
  /** Apply sandbox filesystem rules before a primary Pi file tool runs. */
  authorizeFilesystemToolAccess(
    ctx: ExtensionContext,
    accesses: readonly FilesystemToolAccess[],
    options?: FilesystemToolAuthorizationOptions,
  ): Promise<FilesystemToolAuthorization>;
  /** Register the integration's tools, events, flags, and commands with Pi. */
  register(pi: ExtensionAPI): void;
  /** Return the active Pi extension context, when a session is running. */
  getExtensionContext(): ExtensionContext | undefined;
  /** Publish an integration lifecycle event from an embedded runtime. */
  emit(event: LandstripEvent): void;
  /** Callbacks for querying and toggling sandbox state. */
  readonly sandboxCallbacks?: SandboxCallbacks;
  /** Run a command through the effective Landstrip shell environment and sandbox. */
  runSandboxedCommand?(
    command: string,
    cwd: string,
    options: {
      timeout?: number;
      signal?: AbortSignal;
      onData?: (chunk: Buffer) => void;
      onErrorFd?: (chunk: Buffer) => void;
      env?: NodeJS.ProcessEnv;
      promptOnBlock?: boolean;
      permissionPromptLabel?: string;
    },
    ctx: ExtensionContext,
  ): Promise<{ exitCode: number | null }>;
  /** Connect the subagent and background task runtime. */
  setSubagentRuntime?(runtime: SubagentRuntime): void;
}

/** Callbacks for editing sandbox state from the agents dashboard. */
export interface SandboxCallbacks {
  load(cwd: string, includeProject: boolean): { global: boolean; project?: boolean };
  setEnabled(ctx: ExtensionContext, enabled: boolean, scope: SandboxConfigScope): Promise<void>;
  clearProject(ctx: ExtensionContext): Promise<void>;
  overview(cwd: string, includeProject: boolean): SandboxOverview;
}

/** Display data for the sandbox section of the settings pane. */
export interface SandboxOverview {
  readonly enabled: boolean;
  readonly running: boolean;
  readonly noSandboxFlag: boolean;
  readonly networkMode: 'unrestricted' | 'blocked' | 'proxied';
  readonly shellReadMode: 'host' | 'policy';
  readonly readRuleScope: string;
  readonly windowsMode?: string;
  readonly changeScope: SandboxConfigScope;
  readonly paths: { readonly global: string; readonly project: string; readonly binary: string };
  readonly config: SandboxConfig;
  readonly sessionDomains: readonly string[];
  readonly sessionReadPaths: readonly string[];
  readonly sessionWritePaths: readonly string[];
}

export interface LandstripRpcWorkerOptions extends LandstripProcessOptions {
  readonly permissionPromptLabel?: string;
  readonly env: NodeJS.ProcessEnv;
  readonly readPaths: readonly string[];
  readonly writePaths: readonly string[];
  readonly protectedPaths?: readonly string[];
  /** Domains the worker may reach through the filter proxy without prompting. */
  readonly domains?: readonly string[];
}

export interface LandstripRpcWorkerLaunch extends Omit<LandstripPreparedProcess, 'spawn'> {
  readonly spawn: RpcSpawn;
}

export type {
  LandstripContextV3,
  LandstripEvent,
  LandstripPermissionAsk,
  LandstripPermissionAskDecision,
  LandstripPermissionAskProvider,
  LandstripPermissionAskRequest,
  LandstripPreparedProcess,
  LandstripProcessOptions,
  LandstripSandboxState,
  LandstripShellInvocation,
  LandstripShellPrepareOptions,
  LandstripShellProvider,
  LandstripWorkerExtension,
  PiLandstripRuntimeV3,
} from './api.ts';

/** Register the landstrip extension with Pi. */
export default function (pi: ExtensionAPI) {
  const workerConfig = workerConfigFromEnvironment();
  if (workerConfig) {
    registerSubagentWorker(pi, workerConfig);
    return;
  }
  const permissionPrompts = new PermissionPromptCoordinator();
  const integration = createLandstripIntegrationWithPrompts({}, permissionPrompts);
  const subagentRuntime = registerSubagents(pi, integration, permissionPrompts);
  integration.setSubagentRuntime?.(subagentRuntime);
  integration.register(pi);
}

/** Create a landstrip integration for registration or custom embedding. */
export function createLandstripIntegration(
  options: LandstripIntegrationOptions = {},
): LandstripIntegration {
  return createLandstripIntegrationWithPrompts(options, new PermissionPromptCoordinator());
}

function createLandstripIntegrationWithPrompts(
  options: LandstripIntegrationOptions,
  permissionPrompts: PermissionPromptCoordinator,
): LandstripIntegration {
  const shouldRegisterBashTool = options.registerBashTool ?? true;
  const localCwd = options.cwd ?? process.cwd();
  let subagentRuntime: SubagentRuntime | undefined = options.subagentRuntime;
  let projectConfigTrusted = false;

  function isProjectConfigTrusted(ctx = activeContext): boolean {
    return ctx ? isProjectTrusted(ctx) : projectConfigTrusted;
  }

  function loadConfig(cwd: string, ctx = activeContext): LoadedSandboxConfig {
    return new SandboxConfigStore(cwd).load(isProjectConfigTrusted(ctx));
  }

  let sandboxEnabled = false;
  let sandboxReady = false;
  let sandboxState: LandstripSandboxState = 'unavailable';
  let unsandboxedWorkerWarningShown = false;
  let activeContext: ExtensionContext | undefined;
  let unpublishRuntime: (() => void) | undefined;
  const defaultShellProvider = createPosixShellProvider();
  let externalShellProvider: LandstripShellProvider | undefined;
  let externalPermissionAskProvider: LandstripPermissionAskProvider | undefined;
  const eventHandlers = new Set<(event: LandstripEvent) => void>();
  const workerExtensions = new Map<string, { entry: string; registrations: number }>();
  const sessionGrants = new SessionGrants();
  function getContext(ctx = activeContext): LandstripContextV3 {
    return {
      version: LANDSTRIP_RUNTIME_VERSION,
      host: 'pi',
      role: 'primary',
      sandbox: sandboxState,
      cwd: ctx?.cwd ?? localCwd,
      sessionId: ctx?.sessionManager?.getSessionId(),
      depth: 0,
    };
  }

  function emitEvent(event: LandstripEvent): void {
    for (const handler of eventHandlers) {
      try {
        handler(event);
      } catch (error) {
        console.error(`pi-landstrip: lifecycle listener failed: ${formatError(error)}`);
      }
    }
  }

  function setSandboxState(state: LandstripSandboxState, ctx: ExtensionContext): void {
    if (sandboxState === state) return;
    sandboxState = state;
    emitEvent({ type: 'sandbox.changed', context: getContext(ctx) });
  }

  function on<T extends LandstripEvent['type']>(
    type: T,
    handler: (event: Extract<LandstripEvent, { type: T }>) => void,
  ): () => void {
    const listener = (event: LandstripEvent): void => {
      if (event.type === type) handler(event as Extract<LandstripEvent, { type: T }>);
    };
    eventHandlers.add(listener);
    return () => eventHandlers.delete(listener);
  }

  function registerShellProvider(provider: LandstripShellProvider): () => void {
    const id = provider.id.trim();
    if (!id) throw new Error('Shell provider id must not be empty');
    if (id === POSIX_SHELL_PROVIDER_ID) {
      throw new Error(`Shell provider id "${POSIX_SHELL_PROVIDER_ID}" is reserved`);
    }
    if (externalShellProvider) {
      throw new Error(
        `Shell provider "${externalShellProvider.id}" is already registered; cannot register "${id}"`,
      );
    }

    externalShellProvider = provider;
    let disposed = false;
    return () => {
      if (disposed) return;
      disposed = true;
      if (externalShellProvider === provider) externalShellProvider = undefined;
    };
  }

  function registerPermissionAskProvider(provider: LandstripPermissionAskProvider): () => void {
    const id = provider.id.trim();
    if (!id) throw new Error('Permission ask provider id must not be empty');
    if (externalPermissionAskProvider) {
      throw new Error(
        `Permission ask provider "${externalPermissionAskProvider.id}" is already registered; cannot register "${id}"`,
      );
    }

    externalPermissionAskProvider = provider;
    let disposed = false;
    return () => {
      if (disposed) return;
      disposed = true;
      if (externalPermissionAskProvider === provider) externalPermissionAskProvider = undefined;
    };
  }

  async function resolvePermissionAsk(
    request: LandstripPermissionAskRequest,
  ): Promise<LandstripPermissionAskDecision> {
    const provider = externalPermissionAskProvider;
    if (!provider) return { decision: 'abstain' };

    const result: unknown = await provider.decide(request);
    if (
      typeof result !== 'object' ||
      result === null ||
      !('decision' in result) ||
      typeof result.decision !== 'string' ||
      !['allow', 'deny', 'abstain'].includes(result.decision) ||
      ('reason' in result && result.reason !== undefined && typeof result.reason !== 'string')
    ) {
      throw new Error(`Permission ask provider "${provider.id}" returned an invalid decision`);
    }
    return result as LandstripPermissionAskDecision;
  }

  function activeShellProvider(): LandstripShellProvider {
    return externalShellProvider ?? defaultShellProvider;
  }

  function registerWorkerExtension(extension: LandstripWorkerExtension): () => void {
    const id = extension.id.trim();
    if (!id) throw new Error('Worker extension id must not be empty');
    const requestedEntry = extension.entry.startsWith('file:')
      ? fileURLToPath(extension.entry)
      : extension.entry;
    if (!isAbsolute(requestedEntry)) {
      throw new Error('Worker extension entry must be an absolute path or file URL');
    }
    if (!existsSync(requestedEntry)) {
      throw new Error(`Worker extension entry does not exist: ${requestedEntry}`);
    }
    const entry = realpathSync(requestedEntry);

    const existing = workerExtensions.get(id);
    if (existing && existing.entry !== entry) {
      throw new Error(`Worker extension id is already registered with another entry: ${id}`);
    }
    if (existing) existing.registrations += 1;
    else workerExtensions.set(id, { entry, registrations: 1 });

    let disposed = false;
    return () => {
      if (disposed) return;
      disposed = true;
      const registration = workerExtensions.get(id);
      if (!registration || registration.entry !== entry) return;
      registration.registrations -= 1;
      if (registration.registrations === 0) workerExtensions.delete(id);
    };
  }

  function getWorkerExtensions(): readonly LandstripWorkerExtension[] {
    return [...workerExtensions].map(([id, extension]) => ({ id, entry: extension.entry }));
  }

  function getEffectiveDenyRead(config: SandboxConfig, cwd: string): string[] {
    if (process.platform !== 'win32') return config.filesystem.denyRead;

    // Windows sandbox ACLs propagate to existing descendants, so make read policy
    // an explicit allowlist instead of scanning and granting a volume tree. Ignore
    // POSIX-only absolute paths because no corresponding ACL target exists.
    const volumeRoot = parse(resolve(cwd)).root;
    return createWindowsDenyRead(config.filesystem.denyRead, volumeRoot);
  }

  function hasBaselineWindowsApplicationAccess(filePath: string): boolean {
    const normalizedPath = normalizePathSeparators(resolve(filePath)).toLowerCase();
    const systemRoots = [
      process.env.ProgramFiles,
      process.env['ProgramFiles(x86)'],
      process.env.ProgramW6432,
      process.env.SystemRoot,
    ];

    return systemRoots.some((root) => {
      if (!root) return false;
      return pathUnderDirectory(
        normalizedPath,
        normalizePathSeparators(resolve(root)).toLowerCase(),
      );
    });
  }

  function withWindowsProcessReadAccess(
    allowances: ExecutionAllowances,
    command: string,
    cwd: string,
    additionalPaths: string[] = [],
  ): ExecutionAllowances {
    if (process.platform !== 'win32') return allowances;

    const executable = resolve(cwd, command);
    // Both standard AppContainers and restricted-user tokens receive baseline
    // read/execute access to Windows and Program Files through ALL APPLICATION
    // PACKAGES. Adding a sandbox-specific ACE there requires elevated WRITE_DAC.
    const executablePaths = hasBaselineWindowsApplicationAccess(executable) ? [] : [executable];
    return {
      ...allowances,
      readPaths: [...new Set([...allowances.readPaths, ...executablePaths, ...additionalPaths])],
    };
  }

  async function applyDomainChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    await new SandboxConfigStore(cwd).persistGrant(
      choice,
      isProjectConfigTrusted(ctx),
      'allowedDomains',
      [domain],
    );
    sessionGrants.grantDomain(choice, domain, allowances);
  }

  async function applyUnixSocketChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    socketPath: string,
    key: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    await new SandboxConfigStore(cwd).persistGrant(
      choice,
      isProjectConfigTrusted(ctx),
      'allowUnixSockets',
      [socketPath],
    );
    sessionGrants.grantUnixSocket(choice, socketPath, key, allowances);
  }

  // Breadth-first: approve the broadest reasonable ancestor of the blocked file
  // (see sessionScopeFor) instead of the exact path, so the still-running
  // command stops prompting for sibling files under the same tree. When the
  // scope widens beyond the file, tell the user what was actually granted.
  function noteScope(
    ctx: ExtensionContext,
    verb: string,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    scopes: readonly string[],
  ): void {
    if (scopes.length !== 1 || scopes[0] !== filePath) {
      notify(ctx, `${verb} allowed (${choice}): ${scopes.join(', ')}`, 'info');
    }
  }

  async function applyReadChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
    scope = sessionScopeFor(filePath, cwd),
  ): Promise<void> {
    const config = loadConfig(cwd, ctx);
    const effectiveDenyRead = allowances?.explicitDenyRead
      ? mergeArray(config.filesystem.denyRead, [
          ...allowances.explicitDenyRead.patterns,
          ...[...allowances.explicitDenyRead.globRoots.values()].flat(),
        ])
      : config.filesystem.denyRead;
    const scopes = readGrantScopesFor(
      filePath,
      sessionGrants.effectiveAllowRead(config, cwd, allowances),
      effectiveDenyRead,
      cwd,
      scope,
    );
    await new SandboxConfigStore(cwd).persistGrant(
      choice,
      isProjectConfigTrusted(ctx),
      'allowRead',
      scopes,
    );
    sessionGrants.grantRead(choice, scopes, allowances);
    noteScope(ctx, 'Read', choice, filePath, scopes);
  }

  async function applyWriteChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const config = loadConfig(cwd, ctx);
    const scopes = writeGrantScopesFor(
      filePath,
      sessionGrants.effectiveAllowWrite(config, allowances),
      config.filesystem.denyWrite,
      cwd,
    );
    await new SandboxConfigStore(cwd).persistGrant(
      choice,
      isProjectConfigTrusted(ctx),
      'allowWrite',
      scopes,
    );
    sessionGrants.grantWrite(choice, scopes, allowances);
    noteScope(ctx, 'Write', choice, filePath, scopes);
  }

  async function authorizeFilesystemToolAccess(
    ctx: ExtensionContext,
    accesses: readonly FilesystemToolAccess[],
    options: FilesystemToolAuthorizationOptions = {},
  ): Promise<FilesystemToolAuthorization> {
    const normalized = [
      ...new Map(
        accesses.map((access) => {
          const path = normalizeBlockedPath(access.path, ctx.cwd);
          return [`${access.operation}\u0000${path}`, { ...access, path }] as const;
        }),
      ).values(),
    ];

    if (getNoSandboxFlag()) return { allowed: true, prompted: false };

    const blockedAccesses = (config: SandboxConfig): FilesystemToolAccess[] => {
      const enforceReads = enforcesShellReadPolicy(config.shell.readAccess);
      return normalized.filter((access) =>
        access.operation === 'read'
          ? enforceReads &&
            !readAllowed(
              access.path,
              sessionGrants.effectiveAllowRead(config, ctx.cwd),
              getEffectiveDenyRead(config, ctx.cwd),
              ctx.cwd,
            )
          : shouldPromptForWrite(
              access.path,
              sessionGrants.effectiveAllowWrite(config),
              config.filesystem.denyWrite,
              ctx.cwd,
            ),
      );
    };

    const current = (): FilesystemToolAuthorization | undefined => {
      const config = loadConfig(ctx.cwd, ctx);
      if (!config.enabled) return { allowed: true, prompted: false };
      for (const access of normalized) {
        const denied =
          access.operation === 'read'
            ? matchesPattern(access.path, config.filesystem.denyReadAlways, ctx.cwd)
            : matchesWriteDenyPattern(
                access.path,
                config.filesystem.denyWriteAlways,
                ctx.cwd,
                sessionGrants.effectiveAllowWrite(config),
              );
        if (denied) {
          return {
            allowed: false,
            prompted: false,
            reason: `${access.operation === 'read' ? 'Read' : 'Write'} denied by sandbox policy: ${access.path}`,
          };
        }
      }

      return blockedAccesses(config).length === 0 ? { allowed: true, prompted: false } : undefined;
    };

    if (!ctx.hasUI) {
      return (
        current() ?? {
          allowed: false,
          prompted: false,
          reason: 'Filesystem access requires approval',
        }
      );
    }
    return permissionPrompts.resolve(
      current,
      async (promptSignal) => {
        const blocked = blockedAccesses(loadConfig(ctx.cwd, ctx));
        const paths = blocked.map(({ operation, path }) => `${operation}: ${path}`).join('\n');
        const note = options.authorizationNote ? `\n\n${options.authorizationNote}` : '';
        const choice = await showPermissionPrompt(
          ctx,
          `Filesystem policy blocked this tool call:\n${paths}${note}`,
          permissionOptionsFor(ctx),
          promptSignal,
        );
        if (choice === 'abort' || promptSignal.aborted) {
          return { allowed: false, prompted: true, reason: 'Filesystem access denied' };
        }
        for (const access of blocked) {
          if (access.operation === 'read') {
            await applyReadChoice(ctx, choice, access.path, ctx.cwd);
          } else {
            await applyWriteChoice(ctx, choice, access.path, ctx.cwd);
          }
        }
        return { allowed: true, prompted: true };
      },
      options.signal,
    );
  }

  async function ensureDomainAllowed(
    ctx: ExtensionContext,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
    signal?: AbortSignal,
  ): Promise<boolean> {
    const current = (): boolean | undefined => {
      const config = loadConfig(cwd, ctx);
      const decision = evaluateDomainAccess(domain, config.network, {
        allowedDomainsOverrides: sessionGrants.domainOverrides(allowances),
      });
      if (decision === 'deny') return false;
      if (decision === 'allow') return true;
      return undefined;
    };
    if (!ctx.hasUI) return current() ?? false;

    return permissionPrompts.resolve(
      current,
      async (promptSignal) => {
        const choice = await showPermissionPrompt(
          ctx,
          `Network blocked: "${domain}" is not in the allowed domains list`,
          permissionOptionsFor(ctx),
          promptSignal,
          allowances?.permissionPromptLabel,
        );
        if (choice === 'abort' || promptSignal.aborted) return false;
        await applyDomainChoice(ctx, choice, domain, cwd, allowances);
        return true;
      },
      signal,
    );
  }

  function buildLandstripPolicy(
    cwd: string,
    proxyPort: number | null,
    audience: PolicyAudience,
    allowances?: ExecutionAllowances,
    ctx = activeContext,
  ): LandstripPolicy {
    const config = loadConfig(cwd, ctx);
    const readPolicy = resolveProcessReadPolicy(
      audience,
      config.shell.readAccess,
      mergeArray(getEffectiveDenyRead(config, cwd), [
        ...(allowances?.explicitDenyRead?.patterns ?? []),
        ...[...(allowances?.explicitDenyRead?.globRoots.values() ?? [])].flat(),
      ]),
      sessionGrants.effectiveAllowRead(config, cwd, allowances),
    );

    return assembleLandstripPolicy({
      network: {
        ...config.network,
        allowUnixSockets: sessionGrants.effectiveUnixSockets(config.network.allowUnixSockets),
      },
      filesystem: {
        ...readPolicy,
        denyReadAlways: mergeArray(config.filesystem.denyReadAlways, allowances?.protectedPaths),
        allowWrite: sessionGrants.effectiveAllowWrite(config, allowances),
        denyWrite: mergeArray(config.filesystem.denyWrite, allowances?.protectedPaths),
        denyWriteAlways: mergeArray(config.filesystem.denyWriteAlways, allowances?.protectedPaths),
      },
      macos: config.macos,
      windows: config.windows,
      httpProxyPort: proxyPort,
    });
  }

  function writePolicyFile(
    cwd: string,
    proxyPort: number | null,
    audience: PolicyAudience,
    allowances?: ExecutionAllowances,
    ctx = activeContext,
  ): { dir: string; path: string } {
    return writeLandstripPolicyFile(
      buildLandstripPolicy(cwd, proxyPort, audience, allowances, ctx),
      'pi-landstrip-',
    );
  }

  function startProxy(
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    signal?: AbortSignal,
    authorization?: string,
    portRange?: ProxyPortRange,
  ): Promise<{ port: number; stop: () => Promise<void> }> {
    return startFilterProxy({
      isDomainAllowed: async (domain) => {
        const config = loadConfig(cwd, ctx);
        if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
        return ensureDomainAllowed(ctx, domain, cwd, allowances, signal);
      },
      authorization,
      portRange,
    });
  }

  function createSocketPair(): Promise<[NetSocket, NetSocket]> {
    return new Promise((resolve, reject) => {
      const server = createServer();
      server.on('error', reject);
      let client: NetSocket | null = null;
      server.on('connection', (serverEnd) => {
        server.removeListener('error', reject);
        server.close();
        if (client) {
          client.removeListener('error', reject);
          resolve([client, serverEnd]);
        }
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as AddressInfo;
        client = new NetSocket();
        client.on('error', reject);
        client.connect(addr.port, '127.0.0.1');
      });
    });
  }

  interface TrapQueryResult {
    action: LandstripControlResponse['action'];
    granted?: boolean;
    reason?: 'unprompted' | 'rejected' | 'hard-deny';
  }

  async function resolveTrapQuery(
    trap: LandstripQueryTrap | { kind: 'filesystem'; operation: 'read' | 'write'; path: string },
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    promptOnBlock: boolean,
    signal?: AbortSignal,
    readScope?: string,
  ): Promise<TrapQueryResult> {
    // Non-loopback IP endpoints only carry address:port and can only be granted
    // for the current command or session. Filesystem Unix domain sockets carry
    // their socket path and can also be persisted to network.allowUnixSockets.
    if (trap.kind !== 'filesystem') {
      const isUnixSocket = isAbsolute(trap.target);
      const socketPath = isUnixSocket ? normalizeBlockedPath(trap.target, cwd) : trap.target;
      const key = `${trap.operation}\u0000${socketPath}`;
      const current = (): TrapQueryResult | undefined => {
        if (allowances.rejectedTargets?.has(key)) {
          return { action: 'deny', reason: 'rejected' };
        }
        if (sessionGrants.hasTarget(key, allowances)) {
          return { action: 'allow' };
        }
        if (isUnixSocket) {
          const config = loadConfig(cwd, ctx);
          if (
            config.network.allowAllUnixSockets ||
            matchesPattern(
              socketPath,
              sessionGrants.effectiveUnixSockets(config.network.allowUnixSockets),
              cwd,
            )
          ) {
            return { action: 'allow' };
          }
        }
        return undefined;
      };
      if (!ctx.hasUI || !promptOnBlock) {
        return current() ?? { action: 'deny', reason: 'unprompted' };
      }

      return permissionPrompts.resolve(
        current,
        async (promptSignal) => {
          const choice = await showPermissionPrompt(
            ctx,
            isUnixSocket
              ? `Unix socket blocked: ${trap.operation} "${socketPath}"`
              : `Network blocked: ${trap.operation} "${trap.target}"`,
            isUnixSocket ? permissionOptionsFor(ctx) : NETWORK_PERMISSION_OPTIONS,
            promptSignal,
            allowances.permissionPromptLabel,
          );
          if (choice === 'abort' || promptSignal.aborted) {
            if (!promptSignal.aborted) (allowances.rejectedTargets ??= new Set()).add(key);
            return { action: 'deny', reason: 'rejected' };
          }
          if (isUnixSocket) {
            try {
              await applyUnixSocketChoice(ctx, choice, socketPath, key, cwd, allowances);
            } catch (error) {
              (allowances.rejectedTargets ??= new Set()).add(key);
              throw error;
            }
          } else {
            sessionGrants.grantTarget(choice, key, allowances);
          }
          return { action: 'allow' };
        },
        signal,
      );
    }

    const path = normalizeBlockedPath(trap.path, cwd);
    let initialCheck = true;
    const current = (): TrapQueryResult | undefined => {
      const granted = !initialCheck;
      initialCheck = false;
      if (matchesPattern(path, allowances.protectedPaths ?? [], cwd)) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      const config = loadConfig(cwd, ctx);
      if (
        trap.operation === 'read' &&
        matchesPattern(path, config.filesystem.denyReadAlways, cwd)
      ) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      if (
        trap.operation === 'read' &&
        allowances.explicitDenyRead &&
        matchesPattern(
          path,
          mergeArray(allowances.explicitDenyRead.patterns, config.explicitDenyRead),
          cwd,
          allowances.explicitDenyRead.globRoots,
        )
      ) {
        return isPathReadAllowed(
          path,
          sessionGrants.explicitAllowRead(
            config.explicitAllowRead,
            allowances.explicitDenyRead.approvedPaths,
          ),
          mergeArray(config.explicitDenyRead, [
            ...allowances.explicitDenyRead.patterns,
            ...[...allowances.explicitDenyRead.globRoots.values()].flat(),
          ]),
          cwd,
          { requireAllowMatch: true },
        )
          ? { action: 'allow', granted }
          : undefined;
      }
      if (
        trap.operation === 'write' &&
        matchesWriteDenyPattern(
          path,
          config.filesystem.denyWriteAlways,
          cwd,
          sessionGrants.effectiveAllowWrite(config, allowances),
        )
      ) {
        return { action: 'deny', reason: 'hard-deny' };
      }
      const allowed =
        trap.operation === 'read'
          ? readAllowed(
              path,
              sessionGrants.effectiveAllowRead(config, cwd, allowances),
              getEffectiveDenyRead(config, cwd),
              cwd,
            )
          : !shouldPromptForWrite(
              path,
              sessionGrants.effectiveAllowWrite(config, allowances),
              config.filesystem.denyWrite,
              cwd,
            );
      return allowed ? { action: 'allow', granted } : undefined;
    };
    if (!ctx.hasUI || !promptOnBlock) {
      return current() ?? { action: 'deny', reason: 'unprompted' };
    }

    return permissionPrompts.resolve(
      current,
      async (promptSignal) => {
        const config = loadConfig(cwd, ctx);
        const reason =
          trap.operation === 'read'
            ? matchesPattern(path, config.filesystem.denyRead, cwd)
              ? 'granting allowRead will override it'
              : undefined
            : matchesWriteDenyPattern(
                  path,
                  config.filesystem.denyWrite,
                  cwd,
                  sessionGrants.effectiveAllowWrite(config, allowances),
                )
              ? 'granting allowWrite will override it'
              : undefined;
        const choice = await promptFilesystemBlock(
          ctx,
          trap.operation,
          path,
          reason,
          promptSignal,
          allowances.permissionPromptLabel,
        );
        if (choice === 'abort' || promptSignal.aborted)
          return { action: 'deny', reason: 'rejected' };
        if (trap.operation === 'read') {
          await applyReadChoice(ctx, choice, path, cwd, allowances, readScope);
        } else {
          await applyWriteChoice(ctx, choice, path, cwd, allowances);
        }
        return { action: 'allow', granted: true };
      },
      signal,
    );
  }

  function attachWorkerTrap(
    socket: NetSocket,
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    signal?: AbortSignal,
  ): void {
    const decoder = new StringDecoder('utf8');
    let buffer = '';
    let prompts = Promise.resolve();
    const reportedErrors = new Set<string>();
    const reportTrapError = (message: string): void => {
      if (reportedErrors.has(message)) return;
      reportedErrors.add(message);
      notify(ctx, message, 'error');
      if (!ctx.hasUI) console.error(`pi-landstrip: ${message}`);
    };
    const respond = (queryId: string, action: LandstripControlResponse['action']): void => {
      if (socket.destroyed) return;
      socket.write(controlResponseLine(queryId, action), (error) => {
        if (error) reportTrapError(`Worker sandbox control response failed: ${error.message}`);
      });
    };

    const handleQuery = (trap: LandstripQueryTrap): void => {
      prompts = prompts
        .then(async () => {
          const result = await resolveTrapQuery(trap, ctx, cwd, allowances, true, signal);
          respond(trap.query_id, result.action);
        })
        .catch((error) => {
          respond(trap.query_id, 'deny');
          if (!signal?.aborted && formatError(error) !== 'Permission request cancelled') {
            const target = isFilesystemTrap(trap) ? trap.path : trap.target;
            reportTrapError(
              `Sandbox permission request failed (${trap.operation} "${target}"): ${formatError(error)}`,
            );
          }
        });
    };

    socket.on('error', (error) => {
      reportTrapError(`Worker sandbox control failed: ${error.message}`);
    });

    socket.on('data', (data: Buffer) => {
      buffer += decoder.write(data);
      let newline = buffer.indexOf('\n');
      while (newline >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        newline = buffer.indexOf('\n');
        const trap = parseTrapLine(line);
        if (!trap) continue;
        if (!isQueryTrap(trap)) {
          if (
            isFilesystemTrap(trap) &&
            matchesPattern(
              normalizeBlockedPath(trap.path, cwd),
              allowances.protectedPaths ?? [],
              cwd,
            )
          ) {
            continue;
          }
          reportTrapError(formatLandstripTraps([trap]));
          continue;
        }
        handleQuery(trap);
      }
    });
  }

  function prepareUnsandboxedProcess(options: LandstripRpcWorkerOptions): LandstripPreparedProcess {
    let spawned = false;
    let disposed = false;
    let disposePromise: Promise<void> | undefined;
    let preparedChild: ChildProcess | undefined;
    const spawnWorker: LandstripSpawn = (command, args, spawnOptions) => {
      if (disposed) throw new Error('Prepared process has been disposed');
      if (spawned) throw new Error('Prepared process can only be spawned once');
      spawned = true;
      const child = spawn(command, [...args], {
        ...spawnOptions,
        cwd: options.cwd,
        env: options.env,
        detached: true,
      });
      patchProcessGroupKill(child);
      preparedChild = child;
      return child;
    };

    return {
      command: options.command,
      args: options.args,
      cwd: options.cwd,
      env: options.env,
      spawn: spawnWorker,
      dispose() {
        disposePromise ??= (async () => {
          disposed = true;
          await stopPreparedChild(preparedChild);
        })();
        return disposePromise;
      },
    };
  }

  async function prepareManagedProcess(
    options: LandstripRpcWorkerOptions,
  ): Promise<LandstripPreparedProcess> {
    if (options.signal?.aborted) throw new Error('Task cancelled');
    if (!ensureSandboxState(options.ctx)) {
      if (sandboxState === 'unavailable') {
        throw new Error('Sandbox is unavailable; refusing subagent process');
      }
      if (!unsandboxedWorkerWarningShown) {
        warnUnsandboxed(
          options.ctx,
          'Subagent processes are running without Landstrip sandboxing',
          'warning',
        );
        unsandboxedWorkerWarningShown = true;
      }
      return prepareUnsandboxedProcess(options);
    }
    const allowances: ExecutionAllowances = {
      permissionPromptLabel: options.permissionPromptLabel,
      domains: [...(options.domains ?? [])],
      readPaths: [...options.readPaths],
      writePaths: [...options.writePaths],
      targets: [],
      protectedPaths: [
        ...new Set(
          (options.protectedPaths ?? []).flatMap((path) => {
            if (/[*?[\]]/.test(path)) {
              throw new Error(
                `Worker protected path "${path}" must be a concrete path, not a glob`,
              );
            }
            return [expandPath(path, options.cwd), canonicalizePath(path, options.cwd)];
          }),
        ),
      ],
    };
    const processAllowances = withWindowsProcessReadAccess(
      allowances,
      options.command,
      options.cwd,
    );
    const config = loadConfig(options.cwd, options.ctx);
    const explicitDenyGlobRoots = new Map<string, string[]>();
    processAllowances.explicitDenyRead = {
      patterns: config.explicitDenyRead,
      globRoots: explicitDenyGlobRoots,
      approvedPaths: [],
    };
    const startupPaths = [
      ...new Set([options.cwd, options.command, ...processAllowances.readPaths]),
    ];
    for (const path of startupPaths) {
      if (/[*?[\]]/.test(path)) {
        throw new Error(`Worker startup read path "${path}" must be a concrete path, not a glob`);
      }
      if (
        matchesPattern(
          path,
          mergeArray(config.filesystem.denyReadAlways, processAllowances.protectedPaths),
          options.cwd,
        )
      ) {
        throw new Error(`Worker startup read path "${path}" is denied by sandbox policy`);
      }
    }
    for (const path of startupPaths) {
      const result = await resolveTrapQuery(
        { kind: 'filesystem', operation: 'read', path },
        options.ctx,
        options.cwd,
        processAllowances,
        true,
        options.signal,
        normalizeBlockedPath(path, options.cwd),
      );
      if (result.action !== 'allow') {
        throw new Error(`Worker startup read access denied: ${path} (${result.reason})`);
      }
    }
    const { token: proxyToken, authorization: proxyAuthorization } = createProxyCredentials();
    const proxy = shouldStartProxy(config)
      ? await startProxy(
          options.ctx,
          options.cwd,
          processAllowances,
          options.signal,
          proxyAuthorization,
          restrictedUserProxyPortRange(),
        )
      : null;
    let policy: ReturnType<typeof writePolicyFile> | undefined;
    let trapSocket: NetSocket | undefined;
    let childEnd: NetSocket | undefined;
    let preparedChild: ChildProcess | undefined;
    let disposed = false;
    const isolatedTmpDir = (() => {
      if (process.platform !== 'linux') return undefined;
      const raw = options.env?.TMPDIR?.trim();
      if (!raw) return undefined;
      const resolved = canonicalizePath(raw, options.cwd);
      if (resolved === canonicalizePath(tmpdir(), options.cwd)) return undefined;
      const hostTmpDir = process.env.TMPDIR?.trim();
      if (hostTmpDir && resolved === canonicalizePath(hostTmpDir, options.cwd)) return undefined;
      return resolved;
    })();
    const cleanup = async (): Promise<unknown[]> => {
      const errors: unknown[] = [];
      for (const release of [
        () => stopPreparedChild(preparedChild),
        async () => {
          if (preparedChild?.pid === undefined || !isolatedTmpDir) return;
          const deadline = Date.now() + 2_000;
          for (;;) {
            let parentDev: number;
            let entries: string[];
            try {
              parentDev = lstatSync(isolatedTmpDir).dev;
              entries = readdirSync(isolatedTmpDir);
            } catch (error) {
              const code = (error as NodeJS.ErrnoException).code;
              if (code === 'ENOENT' || code === 'ENOTDIR') return;
              throw error;
            }
            const mounts = entries.filter((entry) => entry.startsWith('.mount_'));
            if (mounts.length === 0) return;
            for (const entry of mounts) {
              const mountPath = join(isolatedTmpDir, entry);
              try {
                if (lstatSync(mountPath).dev === parentDev) {
                  rmdirSync(mountPath);
                }
              } catch (error) {
                const code = (error as NodeJS.ErrnoException).code;
                if (code === 'ENOENT' || code === 'EBUSY') continue;
                if (code === 'ENOTCONN' || code === 'ECONNABORTED') {
                  for (const tool of ['fusermount', 'fusermount3']) {
                    const result = spawnSync(tool, ['-u', '-q', '-z', mountPath], {
                      stdio: 'ignore',
                    });
                    if (result.status === 0) break;
                  }
                  try {
                    rmdirSync(mountPath);
                  } catch (removeError) {
                    const removeCode = (removeError as NodeJS.ErrnoException).code;
                    if (removeCode !== 'ENOENT' && removeCode !== 'EBUSY') {
                      throw removeError;
                    }
                  }
                  continue;
                }
                throw error;
              }
            }
            if (Date.now() >= deadline) {
              throw new Error(`Timed out waiting for AppImage mount cleanup in ${isolatedTmpDir}`);
            }
            await delay(5);
          }
        },
        () => trapSocket?.destroy(),
        () => childEnd?.destroy(),
        () => {
          if (policy) rmSync(policy.dir, { recursive: true, force: true });
        },
        () => proxy?.stop(),
      ]) {
        try {
          await release();
        } catch (error) {
          errors.push(error);
        }
      }
      return errors;
    };
    try {
      if (options.signal?.aborted) throw new Error('Task cancelled');
      policy = writePolicyFile(options.cwd, proxy?.port ?? null, 'worker', processAllowances);
      if (process.platform !== 'win32') {
        [trapSocket, childEnd] = await createSocketPair();
        if (options.signal?.aborted) throw new Error('Task cancelled');
        attachWorkerTrap(trapSocket, options.ctx, options.cwd, processAllowances, options.signal);
      }
    } catch (error) {
      const cleanupErrors = await cleanup();
      if (cleanupErrors.length > 0) {
        throw new AggregateError(
          [error, ...cleanupErrors],
          'Landstrip process preparation cleanup failed',
        );
      }
      throw error;
    }

    const workerPolicy = policy;
    const workerChildEnd = childEnd;
    const workerEnv = createProxyEnvironment(proxy?.port ?? null, {
      token: proxyToken,
      baseEnv: options.env ?? {},
    });
    let spawned = false;
    let disposePromise: Promise<void> | undefined;
    const spawnWorker: LandstripSpawn = (_command, _args, spawnOptions) => {
      if (disposed) throw new Error('Prepared process has been disposed');
      if (spawned) throw new Error('Prepared process can only be spawned once');
      spawned = true;
      const landstripArgs = ['run', '-p', workerPolicy.path];
      const authPipe =
        Array.isArray(spawnOptions.stdio) && spawnOptions.stdio[WORKER_AUTH_FD] === 'pipe';
      if (authPipe && process.platform === 'win32') {
        throw new Error('Sandboxed worker authentication requires inherited Unix file descriptors');
      }
      const stdio: StdioOptions = ['pipe', 'pipe', 'pipe'];
      if (workerChildEnd || authPipe) stdio.push(workerChildEnd ?? 'ignore');
      if (authPipe) {
        stdio.push('pipe');
        landstripArgs.push('--inherit', String(WORKER_AUTH_FD));
      }
      if (workerChildEnd) landstripArgs.push('--trap', '3');
      landstripArgs.push('--', options.command, ...options.args);
      const child = spawn(binaryPath(), landstripArgs, {
        ...spawnOptions,
        cwd: options.cwd,
        env: createLandstripLauncherEnvironment(workerEnv),
        detached: true,
        stdio,
      });
      preparedChild = child;
      patchProcessGroupKill(child);
      workerChildEnd?.destroy();
      return child;
    };

    return {
      command: options.command,
      args: options.args,
      cwd: options.cwd,
      env: workerEnv,
      spawn: spawnWorker,
      dispose() {
        disposePromise ??= (async () => {
          disposed = true;
          const cleanupErrors = await cleanup();
          if (cleanupErrors.length > 0) {
            throw new AggregateError(cleanupErrors, 'Landstrip process disposal cleanup failed');
          }
        })();
        return disposePromise;
      },
    };
  }

  async function prepareRpcWorker(
    options: LandstripRpcWorkerOptions,
  ): Promise<LandstripRpcWorkerLaunch> {
    const prepared = await prepareManagedProcess(options);
    return {
      ...prepared,
      spawn(command, args, spawnOptions) {
        return prepared.spawn(command, args, spawnOptions) as ReturnType<RpcSpawn>;
      },
    };
  }

  async function prepareProcess(
    options: LandstripProcessOptions,
  ): Promise<LandstripPreparedProcess> {
    if (
      process.platform === 'win32' &&
      (getNoSandboxFlag() || !loadConfig(options.cwd, options.ctx).enabled)
    ) {
      throw new Error('Generic process preparation requires sandboxing on Windows');
    }
    return prepareManagedProcess({
      ...options,
      env: options.env ?? process.env,
      readPaths: options.readPaths ?? [],
      writePaths: options.writePaths ?? [],
    });
  }

  function createProviderBashOps(): BashOperations {
    return {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

        const provider = activeShellProvider();
        let invocation: LandstripShellInvocation | undefined;
        try {
          invocation = await provider.prepare({
            command,
            cwd,
            env: shellEnvironment(env, cwd, null),
            signal,
          });
          if (!invocation.executable.trim()) {
            throw new Error(`Shell provider "${provider.id}" returned an empty executable`);
          }
          if (signal?.aborted) throw new Error('aborted');
          const prepared = invocation;

          return await new Promise<{ exitCode: number | null }>((resolvePromise, reject) => {
            let timeoutHandle: NodeJS.Timeout | undefined;
            let timedOut = false;
            let settled = false;
            let childExited = false;
            let childExitCode: number | null = null;
            let postExitTimer: NodeJS.Timeout | undefined;
            let stdoutEnded = false;
            let stderrEnded = false;

            const child = spawn(prepared.executable, prepared.args, {
              cwd,
              env: createLandstripLauncherEnvironment(prepared.launcherEnv),
              detached: true,
              stdio: ['ignore', 'pipe', 'pipe'],
            });
            patchProcessGroupKill(child);

            const cleanup = async (): Promise<void> => {
              if (timeoutHandle) clearTimeout(timeoutHandle);
              if (postExitTimer) clearTimeout(postExitTimer);
              signal?.removeEventListener('abort', onAbort);
              const toDispose = invocation;
              invocation = undefined;
              await toDispose?.dispose?.();
            };
            const finish = (code: number | null): void => {
              if (settled) return;
              settled = true;
              child.stdout?.destroy();
              child.stderr?.destroy();
              void cleanup().then(() => {
                if (signal?.aborted) reject(new Error('aborted'));
                else if (timedOut) reject(new Error(`timeout:${timeout}`));
                else resolvePromise({ exitCode: code });
              }, reject);
            };
            const maybeFinishAfterExit = (): void => {
              if (childExited && stdoutEnded && stderrEnded) finish(childExitCode);
            };
            const killChild = (): void => {
              child.kill('SIGKILL');
            };
            function onAbort(): void {
              killChild();
            }

            child.stdout?.on('data', onData);
            child.stderr?.on('data', onData);
            child.stdout?.once('end', () => {
              stdoutEnded = true;
              maybeFinishAfterExit();
            });
            child.stderr?.once('end', () => {
              stderrEnded = true;
              maybeFinishAfterExit();
            });
            child.once('error', (error) => {
              if (settled) return;
              settled = true;
              void cleanup().then(() => reject(error), reject);
            });
            child.once('exit', (code) => {
              childExited = true;
              childExitCode = code;
              maybeFinishAfterExit();
              if (!settled) postExitTimer = setTimeout(() => finish(code), EXIT_STDIO_GRACE_MS);
            });
            child.once('close', (code) => finish(code));

            if (timeout !== undefined && timeout > 0) {
              timeoutHandle = setTimeout(() => {
                timedOut = true;
                killChild();
              }, timeout * 1000);
            }
            signal?.addEventListener('abort', onAbort, { once: true });
            if (signal?.aborted) onAbort();
          });
        } catch (error) {
          await invocation?.dispose?.();
          throw error;
        }
      },
    };
  }
  function createLandstripBashOps(
    ctx: ExtensionContext,
    callbacks: LandstripBashCallbacks = {},
    allowances: ExecutionAllowances = { domains: [], readPaths: [], writePaths: [], targets: [] },
  ): BashOperations {
    allowances.rejectedTargets ??= new Set();
    return {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

        const provider = activeShellProvider();
        const config = loadConfig(cwd, ctx);
        const { token: proxyToken, authorization: proxyAuthorization } = createProxyCredentials();
        const proxy = shouldStartProxy(config)
          ? await startProxy(
              ctx,
              cwd,
              allowances,
              signal,
              proxyAuthorization,
              restrictedUserProxyPortRange(),
            )
          : null;

        let policy: ReturnType<typeof writePolicyFile> | undefined;
        let invocation: LandstripShellInvocation | undefined;
        let processAllowances = allowances;
        let teardownPromise: Promise<void> | undefined;
        const teardownResources = (): Promise<void> => {
          teardownPromise ??= Promise.all([
            Promise.resolve().then(() => invocation?.dispose?.()),
            Promise.resolve().then(() => {
              if (policy) rmSync(policy.dir, { recursive: true, force: true });
            }),
            Promise.resolve().then(() => proxy?.stop()),
          ]).then(() => undefined);
          return teardownPromise;
        };

        let landstripArgs: string[];
        try {
          invocation = await provider.prepare({
            command,
            cwd,
            env: shellEnvironment(env, cwd, proxy?.port ?? null, proxy ? proxyToken : undefined),
            signal,
          });
          if (!invocation.executable.trim()) {
            throw new Error(`Shell provider "${provider.id}" returned an empty executable`);
          }
          if (signal?.aborted) throw new Error('aborted');

          processAllowances = {
            ...allowances,
            readPaths: [...allowances.readPaths, ...(invocation.readPaths ?? [])],
          };
          processAllowances = withWindowsProcessReadAccess(
            processAllowances,
            invocation.executable,
            cwd,
          );
          policy = writePolicyFile(cwd, proxy?.port ?? null, 'shell', processAllowances, ctx);
          landstripArgs = ['run', '-p', policy.path];
          if (process.platform !== 'win32') landstripArgs.push('--trap', '3');
          landstripArgs.push('--', invocation.executable, ...invocation.args);
        } catch (error) {
          await teardownResources();
          throw error;
        }

        return new Promise((resolvePromise, reject) => {
          let pendingSocketPair: [NetSocket, NetSocket] | undefined;
          (async () => {
            let timeoutHandle: NodeJS.Timeout | undefined;
            let timedOut = false;
            let cleaned = false;
            let trapSocket: NetSocket | undefined;
            let childEnd: NetSocket | undefined;
            if (process.platform !== 'win32') {
              pendingSocketPair = await createSocketPair();
              [trapSocket, childEnd] = pendingSocketPair;
            }
            if (signal?.aborted) throw new Error('aborted');
            const cleanup = async () => {
              if (cleaned) return;
              cleaned = true;
              if (timeoutHandle) clearTimeout(timeoutHandle);
              signal?.removeEventListener('abort', onAbort);
              trapSocket?.destroy();
              await teardownResources();
            };

            const stdio: StdioOptions = childEnd
              ? ['ignore', 'pipe', 'pipe', childEnd]
              : ['ignore', 'pipe', 'pipe'];
            const child: ChildProcess = spawn(binaryPath(), landstripArgs, {
              cwd,
              env: createLandstripLauncherEnvironment(invocation.launcherEnv),
              detached: true,
              stdio,
            });
            patchProcessGroupKill(child);

            // Child has dup'd its end; parent can close its copy.
            childEnd?.destroy();
            pendingSocketPair = undefined;

            function killChild(): void {
              child.kill('SIGKILL');
            }

            const execAbort = new AbortController();
            const querySignal = signal
              ? AbortSignal.any([signal, execAbort.signal])
              : execAbort.signal;

            function onAbort(): void {
              execAbort.abort();
              killChild();
            }

            if (timeout !== undefined && timeout > 0) {
              timeoutHandle = setTimeout(() => {
                timedOut = true;
                execAbort.abort();
                killChild();
              }, timeout * 1000);
            }

            signal?.addEventListener('abort', onAbort, { once: true });
            if (signal?.aborted) onAbort();
            const stderrDecoder = new StringDecoder('utf8');
            let stderrFlushed = false;
            let stderrAcc = '';
            let errorFdAcc = '';

            let execSettled = false;
            let childExited = false;
            let childExitCode: number | null = null;
            let postExitTimer: NodeJS.Timeout | undefined;
            let stdoutEnded = child.stdout === null;
            let stderrEnded = child.stderr === null;
            let trapEnded = trapSocket === undefined;
            const trapDecoder = new StringDecoder('utf8');
            let trapFlushed = false;
            let trapBuffer = '';
            let queryChain: Promise<void> = Promise.resolve();

            const flushStderr = (): void => {
              if (stderrFlushed) return;
              stderrFlushed = true;
              stderrAcc += stderrDecoder.end();
            };

            const respondQuery = (
              queryId: string,
              action: LandstripControlResponse['action'],
            ): void => {
              if (!trapSocket || trapSocket.destroyed) return;
              trapSocket.write(controlResponseLine(queryId, action));
            };

            const appendErrorLine = (line: string): void => {
              const infoLine = line + '\n';
              errorFdAcc += infoLine;
              callbacks.onErrorFd?.(Buffer.from(infoLine, 'utf8'));
            };

            const processTrapLine = (line: string): void => {
              if (line.length === 0) return;
              const trap = parseTrapLine(line);
              if (trap && isQueryTrap(trap)) {
                queryChain = queryChain
                  .then(async () => {
                    const result = await resolveTrapQuery(
                      trap,
                      ctx,
                      cwd,
                      processAllowances,
                      callbacks.promptOnBlock === true,
                      querySignal,
                    );
                    if (result.action === 'deny') {
                      if (result.reason === 'rejected' && isFilesystemTrap(trap)) {
                        callbacks.onRejectedPath?.(
                          trap.operation,
                          normalizeBlockedPath(trap.path, cwd),
                        );
                      }
                      appendErrorLine(line);
                    }
                    respondQuery(trap.query_id, result.action);
                  })
                  .catch((error) => {
                    respondQuery(trap.query_id, 'deny');
                    if (
                      !querySignal.aborted &&
                      formatError(error) !== 'Permission request cancelled'
                    ) {
                      const target = isFilesystemTrap(trap) ? trap.path : trap.target;
                      const message = `Sandbox permission request failed (${trap.operation} "${target}"): ${formatError(error)}`;
                      appendErrorLine(
                        JSON.stringify({ kind: 'internal', code: 'INTERNAL_ERROR', message }),
                      );
                      onData(Buffer.from(`pi-landstrip: ${message}\n`, 'utf8'));
                    }
                  });
              } else {
                appendErrorLine(line);
              }
            };

            const drainTrapLines = (): void => {
              let nl = trapBuffer.indexOf('\n');
              while (nl !== -1) {
                const line = trapBuffer.slice(0, nl);
                trapBuffer = trapBuffer.slice(nl + 1);
                nl = trapBuffer.indexOf('\n');
                processTrapLine(line);
              }
            };

            const flushTrap = (): void => {
              if (trapFlushed) return;
              trapFlushed = true;
              trapBuffer += trapDecoder.end();
              drainTrapLines();
              const rest = trapBuffer.trim();
              trapBuffer = '';
              if (rest.length > 0) processTrapLine(rest);
            };

            const finalizeExec = (code: number | null): void => {
              if (execSettled) return;
              execSettled = true;
              execAbort.abort();
              if (postExitTimer) clearTimeout(postExitTimer);
              flushStderr();
              flushTrap();
              child.stdout?.destroy();
              child.stderr?.destroy();
              void (async () => {
                await queryChain;
                await cleanup();
                if (signal?.aborted) {
                  reject(new Error('aborted'));
                  return;
                }
                if (timedOut) {
                  reject(new Error(`timeout:${timeout}`));
                  return;
                }

                // Structured traps are trusted only from the trap socket; on
                // Windows, where --trap is unsupported, use native
                // kernel-denial text from stderr.
                const blockedPath =
                  extractTrapBlockedPath(errorFdAcc, cwd) ??
                  extractNativeDeniedPath(stderrAcc, cwd);
                if (!blockedPath && ctx.hasUI) {
                  const traps = parseLandstripTraps(errorFdAcc);
                  const denials = traps.filter(isDenialTrap);
                  if (denials.length > 0) {
                    const formatted = formatLandstripTraps(denials);
                    notify(ctx, `Sandbox blocked an operation: ${formatted}`, 'warning');
                  }

                  const failures = traps.filter((trap) => !isDenialTrap(trap));
                  if (failures.length > 0) {
                    notify(ctx, `Sandbox failed: ${formatLandstripTraps(failures)}`, 'error');
                  }
                }

                resolvePromise({ exitCode: code });
              })().catch(reject);
            };

            const maybeFinalizeAfterExit = (): void => {
              if (childExited && !execSettled && stdoutEnded && stderrEnded && trapEnded) {
                finalizeExec(childExitCode);
              }
            };

            const onStdoutEnd = (): void => {
              stdoutEnded = true;
              maybeFinalizeAfterExit();
            };

            const onStderrEnd = (): void => {
              stderrEnded = true;
              flushStderr();
              maybeFinalizeAfterExit();
            };

            const onTrapEnd = (): void => {
              if (trapEnded) return;
              trapEnded = true;
              flushTrap();
              maybeFinalizeAfterExit();
            };

            child.stdout?.on('data', onData);
            child.stderr?.on('data', (data: Buffer) => {
              stderrAcc += stderrDecoder.write(data);
              callbacks.onStderr?.(data);
              onData(data);
            });
            child.stdout?.once('end', onStdoutEnd);
            child.stdout?.once('close', onStdoutEnd);
            child.stderr?.once('end', onStderrEnd);
            child.stderr?.once('close', onStderrEnd);

            trapSocket?.on('data', (data: Buffer) => {
              trapBuffer += trapDecoder.write(data);
              drainTrapLines();
            });
            trapSocket?.once('end', onTrapEnd);
            trapSocket?.once('close', onTrapEnd);
            trapSocket?.on('error', onTrapEnd);

            child.on('error', (error) => {
              if (execSettled) return;
              execSettled = true;
              execAbort.abort();
              if (postExitTimer) clearTimeout(postExitTimer);
              void (async () => {
                try {
                  await queryChain;
                  await cleanup();
                  reject(error);
                } catch (cleanupError) {
                  reject(cleanupError);
                }
              })();
            });

            child.once('exit', (code) => {
              childExited = true;
              childExitCode = code;
              execAbort.abort();
              maybeFinalizeAfterExit();
              if (!execSettled) {
                postExitTimer = setTimeout(() => finalizeExec(code), EXIT_STDIO_GRACE_MS);
              }
            });
            child.once('close', (code) => {
              childExited = true;
              childExitCode ??= code;
              stdoutEnded = true;
              stderrEnded = true;
              flushStderr();
              execAbort.abort();
              maybeFinalizeAfterExit();
              if (!execSettled && !postExitTimer) {
                postExitTimer = setTimeout(() => finalizeExec(childExitCode), EXIT_STDIO_GRACE_MS);
              }
            });
          })().catch((error: unknown) => {
            // A failure before the child is wired (for example, creating the trap
            // channel) never reaches cleanup(), so free temporary resources here.
            pendingSocketPair?.forEach((socket) => socket.destroy());
            void teardownResources().then(
              () => reject(error),
              (cleanupError) =>
                reject(new AggregateError([error, cleanupError], 'Shell setup and cleanup failed')),
            );
          });
        });
      },
    };
  }

  async function runBashWithOptionalRetry(
    id: string,
    params: BashToolInput,
    signal: AbortSignal | undefined,
    onUpdate: AgentToolUpdateCallback<BashToolDetails | undefined> | undefined,
    ctx: ExtensionToolContext,
  ): Promise<AgentToolResult<BashToolDetails | undefined>> {
    let landstripErrorOutput = '';
    let stderrOutput = '';
    let stderrOutputDecoder = new StringDecoder('utf8');
    const rejectedPaths = {
      read: new Set<string>(),
      write: new Set<string>(),
    };
    const allowances: ExecutionAllowances = {
      domains: [],
      readPaths: [],
      writePaths: [],
      targets: [],
    };
    const sandboxedBash = createBashToolDefinition(ctx.cwd, {
      operations: createLandstripBashOps(
        ctx,
        {
          onErrorFd: (data) => {
            landstripErrorOutput += data.toString('utf8');
          },
          onStderr: (data) => {
            stderrOutput += stderrOutputDecoder.write(data);
          },
          onRejectedPath: (operation, path) => {
            rejectedPaths[operation].add(path);
          },
          promptOnBlock: true,
        },
        allowances,
      ),
      shellPath: SettingsManager.create(ctx.cwd).getShellPath(),
    });

    const run = async () => {
      try {
        return await sandboxedBash.execute(id, params, signal, onUpdate, ctx);
      } finally {
        stderrOutput += stderrOutputDecoder.end();
      }
    };
    const formatTrapErrors = (): string | null => {
      const landstripErrors = parseLandstripTraps(landstripErrorOutput);
      if (landstripErrors.length === 0) return null;
      return formatLandstripTraps(landstripErrors);
    };
    const blockedReadPathForRetry = (nativeOutput: string): string | null => {
      const config = loadConfig(ctx.cwd, ctx);
      if (!enforcesShellReadPolicy(config.shell.readAccess)) return null;

      const trappedPath = extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'read');
      if (trappedPath) return trappedPath;

      return extractRetryableNativeReadDeniedPath(
        nativeOutput,
        ctx.cwd,
        sessionGrants.effectiveAllowRead(config, ctx.cwd, allowances),
        getEffectiveDenyRead(config, ctx.cwd),
      );
    };
    const retryWithAccess = async (
      operation: 'read' | 'write',
      blockedPath: string,
    ): Promise<AgentToolResult<BashToolDetails | undefined> | null> => {
      if (!ctx.hasUI || signal?.aborted || rejectedPaths[operation].has(blockedPath)) return null;

      let access: TrapQueryResult;
      try {
        access = await resolveTrapQuery(
          { kind: 'filesystem', operation, path: blockedPath },
          ctx,
          ctx.cwd,
          allowances,
          true,
          signal,
        );
      } catch (error) {
        if (
          signal?.aborted ||
          (error instanceof Error && error.message === 'Permission request cancelled')
        ) {
          return null;
        }
        throw error;
      }
      if (access.action !== 'allow') {
        if (operation === 'write' && access.reason === 'hard-deny') {
          const { globalPath, projectPath } = new SandboxConfigStore(ctx.cwd);
          notify(
            ctx,
            `"${blockedPath}" is blocked by denyWriteAlways. Check:\n  ${projectPath}\n  ${globalPath}`,
            'warning',
          );
        }
        return null;
      }
      if (!access.granted) return null;
      if (operation === 'write') {
        const config = loadConfig(ctx.cwd, ctx);
        if (
          matchesWriteDenyPattern(
            blockedPath,
            config.filesystem.denyWriteAlways,
            ctx.cwd,
            sessionGrants.effectiveAllowWrite(config, allowances),
          )
        ) {
          const { globalPath, projectPath } = new SandboxConfigStore(ctx.cwd);
          notify(
            ctx,
            `"${blockedPath}" was added to allowWrite, but denyWriteAlways still blocks it. Check:\n  ${projectPath}\n  ${globalPath}`,
            'warning',
          );
          return null;
        }
      }
      onUpdate?.({
        content: [
          {
            type: 'text',
            text: `\n--- ${operation === 'read' ? 'Read' : 'Write'} access granted for "${blockedPath}", retrying ---\n`,
          },
        ],
        details: {},
      });
      landstripErrorOutput = '';
      stderrOutput = '';
      stderrOutputDecoder = new StringDecoder('utf8');
      return run();
    };

    let result: AgentToolResult<BashToolDetails | undefined>;
    try {
      result = await run();
    } catch (error) {
      const errorText = formatError(error);
      const fallbackOutput = `${stderrOutput}\n${errorText}`;
      const blockedWritePath =
        extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'write') ??
        extractNativeWriteDeniedPath(fallbackOutput, ctx.cwd, params.command);
      if (blockedWritePath) {
        const retryResult = await retryWithAccess('write', blockedWritePath);
        if (retryResult) return retryResult;
      }

      const blockedReadPath = blockedReadPathForRetry(fallbackOutput);
      if (blockedReadPath) {
        const retryResult = await retryWithAccess('read', blockedReadPath);
        if (retryResult) return retryResult;
      }

      const trapMessage = formatTrapErrors();
      if (trapMessage) {
        throw new Error(errorText ? `${trapMessage}\n\n${errorText}` : trapMessage);
      }
      throw error;
    }
    const trapMessage = formatTrapErrors();
    if (trapMessage) {
      result.content.unshift({ type: 'text', text: `\n${trapMessage}\n` });
    }
    const blockedWritePath =
      extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'write') ??
      extractNativeWriteDeniedPath(stderrOutput, ctx.cwd, params.command);
    if (blockedWritePath) {
      const retryResult = await retryWithAccess('write', blockedWritePath);
      if (retryResult) return retryResult;
    }

    const blockedReadPath = blockedReadPathForRetry(stderrOutput);
    if (!blockedReadPath) return result;

    const retryResult = await retryWithAccess('read', blockedReadPath);
    return retryResult ?? result;
  }

  function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
    if (config.network.allowNetwork) {
      notify(ctx, 'Network sandbox is disabled because network.allowNetwork is true.', 'warning');
      return;
    }
    if (!allowsAllDomains(config.network.allowedDomains)) return;
    notify(
      ctx,
      'Network sandbox allows all domains because network.allowedDomains contains "*".',
      'warning',
    );
  }

  function warnIfWindowsSecurityDowngraded(ctx: ExtensionContext, config: SandboxConfig): void {
    if (process.platform !== 'win32') return;
    let implementation: WindowsImplementation;
    try {
      implementation = windowsStatus().active;
    } catch (error) {
      notify(ctx, formatError(error), 'error');
      return;
    }
    if (implementation !== 'appContainer') return;
    if (config.windows.appContainerMode === 'standard') {
      notify(
        ctx,
        'Windows uses standard AppContainer mode, which is weaker than LPAC isolation.',
        'warning',
      );
    }
    if (config.windows.allowLoopback) {
      notify(
        ctx,
        'Windows loopback access includes all local loopback services, not only the Landstrip proxy.',
        'warning',
      );
    }
  }

  function enableStatus(ctx: ExtensionContext, config: SandboxConfig): void {
    if (!hasTuiStatus(ctx)) return;
    const theme = ctx.ui.theme;
    const dot = theme.fg('success', '●');
    const label = theme.fg('text', 'Sandbox');

    const windowsImplementation = process.platform === 'win32' ? windowsStatus().active : undefined;
    let networkLabel: string;
    let networkColor: 'warning' | 'accent';
    if (config.network.allowNetwork) {
      networkLabel = 'unrestricted';
      networkColor = 'warning';
    } else if (windowsImplementation === 'appContainer' && !config.windows.allowLoopback) {
      networkLabel = 'blocked';
      networkColor = 'accent';
    } else if (allowsAllDomains(config.network.allowedDomains)) {
      networkLabel = 'any domain';
      networkColor = 'warning';
    } else {
      networkLabel = `${config.network.allowedDomains.length} domains`;
      networkColor = 'accent';
    }

    const sep = theme.fg('dim', '·');
    const net = theme.fg(networkColor, networkLabel);
    const write = theme.fg('accent', `${config.filesystem.allowWrite.length} write paths`);
    const fields = [`${dot} ${label}`, net, write];
    if (windowsImplementation !== undefined) {
      const standard =
        windowsImplementation === 'appContainer' && config.windows.appContainerMode === 'standard';
      const implementationLabel =
        windowsImplementation === 'restrictedUser'
          ? 'restricted user'
          : `${config.windows.appContainerMode} AppContainer`;
      fields.splice(1, 0, theme.fg(standard ? 'warning' : 'accent', implementationLabel));
    }

    setTuiStatus(ctx, 'sandbox', fields.join(`  ${sep}  `));
  }

  const headlessWarnings = new Set<string>();

  // Explicitly disabling sandboxing permits the legacy unsandboxed fallback.
  // Initialization failures remain fail-closed so commands never bypass policy silently.
  function warnUnsandboxed(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
    notify(ctx, message, level);
    if (!ctx.hasUI && !headlessWarnings.has(message)) {
      headlessWarnings.add(message);
      console.error(`pi-landstrip: ${message}`);
    }
  }

  function enableSandbox(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd, ctx);

    if (!SUPPORTED_PLATFORMS.has(process.platform)) {
      sandboxEnabled = false;
      sandboxReady = false;
      setSandboxState('unavailable', ctx);
      warnUnsandboxed(
        ctx,
        `landstrip sandboxing is not supported on ${process.platform}`,
        'warning',
      );
      return false;
    }

    // Resolve through the plugin dependency. A missing platform package is a
    // broken installation and must abort enablement instead of selecting an
    // unsandboxed execution route.
    binaryPath();

    sandboxEnabled = true;
    sandboxReady = true;
    setSandboxState('enabled', ctx);
    warnIfAllDomainsAllowed(ctx, config);
    warnIfWindowsSecurityDowngraded(ctx, config);
    enableStatus(ctx, config);
    return true;
  }

  let getNoSandboxFlag = (): boolean => false;
  function disableSandbox(ctx: ExtensionContext): void {
    sandboxEnabled = false;
    sandboxReady = false;
    setSandboxState('disabled', ctx);
    setTuiStatus(ctx, 'sandbox', undefined);
  }

  function ensureSandboxState(ctx: ExtensionContext): boolean {
    if (getNoSandboxFlag()) {
      disableSandbox(ctx);
      return false;
    }

    const config = loadConfig(ctx.cwd, ctx);
    if (!config.enabled) {
      disableSandbox(ctx);
      return false;
    }

    if (!sandboxEnabled || !sandboxReady) return enableSandbox(ctx);
    return true;
  }

  function createBashTool(cwd: string): LandstripBashTool {
    const localBash = createBashToolDefinition(cwd, {
      shellPath: SettingsManager.create(cwd).getShellPath(),
    });
    const baseRenderCall = localBash.renderCall;
    const baseRenderResult = localBash.renderResult;

    return {
      ...localBash,
      label: 'bash (landstrip)',
      description: 'Execute commands with the active Landstrip shell provider.',
      promptGuidelines: [
        ...(localBash.promptGuidelines ?? []),
        'After launching a bash command with background: true, continue only independent work that does not wait on the command; otherwise end the current turn and wait for the automatic completion follow-up turn. Do not sleep or poll tasks to wait.',
      ],
      parameters: LandstripBashSchema,
      renderCall(args, theme, context) {
        const bashArgs = args as LandstripBashInput;
        if (bashArgs.background) {
          const nameSuffix = bashArgs.name ? theme.fg('dim', ` (${bashArgs.name})`) : '';
          return new Text(
            theme.fg('accent', '$ ' + bashArgs.command) + theme.fg('muted', ' [bg]') + nameSuffix,
            0,
            0,
          );
        }
        return baseRenderCall
          ? baseRenderCall(args as any, theme, context as any)
          : new Text(args.command, 0, 0);
      },
      renderResult(result, options, theme, context) {
        const details = result.details as { taskId?: string; description?: string } | undefined;
        if (details?.taskId) {
          const text = result.content[0]?.type === 'text' ? result.content[0].text : '';
          return new Text(
            theme.fg('success', `✓ Task ${details.taskId.slice(0, 8)} started`) +
              '\n' +
              theme.fg('dim', text),
            0,
            0,
          );
        }
        return baseRenderResult
          ? baseRenderResult(result as any, options, theme, context as any)
          : new Text('', 0, 0);
      },
      async execute(id, rawParams, signal, onUpdate, ctx) {
        if (!ctx) throw new Error('Sandbox context is unavailable');
        const params = rawParams as LandstripBashInput;
        if (params.background) {
          if (!ensureSandboxState(ctx)) {
            if (sandboxState === 'unavailable') {
              throw new Error('Sandbox is unavailable; refusing command');
            }
          }
          if (!subagentRuntime) {
            throw new Error('Background task runtime is unavailable');
          }
          return subagentRuntime.runBackgroundShellTask(params, ctx);
        }

        if (!ensureSandboxState(ctx)) {
          if (sandboxState === 'unavailable') {
            throw new Error('Sandbox is unavailable; refusing command');
          }
          if (externalShellProvider !== undefined) {
            const providerBash = createBashToolDefinition(ctx.cwd, {
              operations: createProviderBashOps(),
              shellPath: SettingsManager.create(ctx.cwd).getShellPath(),
            });
            return providerBash.execute(id, params as any, signal, onUpdate, ctx);
          }
          return localBash.execute(id, params as any, signal, onUpdate, ctx);
        }

        return runBashWithOptionalRetry(id, params as any, signal, onUpdate, ctx);
      },
    };
  }

  function register(pi: ExtensionAPI): void {
    const maybePi = pi as ExtensionAPI & {
      getFlag?: (name: string) => unknown;
      registerCommand?: ExtensionAPI['registerCommand'];
      registerFlag?: ExtensionAPI['registerFlag'];
    };

    maybePi.registerFlag?.('no-sandbox', {
      description: 'Disable Landstrip OS sandboxing',
      type: 'boolean',
      default: false,
    });
    getNoSandboxFlag = () => Boolean(maybePi.getFlag?.('no-sandbox'));

    unpublishRuntime?.();
    unpublishRuntime = publishLandstripRuntime(pi, integration);

    if (shouldRegisterBashTool) pi.registerTool(createBashTool(localCwd));

    pi.on('user_bash', async (_event, ctx) => {
      if (!ensureSandboxState(ctx)) {
        if (sandboxState === 'unavailable') {
          throw new Error('Sandbox is unavailable; refusing command');
        }
        if (externalShellProvider !== undefined) {
          return { operations: createProviderBashOps() };
        }
        return;
      }

      return { operations: createLandstripBashOps(ctx, { promptOnBlock: true }) };
    });

    pi.on('session_start', async (_event, ctx) => {
      activeContext = ctx;
      permissionPrompts.reset();
      sessionGrants.reset();
      unsandboxedWorkerWarningShown = false;
      projectConfigTrusted = isProjectTrusted(ctx);
      if (getNoSandboxFlag()) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via --no-sandbox', 'warning');
        if (!unpublishRuntime) unpublishRuntime = publishLandstripRuntime(pi, integration);
        return;
      }

      const config = loadConfig(ctx.cwd, ctx);
      if (!config.enabled) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via config', 'info');
        if (!unpublishRuntime) unpublishRuntime = publishLandstripRuntime(pi, integration);
        return;
      }

      enableSandbox(ctx);
      if (!unpublishRuntime) unpublishRuntime = publishLandstripRuntime(pi, integration);
    });
    pi.on('session_shutdown', () => {
      permissionPrompts.reset();
      activeContext = undefined;
      unpublishRuntime?.();
      unpublishRuntime = undefined;
    });
  }

  async function applySandboxSetting(
    ctx: ExtensionContext,
    enabled: boolean | undefined,
    scope: SandboxConfigScope,
  ): Promise<void> {
    await new SandboxConfigStore(ctx.cwd).setEnabled(scope, enabled);
    const effectiveEnabled = loadConfig(ctx.cwd, ctx).enabled;
    if (!effectiveEnabled) {
      disableSandbox(ctx);
    } else if (!getNoSandboxFlag()) {
      enableSandbox(ctx);
    }
  }

  function sandboxOverview(cwd: string, includeProject: boolean): SandboxOverview {
    const store = new SandboxConfigStore(cwd);
    const config = store.load(includeProject);
    const windowsImplementation = process.platform === 'win32' ? windowsStatus().active : undefined;
    return {
      enabled: config.enabled,
      running: sandboxEnabled && sandboxReady,
      noSandboxFlag: getNoSandboxFlag(),
      networkMode: config.network.allowNetwork
        ? 'unrestricted'
        : windowsImplementation === 'appContainer' && !config.windows.allowLoopback
          ? 'blocked'
          : 'proxied',
      shellReadMode: process.platform === 'win32' ? 'policy' : config.shell.readAccess,
      readRuleScope: enforcesShellReadPolicy(config.shell.readAccess)
        ? 'Workers and shell'
        : 'Workers only',
      windowsMode:
        windowsImplementation === undefined
          ? undefined
          : windowsImplementation === 'restrictedUser'
            ? 'Restricted user'
            : `AppContainer (${config.windows.appContainerMode})`,
      changeScope: store.changeScope(includeProject),
      paths: { global: store.globalPath, project: store.projectPath, binary: binaryPath() },
      config,
      ...sessionGrants.overview(),
    };
  }

  const sandboxCallbacks: SandboxCallbacks = {
    load: (cwd, includeProject) => new SandboxConfigStore(cwd).enabledSettings(includeProject),
    setEnabled: (ctx, enabled, scope) => applySandboxSetting(ctx, enabled, scope),
    clearProject: (ctx) => applySandboxSetting(ctx, undefined, 'project'),
    overview: sandboxOverview,
  };

  const integration: LandstripIntegration = {
    version: LANDSTRIP_RUNTIME_VERSION,
    getContext,
    getExtensionContext: () => activeContext,
    registerShellProvider,
    registerPermissionAskProvider,
    resolvePermissionAsk,
    prepareProcess,
    prepareRpcWorker,
    authorizeFilesystemToolAccess,
    registerWorkerExtension,
    getWorkerExtensions,
    on,
    register,
    emit: emitEvent,
    runSandboxedCommand(
      command: string,
      cwd: string,
      execOptions: {
        timeout?: number;
        signal?: AbortSignal;
        onData?: (chunk: Buffer) => void;
        onErrorFd?: (chunk: Buffer) => void;
        env?: NodeJS.ProcessEnv;
        promptOnBlock?: boolean;
        permissionPromptLabel?: string;
      },
      ctx: ExtensionContext,
    ): Promise<{ exitCode: number | null }> {
      const allowances: ExecutionAllowances = {
        permissionPromptLabel: execOptions.permissionPromptLabel,
        domains: [],
        readPaths: [],
        writePaths: [],
        targets: [],
      };
      const ops = ensureSandboxState(ctx)
        ? createLandstripBashOps(
            ctx,
            {
              promptOnBlock: execOptions.promptOnBlock ?? false,
              onErrorFd: execOptions.onErrorFd,
            },
            allowances,
          )
        : externalShellProvider !== undefined
          ? createProviderBashOps()
          : createLocalBashOperations();
      return ops.exec(command, cwd, {
        onData: execOptions.onData ?? (() => {}),
        signal: execOptions.signal,
        timeout: execOptions.timeout,
        env: execOptions.env,
      });
    },
    setSubagentRuntime(runtime: SubagentRuntime) {
      subagentRuntime = runtime;
    },
    sandboxCallbacks,
  };
  return integration;
}
