// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { type ChildProcess, spawn, spawnSync, type StdioOptions } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import {
  type AddressInfo,
  BlockList,
  connect as connectNet,
  createServer,
  isIP,
  type Socket,
  Socket as NetSocket,
} from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath, URL } from 'node:url';

import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  BashToolDetails,
  BashToolInput,
  ExtensionAPI,
  ExtensionContext,
  Theme,
} from '@earendil-works/pi-coding-agent';

import {
  type BashOperations,
  createBashToolDefinition,
  getAgentDir,
  getShellConfig,
  SettingsManager,
  withFileMutationQueue,
} from '@earendil-works/pi-coding-agent';
import { matchesKey, truncateToWidth } from '@earendil-works/pi-tui';
import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripFilesystemTrap,
  type LandstripNetworkTrap,
  type LandstripTrap,
} from '@landstrip/landstrip';
import {
  type LandstripBashTool,
  type LandstripContextV1,
  type LandstripEvent,
  type LandstripPreparedProcess,
  type LandstripProcessOptions,
  type LandstripSandboxState,
  type LandstripWorkerExtension,
  LANDSTRIP_RUNTIME_VERSION,
  type PiLandstripRuntimeV1,
  publishLandstripRuntime,
} from './api.ts';
import type { RpcSpawn } from './rpc-process.ts';
import {
  type SubagentRuntime,
  registerSubagents,
  registerSubagentWorker,
  workerConfigFromEnvironment,
} from './subagents.ts';
import { availablePrimaryAgents, availableSubagents } from './agents.ts';
import { boxBottom, boxRow, boxTop } from './box.ts';
import {
  getPiConfigPaths,
  loadLandstripConfig,
  MAX_SUBAGENTS,
  setMaxSubagentsConfigForScope,
} from './config.ts';
import { AsyncQueue, expandHomePath, formatError } from './util.ts';

interface SandboxFilesystemConfig {
  denyRead: string[];
  allowRead: string[];
  allowWrite: string[];
  denyWrite: string[];
}

interface SandboxNetworkConfig {
  allowNetwork: boolean;
  allowLocalBinding: boolean;
  allowAllUnixSockets: boolean;
  allowUnixSockets: string[];
  allowedDomains: string[];
  deniedDomains: string[];
}

interface SandboxConfig {
  enabled: boolean;
  network: SandboxNetworkConfig;
  filesystem: SandboxFilesystemConfig;
}

type SandboxFilesystemConfigFile = Partial<SandboxFilesystemConfig>;
type SandboxNetworkConfigFile = Partial<SandboxNetworkConfig>;

interface SandboxConfigFile {
  enabled?: boolean;
  network?: SandboxNetworkConfigFile;
  filesystem?: SandboxFilesystemConfigFile;
}

type SandboxConfigScope = 'global' | 'project';

interface LandstripPolicy {
  network: {
    allowNetwork: boolean;
    allowLocalBinding: boolean;
    allowAllUnixSockets: boolean;
    allowUnixSockets: string[];
    httpProxyPort?: number;
    socksProxyPort?: number;
  };
  filesystem: SandboxFilesystemConfig;
}

type LandstripDenialTrap = LandstripFilesystemTrap | LandstripNetworkTrap;

interface LandstripBashCallbacks {
  onStderr?: (data: Buffer) => void;
  onErrorFd?: (data: Buffer) => void;
  promptOnBlock?: boolean;
}

interface ExecutionAllowances {
  readonly domains: string[];
  readonly readPaths: string[];
  readonly writePaths: string[];
  readonly targets: string[];
}

const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);
const prohibitedProxyAddresses = new BlockList();

for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  prohibitedProxyAddresses.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  prohibitedProxyAddresses.addSubnet(network, prefix, 'ipv6');
}

// Grace period after the child exits for its stdio to drain before we stop
// waiting; matches pi's own bash backend so a backgrounded process cannot hang us.
const EXIT_STDIO_GRACE_MS = 100;
const PROXY_ENVIRONMENT_VARIABLES = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
] as const;

const packageDir = dirname(fileURLToPath(import.meta.url));
type PermissionChoice = 'abort' | 'once' | 'session' | 'project' | 'global';
type NotificationLevel = Parameters<ExtensionContext['ui']['notify']>[1];

interface PromptOption {
  label: string;
  key: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

const PERMISSION_OPTIONS: PromptOption[] = [
  { label: 'Allow once', key: 'o', action: 'once' },
  { label: 'Allow for this session only', key: 's', action: 'session' },
  { label: 'Abort (keep blocked)', key: 'esc', action: 'abort' },
  {
    label: 'Allow for this project',
    key: 'P',
    action: 'project',
    confirm: true,
    hint: '-> .pi/sandbox.json',
  },
  {
    label: 'Allow for all projects',
    key: 'A',
    action: 'global',
    confirm: true,
    hint: '-> ~/.pi/agent/sandbox.json',
  },
];

const NETWORK_PERMISSION_OPTIONS: PromptOption[] = [
  { label: 'Allow once', key: 'o', action: 'once' },
  { label: 'Allow for this session only', key: 's', action: 'session' },
  { label: 'Abort (keep blocked)', key: 'esc', action: 'abort' },
];

function loadSandboxConfig(cwd: string, includeProject: boolean): SandboxConfig {
  const projectConfigPath = join(cwd, '.pi', 'sandbox.json');
  const globalConfigPath = join(getAgentDir(), 'sandbox.json');

  if (!existsSync(globalConfigPath)) {
    const templatePath = join(packageDir, 'sandbox.json');
    mkdirSync(dirname(globalConfigPath), { recursive: true });
    writeFileSync(globalConfigPath, readFileSync(templatePath, 'utf-8'), 'utf-8');
  }

  let globalConfig: SandboxConfig = JSON.parse(
    readFileSync(join(packageDir, 'sandbox.json'), 'utf-8'),
  );
  try {
    const override = JSON.parse(readFileSync(globalConfigPath, 'utf-8'));
    globalConfig = deepMerge(globalConfig, override);
  } catch (error) {
    console.error(`Warning: Could not parse ${globalConfigPath}: ${error}`);
  }

  if (includeProject && existsSync(projectConfigPath)) {
    try {
      const projectConfig = JSON.parse(readFileSync(projectConfigPath, 'utf-8'));
      return deepMerge(globalConfig, projectConfig);
    } catch (error) {
      console.error(`Warning: Could not parse ${projectConfigPath}: ${error}`);
    }
  }

  return globalConfig;
}

function mergeArray(base: string[], override?: string[]): string[] {
  if (!override) return base;
  return [...new Set([...base, ...override])];
}

function deepMerge(base: SandboxConfig, overrides: SandboxConfigFile): SandboxConfig {
  const network = overrides.network;
  const filesystem = overrides.filesystem;

  return {
    enabled: overrides.enabled ?? base.enabled,
    network: {
      allowNetwork: network?.allowNetwork ?? base.network.allowNetwork,
      allowLocalBinding: network?.allowLocalBinding ?? base.network.allowLocalBinding,
      allowAllUnixSockets: network?.allowAllUnixSockets ?? base.network.allowAllUnixSockets,
      allowUnixSockets: mergeArray(base.network.allowUnixSockets, network?.allowUnixSockets),
      allowedDomains: mergeArray(base.network.allowedDomains, network?.allowedDomains),
      deniedDomains: mergeArray(base.network.deniedDomains, network?.deniedDomains),
    },
    filesystem: {
      denyRead: mergeArray(base.filesystem.denyRead, filesystem?.denyRead),
      allowRead: mergeArray(base.filesystem.allowRead, filesystem?.allowRead),
      allowWrite: mergeArray(base.filesystem.allowWrite, filesystem?.allowWrite),
      denyWrite: mergeArray(base.filesystem.denyWrite, filesystem?.denyWrite),
    },
  };
}

function getConfigPaths(cwd: string): { globalPath: string; projectPath: string } {
  return getPiConfigPaths(cwd, 'sandbox.json');
}

function readOrEmptyConfig(configPath: string): SandboxConfigFile {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, 'utf-8'));
  } catch {
    return {};
  }
}

function writeConfigFile(configPath: string, config: SandboxConfigFile): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf-8');
}

function getSandboxConfigWriteTarget(
  cwd: string,
  includeProject = true,
): { scope: SandboxConfigScope; path: string } {
  const { globalPath, projectPath } = getConfigPaths(cwd);
  if (includeProject && existsSync(projectPath)) {
    return { scope: 'project', path: projectPath };
  }
  return { scope: 'global', path: globalPath };
}

async function setSandboxConfigEnabled(
  cwd: string,
  enabled: boolean,
  includeProject = true,
): Promise<SandboxConfigScope> {
  const { scope, path } = getSandboxConfigWriteTarget(cwd, includeProject);
  await withFileMutationQueue(path, async () => {
    const config = readOrEmptyConfig(path);
    config.enabled = enabled;
    writeConfigFile(path, config);
  });

  return scope;
}

async function addConfigValue(
  configPath: string,
  value: string,
  readValues: (config: SandboxConfigFile) => string[],
  writeValues: (config: SandboxConfigFile, values: string[]) => void,
): Promise<void> {
  await withFileMutationQueue(configPath, async () => {
    const config = readOrEmptyConfig(configPath);
    const existing = readValues(config);
    if (existing.includes(value)) return;
    writeValues(config, [...existing, value]);
    writeConfigFile(configPath, config);
  });
}

function addDomainToConfig(configPath: string, domain: string): Promise<void> {
  return addConfigValue(
    configPath,
    domain,
    (config) => config.network?.allowedDomains ?? [],
    (config, allowedDomains) => {
      config.network = {
        ...config.network,
        allowedDomains,
        deniedDomains: config.network?.deniedDomains ?? [],
      };
    },
  );
}

function addReadPathToConfig(configPath: string, pathToAdd: string): Promise<void> {
  return addConfigValue(
    configPath,
    pathToAdd,
    (config) => config.filesystem?.allowRead ?? [],
    (config, allowRead) => {
      config.filesystem = { ...config.filesystem, allowRead };
    },
  );
}

function addWritePathToConfig(configPath: string, pathToAdd: string): Promise<void> {
  return addConfigValue(
    configPath,
    pathToAdd,
    (config) => config.filesystem?.allowWrite ?? [],
    (config, allowWrite) => {
      config.filesystem = { ...config.filesystem, allowWrite };
    },
  );
}

function mergeAllowances(base: string[], session: string[], execution?: string[]): string[] {
  return [...base, ...session, ...(execution ?? [])];
}

function domainMatchesPattern(domain: string, pattern: string): boolean {
  // A trailing dot ("pastebin.com.") is the same host to DNS but would slip past
  // a literal deny entry; strip it from both sides before matching.
  const normalizedDomain = domain.toLowerCase().replace(/\.+$/, '');
  const normalizedPattern = pattern.toLowerCase().replace(/\.+$/, '');

  if (normalizedPattern === '*') return true;
  if (normalizedPattern.startsWith('*.')) {
    const base = normalizedPattern.slice(2);
    return normalizedDomain === base || normalizedDomain.endsWith(`.${base}`);
  }

  return normalizedDomain === normalizedPattern;
}

export function domainMatchesAny(domain: string, patterns: string[]): boolean {
  return patterns.some((pattern) => domainMatchesPattern(domain, pattern));
}

function allowsAllDomains(allowedDomains: string[]): boolean {
  return allowedDomains.includes('*');
}

export function shouldPromptForWrite(path: string, allowWrite: string[], cwd: string): boolean {
  return allowWrite.length === 0 || !matchesPattern(path, allowWrite, cwd);
}

// Relative entries (notably ".") resolve against `cwd` — the command's working
// directory that landstrip itself uses as its policy base — not the extension
// process's own cwd. Resolving against process.cwd() would let the broker's
// allow/deny decision diverge from landstrip's whenever the agent operates
// outside the directory pi was launched from.
function expandPath(filePath: string, cwd: string): string {
  return resolve(cwd, expandHomePath(filePath));
}

function canonicalizePath(filePath: string, cwd: string): string {
  const abs = expandPath(filePath, cwd);

  try {
    return realpathSync.native(abs);
  } catch {
    const tail: string[] = [];
    let probe = abs;

    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return abs;
      tail.unshift(basename(probe));
      probe = parent;
    }

    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return abs;
    }
  }
}

export function matchesPattern(filePath: string, patterns: string[], cwd: string): boolean {
  const abs = canonicalizePath(filePath, cwd);

  return patterns.some((pattern) => {
    const absPattern = pattern.includes('*')
      ? expandPath(pattern, cwd)
      : canonicalizePath(pattern, cwd);

    if (pattern.includes('*')) {
      // Mirror landstrip's matcher: `**/` spans directories, `**` spans any run,
      // but a single `*` stops at `/` — so `/srv/*/pub` cannot reach
      // `/srv/a/secret/pub`. Compiling `*` to `.*` would over-match across `/`.
      const escaped = absPattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*\/|\*\*|\*/g, (token) =>
          token === '**/' ? '(?:.*/)?' : token === '**' ? '.*' : '[^/]*',
        );
      return new RegExp(`^${escaped}$`).test(abs);
    }

    const sep = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sep);
  });
}

function normalizeBlockedPath(path: string, cwd: string): string {
  return canonicalizePath(isAbsolute(path) ? path : join(cwd, path), cwd);
}

// Breadth-first filesystem approval: when the user allows a blocked read/write,
// approve the broadest reasonable ancestor (e.g. `~/.cargo`, not each subcrate
// file) so a single scan does not spawn one prompt per file. matchesPattern
// already treats a bare directory entry as covering everything beneath it, so
// storing the scope is enough for sibling files to auto-allow.
function pathUnderDirectory(filePath: string, dir: string): boolean {
  if (filePath === dir) return true;
  const sep = dir.endsWith('/') ? '' : '/';
  return filePath.startsWith(dir + sep);
}

// The broadest ancestor worth approving in one action: the immediate child of
// `$HOME` (e.g. `~/.cargo`) for paths under the user's home, the project root
// for paths under it, otherwise the containing directory. When the file sits
// directly on a boundary (so the only ancestor is `$HOME` itself, which would
// over-broaden), fall back to the exact file so nothing widens silently.
export function sessionScopeFor(filePath: string, baseDirectory: string): string {
  const dir = dirname(filePath);
  const home = homedir();
  const boundaries = new Set<string>();
  if (home) boundaries.add(home);
  try {
    const realHome = realpathSync.native(home);
    if (realHome) boundaries.add(realHome);
  } catch {
    // $HOME not resolvable — fall back to the raw value only.
  }

  for (const boundary of boundaries) {
    if (pathUnderDirectory(dir, boundary)) {
      const rest = dir.slice(boundary.length).replace(/^\/+/, '');
      const first = rest.split('/')[0];
      if (!first) return filePath;
      return boundary.endsWith('/') ? boundary + first : `${boundary}/${first}`;
    }
  }

  if (pathUnderDirectory(dir, baseDirectory)) return baseDirectory;
  return dir;
}

// Length of the longest entry in `patterns` that matches `path`, or -1 for no
// match. Canonicalized so the value reflects how specific the rule is.
function longestPrefixMatch(path: string, patterns: string[], cwd: string): number {
  let best = -1;
  for (const pattern of patterns) {
    if (!matchesPattern(path, [pattern], cwd)) continue;
    const canonical = pattern.includes('*')
      ? expandPath(pattern, cwd)
      : canonicalizePath(pattern, cwd);
    if (canonical.length > best) best = canonical.length;
  }
  return best;
}

// Most-specific-match wins: a read is allowed when its longest matching
// allowRead entry is at least as specific as its longest matching denyRead
// entry. So an explicit allow (e.g. a granted `~/.cache`) overrides the broad
// `denyRead` gate (`/home`), while a narrow denyRead carve-out still beats a
// broad allow. Ties favor allow. denyWrite stays an absolute block elsewhere.
export function readAllowed(
  path: string,
  allowRead: string[],
  denyRead: string[],
  cwd: string,
): boolean {
  const allow = longestPrefixMatch(path, allowRead, cwd);
  if (allow < 0) return false;
  return allow >= longestPrefixMatch(path, denyRead, cwd);
}

function isPathLike(value: string): boolean {
  const trimmed = value.trim();
  return (
    trimmed === '~' ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('~/') ||
    trimmed.startsWith('./') ||
    trimmed.startsWith('../') ||
    trimmed.startsWith('.') ||
    trimmed.includes('/')
  );
}

function normalizePathMatch(value: string, cwd: string): string | null {
  return isPathLike(value) ? normalizeBlockedPath(value, cwd) : null;
}

function isFilesystemTrap(trap: LandstripTrap): trap is LandstripFilesystemTrap {
  return trap.kind === 'filesystem';
}

// filesystem and network traps report an access the policy denied; launch, usage
// and internal traps report that landstrip itself failed.
function isDenialTrap(trap: LandstripTrap): trap is LandstripDenialTrap {
  return trap.kind === 'filesystem' || trap.kind === 'network';
}

// A `state: "query"` trap suspends the child's syscall until we answer it on the
// trap socket. An `info` trap is terminal and carries a `query_id` of "0".
export function isQueryTrap(trap: LandstripTrap): trap is LandstripDenialTrap {
  return isDenialTrap(trap) && trap.state === 'query';
}

// Structured traps come only from the trap socket (fd 3); the sandboxed command
// controls its own stderr and could forge a trap line, so these `extractBlocked*`
// helpers must be fed only that trusted channel. Agent-controlled stderr is read
// with the `extractNative*` regexes instead, which match a real kernel-denial
// message rather than a JSON record.
function extractBlockedPath(trapOutput: string, cwd: string): string | null {
  const landstripErrors = parseLandstripTraps(trapOutput).filter(isFilesystemTrap);
  if (landstripErrors.length > 0) {
    return normalizeBlockedPath(landstripErrors[0].path, cwd);
  }

  return null;
}

function extractNativeDeniedPath(output: string, cwd: string): string | null {
  let match = output.match(/['"]([^'"\n]+)['"]:\s+(?:Operation not permitted|Permission denied)/);
  if (match) return normalizePathMatch(match[1], cwd);

  // bash/sh: line X: /path: Permission denied
  match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?([^:\n]+): (?:Operation not permitted|Permission denied)/,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  // ls/cat/cp: cannot open/access/stat '/path': Permission denied
  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot (?:open|access|stat|create)(?: directory)? '?([^'\n]+?)'?(?: for (?:reading|writing))?: (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  // Generic: cmd: /absolute/path: Permission denied or Operation not permitted
  match = output.match(
    /^[a-zA-Z0-9_-]+: (\/[^:\n]+): (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizeBlockedPath(match[1], cwd);

  return null;
}

function extractNativeWriteDeniedPath(output: string, cwd: string): string | null {
  let match = output.match(
    /(?:[Uu]nable to create|cannot (?:create|touch|mkdir|remove|unlink|rename)|for writing)[^'"\n]*['"]([^'"\n]+)['"]:\s+(?:Operation not permitted|Permission denied)/m,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot create(?: directory)? '?([^'\n]+?)'?(?: for writing)?: (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  match = output.match(
    /^[a-zA-Z0-9_-]+: couldn't open temporary file (\/[^:\n]+): (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  return null;
}

function extractTrapBlockedPath(
  trapOutput: string,
  cwd: string,
  operation: 'read' | 'write',
): string | null {
  for (const error of parseLandstripTraps(trapOutput).filter(isFilesystemTrap)) {
    if (error.operation === operation) {
      return normalizeBlockedPath(error.path, cwd);
    }
  }

  return null;
}

// landstrip emits each trap as a flat JSON record tagged by a `kind` discriminant
// (`filesystem`, `network`, `launch`, `usage`, `internal`) alongside a stable
// `code` and variant-specific fields. The declarations it ships are erased at
// compile time, so validate the fields this extension reads before trusting a
// decoded line.
function isLandstripTrap(value: unknown): value is LandstripTrap {
  if (typeof value !== 'object' || value === null) return false;

  const obj = value as Record<string, unknown>;
  switch (obj.kind) {
    case 'filesystem':
      return (
        (obj.operation === 'read' || obj.operation === 'write') &&
        typeof obj.path === 'string' &&
        typeof obj.query_id === 'string'
      );
    case 'network':
      return (
        typeof obj.operation === 'string' &&
        typeof obj.target === 'string' &&
        typeof obj.query_id === 'string'
      );
    case 'launch':
      return typeof obj.program === 'string' && typeof obj.message === 'string';
    case 'usage':
      return typeof obj.message === 'string';
    case 'internal':
      return typeof obj.code === 'string' && typeof obj.message === 'string';
    default:
      return false;
  }
}

export function parseTrapLine(line: string): LandstripTrap | null {
  try {
    const parsed: unknown = JSON.parse(line);
    return isLandstripTrap(parsed) ? parsed : null;
  } catch {
    // Ignore non-JSON lines (e.g. stderr from child processes)
    return null;
  }
}

function parseLandstripTraps(output: string): LandstripTrap[] {
  const traps: LandstripTrap[] = [];

  for (const line of output.trim().split('\n')) {
    const trap = parseTrapLine(line);
    if (trap) traps.push(trap);
  }

  return traps;
}

export function formatLandstripTraps(traps: LandstripTrap[]): string {
  return traps
    .map((trap) => {
      switch (trap.kind) {
        case 'filesystem':
          return `landstrip: filesystem ${trap.operation} denied: ${trap.path} (${trap.mechanism})`;
        case 'network':
          return `landstrip: network ${trap.operation} denied: ${trap.target} (${trap.mechanism})`;
        case 'launch':
          return `landstrip: launch failed: ${trap.program}: ${trap.message}`;
        case 'usage':
          return `landstrip: usage error: ${trap.message}`;
        case 'internal': {
          const mechanism = trap.mechanism ? ` (${trap.mechanism})` : '';
          return `landstrip: ${trap.code}${mechanism}: ${trap.message}`;
        }
      }
    })
    .join('\n');
}

// The broker matches an answer to its query by the exact decimal `query_id`
// string the trap carried. A numeric id fails its deserializer, the line is
// dropped, and the child's syscall stays suspended.
export function controlResponseLine(
  queryId: string,
  action: LandstripControlResponse['action'],
): string {
  const response: LandstripControlResponse = { query_id: queryId, action };
  return JSON.stringify(response) + '\n';
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

function themeColors(theme: Theme) {
  return {
    dim: (value: string) => theme.fg('dim', value),
    muted: (value: string) => theme.fg('muted', value),
    accent: (value: string) => theme.fg('accent', value),
    text: (value: string) => theme.fg('text', value),
  };
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
  if (!child) return;

  child.kill('SIGKILL');
  if (child.exitCode !== null || child.signalCode !== null) return;

  await new Promise<void>((resolve) => {
    let settleTimer: NodeJS.Timeout | undefined;
    const done = (): void => {
      if (settleTimer) clearTimeout(settleTimer);
      child.removeListener('exit', done);
      resolve();
    };
    child.once('exit', done);
    settleTimer = setTimeout(done, 1_000);
  });
}

const permissionPromptQueue = new AsyncQueue();

async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
  options: PromptOption[],
  signal?: AbortSignal,
): Promise<PermissionChoice> {
  if (!ctx.hasUI) return 'abort';

  const releasePrompt = await permissionPromptQueue.acquire();

  try {
    const labels = options.map((option) =>
      option.hint ? `${option.label} ${option.hint}` : option.label,
    );
    const selected = await ctx.ui.select(title, labels, { signal });
    const index = selected === undefined ? -1 : labels.indexOf(selected);
    const option = options[index];
    if (!option) return 'abort';
    if (option.confirm) {
      const confirmed = await ctx.ui.confirm(
        `Confirm ${option.label.toLowerCase()}`,
        option.hint ?? 'This changes persisted sandbox policy.',
        { signal },
      );
      if (!confirmed) return 'abort';
    }
    return option.action;
  } finally {
    releasePrompt();
  }
}

function promptDomainBlock(
  ctx: ExtensionContext,
  domain: string,
  signal?: AbortSignal,
): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Network blocked: "${domain}" is not in allowedDomains`,
    PERMISSION_OPTIONS,
    signal,
  );
}

function promptReadBlock(
  ctx: ExtensionContext,
  filePath: string,
  reason?: string,
  signal?: AbortSignal,
): Promise<PermissionChoice> {
  const title = reason
    ? `Read blocked: "${filePath}" is in denyRead (${reason})`
    : `Read blocked: "${filePath}" is not in allowRead`;
  return showPermissionPrompt(ctx, title, PERMISSION_OPTIONS, signal);
}

function promptWriteBlock(
  ctx: ExtensionContext,
  filePath: string,
  signal?: AbortSignal,
): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Write blocked: "${filePath}" is not in allowWrite`,
    PERMISSION_OPTIONS,
    signal,
  );
}

// The broker knows only address:port, and no sandbox field can express a grant
// for one non-loopback endpoint: allowedDomains is enforced by the proxy,
// allowLocalBinding grants all loopback endpoints, and allowNetwork disables
// network enforcement. So a non-loopback connection is granted for the session
// or not at all.
function promptNetworkBlock(
  ctx: ExtensionContext,
  operation: string,
  target: string,
  signal?: AbortSignal,
): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Network blocked: ${operation} to "${target}"`,
    NETWORK_PERMISSION_OPTIONS,
    signal,
  );
}

// The binary is bundled and version-locked to @landstrip/landstrip via npm, so
// compatibility is settled at install time; only confirm it is runnable here.
function landstripAvailable(): boolean {
  try {
    return spawnSync(binaryPath(), ['--version']).status === 0;
  } catch {
    return false;
  }
}

function landstripDisplayPath(): string {
  try {
    return binaryPath();
  } catch {
    return 'unavailable';
  }
}

// Write the full environment to a temporary shell file.
//
// Sandboxed process reaches environment through the filesystem instead of the
// execve() argument buffer, which has a ~128 KiB cap.
export function writeEnvFile(
  env: NodeJS.ProcessEnv,
  proxyPort: number | null,
): { dir: string; path: string } {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    // bash exports non-identifier names (e.g. a `BASH_FUNC_foo%%` function
    // export) that `export NAME=...` rejects; emitting one makes `source` exit
    // non-zero and the `&&`-chained command never runs. Skip what the shell
    // itself cannot set.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    // Escape single quotes: ' -> '\''
    const escaped = value.replace(/'/g, "'\\''");
    lines.push(`export ${key}='${escaped}'`);
  }
  if (proxyPort !== null) {
    const url = `http://127.0.0.1:${proxyPort}`;
    for (const name of PROXY_ENVIRONMENT_VARIABLES) {
      lines.push(`export ${name}='${url}'`);
    }
    lines.push("export NO_PROXY=''");
    lines.push("export no_proxy=''");
  }
  const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-env-'));
  const path = join(dir, 'env.sh');
  writeFileSync(path, lines.join('\n'), 'utf-8');
  return { dir, path };
}

function parseProxyPort(value: string | undefined, defaultPort: number): number | null {
  const rawPort = value ?? String(defaultPort);
  if (!/^\d+$/.test(rawPort)) return null;

  const port = Number(rawPort);
  return port >= 1 && port <= 65535 ? port : null;
}

function splitHostPort(target: string, defaultPort: number): { host: string; port: number } | null {
  const bracketMatch = target.match(/^\[([^\]]+)\](?::(.*))?$/);
  if (bracketMatch) {
    const port = parseProxyPort(bracketMatch[2], defaultPort);
    return port === null ? null : { host: bracketMatch[1], port };
  }

  const lastColon = target.lastIndexOf(':');
  if (lastColon > -1 && target.indexOf(':') === lastColon) {
    const port = parseProxyPort(target.slice(lastColon + 1), defaultPort);
    return port === null ? null : { host: target.slice(0, lastColon), port };
  }

  return { host: target, port: defaultPort };
}

function denyProxyRequest(client: Socket, status = '403 Forbidden'): void {
  client.write(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\n\r\n`);
  client.end();
}

export function isPublicProxyAddress(address: string, family = isIP(address)): boolean {
  if (family === 4) return !prohibitedProxyAddresses.check(address, 'ipv4');
  if (family === 6) return !prohibitedProxyAddresses.check(address, 'ipv6');
  return false;
}

async function resolveProxyEndpoint(host: string): Promise<{ address: string; family: 4 | 6 }> {
  const literalFamily = isIP(host);
  if (literalFamily === 4 || literalFamily === 6) {
    if (!isPublicProxyAddress(host, literalFamily)) {
      throw new Error(`Proxy destination is not public: ${host}`);
    }
    return { address: host, family: literalFamily };
  }
  const addresses = await lookup(host, { all: true, verbatim: true });
  if (
    addresses.length === 0 ||
    addresses.some(({ address, family }) => !isPublicProxyAddress(address, family))
  ) {
    throw new Error(`Proxy destination resolves to a non-public address: ${host}`);
  }
  const endpoint = addresses[0];
  if (!endpoint || (endpoint.family !== 4 && endpoint.family !== 6)) {
    throw new Error(`Proxy could not resolve destination: ${host}`);
  }
  return { address: endpoint.address, family: endpoint.family };
}

function pipeSockets(client: Socket, upstream: Socket, initialData?: Buffer): void {
  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());

  if (initialData?.length) upstream.write(initialData);

  client.pipe(upstream);
  upstream.pipe(client);
}

/** Options for creating a landstrip sandbox integration. */
export interface LandstripIntegrationOptions {
  /** Register a sandboxed bash tool when the integration is registered. */
  readonly registerBashTool?: boolean;
  /** Working directory used when registering the default bash tool. */
  readonly cwd?: string;
}

/** Landstrip sandbox integration hooks for Pi. */
export interface LandstripIntegration extends PiLandstripRuntimeV1 {
  /** Prepare a full Pi RPC process constrained by the effective sandbox policy. */
  prepareRpcWorker(options: LandstripRpcWorkerOptions): Promise<LandstripRpcWorkerLaunch>;
  /** Register the integration's tools, events, flags, and commands with Pi. */
  register(pi: ExtensionAPI, runtime?: SubagentRuntime): void;
  /** Publish an integration lifecycle event from an embedded runtime. */
  emit(event: LandstripEvent): void;
}

export interface LandstripRpcWorkerOptions extends LandstripProcessOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly readPaths: readonly string[];
  readonly writePaths: readonly string[];
}

export interface LandstripRpcWorkerLaunch extends LandstripPreparedProcess {
  readonly spawn: RpcSpawn;
}

export type {
  LandstripBashTool,
  LandstripContextV1,
  LandstripEvent,
  LandstripPreparedProcess,
  LandstripProcessOptions,
  LandstripSandboxState,
  LandstripWorkerExtension,
  PiLandstripRuntimeV1,
} from './api.ts';

/** Register the landstrip extension with Pi. */
export default function (pi: ExtensionAPI) {
  const workerConfig = workerConfigFromEnvironment();
  if (workerConfig) {
    registerSubagentWorker(pi, workerConfig);
    return;
  }
  const integration = createLandstripIntegration();
  const runtime = registerSubagents(pi, integration);
  integration.register(pi, runtime);
}

/** Create a landstrip integration for registration or custom embedding. */
export function createLandstripIntegration(
  options: LandstripIntegrationOptions = {},
): LandstripIntegration {
  const shouldRegisterBashTool = options.registerBashTool ?? true;
  const localCwd = options.cwd ?? process.cwd();
  let projectConfigTrusted = false;

  function loadConfig(cwd: string): SandboxConfig {
    return loadSandboxConfig(cwd, projectConfigTrusted);
  }

  function createPlainBashTool(cwd: string): LandstripBashTool {
    return createBashToolDefinition(cwd, {
      shellPath: SettingsManager.create(cwd).getShellPath(),
    });
  }

  let sandboxEnabled = false;
  let sandboxReady = false;
  let sandboxState: LandstripSandboxState = 'unavailable';
  let unsandboxedWorkerWarningShown = false;
  let activeContext: ExtensionContext | undefined;
  let unpublishRuntime: (() => void) | undefined;
  const eventHandlers = new Set<(event: LandstripEvent) => void>();
  const workerExtensions = new Map<string, { entry: string; registrations: number }>();
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  const sessionAllowedTargets: string[] = [];

  function getContext(ctx = activeContext): LandstripContextV1 {
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

  function resetSessionAllowances(): void {
    sessionAllowedDomains.length = 0;
    sessionAllowedReadPaths.length = 0;
    sessionAllowedWritePaths.length = 0;
    sessionAllowedTargets.length = 0;
    unsandboxedWorkerWarningShown = false;
  }

  function getEffectiveAllowedDomains(
    config: SandboxConfig,
    allowances?: ExecutionAllowances,
  ): string[] {
    return mergeAllowances(
      config.network.allowedDomains,
      sessionAllowedDomains,
      allowances?.domains,
    );
  }

  function getEffectiveAllowRead(
    config: SandboxConfig,
    allowances?: ExecutionAllowances,
  ): string[] {
    return mergeAllowances(
      config.filesystem.allowRead,
      sessionAllowedReadPaths,
      allowances?.readPaths,
    );
  }

  function getEffectiveAllowWrite(
    config: SandboxConfig,
    allowances?: ExecutionAllowances,
  ): string[] {
    return mergeAllowances(
      config.filesystem.allowWrite,
      sessionAllowedWritePaths,
      allowances?.writePaths,
    );
  }

  async function applyDomainChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (choice === 'project') await addDomainToConfig(projectPath, domain);
    if (choice === 'global') await addDomainToConfig(globalPath, domain);
    const target = choice === 'once' ? allowances?.domains : sessionAllowedDomains;
    if (target && !target.includes(domain)) target.push(domain);
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
    scope: string,
  ): void {
    if (scope !== filePath) notify(ctx, `${verb} allowed (${choice}): ${scope}`, 'info');
  }

  async function applyReadChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    const scope = sessionScopeFor(filePath, cwd);
    if (choice === 'project') await addReadPathToConfig(projectPath, scope);
    if (choice === 'global') await addReadPathToConfig(globalPath, scope);
    const target = choice === 'once' ? allowances?.readPaths : sessionAllowedReadPaths;
    if (target && !target.includes(scope)) target.push(scope);
    noteScope(ctx, 'Read', choice, filePath, scope);
  }

  async function applyWriteChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
    allowances?: ExecutionAllowances,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    const scope = sessionScopeFor(filePath, cwd);
    if (choice === 'project') await addWritePathToConfig(projectPath, scope);
    if (choice === 'global') await addWritePathToConfig(globalPath, scope);
    const target = choice === 'once' ? allowances?.writePaths : sessionAllowedWritePaths;
    if (target && !target.includes(scope)) target.push(scope);
    noteScope(ctx, 'Write', choice, filePath, scope);
  }

  async function ensureDomainAllowed(
    ctx: ExtensionContext,
    domain: string,
    cwd: string,
    allowances?: ExecutionAllowances,
    signal?: AbortSignal,
  ): Promise<boolean> {
    const config = loadConfig(cwd);

    if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
    if (domainMatchesAny(domain, getEffectiveAllowedDomains(config, allowances))) return true;

    const choice = await promptDomainBlock(ctx, domain, signal);
    if (choice === 'abort') return false;

    await applyDomainChoice(choice, domain, cwd, allowances);
    return true;
  }

  function buildLandstripPolicy(
    cwd: string,
    proxyPort: number | null,
    allowances?: ExecutionAllowances,
  ): LandstripPolicy {
    const config = loadConfig(cwd);

    return {
      network: {
        allowNetwork: config.network.allowNetwork,
        allowLocalBinding: config.network.allowLocalBinding,
        allowAllUnixSockets: config.network.allowAllUnixSockets,
        allowUnixSockets: config.network.allowUnixSockets,
        ...(proxyPort !== null ? { httpProxyPort: proxyPort } : {}),
      },
      filesystem: {
        denyRead: config.filesystem.denyRead,
        allowRead: getEffectiveAllowRead(config, allowances),
        allowWrite: getEffectiveAllowWrite(config, allowances),
        denyWrite: config.filesystem.denyWrite,
      },
    };
  }

  function writePolicyFile(
    cwd: string,
    proxyPort: number | null,
    allowances?: ExecutionAllowances,
  ): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-'));
    const path = join(dir, 'policy.json');
    writeFileSync(
      path,
      JSON.stringify(buildLandstripPolicy(cwd, proxyPort, allowances), null, 2) + '\n',
      'utf-8',
    );

    return { dir, path };
  }

  function startProxy(
    ctx: ExtensionContext,
    allowances: ExecutionAllowances,
    signal?: AbortSignal,
    authorization?: string,
  ): Promise<{ port: number; stop: () => Promise<void> }> {
    const sockets = new Set<Socket>();

    async function domainAllowed(domain: string): Promise<boolean> {
      const config = loadConfig(ctx.cwd);
      if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
      return ensureDomainAllowed(ctx, domain, ctx.cwd, allowances, signal);
    }

    // Track the upstream socket so stop() tears it down, and abandon a still-
    // connecting upstream when its client goes away — otherwise a connect to a
    // black-holed host lingers in SYN-retry (~2 min), leaking an fd per request.
    function trackUpstream(upstream: Socket, client: Socket, settled: () => boolean): void {
      sockets.add(upstream);
      upstream.once('close', () => sockets.delete(upstream));
      client.once('close', () => {
        if (!settled()) upstream.destroy();
      });
    }

    async function handleConnect(client: Socket, target: string, rest: Buffer): Promise<void> {
      const endpoint = splitHostPort(target, 443);
      if (!endpoint || !Number.isFinite(endpoint.port)) {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }

      if (!(await domainAllowed(endpoint.host))) {
        denyProxyRequest(client);
        return;
      }

      const resolved = await resolveProxyEndpoint(endpoint.host);
      let settled = false;
      const upstream = connectNet(
        { host: resolved.address, port: endpoint.port, family: resolved.family },
        () => {
          settled = true;
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          pipeSockets(client, upstream, rest);
        },
      );
      trackUpstream(upstream, client, () => settled);
      upstream.once('error', () => {
        if (settled) return;
        settled = true;
        denyProxyRequest(client, '502 Bad Gateway');
      });
    }

    async function handleHttp(client: Socket, headerText: string, rest: Buffer): Promise<void> {
      const lines = headerText.split(/\r?\n/);
      const [method, rawTarget, version] = lines[0].split(' ');

      if (!method || !rawTarget || !version) {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }

      let url: URL;
      try {
        url = new URL(rawTarget);
      } catch {
        const host = lines
          .find((line) => line.toLowerCase().startsWith('host:'))
          ?.slice(5)
          .trim();
        if (!host) {
          denyProxyRequest(client, '400 Bad Request');
          return;
        }

        try {
          url = new URL(`http://${host}${rawTarget}`);
        } catch {
          denyProxyRequest(client, '400 Bad Request');
          return;
        }
      }

      if (!(await domainAllowed(url.hostname))) {
        denyProxyRequest(client);
        return;
      }

      const defaultPort = url.protocol === 'https:' ? 443 : 80;
      const port = parseProxyPort(url.port || undefined, defaultPort);
      if (port === null) {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }
      const path = `${url.pathname}${url.search}` || '/';
      lines[0] = `${method} ${path} ${version}`;

      const rewrittenHeader = lines
        .filter(
          (line) =>
            !line.toLowerCase().startsWith('proxy-connection:') &&
            !line.toLowerCase().startsWith('proxy-authorization:'),
        )
        .join('\r\n');
      const resolved = await resolveProxyEndpoint(url.hostname);
      let settled = false;
      const upstream = connectNet({ host: resolved.address, port, family: resolved.family }, () => {
        settled = true;
        upstream.write(`${rewrittenHeader}\r\n\r\n`);
        pipeSockets(client, upstream, rest);
      });
      trackUpstream(upstream, client, () => settled);
      upstream.once('error', () => {
        if (settled) return;
        settled = true;
        denyProxyRequest(client, '502 Bad Gateway');
      });
    }

    function handleClient(client: Socket): void {
      sockets.add(client);
      client.on('close', () => sockets.delete(client));
      client.on('error', () => sockets.delete(client));

      let buffered = Buffer.alloc(0);

      client.on('data', (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        const headerEnd = buffered.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
          if (buffered.length > 65536)
            denyProxyRequest(client, '431 Request Header Fields Too Large');
          return;
        }

        client.pause();
        client.removeAllListeners('data');

        const header = buffered.subarray(0, headerEnd).toString('utf-8');
        const rest = buffered.subarray(headerEnd + 4);
        if (authorization) {
          const supplied = header
            .split(/\r?\n/)
            .find((line) => line.toLowerCase().startsWith('proxy-authorization:'))
            ?.slice('proxy-authorization:'.length)
            .trim();
          if (supplied !== authorization) {
            denyProxyRequest(client, '407 Proxy Authentication Required');
            return;
          }
        }
        const firstLine = header.split(/\r?\n/, 1)[0];
        const [method, target] = firstLine.split(' ');

        const task =
          method?.toUpperCase() === 'CONNECT'
            ? handleConnect(client, target, rest)
            : handleHttp(client, header, rest);
        task.catch(() => denyProxyRequest(client, '502 Bad Gateway'));
      });
    }

    const server = createServer(handleClient);
    let stopped = false;

    return new Promise((resolve, reject) => {
      server.on('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.removeListener('error', reject);
        const address = server.address() as AddressInfo;

        resolve({
          port: address.port,
          stop: () =>
            new Promise<void>((done) => {
              if (stopped) {
                done();
                return;
              }
              stopped = true;
              for (const socket of sockets) socket.destroy();
              server.close(() => done());
            }),
        });
      });
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
    reason?: 'unprompted' | 'rejected' | 'hard-deny';
  }

  async function resolveTrapQuery(
    trap: LandstripFilesystemTrap | LandstripNetworkTrap,
    ctx: ExtensionContext,
    cwd: string,
    allowances: ExecutionAllowances,
    promptOnBlock: boolean,
    signal?: AbortSignal,
  ): Promise<TrapQueryResult> {
    if (!isFilesystemTrap(trap)) {
      const key = `${trap.operation}\u0000${trap.target}`;
      if (sessionAllowedTargets.includes(key) || allowances.targets.includes(key)) {
        return { action: 'allow' };
      }
      if (!ctx.hasUI || !promptOnBlock) return { action: 'deny', reason: 'unprompted' };

      const choice = await promptNetworkBlock(ctx, trap.operation, trap.target, signal);
      if (choice === 'abort') return { action: 'deny', reason: 'rejected' };
      const targets = choice === 'once' ? allowances.targets : sessionAllowedTargets;
      targets.push(key);
      return { action: 'allow' };
    }

    const path = normalizeBlockedPath(trap.path, cwd);
    const config = loadConfig(cwd);
    const allowed =
      trap.operation === 'read'
        ? readAllowed(
            path,
            getEffectiveAllowRead(config, allowances),
            config.filesystem.denyRead,
            cwd,
          )
        : !matchesPattern(path, config.filesystem.denyWrite, cwd) &&
          !shouldPromptForWrite(path, getEffectiveAllowWrite(config, allowances), cwd);
    if (allowed) return { action: 'allow' };
    if (trap.operation === 'write' && matchesPattern(path, config.filesystem.denyWrite, cwd)) {
      return { action: 'deny', reason: 'hard-deny' };
    }
    if (!ctx.hasUI || !promptOnBlock) return { action: 'deny', reason: 'unprompted' };

    const choice =
      trap.operation === 'read'
        ? await promptReadBlock(
            ctx,
            path,
            matchesPattern(path, config.filesystem.denyRead, cwd)
              ? 'granting allowRead will override it'
              : undefined,
            signal,
          )
        : await promptWriteBlock(ctx, path, signal);
    if (choice === 'abort') return { action: 'deny', reason: 'rejected' };
    if (trap.operation === 'read') {
      await applyReadChoice(ctx, choice, path, cwd, allowances);
    } else {
      await applyWriteChoice(ctx, choice, path, cwd, allowances);
    }
    return { action: 'allow' };
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
    const reportTrapError = (message: string): void => {
      notify(ctx, message, 'error');
      if (!ctx.hasUI) console.error(`pi-landstrip: ${message}`);
    };
    const respond = (queryId: string, action: LandstripControlResponse['action']): void => {
      if (socket.destroyed) return;
      socket.write(controlResponseLine(queryId, action), (error) => {
        if (error) reportTrapError(`Worker sandbox control response failed: ${error.message}`);
      });
    };

    const handleQuery = (trap: LandstripFilesystemTrap | LandstripNetworkTrap): void => {
      prompts = prompts
        .then(async () => {
          const result = await resolveTrapQuery(trap, ctx, cwd, allowances, true, signal);
          respond(trap.query_id, result.action);
        })
        .catch(() => respond(trap.query_id, 'deny'));
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
          reportTrapError(`Worker sandbox reported: ${formatLandstripTraps([trap])}`);
          continue;
        }
        handleQuery(trap);
      }
    });
  }

  function prepareUnsandboxedRpcWorker(
    options: LandstripRpcWorkerOptions,
  ): LandstripRpcWorkerLaunch {
    let spawned = false;
    let disposed = false;
    let disposePromise: Promise<void> | undefined;
    let preparedChild: ChildProcess | undefined;
    const spawnWorker: RpcSpawn = (command, args, spawnOptions) => {
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
      return child as ReturnType<RpcSpawn>;
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

  async function prepareRpcWorker(
    options: LandstripRpcWorkerOptions,
  ): Promise<LandstripRpcWorkerLaunch> {
    if (options.signal?.aborted) throw new Error('Task cancelled');
    if (!ensureSandboxState(options.ctx)) {
      const explicitlyDisabled = noSandboxFlag || !loadConfig(options.cwd).enabled;
      if (!explicitlyDisabled) {
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
      return prepareUnsandboxedRpcWorker(options);
    }
    const allowances: ExecutionAllowances = {
      domains: [],
      readPaths: [...options.readPaths],
      writePaths: [...options.writePaths],
      targets: [],
    };
    const config = loadConfig(options.cwd);
    const proxyToken = randomBytes(32).toString('base64url');
    const proxyAuthorization = `Basic ${Buffer.from(`landstrip:${proxyToken}`).toString('base64')}`;
    const proxy = config.network.allowNetwork
      ? null
      : await startProxy(options.ctx, allowances, options.signal, proxyAuthorization);
    let policy: ReturnType<typeof writePolicyFile> | undefined;
    let trapSocket: NetSocket | undefined;
    let childEnd: NetSocket | undefined;
    let disposed = false;
    try {
      if (options.signal?.aborted) throw new Error('Task cancelled');
      policy = writePolicyFile(options.cwd, proxy?.port ?? null, allowances);
      if (process.platform !== 'win32') {
        [trapSocket, childEnd] = await createSocketPair();
        if (options.signal?.aborted) throw new Error('Task cancelled');
        attachWorkerTrap(trapSocket, options.ctx, options.cwd, allowances, options.signal);
      }
    } catch (error) {
      trapSocket?.destroy();
      childEnd?.destroy();
      if (policy) rmSync(policy.dir, { recursive: true, force: true });
      await proxy?.stop();
      throw error;
    }

    const workerPolicy = policy;
    const workerTrapSocket = trapSocket;
    const workerChildEnd = childEnd;
    const workerEnv = { ...options.env };
    if (proxy) {
      const url = `http://landstrip:${proxyToken}@127.0.0.1:${proxy.port}`;
      for (const name of PROXY_ENVIRONMENT_VARIABLES) {
        workerEnv[name] = url;
      }
      workerEnv.NO_PROXY = '';
      workerEnv.no_proxy = '';
    }
    let spawned = false;
    let disposePromise: Promise<void> | undefined;
    let preparedChild: ChildProcess | undefined;
    const spawnWorker: RpcSpawn = (_command, _args, spawnOptions) => {
      if (disposed) throw new Error('Prepared process has been disposed');
      if (spawned) throw new Error('Prepared process can only be spawned once');
      spawned = true;
      const landstripArgs = ['-p', workerPolicy.path, options.command, ...options.args];
      const stdio: StdioOptions = workerChildEnd
        ? ['pipe', 'pipe', 'pipe', workerChildEnd]
        : ['pipe', 'pipe', 'pipe'];
      if (workerChildEnd) landstripArgs.unshift('--trap-fd', '3');
      const child = spawn(binaryPath(), landstripArgs, {
        ...spawnOptions,
        cwd: options.cwd,
        env: workerEnv,
        detached: true,
        stdio,
      });
      workerChildEnd?.destroy();
      patchProcessGroupKill(child);
      preparedChild = child;
      return child as ReturnType<RpcSpawn>;
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
          await stopPreparedChild(preparedChild);
          workerTrapSocket?.destroy();
          workerChildEnd?.destroy();
          rmSync(workerPolicy.dir, { recursive: true, force: true });
          await proxy?.stop();
        })();
        return disposePromise;
      },
    };
  }

  async function prepareProcess(
    options: LandstripProcessOptions,
  ): Promise<LandstripPreparedProcess> {
    if (process.platform === 'win32' && (noSandboxFlag || !loadConfig(options.cwd).enabled)) {
      throw new Error('Generic process preparation requires sandboxing on Windows');
    }
    return prepareRpcWorker({
      ...options,
      env: options.env ?? process.env,
      readPaths: options.readPaths ?? [],
      writePaths: options.writePaths ?? [],
    });
  }

  function createLandstripBashOps(
    ctx: ExtensionContext,
    callbacks: LandstripBashCallbacks = {},
    allowances: ExecutionAllowances = { domains: [], readPaths: [], writePaths: [], targets: [] },
  ): BashOperations {
    return {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

        const { shell, args } = getShellConfig(SettingsManager.create(cwd).getShellPath());
        const config = loadConfig(cwd);
        const allowNetwork = config.network.allowNetwork;
        const proxy = allowNetwork ? null : await startProxy(ctx, allowances, signal);

        // Started/created before the child exists, so tear them down on any early
        // failure too — the env file holds a copy of the environment (secrets),
        // and the proxy keeps a listening socket. Idempotent: safe to call twice.
        let policy: ReturnType<typeof writePolicyFile> | undefined;
        let envFile: ReturnType<typeof writeEnvFile> | undefined;
        let teardownPromise: Promise<void> | undefined;
        const teardownResources = (): Promise<void> => {
          teardownPromise ??= (async () => {
            await proxy?.stop();
            if (policy) rmSync(policy.dir, { recursive: true, force: true });
            if (envFile) rmSync(envFile.dir, { recursive: true, force: true });
          })();
          return teardownPromise;
        };

        let landstripArgs: string[];
        try {
          policy = writePolicyFile(cwd, proxy?.port ?? null, allowances);
          envFile = writeEnvFile(
            { ...process.env, ...env, PWD: resolve(cwd) },
            proxy?.port ?? null,
          );
          const wrappedCommand = `source '${envFile.path}' && ${command}`;
          landstripArgs = ['-p', policy.path, shell, ...args, wrappedCommand];
          if (process.platform !== 'win32') landstripArgs.unshift('--trap-fd', '3');
        } catch (error) {
          await teardownResources();
          throw error;
        }

        return new Promise((resolvePromise, reject) => {
          (async () => {
            let timeoutHandle: NodeJS.Timeout | undefined;
            let timedOut = false;
            let cleaned = false;
            let trapSocket: NetSocket | undefined;
            let childEnd: NetSocket | undefined;
            if (process.platform !== 'win32') [trapSocket, childEnd] = await createSocketPair();

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
              env: { PATH: process.env.PATH, HOME: process.env.HOME },
              detached: true,
              stdio,
            });
            patchProcessGroupKill(child);

            // Child has dup'd its end; parent can close its copy.
            childEnd?.destroy();

            function killChild(): void {
              child.kill('SIGKILL');
            }

            function onAbort(): void {
              killChild();
            }

            if (timeout !== undefined && timeout > 0) {
              timeoutHandle = setTimeout(() => {
                timedOut = true;
                killChild();
              }, timeout * 1000);
            }

            signal?.addEventListener('abort', onAbort, { once: true });
            let stderrAcc = '';
            let errorFdAcc = '';

            let execSettled = false;
            let childExited = false;
            let childExitCode: number | null = null;
            let postExitTimer: NodeJS.Timeout | undefined;
            let stdoutEnded = child.stdout === null;
            let stderrEnded = child.stderr === null;

            const finalizeExec = (code: number | null): void => {
              if (execSettled) return;
              execSettled = true;
              if (postExitTimer) clearTimeout(postExitTimer);
              // Stop tracking the inherited pipes: a backgrounded grandchild can
              // hold them open after the command itself exits, so 'close' would
              // otherwise never arrive.
              child.stdout?.destroy();
              child.stderr?.destroy();
              void (async () => {
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
                // Windows, where trap-fd inheritance is unsupported, use native
                // kernel-denial text from stderr.
                const blockedPath =
                  extractBlockedPath(errorFdAcc, cwd) ?? extractNativeDeniedPath(stderrAcc, cwd);
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
              if (childExited && !execSettled && stdoutEnded && stderrEnded) {
                finalizeExec(childExitCode);
              }
            };

            child.stdout?.on('data', onData);
            child.stderr?.on('data', (data: Buffer) => {
              stderrAcc += data.toString('utf8');
              callbacks.onStderr?.(data);
              onData(data);
            });
            child.stdout?.once('end', () => {
              stdoutEnded = true;
              maybeFinalizeAfterExit();
            });
            child.stderr?.once('end', () => {
              stderrEnded = true;
              maybeFinalizeAfterExit();
            });
            const trapDecoder = new StringDecoder('utf8');
            let trapBuffer = '';
            let queryChain: Promise<void> = Promise.resolve();

            const respondQuery = (
              queryId: string,
              action: LandstripControlResponse['action'],
            ): void => {
              if (!trapSocket || trapSocket.destroyed) return;
              trapSocket.write(controlResponseLine(queryId, action));
            };

            // Surface a denial through the error-fd accumulator so the post-close
            // notify and the runBashWithOptionalRetry prompt/retry paths still work.
            const appendErrorLine = (line: string): void => {
              const infoLine = line + '\n';
              errorFdAcc += infoLine;
              callbacks.onErrorFd?.(Buffer.from(infoLine, 'utf8'));
            };

            trapSocket?.on('data', (data: Buffer) => {
              trapBuffer += trapDecoder.write(data);
              let nl = trapBuffer.indexOf('\n');
              while (nl !== -1) {
                const line = trapBuffer.slice(0, nl);
                trapBuffer = trapBuffer.slice(nl + 1);
                nl = trapBuffer.indexOf('\n');
                if (line.length === 0) continue;
                const trap = parseTrapLine(line);
                // An unanswered query holds the child's syscall, so every query
                // gets an answer; anything else is informational and kept for
                // post-close handling.
                if (trap && isQueryTrap(trap)) {
                  queryChain = queryChain
                    .then(async () => {
                      const result = await resolveTrapQuery(
                        trap,
                        ctx,
                        cwd,
                        allowances,
                        callbacks.promptOnBlock === true,
                        signal,
                      );
                      if (
                        result.reason === 'unprompted' ||
                        (!isFilesystemTrap(trap) && result.reason === 'rejected')
                      ) {
                        appendErrorLine(line);
                      }
                      respondQuery(trap.query_id, result.action);
                    })
                    .catch(() => respondQuery(trap.query_id, 'deny'));
                } else {
                  appendErrorLine(line);
                }
              }
            });

            child.on('error', (error) => {
              if (execSettled) return;
              execSettled = true;
              if (postExitTimer) clearTimeout(postExitTimer);
              void (async () => {
                try {
                  await cleanup();
                  reject(error);
                } catch (cleanupError) {
                  reject(cleanupError);
                }
              })();
            });

            // Settle on 'exit' — the command itself has ended — rather than
            // waiting for 'close', which only fires once every inherited stdio
            // pipe is closed. A backgrounded process holding one open would
            // otherwise block us indefinitely.
            child.once('exit', (code) => {
              childExited = true;
              childExitCode = code;
              maybeFinalizeAfterExit();
              if (!execSettled) {
                postExitTimer = setTimeout(() => finalizeExec(code), EXIT_STDIO_GRACE_MS);
              }
            });
            child.once('close', (code) => finalizeExec(code));
          })().catch(async (error: unknown) => {
            // A failure before the child is wired (for example, creating the trap
            // channel) never reaches cleanup(), so free temporary resources here.
            await teardownResources();
            reject(error);
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
    ctx: ExtensionContext,
  ): Promise<AgentToolResult<BashToolDetails | undefined>> {
    let landstripErrorOutput = '';
    let stderrOutput = '';
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
            stderrOutput += data.toString('utf8');
          },
          promptOnBlock: true,
        },
        allowances,
      ),
      shellPath: SettingsManager.create(ctx.cwd).getShellPath(),
    });

    const run = () => sandboxedBash.execute(id, params, signal, onUpdate, ctx);
    const retryWithAccess = async (
      operation: 'read' | 'write',
      blockedPath: string,
    ): Promise<AgentToolResult<BashToolDetails | undefined> | null> => {
      if (!ctx.hasUI) return null;

      let config = loadConfig(ctx.cwd);
      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
      if (
        operation === 'write' &&
        matchesPattern(blockedPath, config.filesystem.denyWrite, ctx.cwd)
      ) {
        notify(
          ctx,
          `"${blockedPath}" is blocked by denyWrite. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
      }

      const needsPrompt =
        operation === 'read'
          ? !matchesPattern(blockedPath, getEffectiveAllowRead(config, allowances), ctx.cwd)
          : shouldPromptForWrite(blockedPath, getEffectiveAllowWrite(config, allowances), ctx.cwd);
      if (needsPrompt) {
        const choice =
          operation === 'read'
            ? await promptReadBlock(
                ctx,
                blockedPath,
                matchesPattern(blockedPath, config.filesystem.denyRead, ctx.cwd)
                  ? 'granting allowRead will override it'
                  : undefined,
                signal,
              )
            : await promptWriteBlock(ctx, blockedPath, signal);
        if (choice === 'abort') return null;
        if (operation === 'read') {
          await applyReadChoice(ctx, choice, blockedPath, ctx.cwd, allowances);
        } else {
          await applyWriteChoice(ctx, choice, blockedPath, ctx.cwd, allowances);
        }
      }

      config = loadConfig(ctx.cwd);
      if (
        operation === 'write' &&
        matchesPattern(blockedPath, config.filesystem.denyWrite, ctx.cwd)
      ) {
        notify(
          ctx,
          `"${blockedPath}" was added to allowWrite, but denyWrite still blocks it. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
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
        extractNativeWriteDeniedPath(fallbackOutput, ctx.cwd);
      if (blockedWritePath) {
        const retryResult = await retryWithAccess('write', blockedWritePath);
        if (retryResult) return retryResult;
      }

      const blockedReadPath =
        extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'read') ??
        extractNativeDeniedPath(fallbackOutput, ctx.cwd);
      if (blockedReadPath) {
        const retryResult = await retryWithAccess('read', blockedReadPath);
        if (retryResult) return retryResult;
      }

      const landstripErrors = parseLandstripTraps(landstripErrorOutput);
      if (landstripErrors.length > 0) {
        throw new Error(formatLandstripTraps(landstripErrors));
      }
      throw error;
    }
    const landstripErrors = parseLandstripTraps(landstripErrorOutput);
    if (landstripErrors.length > 0) {
      const message = formatLandstripTraps(landstripErrors);
      result.content.unshift({ type: 'text', text: `\n${message}\n` });
    }
    const blockedWritePath =
      extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'write') ??
      extractNativeWriteDeniedPath(stderrOutput, ctx.cwd);
    if (blockedWritePath) {
      const retryResult = await retryWithAccess('write', blockedWritePath);
      if (retryResult) return retryResult;
    }

    const blockedReadPath =
      extractTrapBlockedPath(landstripErrorOutput, ctx.cwd, 'read') ??
      extractNativeDeniedPath(stderrOutput, ctx.cwd);
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

  function enableStatus(ctx: ExtensionContext, config: SandboxConfig): void {
    if (!hasTuiStatus(ctx)) return;
    const theme = ctx.ui.theme;
    const dot = theme.fg('success', '●');
    const label = theme.fg('text', 'Sandbox');

    let networkLabel: string;
    let networkColor: 'warning' | 'accent';
    if (config.network.allowNetwork) {
      networkLabel = 'unrestricted';
      networkColor = 'warning';
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

    setTuiStatus(ctx, 'sandbox', `${dot} ${label}  ${sep}  ${net}  ${sep}  ${write}`);
  }

  const headlessWarnings = new Set<string>();

  // When sandboxing cannot be applied, bash falls back to running unsandboxed.
  // notify() is a no-op without a UI, so in headless/RPC mode also print to
  // stderr (once per message) rather than failing open silently.
  function warnUnsandboxed(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
    notify(ctx, message, level);
    if (!ctx.hasUI && !headlessWarnings.has(message)) {
      headlessWarnings.add(message);
      console.error(`pi-landstrip: ${message}`);
    }
  }

  function enableSandbox(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd);

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

    if (!landstripAvailable()) {
      sandboxEnabled = false;
      sandboxReady = false;
      setSandboxState('unavailable', ctx);
      warnUnsandboxed(
        ctx,
        `landstrip was not found. Reinstall with: npm install @landstrip/landstrip`,
        'error',
      );
      return false;
    }

    sandboxEnabled = true;
    sandboxReady = true;
    setSandboxState('enabled', ctx);
    warnIfAllDomainsAllowed(ctx, config);
    enableStatus(ctx, config);
    return true;
  }

  let noSandboxFlag = false;
  function disableSandbox(ctx: ExtensionContext): void {
    sandboxEnabled = false;
    sandboxReady = false;
    setSandboxState('disabled', ctx);
    setTuiStatus(ctx, 'sandbox', undefined);
  }

  function ensureSandboxState(ctx: ExtensionContext): boolean {
    if (noSandboxFlag) {
      disableSandbox(ctx);
      return false;
    }

    const config = loadConfig(ctx.cwd);
    if (!config.enabled) {
      disableSandbox(ctx);
      return false;
    }

    if (!sandboxEnabled || !sandboxReady) return enableSandbox(ctx);
    return true;
  }

  function createBashTool(
    cwd: string,
    ctx?: ExtensionContext,
    requireSandbox = false,
  ): LandstripBashTool {
    const localBash = createPlainBashTool(cwd);

    return {
      ...localBash,
      label: 'bash (landstrip)',
      async execute(id, params, signal, onUpdate, callCtx) {
        const effectiveCtx = ctx ?? callCtx;
        if (!effectiveCtx || !ensureSandboxState(effectiveCtx)) {
          if (requireSandbox) throw new Error('Sandbox is unavailable; refusing subagent command');
          return localBash.execute(id, params, signal, onUpdate, effectiveCtx);
        }

        return runBashWithOptionalRetry(id, params, signal, onUpdate, effectiveCtx);
      },
    };
  }

  function register(pi: ExtensionAPI, runtime?: SubagentRuntime): void {
    const maybePi = pi as ExtensionAPI & {
      getFlag?: (name: string) => unknown;
      registerCommand?: ExtensionAPI['registerCommand'];
      registerFlag?: ExtensionAPI['registerFlag'];
    };

    maybePi.registerFlag?.('no-sandbox', {
      description: 'Disable landstrip sandboxing for bash commands',
      type: 'boolean',
      default: false,
    });

    unpublishRuntime?.();
    unpublishRuntime = publishLandstripRuntime(pi, integration);

    if (shouldRegisterBashTool) pi.registerTool(createBashTool(localCwd));

    pi.on('user_bash', async (_event, ctx) => {
      if (!ensureSandboxState(ctx)) return;

      return { operations: createLandstripBashOps(ctx, { promptOnBlock: true }) };
    });

    pi.on('session_start', async (_event, ctx) => {
      activeContext = ctx;
      resetSessionAllowances();
      const trustContext = ctx as ExtensionContext & { isProjectTrusted?: () => boolean };
      projectConfigTrusted = trustContext.isProjectTrusted?.() ?? false;
      noSandboxFlag = Boolean(maybePi.getFlag?.('no-sandbox'));

      if (noSandboxFlag) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via --no-sandbox', 'warning');
        if (!unpublishRuntime) unpublishRuntime = publishLandstripRuntime(pi, integration);
        return;
      }

      const config = loadConfig(ctx.cwd);
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
      activeContext = undefined;
      unpublishRuntime?.();
      unpublishRuntime = undefined;
    });
    maybePi.registerCommand?.('sandbox', {
      description: 'Show config and toggle the sandbox',
      handler: async (_args, ctx) => {
        if (!ctx.hasUI) return;
        const config = loadConfig(ctx.cwd);
        const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
        const shouldToggle = await ctx.ui.custom<boolean>(
          (_tui, theme, _kb, done) => {
            const { dim, muted, accent, text } = themeColors(theme);

            function sandboxStatus(): { color: 'success' | 'warning'; label: string } {
              if (noSandboxFlag) return { color: 'warning', label: 'Disabled (--no-sandbox)' };
              if (!config.enabled) return { color: 'warning', label: 'Disabled' };
              if (!sandboxEnabled || !sandboxReady) return { color: 'warning', label: 'Inactive' };
              return { color: 'success', label: 'Active' };
            }

            function boolValue(value: boolean): string {
              return value ? theme.fg('warning', 'yes') : theme.fg('success', 'no');
            }

            return {
              render(width: number): string[] {
                const innerWidth = Math.max(1, width - 4);
                const row = (content = '') => boxRow(theme, width, content);
                const lines = [boxTop(theme, width, 'Sandbox')];
                const status = sandboxStatus();
                const statusDot = theme.fg(status.color, '●');
                const pathSnippet = text(
                  truncateToWidth(landstripDisplayPath(), Math.max(20, innerWidth - 28)),
                );
                const section = (title: string, detail?: string): void => {
                  lines.push(row(''));
                  lines.push(row(`${accent(title)}${detail ? dim(` · ${detail}`) : ''}`));
                };
                const item = (label: string, value: string): void => {
                  lines.push(row(`  ${dim('•')} ${muted(label.padEnd(13))} ${value}`));
                };
                const listValue = (values: string[]): string => {
                  const value = values.join(', ') || 'none';
                  return text(truncateToWidth(value, Math.max(10, innerWidth - 17)));
                };

                lines.push(
                  row(
                    `${statusDot} ${text(status.label)} ${dim('·')} ${muted('landstrip')} ${pathSnippet}`,
                  ),
                );

                section('Config');
                item('project', text(projectPath));
                item('global', text(globalPath));

                const networkMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';
                section('Network', networkMode);
                item('allow network', boolValue(config.network.allowNetwork));
                item('allowed', listValue(config.network.allowedDomains));
                item('denied', listValue(config.network.deniedDomains));
                item(
                  'unix sockets',
                  config.network.allowAllUnixSockets
                    ? text('all')
                    : listValue(config.network.allowUnixSockets),
                );
                if (sessionAllowedDomains.length > 0) {
                  item('session', theme.fg('accent', sessionAllowedDomains.join(', ')));
                }

                section('Filesystem');
                item('deny read', listValue(config.filesystem.denyRead));
                item('allow read', listValue(config.filesystem.allowRead));
                item('allow write', listValue(config.filesystem.allowWrite));
                item('deny write', listValue(config.filesystem.denyWrite));

                if (sessionAllowedReadPaths.length > 0 || sessionAllowedWritePaths.length > 0) {
                  section('Session grants');
                  if (sessionAllowedReadPaths.length > 0) {
                    item('read', theme.fg('accent', sessionAllowedReadPaths.join(', ')));
                  }
                  if (sessionAllowedWritePaths.length > 0) {
                    item('write', theme.fg('accent', sessionAllowedWritePaths.join(', ')));
                  }
                }

                lines.push(
                  row(''),
                  row(
                    `${dim('enter')} ${muted(config.enabled ? 'disable' : 'enable')}  ${dim('esc')} ${muted('close')}`,
                  ),
                  boxBottom(theme, width),
                );
                return lines;
              },

              handleInput(data: string): void {
                if (matchesKey(data, 'return')) {
                  done(true);
                  return;
                }
                if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) done(false);
              },

              invalidate(): void {},
            };
          },
          {
            overlay: true,
            overlayOptions: { anchor: 'center', width: 78, margin: 2 },
          },
        );
        if (!shouldToggle) return;

        const enabled = !config.enabled;
        try {
          const scope = await setSandboxConfigEnabled(ctx.cwd, enabled, projectConfigTrusted);
          if (!enabled) {
            disableSandbox(ctx);
          } else if (!noSandboxFlag) {
            enableSandbox(ctx);
          }
          if (enabled && noSandboxFlag) {
            notify(ctx, 'Sandbox remains disabled via --no-sandbox', 'warning');
          } else {
            notify(ctx, `Sandbox ${enabled ? 'enabled' : 'disabled'} in ${scope} config`, 'info');
          }
        } catch (error) {
          notify(ctx, `Could not update config: ${error}`, 'error');
        }
      },
    });

    maybePi.registerCommand?.('agents', {
      description: 'Select the primary agent and configure subagents',
      handler: async (_args, ctx) => {
        if (!ctx.hasUI) return;
        await ctx.ui.custom(
          (tui, theme, _kb, done) => {
            let tab: 'agents' | 'subagents' | 'settings' = 'agents';
            const initialAgents = runtime
              ? availablePrimaryAgents(runtime.getAgentCatalog(ctx))
              : [];
            let selectedAgent = Math.max(
              0,
              initialAgents.findIndex((agent) => agent.name === runtime?.getPrimaryAgent()?.name),
            );
            let selectedSubagent = 0;
            let selectedSetting = 0;
            let values = [
              loadLandstripConfig(ctx.cwd, false).maxSubagents,
              loadLandstripConfig(ctx.cwd, projectConfigTrusted).maxSubagents,
            ];
            let editing = false;
            const supportedVariants = new Set([
              'off',
              'minimal',
              'low',
              'medium',
              'high',
              'xhigh',
              'max',
            ]);
            const { dim, muted, accent, text } = themeColors(theme);

            return {
              render(width: number): string[] {
                const row = (content = '') => boxRow(theme, width, content);
                const lines = [boxTop(theme, width, 'Agents')];
                lines.push(
                  row(
                    ` ${tab === 'agents' ? accent('Agents') : muted('Agents')} ${dim('│')} ${tab === 'subagents' ? accent('Subagents') : muted('Subagents')} ${dim('│')} ${tab === 'settings' ? accent('Settings') : muted('Settings')}`,
                  ),
                  row(''),
                );

                if (tab === 'agents') {
                  const catalog = runtime?.getAgentCatalog(ctx);
                  const agents = catalog ? availablePrimaryAgents(catalog) : [];
                  const activeAgent = runtime?.getPrimaryAgent()?.name;
                  selectedAgent = Math.min(selectedAgent, Math.max(0, agents.length - 1));
                  if (agents.length === 0) lines.push(row(muted('No primary agents configured')));
                  for (const [index, agent] of agents.entries()) {
                    const selected = index === selectedAgent;
                    const cursor = selected ? accent('›') : ' ';
                    const active = agent.name === activeAgent ? theme.fg('success', '●') : dim('○');
                    const name = selected ? accent(agent.name) : text(agent.name);
                    const model = dim(`  ${agent.model ?? 'current model'}`);
                    const description = agent.description ? dim(`  ${agent.description}`) : '';
                    lines.push(row(`${cursor} ${active} ${name}${model}${description}`));
                  }
                } else if (tab === 'subagents') {
                  const catalog = runtime?.getAgentCatalog(ctx);
                  const agents = catalog ? availableSubagents(catalog) : [];
                  selectedSubagent = Math.min(selectedSubagent, Math.max(0, agents.length - 1));
                  if (agents.length === 0) lines.push(row(muted('No subagents configured')));
                  const start = Math.max(0, Math.min(selectedSubagent - 3, agents.length - 7));
                  for (const [offset, agent] of agents.slice(start, start + 7).entries()) {
                    const index = start + offset;
                    const selected = index === selectedSubagent;
                    const cursor = selected ? accent('›') : ' ';
                    const name = selected ? accent(`@${agent.name}`) : text(`@${agent.name}`);
                    const flags = [agent.model ?? 'current model', agent.mode];
                    if (agent.hidden) flags.push('hidden');
                    lines.push(row(`${cursor} ${name} ${dim(flags.join(' · '))}`));
                  }

                  const agent = agents[selectedSubagent];
                  if (agent) {
                    lines.push(row(''));
                    const details = [
                      `model ${agent.model ?? 'current model'}`,
                      agent.variant ? `variant ${agent.variant}` : undefined,
                      agent.steps ? `${agent.steps} steps` : undefined,
                    ].filter(Boolean);
                    lines.push(row(`  ${text(details.join(' · '))}`));
                    const permissions = [...(catalog?.permissions ?? []), ...agent.permissions];
                    lines.push(row(`  ${dim('Permissions')}`));
                    if (permissions.length === 0) lines.push(row(`    ${muted('default: ask')}`));
                    for (const rule of permissions.slice(0, 4)) {
                      lines.push(
                        row(
                          `    ${text(`${rule.permission}:${rule.pattern}`)} ${dim('→')} ${theme.fg(
                            rule.action === 'deny'
                              ? 'error'
                              : rule.action === 'allow'
                                ? 'success'
                                : 'warning',
                            rule.action,
                          )}`,
                        ),
                      );
                    }
                    if (permissions.length > 4) {
                      lines.push(row(`    ${muted(`… ${permissions.length - 4} more`)}`));
                    }
                    const unsupported = Object.keys(agent.providerOptions);
                    if (agent.variant && !supportedVariants.has(agent.variant)) {
                      unsupported.push(`variant=${agent.variant}`);
                    }
                    const unsupportedText =
                      unsupported.length > 0 ? unsupported.join(', ') : 'none';
                    lines.push(
                      row(`  ${dim('Unsupported RPC options:')} ${text(unsupportedText)}`),
                    );
                  }
                  if ((catalog?.diagnostics.length ?? 0) > 0) {
                    lines.push(row(`  ${theme.fg('error', 'Catalog diagnostics')}`));
                    for (const diagnostic of catalog?.diagnostics.slice(0, 3) ?? []) {
                      lines.push(row(`    ${theme.fg('error', diagnostic)}`));
                    }
                  }
                  for (const warning of catalog?.warnings.slice(0, 2) ?? []) {
                    lines.push(row(`  ${theme.fg('warning', warning)}`));
                  }
                } else {
                  const scopes = ['Global', 'Project'] as const;
                  for (const [index, scope] of scopes.entries()) {
                    const selected = index === selectedSetting;
                    const unavailable = scope === 'Project' && !projectConfigTrusted;
                    const cursor = selected ? accent('›') : ' ';
                    const value = selected
                      ? accent(`[ ${values[index]} ]`)
                      : text(`[ ${values[index]} ]`);
                    const label = unavailable
                      ? muted(`${scope} (project not trusted)`)
                      : text(scope);
                    lines.push(row(`${cursor} ${value} ${label}`));
                  }
                  if (values[selectedSetting] === 0) {
                    lines.push(row(`    ${dim('Task delegation is disabled for this scope')}`));
                  }
                }

                lines.push(
                  row(''),
                  row(
                    tab === 'agents'
                      ? `${dim('↑↓')} ${muted('select')}  ${dim('enter')} ${muted('activate')}  ${dim('tab')} ${muted('subagents')}  ${dim('esc')} ${muted('close')}`
                      : tab === 'subagents'
                        ? `${dim('↑↓')} ${muted('inspect')}  ${dim('tab')} ${muted('settings')}  ${dim('esc')} ${muted('close')}`
                        : `${dim('↑↓')} ${muted('scope')}  ${dim('0-9/+/-')} ${muted('change')}  ${dim('enter')} ${muted('save')}  ${dim('tab')} ${muted('agents')}  ${dim('esc')} ${muted('close')}`,
                  ),
                  boxBottom(theme, width),
                );
                return lines;
              },

              handleInput(data: string): void {
                if (matchesKey(data, 'escape') || matchesKey(data, 'ctrl+c')) {
                  done(undefined);
                  return;
                }
                if (
                  matchesKey(data, 'tab') ||
                  matchesKey(data, 'left') ||
                  matchesKey(data, 'right')
                ) {
                  const tabs = ['agents', 'subagents', 'settings'] as const;
                  const current = tabs.indexOf(tab);
                  const offset = matchesKey(data, 'left') ? -1 : 1;
                  tab = tabs[(current + offset + tabs.length) % tabs.length] ?? 'agents';
                  editing = false;
                  tui.requestRender();
                  return;
                }
                if (tab === 'agents') {
                  const catalog = runtime?.getAgentCatalog(ctx);
                  const agents = catalog ? availablePrimaryAgents(catalog) : [];
                  if (matchesKey(data, 'up')) selectedAgent = Math.max(0, selectedAgent - 1);
                  else if (matchesKey(data, 'down')) {
                    selectedAgent = Math.min(Math.max(0, agents.length - 1), selectedAgent + 1);
                  } else if (matchesKey(data, 'return')) {
                    const agent = agents[selectedAgent];
                    if (agent) runtime?.selectPrimaryAgent(agent.name, ctx);
                  } else return;
                  tui.requestRender();
                  return;
                }
                if (tab === 'subagents') {
                  const catalog = runtime?.getAgentCatalog(ctx);
                  const agents = catalog ? availableSubagents(catalog) : [];
                  if (matchesKey(data, 'up')) {
                    selectedSubagent = Math.max(0, selectedSubagent - 1);
                  } else if (matchesKey(data, 'down')) {
                    selectedSubagent = Math.min(
                      Math.max(0, agents.length - 1),
                      selectedSubagent + 1,
                    );
                  } else return;
                  tui.requestRender();
                  return;
                }

                if (matchesKey(data, 'up')) {
                  selectedSetting = Math.max(0, selectedSetting - 1);
                  editing = false;
                } else if (matchesKey(data, 'down')) {
                  selectedSetting = Math.min(1, selectedSetting + 1);
                  editing = false;
                } else if (/^[0-9]$/.test(data)) {
                  const value = Number(editing ? `${values[selectedSetting]}${data}` : data);
                  if (value <= MAX_SUBAGENTS) {
                    values[selectedSetting] = value;
                    editing = true;
                  }
                } else if (data === '+' || data === '-') {
                  values[selectedSetting] = Math.min(
                    MAX_SUBAGENTS,
                    Math.max(0, values[selectedSetting] + (data === '+' ? 1 : -1)),
                  );
                  editing = false;
                } else if (matchesKey(data, 'return')) {
                  const scope = selectedSetting === 0 ? 'global' : 'project';
                  if (scope === 'project' && !projectConfigTrusted) {
                    notify(ctx, 'Project settings require a trusted project', 'warning');
                    return;
                  }
                  const maxSubagents = values[selectedSetting];
                  void setMaxSubagentsConfigForScope(ctx.cwd, maxSubagents, scope)
                    .then(() => {
                      const effective = loadLandstripConfig(
                        ctx.cwd,
                        projectConfigTrusted,
                      ).maxSubagents;
                      runtime?.setMaxSubagents(effective);
                      values = [loadLandstripConfig(ctx.cwd, false).maxSubagents, effective];
                      editing = false;
                      notify(
                        ctx,
                        `Maximum concurrent subagents set to ${maxSubagents} in ${scope} config`,
                        'info',
                      );
                      tui.requestRender();
                    })
                    .catch((error: unknown) => {
                      notify(ctx, `Could not update config: ${error}`, 'error');
                    });
                  return;
                } else return;
                tui.requestRender();
              },

              invalidate(): void {},
            };
          },
          {
            overlay: true,
            overlayOptions: { anchor: 'center', width: 72, margin: 2 },
          },
        );
      },
    });
  }

  const integration: LandstripIntegration = {
    version: LANDSTRIP_RUNTIME_VERSION,
    getContext,
    createBashTool,
    prepareProcess,
    prepareRpcWorker,
    registerWorkerExtension,
    getWorkerExtensions,
    on,
    register,
    emit: emitEvent,
  };
  return integration;
}
