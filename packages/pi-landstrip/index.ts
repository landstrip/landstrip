// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import { spawn, spawnSync } from 'node:child_process';
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
  connect as connectNet,
  createServer,
  type Socket,
  Socket as NetSocket,
} from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { URL } from 'node:url';

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
  isToolCallEventType,
  SettingsManager,
  withFileMutationQueue,
} from '@earendil-works/pi-coding-agent';
import { Key, matchesKey, truncateToWidth, visibleWidth } from '@earendil-works/pi-tui';
import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripFilesystemTrap,
  type LandstripNetworkTrap,
  type LandstripTrap,
} from '@landstrip/landstrip';

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

type LandstripOperation = 'read' | 'write';

type LandstripDenialTrap = LandstripFilesystemTrap | LandstripNetworkTrap;

interface LandstripBashCallbacks {
  onStderr?: (data: Buffer) => void;
  onErrorFd?: (data: Buffer) => void;
  promptOnBlock?: boolean;
}

const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);

// Grace period after the child exits for its stdio to drain before we stop
// waiting; matches pi's own bash backend so a backgrounded process cannot hang us.
const EXIT_STDIO_GRACE_MS = 100;

const packageDir = dirname(fileURLToPath(import.meta.url));
type PermissionChoice = 'abort' | 'session' | 'project' | 'global';
type NotificationLevel = Parameters<ExtensionContext['ui']['notify']>[1];

interface PromptOption {
  label: string;
  key: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

const PERMISSION_OPTIONS: PromptOption[] = [
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
  { label: 'Allow for this session only', key: 's', action: 'session' },
  { label: 'Abort (keep blocked)', key: 'esc', action: 'abort' },
];

function loadConfig(cwd: string): SandboxConfig {
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

  if (existsSync(projectConfigPath)) {
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
  return {
    globalPath: join(getAgentDir(), 'sandbox.json'),
    projectPath: join(cwd, '.pi', 'sandbox.json'),
  };
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
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

function getSandboxConfigWriteTarget(cwd: string): { scope: SandboxConfigScope; path: string } {
  const { globalPath, projectPath } = getConfigPaths(cwd);
  const projectConfig = readOrEmptyConfig(projectPath);

  if (projectConfig.enabled !== undefined) return { scope: 'project', path: projectPath };
  return { scope: 'global', path: globalPath };
}

async function setSandboxConfigEnabled(cwd: string, enabled: boolean): Promise<SandboxConfigScope> {
  const { scope, path } = getSandboxConfigWriteTarget(cwd);
  await withFileMutationQueue(path, async () => {
    const config = readOrEmptyConfig(path);
    config.enabled = enabled;
    writeConfigFile(path, config);
  });

  return scope;
}

async function addDomainToConfig(configPath: string, domain: string): Promise<void> {
  await withFileMutationQueue(configPath, async () => {
    const config = readOrEmptyConfig(configPath);
    const existing = config.network?.allowedDomains ?? [];
    if (existing.includes(domain)) return;

    config.network = {
      ...config.network,
      allowedDomains: [...existing, domain],
      deniedDomains: config.network?.deniedDomains ?? [],
    };
    writeConfigFile(configPath, config);
  });
}

async function addReadPathToConfig(configPath: string, pathToAdd: string): Promise<void> {
  await withFileMutationQueue(configPath, async () => {
    const config = readOrEmptyConfig(configPath);
    const existing = config.filesystem?.allowRead ?? [];
    if (existing.includes(pathToAdd)) return;

    config.filesystem = {
      ...config.filesystem,
      allowRead: [...existing, pathToAdd],
    };
    writeConfigFile(configPath, config);
  });
}

async function addWritePathToConfig(configPath: string, pathToAdd: string): Promise<void> {
  await withFileMutationQueue(configPath, async () => {
    const config = readOrEmptyConfig(configPath);
    const existing = config.filesystem?.allowWrite ?? [];
    if (existing.includes(pathToAdd)) return;

    config.filesystem = {
      ...config.filesystem,
      allowWrite: [...existing, pathToAdd],
    };
    writeConfigFile(configPath, config);
  });
}

function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([^\s/:?#]+)(?::\d+)?(?:[/?#]|\s|$)/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1]);
  }

  return [...domains];
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
  return resolve(cwd, filePath.replace(/^~(?=$|\/)/, homedir()));
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

function extractBlockedWritePath(trapOutput: string, cwd: string): string | null {
  for (const error of parseLandstripTraps(trapOutput).filter(isFilesystemTrap)) {
    if (error.operation === 'write') {
      return normalizeBlockedPath(error.path, cwd);
    }
  }

  return null;
}

function extractBlockedReadPath(trapOutput: string, cwd: string): string | null {
  for (const error of parseLandstripTraps(trapOutput).filter(isFilesystemTrap)) {
    if (error.operation === 'read') {
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
  const mode = 'mode' in ctx ? (ctx as Record<string, unknown>).mode : undefined;
  return mode === undefined || mode === 'tui';
}

function setTuiStatus(ctx: ExtensionContext, key: string, value: string | undefined): void {
  if (!hasTuiStatus(ctx)) return;
  ctx.ui.setStatus(key, value);
}

function boxTop(theme: Theme, width: number, title: string): string {
  const label = theme.fg('accent', ` ${title} `);
  const fill = theme.fg('border', '─'.repeat(Math.max(0, width - 4 - visibleWidth(label))));
  return `${theme.fg('border', '╭─')}${label}${fill}${theme.fg('border', '─╮')}`;
}

function boxRow(theme: Theme, width: number, content = ''): string {
  const innerW = Math.max(1, width - 4);
  const border = theme.fg('border', '│');
  const line = truncateToWidth(content, innerW);
  const pad = Math.max(0, innerW - visibleWidth(line));
  return `${border} ${line}${' '.repeat(pad)} ${border}`;
}

function boxBottom(theme: Theme, width: number): string {
  const border = (s: string) => theme.fg('border', s);
  return `${border('╰')}${border('─'.repeat(Math.max(0, width - 2)))}${border('╯')}`;
}

async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
  options: PromptOption[],
): Promise<PermissionChoice> {
  if (!ctx.hasUI) return 'abort';

  const result = await ctx.ui.custom<PermissionChoice>(
    (tui, theme, _kb, done) => {
      let selectedIndex = 0;
      let pendingAction: PermissionChoice | null = null;

      function resolveChoice(action: PermissionChoice): void {
        done(action);
      }

      return {
        render(width: number): string[] {
          const innerW = Math.max(1, width - 4);
          const lines: string[] = [];
          const dim = (s: string) => theme.fg('dim', s);

          lines.push(boxTop(theme, width, 'Sandbox'));
          lines.push(boxRow(theme, width));
          lines.push(boxRow(theme, width, theme.fg('warning', title)));
          lines.push(boxRow(theme, width));

          // Options
          for (let i = 0; i < options.length; i++) {
            const option = options[i];
            const isSelected = i === selectedIndex;
            const isPending = pendingAction === option.action;

            // Section divider before the permanent options (index 2 and 3)
            if (i === 2) {
              lines.push(boxRow(theme, width));
              const secLabel = ' Permanent ';
              const secDash = '─'.repeat(Math.max(0, innerW - visibleWidth(secLabel)));
              lines.push(boxRow(theme, width, dim(secDash + secLabel)));
              lines.push(boxRow(theme, width));
            }

            // Key badge
            const keyBadge = isSelected
              ? theme.fg('accent', `[${option.key}]`)
              : dim(` ${option.key} `);

            // Selection indicator
            let cursor: string;
            if (isSelected && isPending) {
              cursor = theme.fg('warning', '▶');
            } else if (isSelected) {
              cursor = theme.fg('accent', '▶');
            } else {
              cursor = ' ';
            }

            // Label
            let label: string;
            if (isPending) {
              label = theme.fg('warning', option.label + '  — press Enter to confirm');
            } else if (isSelected) {
              label = theme.fg('text', option.label);
            } else {
              label = dim(option.label);
            }

            // Hint
            let hint = '';
            if (option.hint && !isPending) {
              hint = '  ' + dim(option.hint);
            }

            const fullLine = ` ${cursor} ${keyBadge} ${label}${hint}`;
            lines.push(boxRow(theme, width, fullLine));
          }

          // Footer
          lines.push(boxRow(theme, width));
          const footerText = pendingAction
            ? '↑↓ navigate  enter confirm  esc cancel'
            : '↑↓ navigate  enter select  esc dismiss';
          lines.push(boxRow(theme, width, dim(footerText)));
          lines.push(boxBottom(theme, width));

          return lines;
        },

        handleInput(data: string): void {
          if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl('c'))) {
            resolveChoice('abort');
            return;
          }

          if (matchesKey(data, Key.enter)) {
            resolveChoice(pendingAction ?? options[selectedIndex]?.action ?? 'abort');
            return;
          }

          if (matchesKey(data, Key.up)) {
            selectedIndex = Math.max(0, selectedIndex - 1);
            pendingAction = null;
            tui.requestRender();
            return;
          }

          if (matchesKey(data, Key.down)) {
            selectedIndex = Math.min(options.length - 1, selectedIndex + 1);
            pendingAction = null;
            tui.requestRender();
            return;
          }

          for (let i = 0; i < options.length; i++) {
            const option = options[i];

            // Match case-insensitively so a `confirm` option always arms its
            // two-step gate; an exact-key shortcut here would skip it.
            if (data.toLowerCase() === option.key.toLowerCase()) {
              if (option.confirm) {
                pendingAction = option.action;
                selectedIndex = i;
              } else {
                resolveChoice(option.action);
              }
              tui.requestRender();
              return;
            }
          }
        },

        invalidate(): void {},
      };
    },
    {
      overlay: true,
      overlayOptions: {
        anchor: 'center',
        width: 72,
        margin: 2,
      },
    },
  );

  return result ?? 'abort';
}

function promptDomainBlock(ctx: ExtensionContext, domain: string): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Network blocked: "${domain}" is not in allowedDomains`,
    PERMISSION_OPTIONS,
  );
}

function promptReadBlock(
  ctx: ExtensionContext,
  filePath: string,
  reason?: string,
): Promise<PermissionChoice> {
  const title = reason
    ? `Read blocked: "${filePath}" is in denyRead (${reason})`
    : `Read blocked: "${filePath}" is not in allowRead`;
  return showPermissionPrompt(ctx, title, PERMISSION_OPTIONS);
}

function promptWriteBlock(ctx: ExtensionContext, filePath: string): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Write blocked: "${filePath}" is not in allowWrite`,
    PERMISSION_OPTIONS,
  );
}

// The broker knows only address:port, and no sandbox.json field can express a
// grant for one: allowedDomains is a hostname list enforced by the proxy, and the
// landstrip network policy is all-or-nothing (allowNetwork, allowLocalBinding).
// So a connection is granted for the session or not at all.
function promptNetworkBlock(
  ctx: ExtensionContext,
  operation: string,
  target: string,
): Promise<PermissionChoice> {
  return showPermissionPrompt(
    ctx,
    `Network blocked: ${operation} to "${target}"`,
    NETWORK_PERMISSION_OPTIONS,
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
    for (const v of [
      'HTTP_PROXY',
      'HTTPS_PROXY',
      'ALL_PROXY',
      'http_proxy',
      'https_proxy',
      'all_proxy',
    ]) {
      lines.push(`export ${v}='${url}'`);
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

function pipeSockets(client: Socket, upstream: Socket, initialData?: Buffer): void {
  upstream.on('error', () => client.destroy());
  client.on('error', () => upstream.destroy());

  if (initialData?.length) upstream.write(initialData);

  client.pipe(upstream);
  upstream.pipe(client);
}

type LandstripBashTool = ReturnType<typeof createBashToolDefinition>;

/** Options for creating a landstrip sandbox integration. */
export interface LandstripIntegrationOptions {
  /** Register a sandboxed bash tool when the integration is registered. */
  readonly registerBashTool?: boolean;
  /** Working directory used when registering the default bash tool. */
  readonly cwd?: string;
}

/** Landstrip sandbox integration hooks for Pi. */
export interface LandstripIntegration {
  /** Create a bash tool definition that runs commands through landstrip when enabled. */
  createBashTool(cwd: string, ctx?: ExtensionContext): LandstripBashTool;
  /** Register the integration's tools, events, flags, and commands with Pi. */
  register(pi: ExtensionAPI): void;
}

/** Register the landstrip extension with Pi. */
export default function (pi: ExtensionAPI) {
  createLandstripIntegration().register(pi);
}

/** Create a landstrip integration for registration or custom embedding. */
export function createLandstripIntegration(
  options: LandstripIntegrationOptions = {},
): LandstripIntegration {
  const shouldRegisterBashTool = options.registerBashTool ?? true;
  const localCwd = options.cwd ?? process.cwd();

  function createPlainBashTool(cwd: string): LandstripBashTool {
    return createBashToolDefinition(cwd, {
      shellPath: SettingsManager.create(cwd).getShellPath(),
    });
  }

  let sandboxEnabled = false;
  let sandboxReady = false;
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  const sessionAllowedTargets: string[] = [];

  function resetSessionAllowances(): void {
    sessionAllowedDomains.length = 0;
    sessionAllowedReadPaths.length = 0;
    sessionAllowedWritePaths.length = 0;
    sessionAllowedTargets.length = 0;
  }

  function getEffectiveAllowedDomains(config: SandboxConfig): string[] {
    return [...config.network.allowedDomains, ...sessionAllowedDomains];
  }

  function getEffectiveAllowRead(config: SandboxConfig): string[] {
    return [...config.filesystem.allowRead, ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(config: SandboxConfig): string[] {
    return [...config.filesystem.allowWrite, ...sessionAllowedWritePaths];
  }

  async function applyDomainChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    domain: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedDomains.includes(domain)) sessionAllowedDomains.push(domain);
    if (choice === 'project') await addDomainToConfig(projectPath, domain);
    if (choice === 'global') await addDomainToConfig(globalPath, domain);
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
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    const scope = sessionScopeFor(filePath, cwd);
    if (!sessionAllowedReadPaths.includes(scope)) sessionAllowedReadPaths.push(scope);
    if (choice === 'project') await addReadPathToConfig(projectPath, scope);
    if (choice === 'global') await addReadPathToConfig(globalPath, scope);
    noteScope(ctx, 'Read', choice, filePath, scope);
  }

  // Gate a read of `filePath` against allowRead/denyRead, prompting when blocked.
  // Returns a block result when the user aborts, otherwise undefined once access
  // is settled. Shared by the read, grep, ls and find tools.
  async function gateReadAccess(
    ctx: ExtensionContext,
    config: SandboxConfig,
    filePath: string,
  ): Promise<{ block: true; reason: string } | undefined> {
    if (readAllowed(filePath, getEffectiveAllowRead(config), config.filesystem.denyRead, ctx.cwd)) {
      return undefined;
    }
    const choice = await promptReadBlock(
      ctx,
      filePath,
      matchesPattern(filePath, config.filesystem.denyRead, ctx.cwd)
        ? 'granting allowRead will override it'
        : undefined,
    );
    if (choice === 'abort') {
      return { block: true, reason: `Sandbox: read access denied for "${filePath}"` };
    }
    await applyReadChoice(ctx, choice, filePath, ctx.cwd);
    return undefined;
  }

  async function applyWriteChoice(
    ctx: ExtensionContext,
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    const scope = sessionScopeFor(filePath, cwd);
    if (!sessionAllowedWritePaths.includes(scope)) sessionAllowedWritePaths.push(scope);
    if (choice === 'project') await addWritePathToConfig(projectPath, scope);
    if (choice === 'global') await addWritePathToConfig(globalPath, scope);
    noteScope(ctx, 'Write', choice, filePath, scope);
  }

  async function ensureDomainAllowed(
    ctx: ExtensionContext,
    domain: string,
    cwd: string,
  ): Promise<boolean> {
    const config = loadConfig(cwd);

    if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
    if (domainMatchesAny(domain, getEffectiveAllowedDomains(config))) return true;

    const choice = await promptDomainBlock(ctx, domain);
    if (choice === 'abort') return false;

    await applyDomainChoice(choice, domain, cwd);
    return true;
  }

  function buildLandstripPolicy(cwd: string, proxyPort: number | null): LandstripPolicy {
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
        allowRead: getEffectiveAllowRead(config),
        allowWrite: getEffectiveAllowWrite(config),
        denyWrite: config.filesystem.denyWrite,
      },
    };
  }

  function writePolicyFile(cwd: string, proxyPort: number | null): { dir: string; path: string } {
    const dir = mkdtempSync(join(tmpdir(), 'pi-landstrip-'));
    const path = join(dir, 'policy.json');
    writeFileSync(
      path,
      JSON.stringify(buildLandstripPolicy(cwd, proxyPort), null, 2) + '\n',
      'utf-8',
    );

    return { dir, path };
  }

  function startProxy(cwd: string): Promise<{ port: number; stop: () => Promise<void> }> {
    const sockets = new Set<Socket>();

    function domainAllowed(domain: string): boolean {
      const config = loadConfig(cwd);
      if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
      return domainMatchesAny(domain, getEffectiveAllowedDomains(config));
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

      if (!domainAllowed(endpoint.host)) {
        denyProxyRequest(client);
        return;
      }

      let settled = false;
      const upstream = connectNet(endpoint.port, endpoint.host, () => {
        settled = true;
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pipeSockets(client, upstream, rest);
      });
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

      if (!domainAllowed(url.hostname)) {
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
        .filter((line) => !line.toLowerCase().startsWith('proxy-connection:'))
        .join('\r\n');
      let settled = false;
      const upstream = connectNet(port, url.hostname, () => {
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

  function createLandstripBashOps(
    ctx: ExtensionContext,
    callbacks: LandstripBashCallbacks = {},
  ): BashOperations {
    return {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

        const { shell, args } = getShellConfig(SettingsManager.create(cwd).getShellPath());
        const config = loadConfig(cwd);
        const allowNetwork = config.network.allowNetwork;
        const proxy = allowNetwork ? null : await startProxy(cwd);

        // Started/created before the child exists, so tear them down on any early
        // failure too — the env file holds a copy of the environment (secrets),
        // and the proxy keeps a listening socket. Idempotent: safe to call twice.
        let policy: ReturnType<typeof writePolicyFile> | undefined;
        let envFile: ReturnType<typeof writeEnvFile> | undefined;
        const teardownResources = () => {
          void proxy?.stop();
          if (policy) rmSync(policy.dir, { recursive: true, force: true });
          if (envFile) rmSync(envFile.dir, { recursive: true, force: true });
        };

        let landstripArgs: string[];
        try {
          policy = writePolicyFile(cwd, proxy?.port ?? null);
          envFile = writeEnvFile({ ...process.env, ...env }, proxy?.port ?? null);
          const wrappedCommand = `source '${envFile.path}' && ${command}`;
          landstripArgs = ['--trap-fd', '3', '-p', policy.path, shell, ...args, wrappedCommand];
        } catch (error) {
          teardownResources();
          throw error;
        }

        return new Promise((resolvePromise, reject) => {
          (async () => {
            let timeoutHandle: NodeJS.Timeout | undefined;
            let timedOut = false;
            let cleaned = false;

            const [trapSocket, childEnd] = await createSocketPair();

            const cleanup = () => {
              if (cleaned) return;
              cleaned = true;
              if (timeoutHandle) clearTimeout(timeoutHandle);
              signal?.removeEventListener('abort', onAbort);
              teardownResources();
              trapSocket.destroy();
            };

            const child = spawn(binaryPath(), landstripArgs, {
              cwd,
              env: { PATH: process.env.PATH, HOME: process.env.HOME },
              detached: true,
              stdio: ['ignore', 'pipe', 'pipe', childEnd],
            });

            // Child has dup'd its end; parent can close its copy.
            childEnd.destroy();

            function killChild(): void {
              if (child.pid === undefined) return;
              try {
                process.kill(-child.pid, 'SIGKILL');
              } catch {
                child.kill('SIGKILL');
              }
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
                cleanup();
                if (signal?.aborted) {
                  reject(new Error('aborted'));
                  return;
                }
                if (timedOut) {
                  reject(new Error(`timeout:${timeout}`));
                  return;
                }

                // Structured traps are trusted only from the trap socket (fd 3);
                // the command's own stderr is read with the native regexes, which
                // reflect a real kernel denial rather than a forgeable JSON line.
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
            let trapBuffer = '';
            let queryChain: Promise<void> = Promise.resolve();

            const respondQuery = (
              queryId: string,
              action: LandstripControlResponse['action'],
            ): void => {
              if (trapSocket.destroyed) return;
              trapSocket.write(controlResponseLine(queryId, action));
            };

            // Surface a denial through the error-fd accumulator so the post-close
            // notify and the runBashWithOptionalRetry prompt/retry paths still work.
            const appendErrorLine = (line: string): void => {
              const infoLine = line + '\n';
              errorFdAcc += infoLine;
              callbacks.onErrorFd?.(Buffer.from(infoLine, 'utf8'));
            };

            // Answer a landstrip query (state:"query"). The broker suspends the
            // child's syscall until we respond allow/deny on the trap socket.
            const handleQuery = (
              queryId: string,
              operation: LandstripOperation,
              rawPath: string,
              rawLine: string,
            ): void => {
              const path = normalizeBlockedPath(rawPath, cwd);
              const config = loadConfig(cwd);
              const isAllowed = (cfg: SandboxConfig): boolean =>
                operation === 'read'
                  ? readAllowed(path, getEffectiveAllowRead(cfg), cfg.filesystem.denyRead, cwd)
                  : !matchesPattern(path, cfg.filesystem.denyWrite, cwd) &&
                    !shouldPromptForWrite(path, getEffectiveAllowWrite(cfg), cwd);

              if (isAllowed(config)) {
                respondQuery(queryId, 'allow');
                return;
              }
              // Without an interactive prompt, deny and let the retry path grant.
              if (!ctx.hasUI || !callbacks.promptOnBlock) {
                appendErrorLine(rawLine);
                respondQuery(queryId, 'deny');
                return;
              }
              // denyWrite is a hard block: never prompt to override it.
              if (operation === 'write' && matchesPattern(path, config.filesystem.denyWrite, cwd)) {
                respondQuery(queryId, 'deny');
                return;
              }
              // Serialize prompts so concurrent queries never overlap on screen and
              // a path granted by one prompt auto-allows later queries for it.
              queryChain = queryChain
                .then(async () => {
                  const cfg = loadConfig(cwd);
                  if (isAllowed(cfg)) {
                    respondQuery(queryId, 'allow');
                    return;
                  }
                  const choice =
                    operation === 'read'
                      ? await promptReadBlock(
                          ctx,
                          path,
                          matchesPattern(path, cfg.filesystem.denyRead, cwd)
                            ? 'granting allowRead will override it'
                            : undefined,
                        )
                      : await promptWriteBlock(ctx, path);
                  if (choice === 'abort') {
                    respondQuery(queryId, 'deny');
                    return;
                  }
                  if (operation === 'read') await applyReadChoice(ctx, choice, path, cwd);
                  else await applyWriteChoice(ctx, choice, path, cwd);
                  respondQuery(queryId, 'allow');
                })
                .catch(() => respondQuery(queryId, 'deny'));
            };

            // A denied connect or bind is a query too, and the broker re-issues it
            // itself once we allow. The target is address:port, so a grant only
            // lasts for the session (see promptNetworkBlock).
            const handleNetworkQuery = (
              queryId: string,
              operation: string,
              target: string,
              rawLine: string,
            ): void => {
              if (sessionAllowedTargets.includes(target)) {
                respondQuery(queryId, 'allow');
                return;
              }
              if (!ctx.hasUI || !callbacks.promptOnBlock) {
                appendErrorLine(rawLine);
                respondQuery(queryId, 'deny');
                return;
              }
              queryChain = queryChain
                .then(async () => {
                  if (sessionAllowedTargets.includes(target)) {
                    respondQuery(queryId, 'allow');
                    return;
                  }
                  const choice = await promptNetworkBlock(ctx, operation, target);
                  if (choice === 'abort') {
                    appendErrorLine(rawLine);
                    respondQuery(queryId, 'deny');
                    return;
                  }
                  sessionAllowedTargets.push(target);
                  respondQuery(queryId, 'allow');
                })
                .catch(() => respondQuery(queryId, 'deny'));
            };

            trapSocket.on('data', (data: Buffer) => {
              trapBuffer += data.toString('utf8');
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
                  if (isFilesystemTrap(trap)) {
                    handleQuery(trap.query_id, trap.operation, trap.path, line);
                  } else {
                    handleNetworkQuery(trap.query_id, trap.operation, trap.target, line);
                  }
                } else {
                  appendErrorLine(line);
                }
              }
            });

            child.on('error', (error) => {
              if (execSettled) return;
              execSettled = true;
              if (postExitTimer) clearTimeout(postExitTimer);
              cleanup();
              reject(error);
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
          })().catch((error: unknown) => {
            // A failure before the child is wired (e.g. createSocketPair) never
            // reaches cleanup(); free the proxy and temp dirs here too.
            teardownResources();
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
    const sandboxedBash = createBashToolDefinition(ctx.cwd, {
      operations: createLandstripBashOps(ctx, {
        onErrorFd: (data) => {
          landstripErrorOutput += data.toString('utf8');
        },
        onStderr: (data) => {
          stderrOutput += data.toString('utf8');
        },
        promptOnBlock: true,
      }),
      shellPath: SettingsManager.create(ctx.cwd).getShellPath(),
    });

    const run = () => sandboxedBash.execute(id, params, signal, onUpdate, ctx);
    const retryWithWriteAccess = async (
      blockedPath: string,
    ): Promise<AgentToolResult<BashToolDetails | undefined> | null> => {
      if (!ctx.hasUI) return null;

      let config = loadConfig(ctx.cwd);
      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
      if (matchesPattern(blockedPath, config.filesystem.denyWrite, ctx.cwd)) {
        notify(
          ctx,
          `"${blockedPath}" is blocked by denyWrite. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
      }

      if (shouldPromptForWrite(blockedPath, getEffectiveAllowWrite(config), ctx.cwd)) {
        const choice = await promptWriteBlock(ctx, blockedPath);
        if (choice === 'abort') return null;
        await applyWriteChoice(ctx, choice, blockedPath, ctx.cwd);
      }

      config = loadConfig(ctx.cwd);
      if (matchesPattern(blockedPath, config.filesystem.denyWrite, ctx.cwd)) {
        notify(
          ctx,
          `"${blockedPath}" was added to allowWrite, but denyWrite still blocks it. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
      }

      onUpdate?.({
        content: [
          { type: 'text', text: `\n--- Write access granted for "${blockedPath}", retrying ---\n` },
        ],
        details: {},
      });
      landstripErrorOutput = '';
      stderrOutput = '';
      return run();
    };

    const retryWithReadAccess = async (
      blockedPath: string,
    ): Promise<AgentToolResult<BashToolDetails | undefined> | null> => {
      if (!ctx.hasUI) return null;

      const config = loadConfig(ctx.cwd);
      if (!matchesPattern(blockedPath, getEffectiveAllowRead(config), ctx.cwd)) {
        const choice = await promptReadBlock(
          ctx,
          blockedPath,
          matchesPattern(blockedPath, config.filesystem.denyRead, ctx.cwd)
            ? 'granting allowRead will override it'
            : undefined,
        );
        if (choice === 'abort') return null;
        await applyReadChoice(ctx, choice, blockedPath, ctx.cwd);
      }

      onUpdate?.({
        content: [
          { type: 'text', text: `\n--- Read access granted for "${blockedPath}", retrying ---\n` },
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
      const errorText = error instanceof Error ? error.message : String(error);
      const fallbackOutput = `${stderrOutput}\n${errorText}`;
      const blockedWritePath =
        extractBlockedWritePath(landstripErrorOutput, ctx.cwd) ??
        extractNativeWriteDeniedPath(fallbackOutput, ctx.cwd);
      if (blockedWritePath) {
        const retryResult = await retryWithWriteAccess(blockedWritePath);
        if (retryResult) return retryResult;
      }

      const blockedReadPath =
        extractBlockedReadPath(landstripErrorOutput, ctx.cwd) ??
        extractNativeDeniedPath(fallbackOutput, ctx.cwd);
      if (blockedReadPath) {
        const retryResult = await retryWithReadAccess(blockedReadPath);
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
      extractBlockedWritePath(landstripErrorOutput, ctx.cwd) ??
      extractNativeWriteDeniedPath(stderrOutput, ctx.cwd);
    if (blockedWritePath) {
      const retryResult = await retryWithWriteAccess(blockedWritePath);
      if (retryResult) return retryResult;
    }

    const blockedReadPath =
      extractBlockedReadPath(landstripErrorOutput, ctx.cwd) ??
      extractNativeDeniedPath(stderrOutput, ctx.cwd);
    if (!blockedReadPath) return result;

    const retryResult = await retryWithReadAccess(blockedReadPath);
    return retryResult ?? result;
  }

  async function preflightCommandDomains(
    command: string,
    ctx: ExtensionContext,
  ): Promise<string | null> {
    for (const domain of extractDomainsFromCommand(command)) {
      if (!(await ensureDomainAllowed(ctx, domain, ctx.cwd))) return domain;
    }

    return null;
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
      warnUnsandboxed(
        ctx,
        `landstrip was not found. Reinstall with: npm install @landstrip/landstrip`,
        'error',
      );
      return false;
    }

    sandboxEnabled = true;
    sandboxReady = true;
    warnIfAllDomainsAllowed(ctx, config);
    enableStatus(ctx, config);
    return true;
  }

  let noSandboxFlag = false;
  function disableSandbox(ctx: ExtensionContext): void {
    sandboxEnabled = false;
    sandboxReady = false;
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

  function createBashTool(cwd: string, ctx?: ExtensionContext): LandstripBashTool {
    const localBash = createPlainBashTool(cwd);

    return {
      ...localBash,
      label: 'bash (landstrip)',
      async execute(id, params, signal, onUpdate, callCtx) {
        const effectiveCtx = callCtx ?? ctx;
        if (!effectiveCtx || !ensureSandboxState(effectiveCtx))
          return localBash.execute(id, params, signal, onUpdate, effectiveCtx);

        return runBashWithOptionalRetry(id, params, signal, onUpdate, effectiveCtx);
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
      description: 'Disable landstrip sandboxing for bash commands',
      type: 'boolean',
      default: false,
    });

    if (shouldRegisterBashTool) pi.registerTool(createBashTool(localCwd));

    pi.on('user_bash', async (event, ctx) => {
      if (!ensureSandboxState(ctx)) return;
      const config = loadConfig(ctx.cwd);

      if (!config.network.allowNetwork) {
        const blockedDomain = await preflightCommandDomains(event.command, ctx);
        if (blockedDomain) {
          return {
            result: {
              output: `Blocked: "${blockedDomain}" is not allowed by the sandbox. Use /sandbox to review your config.`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
      }

      return { operations: createLandstripBashOps(ctx, { promptOnBlock: true }) };
    });

    pi.on('tool_call', async (event, ctx) => {
      if (!ensureSandboxState(ctx)) return;

      const config = loadConfig(ctx.cwd);

      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);

      if (sandboxReady && isToolCallEventType('bash', event)) {
        if (!config.network.allowNetwork) {
          const blockedDomain = await preflightCommandDomains(event.input.command, ctx);
          if (blockedDomain) {
            return {
              block: true,
              reason: `Network access to "${blockedDomain}" is blocked by the sandbox.`,
            };
          }
        }
      }

      if (isToolCallEventType('read', event)) {
        const result = await gateReadAccess(
          ctx,
          config,
          canonicalizePath(event.input.path, ctx.cwd),
        );
        if (result) return result;
      }

      // grep, ls and find read their target path (default: the cwd) and recurse
      // into it, so gate them against allowRead/denyRead like the read tool —
      // otherwise they run in-process, unsandboxed, and defeat denyRead.
      if (
        isToolCallEventType('grep', event) ||
        isToolCallEventType('ls', event) ||
        isToolCallEventType('find', event)
      ) {
        const result = await gateReadAccess(
          ctx,
          config,
          canonicalizePath(event.input.path ?? '.', ctx.cwd),
        );
        if (result) return result;
      }

      if (isToolCallEventType('write', event) || isToolCallEventType('edit', event)) {
        const filePath = canonicalizePath((event.input as { path: string }).path, ctx.cwd);

        if (matchesPattern(filePath, config.filesystem.denyWrite, ctx.cwd)) {
          return {
            block: true,
            reason:
              `Sandbox: write access denied for "${filePath}" (in denyWrite). ` +
              `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
          };
        }

        if (shouldPromptForWrite(filePath, getEffectiveAllowWrite(config), ctx.cwd)) {
          const choice = await promptWriteBlock(ctx, filePath);
          if (choice === 'abort') {
            return {
              block: true,
              reason: `Sandbox: write access denied for "${filePath}" (not in allowWrite)`,
            };
          }
          await applyWriteChoice(ctx, choice, filePath, ctx.cwd);
        }
      }
    });

    pi.on('session_start', async (_event, ctx) => {
      resetSessionAllowances();
      noSandboxFlag = Boolean(maybePi.getFlag?.('no-sandbox'));

      if (noSandboxFlag) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via --no-sandbox', 'warning');
        return;
      }

      const config = loadConfig(ctx.cwd);
      if (!config.enabled) {
        disableSandbox(ctx);
        notify(ctx, 'Sandbox disabled via config', 'info');
        return;
      }

      enableSandbox(ctx);
    });
    maybePi.registerCommand?.('sandbox', {
      description: 'Show sandbox configuration',
      handler: async (_args, ctx) => {
        let config = loadConfig(ctx.cwd);

        const { globalPath, projectPath } = getConfigPaths(ctx.cwd);

        if (!ctx.hasUI) return;
        await ctx.ui.custom(
          (tui, theme, _kb, done) => {
            const dim = (s: string) => theme.fg('dim', s);
            const muted = (s: string) => theme.fg('muted', s);
            const accent = (s: string) => theme.fg('accent', s);
            const text = (s: string) => theme.fg('text', s);

            function sandboxStatus(): { color: 'success' | 'warning'; label: string } {
              if (noSandboxFlag) return { color: 'warning', label: 'Disabled (--no-sandbox)' };
              if (!config.enabled) return { color: 'warning', label: 'Disabled' };
              if (!sandboxEnabled || !sandboxReady) return { color: 'warning', label: 'Inactive' };
              return { color: 'success', label: 'Active' };
            }

            function boolVal(v: boolean): string {
              return v ? theme.fg('warning', 'yes') : theme.fg('success', 'no');
            }

            return {
              render(width: number): string[] {
                const innerW = Math.max(1, width - 4);
                const row = (content = '') => boxRow(theme, width, content);
                const lines: string[] = [];
                const status = sandboxStatus();
                const toggleValue = config.enabled
                  ? theme.fg('success', 'enabled')
                  : theme.fg('warning', 'disabled');

                function section(titleText: string, detail?: string): void {
                  lines.push(row(''));
                  lines.push(row(`${accent(titleText)}${detail ? dim(` · ${detail}`) : ''}`));
                }

                function item(label: string, value: string): void {
                  lines.push(row(`  ${dim('•')} ${muted(label.padEnd(13))} ${value}`));
                }

                function listValue(values: string[], maxWidth: number): string {
                  const value = values.join(', ') || 'none';
                  return text(truncateToWidth(value, Math.max(10, maxWidth)));
                }

                lines.push(boxTop(theme, width, 'Sandbox'));

                const statusDot = theme.fg(status.color, '●');
                const pathSnippet = text(truncateToWidth(binaryPath(), Math.max(20, innerW - 28)));
                lines.push(
                  row(
                    `${statusDot} ${text(status.label)} ${dim('·')} persisted ${toggleValue} ${dim('·')} ${muted('landstrip')} ${pathSnippet}`,
                  ),
                );

                section('Config');
                item('project', text(projectPath));
                item('global', text(globalPath));

                const netMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';
                section('Network', netMode);
                item('allow network', boolVal(config.network.allowNetwork));
                item('allowed', listValue(config.network.allowedDomains, innerW - 17));
                item('denied', listValue(config.network.deniedDomains, innerW - 17));
                if (sessionAllowedDomains.length > 0)
                  item('session', theme.fg('accent', sessionAllowedDomains.join(', ')));

                section('Filesystem');
                item('deny read', listValue(config.filesystem.denyRead, innerW - 17));
                item('allow read', listValue(config.filesystem.allowRead, innerW - 17));
                item('allow write', listValue(config.filesystem.allowWrite, innerW - 17));
                item('deny write', listValue(config.filesystem.denyWrite, innerW - 17));

                if (sessionAllowedReadPaths.length > 0 || sessionAllowedWritePaths.length > 0) {
                  section('Session grants');
                  if (sessionAllowedReadPaths.length > 0)
                    item('read', theme.fg('accent', sessionAllowedReadPaths.join(', ')));
                  if (sessionAllowedWritePaths.length > 0)
                    item('write', theme.fg('accent', sessionAllowedWritePaths.join(', ')));
                }

                lines.push(row(''));
                lines.push(
                  row(
                    `${dim('t')} ${muted('toggle persisted setting')}  ${dim('esc')} ${muted('close')}`,
                  ),
                );
                lines.push(boxBottom(theme, width));

                return lines;
              },

              handleInput(data: string): void {
                if (data !== 't' && data !== 'T') {
                  done(undefined);
                  return;
                }

                void (async () => {
                  const enabled = !config.enabled;
                  const scope = await setSandboxConfigEnabled(ctx.cwd, enabled);
                  config = loadConfig(ctx.cwd);

                  if (!enabled) {
                    disableSandbox(ctx);
                    notify(ctx, `Sandbox disabled in ${scope} config`, 'info');
                  } else if (noSandboxFlag) {
                    notify(ctx, 'Sandbox remains disabled via --no-sandbox', 'warning');
                  } else if (!config.enabled) {
                    notify(ctx, 'Sandbox remains disabled via config', 'info');
                  } else if (enableSandbox(ctx)) {
                    notify(ctx, `Sandbox enabled in ${scope} config`, 'info');
                  }

                  tui.requestRender();
                })().catch((error: unknown) => {
                  notify(ctx, `Could not update config: ${error}`, 'error');
                });
              },

              invalidate(): void {},
            };
          },
          {
            overlay: true,
            overlayOptions: {
              anchor: 'center',
              width: 78,
              margin: 2,
            },
          },
        );
      },
    });
  }

  return { createBashTool, register };
}
