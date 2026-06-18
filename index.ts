// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

/// <reference path="./landstrip.d.ts" />

import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  BashToolDetails,
  BashToolInput,
  ExtensionAPI,
  ExtensionContext,
  Theme,
} from '@earendil-works/pi-coding-agent';

import { binaryPath } from '@landstrip/landstrip';

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
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { URL } from 'node:url';

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
import { randomBytes } from 'node:crypto';

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

type LandstripTrap =
  | { kind: 'filesystem'; operation: LandstripOperation; file: string; mechanism: string }
  | { kind: 'network'; operation: string; target: string; mechanism: string }
  | { kind: 'launch'; program: string; source: string }
  | { kind: 'usage'; message: string }
  | { kind: 'internal'; detail: Record<string, string> };

interface LandstripBashCallbacks {
  onStderr?: (data: Buffer) => void;
  onErrorFd?: (data: Buffer) => void;
}

const LANDSTRIP_VERSION = [0, 15, 9] as const;
const REQUIRED_LANDSTRIP_VERSION = LANDSTRIP_VERSION.join('.');
const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    allowNetwork: false,
    allowLocalBinding: false,
    allowAllUnixSockets: false,
    allowUnixSockets: [],
    allowedDomains: [],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ['/Users', '/home'],
    allowRead: ['.', '~/.gitconfig', '~/.config/git/config', '/dev/null'],
    allowWrite: ['.', '/dev/null'],
    denyWrite: ['**/.env', '**/.env.*', '**/*.pem', '**/*.key'],
  },
};

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

function loadConfig(cwd: string): SandboxConfig {
  const projectConfigPath = join(cwd, '.pi', 'sandbox.json');
  const globalConfigPath = join(getAgentDir(), 'sandbox.json');

  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

  if (existsSync(globalConfigPath)) {
    try {
      globalConfig = JSON.parse(readFileSync(globalConfigPath, 'utf-8'));
    } catch (error) {
      console.error(`Warning: Could not parse ${globalConfigPath}: ${error}`);
    }
  }

  if (existsSync(projectConfigPath)) {
    try {
      projectConfig = JSON.parse(readFileSync(projectConfigPath, 'utf-8'));
    } catch (error) {
      console.error(`Warning: Could not parse ${projectConfigPath}: ${error}`);
    }
  }

  return deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig);
}

function mergeArray(base: string[], override?: string[]): string[] {
  if (!override) return base;
  return [...new Set([...base, ...override])];
}

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
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

function readOrEmptyConfig(configPath: string): Partial<SandboxConfig> {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, 'utf-8'));
  } catch {
    return {};
  }
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
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
    } as SandboxNetworkConfig;
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
    } as SandboxFilesystemConfig;
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
    } as SandboxFilesystemConfig;
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
  const normalizedDomain = domain.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();

  if (normalizedPattern === '*') return true;
  if (normalizedPattern.startsWith('*.')) {
    const base = normalizedPattern.slice(2);
    return normalizedDomain === base || normalizedDomain.endsWith(`.${base}`);
  }

  return normalizedDomain === normalizedPattern;
}

function domainMatchesAny(domain: string, patterns: string[]): boolean {
  return patterns.some((pattern) => domainMatchesPattern(domain, pattern));
}

function allowsAllDomains(allowedDomains: string[]): boolean {
  return allowedDomains.includes('*');
}

function shouldPromptForWrite(
  path: string,
  allowWrite: string[],
  patternMatcher: (path: string, patterns: string[]) => boolean,
): boolean {
  return allowWrite.length === 0 || !patternMatcher(path, allowWrite);
}

function expandPath(filePath: string): string {
  return resolve(filePath.replace(/^~(?=$|\/)/, homedir()));
}

function canonicalizePath(filePath: string): string {
  const abs = expandPath(filePath);

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

function matchesPattern(filePath: string, patterns: string[]): boolean {
  const abs = canonicalizePath(filePath);

  return patterns.some((pattern) => {
    const absPattern = pattern.includes('*') ? expandPath(pattern) : canonicalizePath(pattern);

    if (pattern.includes('*')) {
      const escaped = absPattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      return new RegExp(`^${escaped}$`).test(abs);
    }

    const sep = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sep);
  });
}

function normalizeBlockedPath(path: string, cwd: string): string {
  return canonicalizePath(isAbsolute(path) ? path : join(cwd, path));
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

type LandstripFilesystemTrap = Extract<LandstripTrap, { kind: 'filesystem' }>;

function isFilesystemTrap(trap: LandstripTrap): trap is LandstripFilesystemTrap {
  return trap.kind === 'filesystem';
}

function extractBlockedPath(output: string, cwd: string): string | null {
  const landstripErrors = parseLandstripTraps(output).filter(isFilesystemTrap);
  if (landstripErrors.length > 0) {
    return normalizeBlockedPath(landstripErrors[0].file, cwd);
  }

  return extractNativeDeniedPath(output, cwd);
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
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?([^:\n]+): (?:Operation not permitted|Permission denied)/,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot create(?: directory)? '?([^'\n]+?)'?(?: for writing)?: (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizePathMatch(match[1], cwd);

  return null;
}

function extractBlockedWritePath(output: string, cwd: string): string | null {
  for (const error of parseLandstripTraps(output).filter(isFilesystemTrap)) {
    if (error.operation === 'write') {
      return normalizeBlockedPath(error.file, cwd);
    }
  }

  return extractNativeWriteDeniedPath(output, cwd);
}

function extractBlockedReadPath(output: string, cwd: string): string | null {
  for (const error of parseLandstripTraps(output).filter(isFilesystemTrap)) {
    if (error.operation === 'read') {
      return normalizeBlockedPath(error.file, cwd);
    }
  }

  return extractNativeDeniedPath(output, cwd);
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

// landstrip emits each trap as a flat JSON record tagged by a `kind`
// discriminant (`filesystem`, `network`, `launch`, `usage`, `internal`)
// alongside a stable `code` and variant-specific fields.
function parseLandstripTrap(obj: Record<string, unknown>): LandstripTrap | null {
  switch (obj.kind) {
    case 'filesystem': {
      const operation = obj.operation;
      const file = asString(obj.path);
      if ((operation === 'read' || operation === 'write') && file !== null) {
        return { kind: 'filesystem', operation, file, mechanism: asString(obj.mechanism) ?? '' };
      }
      return null;
    }
    case 'network': {
      const operation = asString(obj.operation);
      const target = asString(obj.target);
      if (operation !== null && target !== null) {
        return { kind: 'network', operation, target, mechanism: asString(obj.mechanism) ?? '' };
      }
      return null;
    }
    case 'launch': {
      const program = asString(obj.program);
      const source = asString(obj.message);
      if (program !== null && source !== null) {
        return { kind: 'launch', program, source };
      }
      return null;
    }
    case 'usage': {
      const message = asString(obj.message);
      return message !== null ? { kind: 'usage', message } : null;
    }
    case 'internal': {
      const detail: Record<string, string> = {};
      const raw = obj.detail;
      if (typeof raw === 'object' && raw !== null && !Array.isArray(raw)) {
        for (const [key, value] of Object.entries(raw)) {
          if (typeof value === 'string') detail[key] = value;
        }
      }
      return { kind: 'internal', detail };
    }
    default:
      return null;
  }
}

function parseLandstripTraps(output: string): LandstripTrap[] {
  const traps: LandstripTrap[] = [];

  for (const line of output.trim().split('\n')) {
    if (line.length === 0) continue;

    try {
      const parsed: unknown = JSON.parse(line);
      if (typeof parsed !== 'object' || parsed === null) continue;
      const trap = parseLandstripTrap(parsed as Record<string, unknown>);
      if (trap) traps.push(trap);
    } catch {
      // Ignore non-JSON lines (e.g. stderr from child processes)
    }
  }

  return traps;
}

function formatLandstripTraps(traps: LandstripTrap[]): string {
  return traps
    .map((trap) => {
      switch (trap.kind) {
        case 'filesystem':
          return `landstrip: filesystem ${trap.operation} denied: ${trap.file} (${trap.mechanism})`;
        case 'network':
          return `landstrip: network ${trap.operation} denied: ${trap.target} (${trap.mechanism})`;
        case 'launch':
          return `landstrip: launch failed: ${trap.program}: ${trap.source}`;
        case 'usage':
          return `landstrip: usage error: ${trap.message}`;
        case 'internal': {
          const detail = Object.entries(trap.detail)
            .map(([key, value]) => `${key}=${value}`)
            .join(', ');
          return detail ? `landstrip: internal error: ${detail}` : 'landstrip: internal error';
        }
      }
    })
    .join('\n');
}

function notify(ctx: ExtensionContext, message: string, level: NotificationLevel): void {
  if (!ctx.hasUI) return;
  ctx.ui.notify(message, level);
}

function hasTuiStatus(ctx: ExtensionContext): boolean {
  const { mode } = ctx as ExtensionContext & { mode?: string };
  return mode === undefined ? ctx.hasUI : mode === 'tui';
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

            if (data === option.key) {
              resolveChoice(option.action);
              return;
            }

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

function landstripVersion(): string | null {
  const result = spawnSync(binaryPath(), ['--version'], { encoding: 'utf-8' });
  if (result.status !== 0) return null;
  return result.stdout.trim();
}

function parseVersion(version: string): [number, number, number] | null {
  const match = version.match(/\b(\d+)\.(\d+)\.(\d+)\b/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function hasMinimumVersion(version: string, minimum: readonly [number, number, number]): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return false;

  for (let i = 0; i < minimum.length; i++) {
    if (parsed[i] > minimum[i]) return true;
    if (parsed[i] < minimum[i]) return false;
  }

  return true;
}

function proxyEnv(env: NodeJS.ProcessEnv | undefined, port: number): NodeJS.ProcessEnv {
  const url = `http://127.0.0.1:${port}`;

  return {
    ...process.env,
    ...env,
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    ALL_PROXY: url,
    http_proxy: url,
    https_proxy: url,
    all_proxy: url,
    NO_PROXY: '',
    no_proxy: '',
  };
}

function splitHostPort(target: string, defaultPort: number): { host: string; port: number } | null {
  const bracketMatch = target.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketMatch) {
    return {
      host: bracketMatch[1],
      port: bracketMatch[2] ? Number(bracketMatch[2]) : defaultPort,
    };
  }

  const lastColon = target.lastIndexOf(':');
  if (lastColon > -1 && target.indexOf(':') === lastColon) {
    return {
      host: target.slice(0, lastColon),
      port: Number(target.slice(lastColon + 1)),
    };
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

export interface LandstripIntegrationOptions {
  registerBashTool?: boolean;
  cwd?: string;
}

export interface LandstripIntegration {
  createBashTool(cwd: string, ctx?: ExtensionContext): LandstripBashTool;
  register(pi: ExtensionAPI): void;
}

export default function (pi: ExtensionAPI) {
  createLandstripIntegration().register(pi);
}

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

  function resetSessionAllowances(): void {
    sessionAllowedDomains.length = 0;
    sessionAllowedReadPaths.length = 0;
    sessionAllowedWritePaths.length = 0;
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

  async function applyReadChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedReadPaths.includes(filePath)) sessionAllowedReadPaths.push(filePath);
    if (choice === 'project') await addReadPathToConfig(projectPath, filePath);
    if (choice === 'global') await addReadPathToConfig(globalPath, filePath);
  }

  async function applyWriteChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedWritePaths.includes(filePath)) sessionAllowedWritePaths.push(filePath);
    if (choice === 'project') await addWritePathToConfig(projectPath, filePath);
    if (choice === 'global') await addWritePathToConfig(globalPath, filePath);
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

  function startProxy(
    ctx: ExtensionContext,
    cwd: string,
  ): Promise<{ port: number; stop: () => Promise<void> }> {
    const sockets = new Set<Socket>();

    async function handleConnect(client: Socket, target: string, rest: Buffer): Promise<void> {
      const endpoint = splitHostPort(target, 443);
      if (!endpoint || !Number.isFinite(endpoint.port)) {
        denyProxyRequest(client, '400 Bad Request');
        return;
      }

      if (!(await ensureDomainAllowed(ctx, endpoint.host, cwd))) {
        denyProxyRequest(client);
        return;
      }

      let settled = false;
      const upstream = connectNet(endpoint.port, endpoint.host, () => {
        settled = true;
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pipeSockets(client, upstream, rest);
      });
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
        url = new URL(`http://${host}${rawTarget}`);
      }

      if (!(await ensureDomainAllowed(ctx, url.hostname, cwd))) {
        denyProxyRequest(client);
        return;
      }

      const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
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
      const sockPath = join(tmpdir(), `.landstrip-sock-${randomBytes(8).toString('hex')}`);
      const server = createServer();
      server.on('error', reject);
      let client: NetSocket | null = null;
      server.on('connection', (serverEnd) => {
        server.close();
        try {
          rmSync(sockPath, { force: true });
        } catch {
          /* ok */
        }
        if (client) resolve([client, serverEnd]);
      });
      server.listen(sockPath, () => {
        client = new NetSocket();
        client.on('error', reject);
        client.connect(sockPath);
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
        const proxy = allowNetwork ? null : await startProxy(ctx, cwd);
        const policy = writePolicyFile(cwd, proxy?.port ?? null);
        const landstripArgs = ['--trap-fd', '3', '-p', policy.path, shell, ...args, command];

        return new Promise((resolvePromise, reject) => {
          (async () => {
            let timeoutHandle: NodeJS.Timeout | undefined;
            let timedOut = false;
            let cleaned = false;

            // Create socketpair for bidirectional query-response on fd 3.
            const [trapSocket, childEnd] = await createSocketPair();

            const cleanup = () => {
              if (cleaned) return;
              cleaned = true;
              if (timeoutHandle) clearTimeout(timeoutHandle);
              signal?.removeEventListener('abort', onAbort);
              void proxy?.stop();
              trapSocket.destroy();
              rmSync(policy.dir, { recursive: true, force: true });
            };

            const child = spawn(binaryPath(), landstripArgs, {
              cwd,
              env: allowNetwork ? { ...process.env, ...env } : proxyEnv(env, proxy!.port),
              detached: true,
              stdio: ['ignore', 'pipe', 'pipe', childEnd],
            });

            // Child has dup'd its end; parent can close its copy.
            childEnd.destroy();

            function killChild(): void {
              if (!child.pid) return;
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

            child.stdout?.on('data', onData);
            child.stderr?.on('data', (data: Buffer) => {
              stderrAcc += data.toString('utf8');
              callbacks.onStderr?.(data);
              onData(data);
            });
            trapSocket.on('data', (data: Buffer) => {
              errorFdAcc += data.toString('utf8');
              callbacks.onErrorFd?.(data);
            });

            child.on('error', (error) => {
              cleanup();
              reject(error);
            });

            child.on('close', async (code) => {
              cleanup();
              if (signal?.aborted) {
                reject(new Error('aborted'));
                return;
              }
              if (timedOut) {
                reject(new Error(`timeout:${timeout}`));
                return;
              }

              const errorOutput = errorFdAcc || stderrAcc;

              const blockedPath =
                extractBlockedPath(errorOutput, cwd) ??
                (errorFdAcc ? extractBlockedPath(stderrAcc, cwd) : null);
              const blockedWritePath =
                extractBlockedWritePath(errorOutput, cwd) ??
                (errorFdAcc ? extractBlockedWritePath(stderrAcc, cwd) : null);
              if (blockedPath && ctx.hasUI) {
                const config = loadConfig(cwd);
                const isDeniedByDenyRead = matchesPattern(blockedPath, config.filesystem.denyRead);
                const isReadAllowed = matchesPattern(blockedPath, getEffectiveAllowRead(config));
                const isWriteAllowed = !shouldPromptForWrite(
                  blockedPath,
                  getEffectiveAllowWrite(config),
                  matchesPattern,
                );

                if (blockedWritePath === blockedPath && !isWriteAllowed) {
                  const choice = await promptWriteBlock(ctx, blockedPath);
                  if (choice !== 'abort') await applyWriteChoice(choice, blockedPath, cwd);
                } else if (isDeniedByDenyRead || !isReadAllowed) {
                  const choice = await promptReadBlock(
                    ctx,
                    blockedPath,
                    isDeniedByDenyRead ? 'granting allowRead will override it' : undefined,
                  );
                  if (choice !== 'abort') await applyReadChoice(choice, blockedPath, cwd);
                } else if (!isWriteAllowed) {
                  const choice = await promptWriteBlock(ctx, blockedPath);
                  if (choice !== 'abort') await applyWriteChoice(choice, blockedPath, cwd);
                }
              } else if (!blockedPath && ctx.hasUI) {
                const landstripErrors = parseLandstripTraps(errorOutput);
                if (landstripErrors.length > 0) {
                  const formatted = formatLandstripTraps(landstripErrors);
                  notify(ctx, `Sandbox blocked an operation: ${formatted}`, 'warning');
                }
              }

              resolvePromise({ exitCode: code });
            });
          })().catch(reject);
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
      if (matchesPattern(blockedPath, config.filesystem.denyWrite)) {
        notify(
          ctx,
          `"${blockedPath}" is blocked by denyWrite. Check:\n  ${projectPath}\n  ${globalPath}`,
          'warning',
        );
        return null;
      }

      if (shouldPromptForWrite(blockedPath, getEffectiveAllowWrite(config), matchesPattern)) {
        const choice = await promptWriteBlock(ctx, blockedPath);
        if (choice === 'abort') return null;
        await applyWriteChoice(choice, blockedPath, ctx.cwd);
      }

      config = loadConfig(ctx.cwd);
      if (matchesPattern(blockedPath, config.filesystem.denyWrite)) {
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
      if (!matchesPattern(blockedPath, getEffectiveAllowRead(config))) {
        const choice = await promptReadBlock(
          ctx,
          blockedPath,
          matchesPattern(blockedPath, config.filesystem.denyRead)
            ? 'granting allowRead will override it'
            : undefined,
        );
        if (choice === 'abort') return null;
        await applyReadChoice(choice, blockedPath, ctx.cwd);
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
        extractBlockedWritePath(fallbackOutput, ctx.cwd);
      if (blockedWritePath) {
        const retryResult = await retryWithWriteAccess(blockedWritePath);
        if (retryResult) return retryResult;
      }

      const blockedReadPath =
        extractBlockedReadPath(landstripErrorOutput, ctx.cwd) ??
        extractBlockedReadPath(fallbackOutput, ctx.cwd);
      if (blockedReadPath) {
        const retryResult = await retryWithReadAccess(blockedReadPath);
        if (retryResult) return retryResult;
      }

      const landstripErrors = parseLandstripTraps(landstripErrorOutput || errorText);
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
      extractBlockedWritePath(stderrOutput, ctx.cwd);
    if (blockedWritePath) {
      const retryResult = await retryWithWriteAccess(blockedWritePath);
      if (retryResult) return retryResult;
    }

    const blockedReadPath =
      extractBlockedReadPath(landstripErrorOutput, ctx.cwd) ??
      extractBlockedReadPath(stderrOutput, ctx.cwd);
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

  function enableSandbox(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd);

    if (!SUPPORTED_PLATFORMS.has(process.platform)) {
      sandboxEnabled = false;
      sandboxReady = false;
      notify(ctx, `landstrip sandboxing is not supported on ${process.platform}`, 'warning');
      return false;
    }

    const version = landstripVersion();
    if (!version) {
      sandboxEnabled = false;
      sandboxReady = false;
      notify(
        ctx,
        `landstrip was not found. Reinstall with: npm install @landstrip/landstrip`,
        'error',
      );
      return false;
    }

    if (!hasMinimumVersion(version, LANDSTRIP_VERSION)) {
      sandboxEnabled = false;
      sandboxReady = false;
      notify(
        ctx,
        `landstrip ${REQUIRED_LANDSTRIP_VERSION} or newer is required; found: ${version}`,
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

      return { operations: createLandstripBashOps(ctx) };
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
        const filePath = canonicalizePath(event.input.path);
        if (!matchesPattern(filePath, getEffectiveAllowRead(config))) {
          const choice = await promptReadBlock(ctx, filePath);
          if (choice === 'abort') {
            return {
              block: true,
              reason: `Sandbox: read access denied for "${filePath}"`,
            };
          }
          await applyReadChoice(choice, filePath, ctx.cwd);
        }
      }

      if (isToolCallEventType('write', event) || isToolCallEventType('edit', event)) {
        const filePath = canonicalizePath((event.input as { path: string }).path);

        if (matchesPattern(filePath, config.filesystem.denyWrite)) {
          return {
            block: true,
            reason:
              `Sandbox: write access denied for "${filePath}" (in denyWrite). ` +
              `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
          };
        }

        if (shouldPromptForWrite(filePath, getEffectiveAllowWrite(config), matchesPattern)) {
          const choice = await promptWriteBlock(ctx, filePath);
          if (choice === 'abort') {
            return {
              block: true,
              reason: `Sandbox: write access denied for "${filePath}" (not in allowWrite)`,
            };
          }
          await applyWriteChoice(choice, filePath, ctx.cwd);
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
