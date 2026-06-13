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
} from '@earendil-works/pi-coding-agent';

import { binaryPath } from '@jarkkojs/landstrip';

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
import { type AddressInfo, connect as connectNet, createServer, type Socket } from 'node:net';
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
} from '@earendil-works/pi-coding-agent';
import { Key, matchesKey, truncateToWidth, visibleWidth } from '@earendil-works/pi-tui';

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

interface LandstripPolicy {
  network: {
    allowNetwork: boolean;
    allowLocalBinding: boolean;
    allowAllUnixSockets: boolean;
    allowUnixSockets: string[];
    httpProxyPort?: number;
  };
  filesystem: SandboxFilesystemConfig;
}

interface LandstripErrorResponse {
  reason: 'Other' | 'LaunchFailed' | 'SetupFailed' | 'Usage';
  file?: string;
  program?: string;
  type?: 'filesystem' | 'network' | 'platform' | 'launch' | 'encoding';
  source: string;
}

const LANDSTRIP_VERSION = [0, 11, 3] as const;
const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    allowNetwork: false,
    allowLocalBinding: false,
    allowAllUnixSockets: false,
    allowUnixSockets: [],
    allowedDomains: [
      'npmjs.org',
      '*.npmjs.org',
      'registry.npmjs.org',
      'registry.yarnpkg.com',
      'pypi.org',
      '*.pypi.org',
      'github.com',
      '*.github.com',
      'api.github.com',
      'raw.githubusercontent.com',
      'crates.io',
      '*.crates.io',
      'static.crates.io',
    ],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ['/Users', '/home'],
    allowRead: ['.', '~/.config', '~/.gitconfig', '~/.local', '~/.cargo', '/dev/null'],
    allowWrite: ['.', '/tmp', '/dev/null'],
    denyWrite: ['.env', '.env.*', '*.pem', '*.key'],
  },
};

type PermissionChoice = 'abort' | 'session' | 'project' | 'global';

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

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
  return {
    enabled: overrides.enabled ?? base.enabled,
    network: {
      ...base.network,
      ...overrides.network,
    },
    filesystem: {
      ...base.filesystem,
      ...overrides.filesystem,
    },
  };
}

function getConfigPaths(cwd: string): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(homedir(), '.pi', 'agent', 'sandbox.json'),
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

function addDomainToConfig(configPath: string, domain: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.network?.allowedDomains ?? [];
  if (existing.includes(domain)) return;

  config.network = {
    ...config.network,
    allowedDomains: [...existing, domain],
    deniedDomains: config.network?.deniedDomains ?? [],
  } as SandboxNetworkConfig;
  writeConfigFile(configPath, config);
}

function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowRead ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowRead: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    allowWrite: config.filesystem?.allowWrite ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  } as SandboxFilesystemConfig;
  writeConfigFile(configPath, config);
}

function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowWrite ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowWrite: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    allowRead: config.filesystem?.allowRead ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  } as SandboxFilesystemConfig;
  writeConfigFile(configPath, config);
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

function extractCandidatePaths(command: string): string[] {
  const paths: string[] = [];
  // Split on whitespace, preserving quoted strings minimally
  const tokens = command.match(/[^\s"']+|"[^"]*"|'[^']*'/g) ?? [];
  for (const token of tokens) {
    const clean = token.replace(/^["']|["']$/g, '').replace(/[,;]$/, '');
    if (
      clean.startsWith('/') ||
      clean.startsWith('~/') ||
      clean === '~' ||
      clean.startsWith('./') ||
      clean.startsWith('../')
    ) {
      paths.push(clean);
    }
  }
  return paths;
}

function extractBlockedPath(output: string, cwd: string, command?: string): string | null {
  // bash/sh: line X: /path: Permission denied
  let match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?([^:\n]+): (?:Operation not permitted|Permission denied)/,
  );
  if (match) return normalizeBlockedPath(match[1], cwd);

  // ls/cat/cp: cannot open/access/stat '/path': Permission denied
  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot (?:open|access|stat|create)(?: directory)? '?([^'\n]+?)'?(?: for (?:reading|writing))?: Permission denied$/m,
  );
  if (match) return normalizeBlockedPath(match[1], cwd);

  // Generic: cmd: /absolute/path: Permission denied or Operation not permitted
  match = output.match(
    /^[a-zA-Z0-9_-]+: (\/[^\n:]+): (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizeBlockedPath(match[1], cwd);

  // Landstrip structured error format with file field
  const landstripErrors = parseLandstripErrors(output);
  for (const error of landstripErrors) {
    if (error.file) return normalizeBlockedPath(error.file, cwd);
  }

  // If landstrip reported an error but without a file field, try to
  // extract the blocked path from the command itself
  if (landstripErrors.length > 0 && command) {
    const config = loadConfig(cwd);
    for (const candidate of extractCandidatePaths(command)) {
      const resolved = canonicalizePath(candidate);
      if (
        matchesPattern(resolved, config.filesystem.denyRead) ||
        !matchesPattern(resolved, config.filesystem.allowRead)
      ) {
        return resolved;
      }
    }
  }

  return null;
}

function extractBlockedWritePath(output: string, cwd: string, command?: string): string | null {
  return extractBlockedPath(output, cwd, command);
}

function parseLandstripErrors(output: string): LandstripErrorResponse[] {
  const errors: LandstripErrorResponse[] = [];

  for (const block of output.trim().split(/\n\n+/)) {
    const fields: Record<string, string> = {};

    for (const line of block.split('\n')) {
      const colonIndex = line.indexOf(':');
      if (colonIndex === -1) continue;
      const key = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      if (key.length > 0 && value.length > 0) fields[key] = value;
    }

    if (
      fields.reason &&
      ['Other', 'LaunchFailed', 'SetupFailed', 'Usage'].includes(fields.reason) &&
      fields.source
    ) {
      const error: LandstripErrorResponse = {
        reason: fields.reason as LandstripErrorResponse['reason'],
        source: fields.source,
      };

      if (fields.file) error.file = fields.file;
      if (fields.program) error.program = fields.program;

      if (
        fields.type &&
        ['filesystem', 'network', 'platform', 'launch', 'encoding'].includes(fields.type)
      ) {
        error.type = fields.type as LandstripErrorResponse['type'];
      }

      errors.push(error);
    }
  }

  return errors;
}

function formatLandstripErrors(errors: LandstripErrorResponse[]): string {
  return errors
    .map((err) => {
      const parts: string[] = [`landstrip: ${err.reason}`];

      if (err.file) {
        parts.push(` (${err.file})`);
      }
      if (err.program) {
        parts.push(` ${err.program}`);
      }
      if (err.type) {
        parts.push(`:${err.type}`);
      }
      parts.push(`: ${err.source}`);

      return parts.join('');
    })
    .join('\n');
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
          const innerW = width - 4;
          const lines: string[] = [];
          const border = theme.fg('border', '│');
          const dim = (s: string) => theme.fg('dim', s);
          const borderFg = (s: string) => theme.fg('border', s);

          // Top border with title
          const label = ' Sandbox ';
          const topLeft = borderFg('╭─');
          const topRight = borderFg('─╮');
          const topFill = borderFg('─'.repeat(Math.max(0, width - 4 - visibleWidth(label))));
          lines.push(`${topLeft}${theme.fg('accent', label)}${topFill}${topRight}`);

          // Blank spacing
          lines.push(`${border} ${' '.repeat(innerW)} ${border}`);

          // Title line
          const titleText = truncateToWidth(theme.fg('warning', title), innerW);
          const titlePad = Math.max(0, innerW - visibleWidth(titleText));
          lines.push(`${border} ${titleText}${' '.repeat(titlePad)} ${border}`);

          lines.push(`${border} ${' '.repeat(innerW)} ${border}`);

          // Options
          for (let i = 0; i < options.length; i++) {
            const option = options[i];
            const isSelected = i === selectedIndex;
            const isPending = pendingAction === option.action;

            // Section divider before the permanent options (index 2 and 3)
            if (i === 2) {
              lines.push(`${border} ${' '.repeat(innerW)} ${border}`);
              const secLabel = ' Permanent ';
              const secDash = '─'.repeat(Math.max(0, innerW - visibleWidth(secLabel)));
              lines.push(`${border} ${dim(secDash + secLabel)} ${border}`);
              lines.push(`${border} ${' '.repeat(innerW)} ${border}`);
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
            const line = truncateToWidth(fullLine, innerW);
            const pad = Math.max(0, innerW - visibleWidth(line));
            lines.push(`${border} ${line}${' '.repeat(pad)} ${border}`);
          }

          // Footer
          lines.push(`${border} ${' '.repeat(innerW)} ${border}`);
          const footerText = pendingAction
            ? '↑↓ navigate  enter confirm  esc cancel'
            : '↑↓ navigate  enter select  esc dismiss';
          const footerLine = dim(footerText);
          const footerPad = Math.max(0, innerW - visibleWidth(footerLine));
          lines.push(`${border} ${footerLine}${' '.repeat(footerPad)} ${border}`);

          // Bottom border
          const botLeft = borderFg('╰');
          const botRight = borderFg('╯');
          const botFill = borderFg('─'.repeat(width - 2));
          lines.push(`${botLeft}${botFill}${botRight}`);

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

  function getEffectiveAllowedDomains(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...config.network.allowedDomains, ...sessionAllowedDomains];
  }

  function getEffectiveAllowRead(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...config.filesystem.allowRead, ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...config.filesystem.allowWrite, ...sessionAllowedWritePaths];
  }

  async function applyDomainChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    domain: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedDomains.includes(domain)) sessionAllowedDomains.push(domain);
    if (choice === 'project') addDomainToConfig(projectPath, domain);
    if (choice === 'global') addDomainToConfig(globalPath, domain);
  }

  async function applyReadChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedReadPaths.includes(filePath)) sessionAllowedReadPaths.push(filePath);
    if (choice === 'project') addReadPathToConfig(projectPath, filePath);
    if (choice === 'global') addReadPathToConfig(globalPath, filePath);
  }

  async function applyWriteChoice(
    choice: Exclude<PermissionChoice, 'abort'>,
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedWritePaths.includes(filePath)) sessionAllowedWritePaths.push(filePath);
    if (choice === 'project') addWritePathToConfig(projectPath, filePath);
    if (choice === 'global') addWritePathToConfig(globalPath, filePath);
  }

  async function ensureDomainAllowed(
    ctx: ExtensionContext,
    domain: string,
    cwd: string,
  ): Promise<boolean> {
    const config = loadConfig(cwd);

    if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
    if (domainMatchesAny(domain, getEffectiveAllowedDomains(cwd))) return true;

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
        allowRead: [...config.filesystem.allowRead, ...sessionAllowedReadPaths],
        allowWrite: [...config.filesystem.allowWrite, ...sessionAllowedWritePaths],
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

      const upstream = connectNet(endpoint.port, endpoint.host, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pipeSockets(client, upstream, rest);
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
      const upstream = connectNet(port, url.hostname, () => {
        upstream.write(`${rewrittenHeader}\r\n\r\n`);
        pipeSockets(client, upstream, rest);
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

  function createLandstripBashOps(
    ctx: ExtensionContext,
    onStderr: (data: Buffer) => void = () => {},
  ): BashOperations {
    return {
      async exec(command, cwd, { onData, signal, timeout, env }) {
        if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

        const { shell, args } = getShellConfig(SettingsManager.create(cwd).getShellPath());
        const config = loadConfig(cwd);
        const allowNetwork = config.network.allowNetwork;
        const proxy = allowNetwork ? null : await startProxy(ctx, cwd);
        const proxyPort = proxy ? proxy.port : null;
        const policy = writePolicyFile(cwd, proxyPort);
        const landstripArgs = ['-p', policy.path, shell, ...args, command];

        return new Promise((resolvePromise, reject) => {
          let timeoutHandle: NodeJS.Timeout | undefined;
          let timedOut = false;
          let cleaned = false;

          const cleanup = () => {
            if (cleaned) return;
            cleaned = true;
            if (timeoutHandle) clearTimeout(timeoutHandle);
            signal?.removeEventListener('abort', onAbort);
            void proxy?.stop();
            rmSync(policy.dir, { recursive: true, force: true });
          };

          const child = spawn(binaryPath(), landstripArgs, {
            cwd,
            env: allowNetwork ? { ...process.env, ...env } : proxyEnv(env, proxy!.port),
            detached: true,
            stdio: ['ignore', 'pipe', 'pipe'],
          });

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

          child.stdout?.on('data', onData);
          child.stderr?.on('data', (data: Buffer) => {
            stderrAcc += data.toString('utf8');
            onStderr(data);
            onData(data);
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

            const blockedPath = extractBlockedPath(stderrAcc, cwd, command);
            if (blockedPath && ctx.hasUI) {
              const config = loadConfig(cwd);
              const isDeniedByDenyRead = matchesPattern(blockedPath, config.filesystem.denyRead);
              const isReadAllowed = matchesPattern(blockedPath, getEffectiveAllowRead(cwd));
              const isWriteAllowed = !shouldPromptForWrite(
                blockedPath,
                getEffectiveAllowWrite(cwd),
                matchesPattern,
              );

              if (isDeniedByDenyRead || !isReadAllowed) {
                const choice = await promptReadBlock(
                  ctx,
                  blockedPath,
                  isDeniedByDenyRead ? 'denyRead overrides allowRead' : undefined,
                );
                if (choice !== 'abort') await applyReadChoice(choice, blockedPath, cwd);
              } else if (!isWriteAllowed) {
                const choice = await promptWriteBlock(ctx, blockedPath);
                if (choice !== 'abort') await applyWriteChoice(choice, blockedPath, cwd);
              }
            } else if (!blockedPath && ctx.hasUI) {
              const landstripErrors = parseLandstripErrors(stderrAcc);
              if (landstripErrors.length > 0) {
                const formatted = formatLandstripErrors(landstripErrors);
                ctx.ui.notify(`Sandbox blocked an operation: ${formatted}`, 'warning');
              }
            }

            resolvePromise({ exitCode: code });
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
    let landstripStderr = '';
    const sandboxedBash = createBashToolDefinition(ctx.cwd, {
      operations: createLandstripBashOps(ctx, (data) => {
        landstripStderr += data.toString('utf8');
      }),
      shellPath: SettingsManager.create(ctx.cwd).getShellPath(),
    });

    const run = () => sandboxedBash.execute(id, params, signal, onUpdate, ctx);
    let result: AgentToolResult<BashToolDetails | undefined>;
    try {
      result = await run();
    } catch (error) {
      const landstripErrors = parseLandstripErrors(landstripStderr);
      if (landstripErrors.length > 0) {
        throw new Error(formatLandstripErrors(landstripErrors));
      }
      throw error;
    }
    const outputText = result.content
      .filter((content) => content.type === 'text')
      .map((content) => content.text)
      .join('\n');
    const landstripErrors = parseLandstripErrors(landstripStderr);
    if (landstripErrors.length > 0) {
      const message = formatLandstripErrors(landstripErrors);
      result.content.unshift({ type: 'text', text: `\n${message}\n` });
    }
    const blockedPath = extractBlockedWritePath(outputText, ctx.cwd, params.command);

    if (!blockedPath || !ctx.hasUI) return result;

    const choice = await promptWriteBlock(ctx, blockedPath);
    if (choice === 'abort') return result;

    await applyWriteChoice(choice, blockedPath, ctx.cwd);

    const config = loadConfig(ctx.cwd);
    const { globalPath, projectPath } = getConfigPaths(ctx.cwd);
    if (matchesPattern(blockedPath, config.filesystem.denyWrite)) {
      ctx.ui.notify(
        `"${blockedPath}" was added to allowWrite, but denyWrite still blocks it. Check:\n  ${projectPath}\n  ${globalPath}`,
        'warning',
      );
      return result;
    }

    onUpdate?.({
      content: [
        { type: 'text', text: `\n--- Write access granted for "${blockedPath}", retrying ---\n` },
      ],
      details: {},
    });
    return run();
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
      ctx.ui.notify('Network sandbox is disabled because network.allowNetwork is true.', 'warning');
      return;
    }
    if (!allowsAllDomains(config.network.allowedDomains)) return;
    ctx.ui.notify(
      'Network sandbox allows all domains because network.allowedDomains contains "*".',
      'warning',
    );
  }

  function enableStatus(ctx: ExtensionContext, config: SandboxConfig): void {
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

    ctx.ui.setStatus('sandbox', `${dot} ${label}  ${sep}  ${net}  ${sep}  ${write}`);
  }

  function enableSandbox(ctx: ExtensionContext): boolean {
    const config = loadConfig(ctx.cwd);

    if (!SUPPORTED_PLATFORMS.has(process.platform)) {
      sandboxEnabled = false;
      sandboxReady = false;
      ctx.ui.notify(`landstrip sandboxing is not supported on ${process.platform}`, 'warning');
      return false;
    }

    const version = landstripVersion();
    if (!version) {
      sandboxEnabled = false;
      sandboxReady = false;
      ctx.ui.notify(
        `landstrip was not found. Reinstall with: npm install @jarkkojs/landstrip`,
        'error',
      );
      return false;
    }

    if (!hasMinimumVersion(version, LANDSTRIP_VERSION)) {
      sandboxEnabled = false;
      sandboxReady = false;
      ctx.ui.notify(`landstrip 0.11.3 or newer is required; found: ${version}`, 'error');
      return false;
    }

    sandboxEnabled = true;
    sandboxReady = true;
    warnIfAllDomainsAllowed(ctx, config);
    enableStatus(ctx, config);
    return true;
  }

  function createBashTool(cwd: string, ctx?: ExtensionContext): LandstripBashTool {
    const localBash = createPlainBashTool(cwd);

    return {
      ...localBash,
      label: 'bash (landstrip)',
      async execute(id, params, signal, onUpdate, callCtx) {
        const effectiveCtx = callCtx ?? ctx;
        if (!sandboxEnabled || !sandboxReady || !effectiveCtx)
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
      if (!sandboxEnabled || !sandboxReady) return;
      const config = loadConfig(ctx.cwd);
      if (!config.enabled) return;

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
      if (!sandboxEnabled) return;

      const config = loadConfig(ctx.cwd);
      if (!config.enabled) return;

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
        if (!matchesPattern(filePath, getEffectiveAllowRead(ctx.cwd))) {
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

        if (shouldPromptForWrite(filePath, getEffectiveAllowWrite(ctx.cwd), matchesPattern)) {
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
      const noSandbox = maybePi.getFlag?.('no-sandbox') as boolean;

      if (noSandbox) {
        sandboxEnabled = false;
        sandboxReady = false;
        ctx.ui.notify('Sandbox disabled via --no-sandbox', 'warning');
        return;
      }

      const config = loadConfig(ctx.cwd);
      if (!config.enabled) {
        sandboxEnabled = false;
        sandboxReady = false;
        ctx.ui.notify('Sandbox disabled via config', 'info');
        return;
      }

      enableSandbox(ctx);
    });

    maybePi.registerCommand?.('sandbox-enable', {
      description: 'Enable the landstrip sandbox for this session',
      handler: async (_args, ctx) => {
        if (sandboxEnabled) {
          ctx.ui.notify('Sandbox is already enabled', 'info');
          return;
        }

        if (enableSandbox(ctx)) ctx.ui.notify('Sandbox enabled', 'info');
      },
    });

    maybePi.registerCommand?.('sandbox-disable', {
      description: 'Disable the landstrip sandbox for this session',
      handler: async (_args, ctx) => {
        if (!sandboxEnabled) {
          ctx.ui.notify('Sandbox is already disabled', 'info');
          return;
        }

        sandboxEnabled = false;
        sandboxReady = false;
        ctx.ui.setStatus('sandbox', undefined);
        ctx.ui.notify('Sandbox disabled', 'info');
      },
    });

    maybePi.registerCommand?.('sandbox', {
      description: 'Show sandbox configuration',
      handler: async (_args, ctx) => {
        if (!sandboxEnabled) {
          ctx.ui.notify('Sandbox is disabled', 'info');
          return;
        }

        const config = loadConfig(ctx.cwd);
        const { globalPath, projectPath } = getConfigPaths(ctx.cwd);

        await ctx.ui.custom(
          (tui, theme, _kb, done) => {
            const dim = (s: string) => theme.fg('dim', s);
            const muted = (s: string) => theme.fg('muted', s);
            const accent = (s: string) => theme.fg('accent', s);
            const text = (s: string) => theme.fg('text', s);
            const borderFg = (s: string) => theme.fg('border', s);

            function boolVal(v: boolean): string {
              return v ? theme.fg('warning', 'yes') : theme.fg('success', 'no');
            }

            function makeRow(content: string, innerW: number, border: string): string {
              const line = truncateToWidth(content, innerW);
              const pad = Math.max(0, innerW - visibleWidth(line));
              return `${border} ${line}${' '.repeat(pad)} ${border}`;
            }

            return {
              render(width: number): string[] {
                const innerW = width - 4;
                const border = borderFg('│');
                const row = (c: string) => makeRow(c, innerW, border);
                const lines: string[] = [];

                // Top border
                const title = accent(' Sandbox Configuration ');
                const topFill = borderFg('─'.repeat(Math.max(0, width - 4 - visibleWidth(title))));
                lines.push(`${borderFg('╭─')}${title}${topFill}${borderFg('─╮')}`);

                // Status
                const statusDot = theme.fg('success', '●');
                const pathSnippet = text(truncateToWidth(binaryPath(), Math.max(20, innerW - 27)));
                lines.push(
                  row(
                    `  ${statusDot} ${text('Active')}  ${dim('·')}  ${muted('landstrip:')} ${pathSnippet}`,
                  ),
                );

                // Config files
                lines.push(row(`  ${dim('Config files:')}`));
                lines.push(row(`    ${dim('project')} ${text(projectPath)}`));
                lines.push(row(`    ${dim('global')}  ${text(globalPath)}`));

                // Network section
                lines.push(row(''));
                lines.push(row(`${'─'.repeat(innerW)}`));
                const netMode = config.network.allowNetwork ? ' (unrestricted)' : ' (proxied)';
                lines.push(row(`  ${accent('Network')}${dim(netMode)}`));
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Allow network:')} ${boolVal(config.network.allowNetwork)}`,
                  ),
                );
                const domainsStr = config.network.allowedDomains.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Allowed:')} ${text(truncateToWidth(domainsStr, Math.max(10, innerW - 15)))}`,
                  ),
                );
                const denyStr = config.network.deniedDomains.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Denied:')} ${text(truncateToWidth(denyStr, Math.max(10, innerW - 14)))}`,
                  ),
                );
                if (sessionAllowedDomains.length > 0) {
                  lines.push(
                    row(
                      `  ${dim('•')} ${muted('Session:')} ${theme.fg('accent', sessionAllowedDomains.join(', '))}`,
                    ),
                  );
                }

                // Filesystem section
                lines.push(row(''));
                lines.push(row(`${'─'.repeat(innerW)}`));
                lines.push(row(`  ${accent('Filesystem')}`));
                const denyReadStr = config.filesystem.denyRead.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Deny read:')} ${text(truncateToWidth(denyReadStr, Math.max(10, innerW - 16)))}`,
                  ),
                );
                const allowReadStr = config.filesystem.allowRead.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Allow read:')} ${text(truncateToWidth(allowReadStr, Math.max(10, innerW - 17)))}`,
                  ),
                );
                const allowWriteStr = config.filesystem.allowWrite.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Allow write:')} ${text(truncateToWidth(allowWriteStr, Math.max(10, innerW - 18)))}`,
                  ),
                );
                const denyWriteStr = config.filesystem.denyWrite.join(', ') || '(none)';
                lines.push(
                  row(
                    `  ${dim('•')} ${muted('Deny write:')} ${text(truncateToWidth(denyWriteStr, Math.max(10, innerW - 17)))}`,
                  ),
                );

                // Session allowances
                if (sessionAllowedReadPaths.length > 0 || sessionAllowedWritePaths.length > 0) {
                  lines.push(row(''));
                  if (sessionAllowedReadPaths.length > 0) {
                    lines.push(
                      row(
                        `  ${dim('•')} ${muted('Session read:')} ${theme.fg('accent', sessionAllowedReadPaths.join(', '))}`,
                      ),
                    );
                  }
                  if (sessionAllowedWritePaths.length > 0) {
                    lines.push(
                      row(
                        `  ${dim('•')} ${muted('Session write:')} ${theme.fg('accent', sessionAllowedWritePaths.join(', '))}`,
                      ),
                    );
                  }
                }

                // Footer
                lines.push(row(''));
                lines.push(row(`  ${dim('esc')} ${muted('or any key to close')}`));

                // Bottom border
                lines.push(`${borderFg('╰')}${borderFg('─'.repeat(width - 2))}${borderFg('╯')}`);

                return lines;
              },

              handleInput(): void {
                done(undefined);
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
