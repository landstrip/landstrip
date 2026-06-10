// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { Hooks, Plugin, PluginInput, PluginOptions } from '@opencode-ai/plugin';

import { binaryPath } from '@jarkkojs/landstrip';

import { spawnSync } from 'node:child_process';
import {
  existsSync,
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

interface SandboxConfigOverrides {
  enabled?: boolean;
  network?: Partial<SandboxNetworkConfig>;
  filesystem?: Partial<SandboxFilesystemConfig>;
}

interface BashSandboxState {
  originalCommand: string;
  wrappedCommand: string;
  policyDir: string;
  port: number | null;
  stop: (() => Promise<void>) | null;
}

type ToastVariant = 'info' | 'success' | 'warning' | 'error';

const LANDSTRIP_VERSION = [0, 11, 0] as const;
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
    allowRead: [
      '.',
      '/dev/null',
      '~/.config/opencode',
      '~/.config/git',
      '~/.gitconfig',
      '~/.local',
      '~/.cargo',
    ],
    allowWrite: ['.', '/tmp', '/dev/null'],
    denyWrite: ['.env', '.env.*', '*.pem', '*.key'],
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.every((item) => typeof item === 'string') ? [...value] : undefined;
}

function normalizeNetworkConfig(value: unknown): Partial<SandboxNetworkConfig> | undefined {
  if (!isRecord(value)) return undefined;

  const config: Partial<SandboxNetworkConfig> = {};
  if (typeof value.allowNetwork === 'boolean') config.allowNetwork = value.allowNetwork;
  if (typeof value.allowLocalBinding === 'boolean')
    config.allowLocalBinding = value.allowLocalBinding;
  if (typeof value.allowAllUnixSockets === 'boolean')
    config.allowAllUnixSockets = value.allowAllUnixSockets;

  const allowUnixSockets = stringArray(value.allowUnixSockets);
  if (allowUnixSockets) config.allowUnixSockets = allowUnixSockets;

  const allowedDomains = stringArray(value.allowedDomains);
  if (allowedDomains) config.allowedDomains = allowedDomains;

  const deniedDomains = stringArray(value.deniedDomains);
  if (deniedDomains) config.deniedDomains = deniedDomains;

  return config;
}

function normalizeFilesystemConfig(value: unknown): Partial<SandboxFilesystemConfig> | undefined {
  if (!isRecord(value)) return undefined;

  const config: Partial<SandboxFilesystemConfig> = {};
  const denyRead = stringArray(value.denyRead);
  if (denyRead) config.denyRead = denyRead;

  const allowRead = stringArray(value.allowRead);
  if (allowRead) config.allowRead = allowRead;

  const allowWrite = stringArray(value.allowWrite);
  if (allowWrite) config.allowWrite = allowWrite;

  const denyWrite = stringArray(value.denyWrite);
  if (denyWrite) config.denyWrite = denyWrite;

  return config;
}

function normalizeConfig(value: unknown): SandboxConfigOverrides {
  if (!isRecord(value)) return {};

  const config: SandboxConfigOverrides = {};
  if (typeof value.enabled === 'boolean') config.enabled = value.enabled;

  const network = normalizeNetworkConfig(value.network);
  if (network) config.network = network;

  const filesystem = normalizeFilesystemConfig(value.filesystem);
  if (filesystem) config.filesystem = filesystem;

  return config;
}

function normalizeOptions(options: PluginOptions | undefined): SandboxConfigOverrides {
  if (!isRecord(options)) return {};
  return normalizeConfig(isRecord(options.config) ? options.config : options);
}

function deepMerge(base: SandboxConfig, overrides: SandboxConfigOverrides): SandboxConfig {
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

function getConfigPaths(baseDirectory: string): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(homedir(), '.config', 'opencode', 'sandbox.json'),
    projectPath: join(baseDirectory, '.opencode', 'sandbox.json'),
  };
}

function readConfigFile(configPath: string): SandboxConfigOverrides {
  if (!existsSync(configPath)) return {};

  try {
    return normalizeConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
  } catch (error) {
    console.error(`Warning: Could not parse ${configPath}: ${error}`);
    return {};
  }
}

function loadConfig(baseDirectory: string, optionOverrides: SandboxConfigOverrides): SandboxConfig {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  return deepMerge(
    deepMerge(deepMerge(DEFAULT_CONFIG, readConfigFile(globalPath)), readConfigFile(projectPath)),
    optionOverrides,
  );
}

function expandPath(filePath: string, baseDirectory: string): string {
  const expanded = filePath.replace(/^~(?=$|[/])/, homedir());
  return resolve(isAbsolute(expanded) ? expanded : join(baseDirectory, expanded));
}

function configuredShellPath(config: unknown): string | undefined {
  if (!isRecord(config)) return undefined;
  return typeof config.shell === 'string' ? config.shell : undefined;
}

function canonicalizePath(filePath: string, baseDirectory: string): string {
  const abs = expandPath(filePath, baseDirectory);

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

function matchesPattern(filePath: string, patterns: string[], baseDirectory: string): boolean {
  const abs = canonicalizePath(filePath, baseDirectory);

  return patterns.some((pattern) => {
    const absPattern = pattern.includes('*')
      ? expandPath(pattern, baseDirectory)
      : canonicalizePath(pattern, baseDirectory);

    if (pattern.includes('*')) {
      const escaped = absPattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      return new RegExp(`^${escaped}$`).test(abs);
    }

    const sep = absPattern.endsWith('/') ? '' : '/';
    return abs === absPattern || abs.startsWith(absPattern + sep);
  });
}

function resolveFilesystemPatterns(patterns: string[], baseDirectory: string): string[] {
  return patterns.map((pattern) =>
    pattern.includes('*')
      ? expandPath(pattern, baseDirectory)
      : canonicalizePath(pattern, baseDirectory),
  );
}

function resolveFilesystemConfig(
  config: SandboxFilesystemConfig,
  baseDirectory: string,
): SandboxFilesystemConfig {
  return {
    denyRead: resolveFilesystemPatterns(config.denyRead, baseDirectory),
    allowRead: resolveFilesystemPatterns(config.allowRead, baseDirectory),
    allowWrite: resolveFilesystemPatterns(config.allowWrite, baseDirectory),
    denyWrite: resolveFilesystemPatterns(config.denyWrite, baseDirectory),
  };
}

function shouldPromptForRead(path: string, allowRead: string[], baseDirectory: string): boolean {
  return allowRead.length === 0 || !matchesPattern(path, allowRead, baseDirectory);
}

function shouldPromptForWrite(path: string, allowWrite: string[], baseDirectory: string): boolean {
  return allowWrite.length === 0 || !matchesPattern(path, allowWrite, baseDirectory);
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

function normalizeBlockedPath(path: string, baseDirectory: string): string {
  return canonicalizePath(isAbsolute(path) ? path : join(baseDirectory, path), baseDirectory);
}

function extractCandidatePaths(command: string): string[] {
  const paths: string[] = [];
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

function extractBlockedPath(
  output: string,
  baseDirectory: string,
  command?: string,
): string | null {
  // bash/sh: line X: /path: Permission denied
  let match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?([^:\n]+): (?:Operation not permitted|Permission denied)/,
  );
  if (match) return normalizeBlockedPath(match[1], baseDirectory);

  // ls/cat/cp: cannot open/access/stat '/path': Permission denied
  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot (?:open|access|stat|create)(?: directory)? '?([^'\n]+?)'?(?: for (?:reading|writing))?: Permission denied$/m,
  );
  if (match) return normalizeBlockedPath(match[1], baseDirectory);

  // Generic: cmd: /absolute/path: Permission denied or Operation not permitted
  match = output.match(
    /^[a-zA-Z0-9_-]+: (\/[^\n:]+): (?:Operation not permitted|Permission denied)$/m,
  );
  if (match) return normalizeBlockedPath(match[1], baseDirectory);

  // Landstrip structured error format with file field
  const landstripErrors = parseLandstripErrors(output);
  for (const error of landstripErrors) {
    if (error.file) return normalizeBlockedPath(error.file, baseDirectory);
  }

  // If landstrip reported an error but without a file field, try to
  // extract the blocked path from the command itself
  if (landstripErrors.length > 0 && command) {
    for (const candidate of extractCandidatePaths(command)) {
      const resolved = canonicalizePath(candidate, baseDirectory);
      return resolved;
    }
  }

  return null;
}

function extractBlockedWritePath(
  output: string,
  baseDirectory: string,
  command?: string,
): string | null {
  return extractBlockedPath(output, baseDirectory, command);
}

function isBlockedByDenyRead(path: string, config: SandboxConfig, baseDirectory: string): boolean {
  return matchesPattern(path, config.filesystem.denyRead, baseDirectory);
}

function firstBlockedDomain(
  command: string,
  config: SandboxConfig,
): { domain: string; reason: 'allowedDomains' | 'deniedDomains' } | null {
  for (const domain of extractDomainsFromCommand(command)) {
    if (domainMatchesAny(domain, config.network.deniedDomains)) {
      return { domain, reason: 'deniedDomains' };
    }

    if (!domainMatchesAny(domain, config.network.allowedDomains)) {
      return { domain, reason: 'allowedDomains' };
    }
  }

  return null;
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

function buildLandstripPolicy(
  config: SandboxConfig,
  baseDirectory: string,
  proxyPort: number | null,
): LandstripPolicy {
  return {
    network: {
      allowNetwork: config.network.allowNetwork,
      allowLocalBinding: config.network.allowLocalBinding,
      allowAllUnixSockets: config.network.allowAllUnixSockets,
      allowUnixSockets: config.network.allowUnixSockets,
      ...(proxyPort !== null ? { httpProxyPort: proxyPort } : {}),
    },
    filesystem: resolveFilesystemConfig(config.filesystem, baseDirectory),
  };
}

function writePolicyFile(
  config: SandboxConfig,
  baseDirectory: string,
  proxyPort: number | null,
): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), 'opencode-landstrip-XXXXXX'));
  const path = join(dir, 'policy.json');
  writeFileSync(
    path,
    JSON.stringify(buildLandstripPolicy(config, baseDirectory, proxyPort), null, 2) + '\n',
  );

  return { dir, path };
}

function startProxy(config: SandboxConfig): Promise<{ port: number; stop: () => Promise<void> }> {
  const sockets = new Set<Socket>();

  function domainAllowed(domain: string): boolean {
    if (domainMatchesAny(domain, config.network.deniedDomains)) return false;
    return domainMatchesAny(domain, config.network.allowedDomains);
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

    if (!domainAllowed(url.hostname)) {
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

  return new Promise((resolvePromise, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address() as AddressInfo;

      resolvePromise({
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

function proxyEnv(port: number | null): Record<string, string> | undefined {
  if (port === null) return undefined;
  const url = `http://127.0.0.1:${port}`;

  return {
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

function shellQuote(value: string): string {
  if (value.length === 0) return "''";
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function shellArgs(shell: string, command: string): string[] {
  const name = basename(shell).toLowerCase();
  if (name.includes('fish')) return [shell, '-c', command];
  return [shell, '-lc', command];
}

function buildWrappedCommand(policyPath: string, shell: string, command: string): string {
  const args = ['-p', policyPath, ...shellArgs(shell, command)];

  return [binaryPath(), ...args].map(shellQuote).join(' ');
}

function isGeneratedWrappedCommand(command: string): boolean {
  return (
    command.startsWith(`${shellQuote(binaryPath())} `) &&
    command.includes(` ${shellQuote('-p')} `) &&
    command.includes('opencode-landstrip-')
  );
}

function landstripDescription(description: string): string {
  return description.endsWith(' (landstrip)') ? description : `${description} (landstrip)`;
}

function getToolPath(args: Record<string, unknown>): string | undefined {
  const filePath = args.filePath ?? args.path;
  return typeof filePath === 'string' ? filePath : undefined;
}

function getSearchPath(args: Record<string, unknown>): string {
  return typeof args.path === 'string' ? args.path : '.';
}

function extractPatchPaths(patchText: string): string[] {
  const paths: string[] = [];

  for (const line of patchText.split(/\r?\n/)) {
    const fileMatch = line.match(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/);
    if (fileMatch) {
      paths.push(fileMatch[1].trim());
      continue;
    }

    const moveMatch = line.match(/^\*\*\* Move to: (.+)$/);
    if (moveMatch) paths.push(moveMatch[1].trim());
  }

  return paths;
}

function errorWithConfigPaths(baseDirectory: string, message: string): Error {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  return new Error(`${message}\n\nUpdate sandbox config in:\n  ${projectPath}\n  ${globalPath}`);
}

function assertReadAllowed(
  path: string,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowRead: string[],
): void {
  const filePath = canonicalizePath(path, baseDirectory);

  if (!shouldPromptForRead(filePath, effectiveAllowRead, baseDirectory)) return;

  if (isBlockedByDenyRead(filePath, config, baseDirectory)) {
    throw errorWithConfigPaths(
      baseDirectory,
      `Sandbox: read access denied for "${filePath}" (denyRead overrides allowRead).`,
    );
  }

  throw errorWithConfigPaths(
    baseDirectory,
    `Sandbox: read access denied for "${filePath}" (not in filesystem.allowRead).`,
  );
}

function assertWriteAllowed(
  path: string,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowWrite: string[],
): void {
  const filePath = canonicalizePath(path, baseDirectory);

  if (!shouldPromptForWrite(filePath, effectiveAllowWrite, baseDirectory)) return;

  if (matchesPattern(filePath, config.filesystem.denyWrite, baseDirectory)) {
    throw errorWithConfigPaths(
      baseDirectory,
      `Sandbox: write access denied for "${filePath}" (in filesystem.denyWrite).`,
    );
  }

  throw errorWithConfigPaths(
    baseDirectory,
    `Sandbox: write access denied for "${filePath}" (not in filesystem.allowWrite).`,
  );
}

function assertApplyPatchAllowed(
  args: Record<string, unknown>,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowWrite: string[],
): void {
  if (typeof args.patchText !== 'string') return;
  for (const path of extractPatchPaths(args.patchText))
    assertWriteAllowed(path, config, baseDirectory, effectiveAllowWrite);
}

const plugin: Plugin = async ({ client, directory }: PluginInput, options?: PluginOptions) => {
  const optionOverrides = normalizeOptions(options);
  const activeBash = new Map<string, BashSandboxState>();
  const notified = new Set<string>();
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  let enabledNotified = false;
  let configuredShell: string | undefined;
  let landstripCheck: { ok: true; version: string } | { ok: false; reason: string } | undefined;

  function getEffectiveAllowRead(config: SandboxConfig): string[] {
    return [...config.filesystem.allowRead, ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(config: SandboxConfig): string[] {
    return [...config.filesystem.allowWrite, ...sessionAllowedWritePaths];
  }

  client.app
    .log({
      body: {
        service: 'opencode-landstrip',
        level: 'info',
        message: `plugin loaded for ${directory}`,
      },
      query: { directory },
    })
    .catch(() => undefined);

  client.tui
    .showToast({
      body: {
        title: 'Sandbox',
        message: `Loaded for ${directory}`,
        variant: 'info',
        duration: 5000,
      },
    })
    .catch(() => undefined);

  async function notifyOnce(key: string, message: string, variant: ToastVariant): Promise<void> {
    if (notified.has(key)) return;
    notified.add(key);

    await client.tui
      .showToast({
        body: { title: 'opencode-landstrip', message, variant },
        query: { directory },
      })
      .catch(() => undefined);

    await client.app
      .log({
        body: {
          service: 'opencode-landstrip',
          level: variant === 'error' ? 'error' : variant === 'warning' ? 'warn' : 'info',
          message,
        },
        query: { directory },
      })
      .catch(() => undefined);
  }

  function checkLandstrip(): typeof landstripCheck {
    if (landstripCheck) return landstripCheck;

    if (!SUPPORTED_PLATFORMS.has(process.platform)) {
      landstripCheck = {
        ok: false,
        reason: `landstrip sandboxing is not supported on ${process.platform}`,
      };
      return landstripCheck;
    }

    const version = landstripVersion();
    if (!version) {
      landstripCheck = {
        ok: false,
        reason: `landstrip was not found. Reinstall with: npm install @jarkkojs/landstrip`,
      };
      return landstripCheck;
    }

    if (!hasMinimumVersion(version, LANDSTRIP_VERSION)) {
      landstripCheck = {
        ok: false,
        reason: `landstrip 0.11.0 or newer is required; found: ${version}`,
      };
      return landstripCheck;
    }

    landstripCheck = { ok: true, version };
    return landstripCheck;
  }

  async function activeConfig(): Promise<SandboxConfig | null> {
    const config = loadConfig(directory, optionOverrides);
    if (!config.enabled) return null;

    const check = checkLandstrip();
    if (!check?.ok) {
      await notifyOnce(
        `disabled:${check?.reason ?? 'unknown'}`,
        check?.reason ?? 'Sandbox disabled',
        'error',
      );
      return null;
    }

    if (!enabledNotified) {
      enabledNotified = true;
      if (config.network.allowNetwork) {
        await notifyOnce(
          'network-allow',
          'Network sandbox is disabled because network.allowNetwork is true.',
          'warning',
        );
      } else {
        const networkLabel = allowsAllDomains(config.network.allowedDomains)
          ? 'all domains'
          : `${config.network.allowedDomains.length} domains`;
        await notifyOnce(
          'enabled',
          `Sandbox enabled: ${networkLabel}, ${config.filesystem.allowWrite.length} write paths`,
          'info',
        );
        if (allowsAllDomains(config.network.allowedDomains)) {
          await notifyOnce(
            'network-all',
            'Network sandbox allows all domains because network.allowedDomains contains "*".',
            'warning',
          );
        }
      }
    }

    return config;
  }

  async function cleanupBash(callID: string): Promise<void> {
    const state = activeBash.get(callID);
    if (!state) return;

    activeBash.delete(callID);
    if (state.stop) await state.stop().catch(() => undefined);
    rmSync(state.policyDir, { recursive: true, force: true });
  }

  async function prepareBash(
    callID: string,
    args: Record<string, unknown>,
    config: SandboxConfig,
  ): Promise<void> {
    if (typeof args.command !== 'string') return;

    const existing = activeBash.get(callID);
    if (existing) {
      if (args.command === existing.originalCommand || args.command === existing.wrappedCommand) {
        args.command = existing.wrappedCommand;
        if (typeof args.description === 'string')
          args.description = landstripDescription(args.description);
        return;
      }

      await cleanupBash(callID);
    }

    if (isGeneratedWrappedCommand(args.command)) {
      if (typeof args.description === 'string')
        args.description = landstripDescription(args.description);
      return;
    }

    const allowNetwork = config.network.allowNetwork;

    if (!allowNetwork) {
      const blockedDomain = firstBlockedDomain(args.command, config);
      if (blockedDomain) {
        const reason =
          blockedDomain.reason === 'deniedDomains'
            ? 'is blocked by network.deniedDomains'
            : 'is not in network.allowedDomains';
        throw errorWithConfigPaths(
          directory,
          `Sandbox: network access denied for "${blockedDomain.domain}" (${reason}).`,
        );
      }
    }

    const proxy = allowNetwork ? null : await startProxy(config);
    const proxyPort = proxy ? proxy.port : null;
    let policy: { dir: string; path: string };

    try {
      policy = writePolicyFile(config, directory, proxyPort);
    } catch (error) {
      if (proxy) await proxy.stop().catch(() => undefined);
      throw error;
    }

    const originalCommand = args.command;
    const wrappedCommand = buildWrappedCommand(
      policy.path,
      configuredShell ?? process.env.SHELL ?? '/bin/sh',
      originalCommand,
    );

    activeBash.set(callID, {
      originalCommand,
      wrappedCommand,
      policyDir: policy.dir,
      port: proxyPort,
      stop: proxy ? proxy.stop : null,
    });

    args.command = wrappedCommand;
    if (typeof args.description === 'string')
      args.description = landstripDescription(args.description);
  }

  function buildConfigSummary(config: SandboxConfig): string {
    const { globalPath, projectPath } = getConfigPaths(directory);
    const check = checkLandstrip();
    const version = check?.ok === true ? check.version : 'unknown';
    const status = config.enabled && check?.ok === true ? 'enabled' : 'disabled';

    const lines = [
      'Sandbox Configuration',
      `  Status:         ${status}`,
      `  Project config: ${projectPath}`,
      `  Global config:  ${globalPath}`,
      `  landstrip:      ${binaryPath()} (v${version})`,
      '',
      `  Allow network:  ${config.network.allowNetwork}`,
      '',
      'Network (bash commands go through HTTP proxy):',
      `  Allow local binding: ${config.network.allowLocalBinding}`,
      `  Allow all Unix sockets: ${config.network.allowAllUnixSockets}`,
      ...(config.network.allowUnixSockets.length > 0
        ? [`  Allow Unix sockets: ${config.network.allowUnixSockets.join(', ')}`]
        : []),
      `  Allowed domains: ${config.network.allowedDomains.join(', ') || '(none)'}`,
      `  Denied domains:  ${config.network.deniedDomains.join(', ') || '(none)'}`,
      '',
      'Filesystem (bash + read/write/edit tools):',
      `  Deny Read:   ${config.filesystem.denyRead.join(', ') || '(none)'}`,
      `  Allow Read:  ${config.filesystem.allowRead.join(', ') || '(none)'}`,
      `  Allow Write: ${config.filesystem.allowWrite.join(', ') || '(none)'}`,
      `  Deny Write:  ${config.filesystem.denyWrite.join(', ') || '(none)'}`,
    ];

    return lines.join('\n');
  }

  const hooks: Hooks = {
    config: async (config) => {
      configuredShell = configuredShellPath(config);
    },

    'tool.execute.before': async (input, output) => {
      if (!isRecord(output.args)) return;

      const config = await activeConfig();
      if (!config) return;

      const effectiveAllowRead = getEffectiveAllowRead(config);
      const effectiveAllowWrite = getEffectiveAllowWrite(config);

      if (input.tool === 'bash') {
        await prepareBash(input.callID, output.args, config);
        return;
      }

      if (input.tool === 'read') {
        const path = getToolPath(output.args);
        if (path) assertReadAllowed(path, config, directory, effectiveAllowRead);
        return;
      }

      if (input.tool === 'glob' || input.tool === 'grep' || input.tool === 'list') {
        assertReadAllowed(getSearchPath(output.args), config, directory, effectiveAllowRead);
        return;
      }

      if (input.tool === 'write' || input.tool === 'edit') {
        const path = getToolPath(output.args);
        if (path) assertWriteAllowed(path, config, directory, effectiveAllowWrite);
        return;
      }

      if (input.tool === 'apply_patch')
        assertApplyPatchAllowed(output.args, config, directory, effectiveAllowWrite);
    },

    'shell.env': async (input, output) => {
      if (!input.callID) return;
      const state = activeBash.get(input.callID);
      if (!state) return;

      const envVars = proxyEnv(state.port);
      if (envVars) Object.assign(output.env, envVars);
    },

    'tool.execute.after': async (input, output) => {
      if (input.tool !== 'bash') return;

      const state = activeBash.get(input.callID);
      if (!state) {
        await cleanupBash(input.callID);
        return;
      }

      const outputText = output?.output ?? '';
      const errors = parseLandstripErrors(outputText);
      if (errors.length > 0) {
        const message = formatLandstripErrors(errors);
        await client.tui
          .showToast({
            body: { title: 'opencode-landstrip', message, variant: 'error' },
            query: { directory },
          })
          .catch(() => undefined);
        await client.app
          .log({
            body: {
              service: 'opencode-landstrip',
              level: 'error',
              message,
            },
            query: { directory },
          })
          .catch(() => undefined);
      }

      const blockedPath = extractBlockedWritePath(outputText, directory, state.originalCommand);
      if (blockedPath) {
        const config = loadConfig(directory, optionOverrides);
        if (
          !sessionAllowedWritePaths.includes(blockedPath) &&
          !matchesPattern(blockedPath, config.filesystem.allowWrite, directory) &&
          !matchesPattern(blockedPath, config.filesystem.denyWrite, directory)
        ) {
          sessionAllowedWritePaths.push(blockedPath);
          await notifyOnce(
            `write-allow:${blockedPath}`,
            `Write access granted for session: "${blockedPath}"`,
            'warning',
          );
        }
      }

      await cleanupBash(input.callID);
    },

    'command.execute.before': async (input, output) => {
      if (input.command === 'sandbox' || input.command === '/sandbox') {
        const config = loadConfig(directory, optionOverrides);
        const summary = buildConfigSummary(config);
        await client.tui
          .showToast({
            body: { title: 'Sandbox', message: summary, variant: 'info', duration: 15000 },
            query: { directory },
          })
          .catch(() => undefined);
        return;
      }

      // Check domain in user shell commands (commands starting with !)
      if (input.command.startsWith('!')) {
        const shellCommand = input.command.slice(1).trim();
        const config = await activeConfig();
        if (!config || config.network.allowNetwork) return;

        const blockedDomain = firstBlockedDomain(shellCommand, config);
        if (blockedDomain) {
          const reason =
            blockedDomain.reason === 'deniedDomains'
              ? 'is blocked by network.deniedDomains'
              : 'is not in network.allowedDomains';
          output.parts.push({
            type: 'text',
            text: `Sandbox: network access denied for "${blockedDomain.domain}" (${reason}).`,
            id: '',
            sessionID: input.sessionID,
            messageID: '',
          });
        }
      }
    },

    dispose: async () => {
      await Promise.all([...activeBash.keys()].map((callID) => cleanupBash(callID)));
    },
  };

  return hooks;
};

export default plugin;
