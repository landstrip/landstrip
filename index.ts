// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { Hooks, Plugin, PluginInput, PluginOptions } from '@opencode-ai/plugin';

import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { type AddressInfo, connect as connectNet, createServer, type Socket } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { URL } from 'node:url';

import {
  type SandboxConfig,
  type SandboxFilesystemConfig,
  extractDomainsFromCommand,
  getConfigPaths,
  isRecord,
  landstripBinaryPath,
  loadConfig,
  normalizeOptions,
} from './shared.js';

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

type LandstripTrap =
  | { kind: 'Filesystem'; operation: 'read' | 'write'; path: string; mechanism: string }
  | { kind: 'Network'; operation: string; target: string; mechanism: string }
  | { kind: 'Launch'; program: string; message: string }
  | { kind: 'Usage'; message: string }
  | { kind: 'Internal'; fields: Record<string, string> };

interface BashSandboxState {
  originalCommand: string;
  wrappedCommand: string;
  policyDir: string;
  port: number | null;
  stop: (() => Promise<void>) | null;
}

type SandboxPermissionKind = 'read' | 'write' | 'domain';

interface SandboxPermissionDecision {
  status: 'allow' | 'ask' | 'deny';
  kind: SandboxPermissionKind;
  resource: string;
  message: string;
}

type ToastVariant = 'info' | 'success' | 'warning' | 'error';

const LANDSTRIP_VERSION = [0, 14, 5] as const;
const REQUIRED_LANDSTRIP_VERSION = LANDSTRIP_VERSION.join('.');
const LANDSTRIP_OPERATIONS = new Set<'read' | 'write'>(['read', 'write']);
const SUPPORTED_PLATFORMS = new Set<NodeJS.Platform>(['linux', 'darwin', 'win32']);

function isLandstripOperation(value: unknown): value is 'read' | 'write' {
  return typeof value === 'string' && LANDSTRIP_OPERATIONS.has(value as 'read' | 'write');
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

/**
 * Translates an absolute glob pattern to a regular expression using standard
 * path semantics: `**` crosses directory boundaries (and `**​/` may match zero
 * segments), while a single `*` is confined to one path segment.
 */
function globToRegExp(globPattern: string): RegExp {
  let regex = '';

  for (let i = 0; i < globPattern.length; i++) {
    const char = globPattern[i];
    if (char === '*') {
      if (globPattern[i + 1] === '*') {
        i++;
        if (globPattern[i + 1] === '/') {
          i++;
          regex += '(?:.*/)?';
        } else {
          regex += '.*';
        }
      } else {
        regex += '[^/]*';
      }
    } else if (/[.+^${}()|[\]\\]/.test(char)) {
      regex += `\\${char}`;
    } else {
      regex += char;
    }
  }

  return new RegExp(`^${regex}$`);
}

function matchesPattern(filePath: string, patterns: string[], baseDirectory: string): boolean {
  const abs = canonicalizePath(filePath, baseDirectory);

  return patterns.some((pattern) => {
    const absPattern = pattern.includes('*')
      ? expandPath(pattern, baseDirectory)
      : canonicalizePath(pattern, baseDirectory);

    if (pattern.includes('*')) {
      return globToRegExp(absPattern).test(abs);
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

  // Landstrip structured trap format carrying a denied path
  const landstripErrors = parseLandstripErrors(output);
  for (const trap of landstripErrors) {
    if (trap.kind === 'Filesystem') return normalizeBlockedPath(trap.path, baseDirectory);
    if (trap.kind === 'Internal' && trap.fields.file) {
      return normalizeBlockedPath(trap.fields.file, baseDirectory);
    }
  }

  // If landstrip reported a trap but without a path, try to
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

function evaluateReadPermission(
  path: string,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowRead: string[],
): SandboxPermissionDecision {
  const filePath = canonicalizePath(path, baseDirectory);

  if (isBlockedByDenyRead(filePath, config, baseDirectory)) {
    return {
      status: 'deny',
      kind: 'read',
      resource: filePath,
      message: `Sandbox: read access denied for "${filePath}" (denyRead overrides allowRead).`,
    };
  }

  if (!shouldPromptForRead(filePath, effectiveAllowRead, baseDirectory)) {
    return { status: 'allow', kind: 'read', resource: filePath, message: '' };
  }

  return {
    status: 'ask',
    kind: 'read',
    resource: filePath,
    message: `Sandbox: read access requires approval for "${filePath}" (not in filesystem.allowRead).`,
  };
}

function evaluateWritePermission(
  path: string,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowWrite: string[],
): SandboxPermissionDecision {
  const filePath = canonicalizePath(path, baseDirectory);

  if (matchesPattern(filePath, config.filesystem.denyWrite, baseDirectory)) {
    return {
      status: 'deny',
      kind: 'write',
      resource: filePath,
      message: `Sandbox: write access denied for "${filePath}" (in filesystem.denyWrite).`,
    };
  }

  if (!shouldPromptForWrite(filePath, effectiveAllowWrite, baseDirectory)) {
    return { status: 'allow', kind: 'write', resource: filePath, message: '' };
  }

  return {
    status: 'ask',
    kind: 'write',
    resource: filePath,
    message: `Sandbox: write access requires approval for "${filePath}" (not in filesystem.allowWrite).`,
  };
}

function evaluateDomainPermission(
  domain: string,
  config: SandboxConfig,
): SandboxPermissionDecision {
  if (config.network.allowNetwork) {
    return { status: 'allow', kind: 'domain', resource: domain, message: '' };
  }

  if (domainMatchesAny(domain, config.network.deniedDomains)) {
    return {
      status: 'deny',
      kind: 'domain',
      resource: domain,
      message: `Sandbox: network access denied for "${domain}" (is blocked by network.deniedDomains).`,
    };
  }

  if (domainMatchesAny(domain, config.network.allowedDomains)) {
    return { status: 'allow', kind: 'domain', resource: domain, message: '' };
  }

  return {
    status: 'ask',
    kind: 'domain',
    resource: domain,
    message: `Sandbox: network access requires approval for "${domain}" (not in network.allowedDomains).`,
  };
}

function landstripVersion(): string | null {
  const result = spawnSync(landstripBinaryPath(), ['--version'], { encoding: 'utf-8' });
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

function decodeLandstripTrap(value: unknown): LandstripTrap | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length !== 1) return null;
  const [kind, payload] = entries[0];

  switch (kind) {
    case 'Filesystem': {
      if (!Array.isArray(payload)) return null;
      const [operation, path, mechanism] = payload;
      if (!isLandstripOperation(operation) || typeof path !== 'string') return null;
      return { kind, operation, path, mechanism: typeof mechanism === 'string' ? mechanism : '' };
    }
    case 'Network': {
      if (!Array.isArray(payload)) return null;
      const [operation, target, mechanism] = payload;
      if (typeof operation !== 'string' || typeof target !== 'string') return null;
      return { kind, operation, target, mechanism: typeof mechanism === 'string' ? mechanism : '' };
    }
    case 'Launch': {
      if (!Array.isArray(payload)) return null;
      const [program, message] = payload;
      if (typeof program !== 'string') return null;
      return { kind, program, message: typeof message === 'string' ? message : '' };
    }
    case 'Usage': {
      if (typeof payload !== 'string') return null;
      return { kind, message: payload };
    }
    case 'Internal': {
      if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null;
      const fields: Record<string, string> = {};
      for (const [key, val] of Object.entries(payload as Record<string, unknown>)) {
        fields[key] = typeof val === 'string' ? val : JSON.stringify(val);
      }
      return { kind, fields };
    }
    default:
      return null;
  }
}

function parseLandstripErrors(output: string): LandstripTrap[] {
  const traps: LandstripTrap[] = [];

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed[0] !== '{') continue;

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }

    const trap = decodeLandstripTrap(parsed);
    if (trap) traps.push(trap);
  }

  return traps;
}

function formatLandstripTrap(trap: LandstripTrap): string {
  switch (trap.kind) {
    case 'Filesystem':
      return `landstrip: filesystem ${trap.operation} denied (${trap.path})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'Network':
      return `landstrip: network ${trap.operation} denied (${trap.target})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'Launch':
      return `landstrip: launch failed (${trap.program})${trap.message ? `: ${trap.message}` : ''}`;
    case 'Usage':
      return `landstrip: usage error: ${trap.message}`;
    case 'Internal': {
      const detail = Object.entries(trap.fields)
        .map(([key, val]) => `${key}: ${val}`)
        .join(', ');
      return `landstrip: internal error${detail ? ` (${detail})` : ''}`;
    }
  }
}

function formatLandstripErrors(traps: LandstripTrap[]): string {
  return traps.map(formatLandstripTrap).join('\n');
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
  const dir = mkdtempSync(join(tmpdir(), 'opencode-landstrip-'));
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

    let connected = false;
    const upstream = connectNet(endpoint.port, endpoint.host, () => {
      connected = true;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      pipeSockets(client, upstream, rest);
    });
    upstream.on('error', () => {
      if (!connected) denyProxyRequest(client, '502 Bad Gateway');
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
    let connected = false;
    const upstream = connectNet(port, url.hostname, () => {
      connected = true;
      upstream.write(`${rewrittenHeader}\r\n\r\n`);
      pipeSockets(client, upstream, rest);
    });
    upstream.on('error', () => {
      if (!connected) denyProxyRequest(client, '502 Bad Gateway');
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
        if (buffered.length > 65536) {
          client.removeAllListeners('data');
          client.pause();
          denyProxyRequest(client, '431 Request Header Fields Too Large');
        }
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

  return [landstripBinaryPath(), ...args].map(shellQuote).join(' ');
}

function isGeneratedWrappedCommand(command: string): boolean {
  return (
    command.startsWith(`${shellQuote(landstripBinaryPath())} `) &&
    command.includes(` ${shellQuote('-p')} `) &&
    command.includes('opencode-landstrip-')
  );
}

function landstripDescription(description: string): string {
  return description.endsWith(' (landstrip)') ? description : `${description} (landstrip)`;
}

function splitShellQuotedArgs(command: string): string[] {
  const args: string[] = [];
  let i = 0;
  while (i < command.length) {
    while (i < command.length && command[i] === ' ') i++;
    if (i >= command.length) break;
    if (command[i] === "'") {
      i++;
      let arg = '';
      while (i < command.length && command[i] !== "'") {
        arg += command[i];
        i++;
      }
      if (i < command.length) i++;
      args.push(arg);
    } else {
      let arg = '';
      while (i < command.length && command[i] !== ' ') {
        arg += command[i];
        i++;
      }
      args.push(arg);
    }
  }
  return args;
}

function extractOriginalCommand(wrappedCommand: string): string | null {
  const args = splitShellQuotedArgs(wrappedCommand);
  const pIdx = args.indexOf('-p');
  if (pIdx === -1 || pIdx + 3 >= args.length) return null;
  const flagIdx = pIdx + 3;
  const flag = args[flagIdx];
  if (flag !== '-lc' && flag !== '-c') return null;
  return args.slice(flagIdx + 1).join(' ');
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

const plugin: Plugin = async ({ client, directory }: PluginInput, options?: PluginOptions) => {
  const optionOverrides = normalizeOptions(options);
  const activeBash = new Map<string, BashSandboxState>();
  const notified = new Set<string>();
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];
  const sessionAllowedDomains: string[] = [];
  const callAllowances = new Set<string>();
  let enabledNotified = false;
  let sandboxDisabled = false;
  let configuredShell: string | undefined;
  let landstripCheck: { ok: true; version: string } | { ok: false; reason: string } | undefined;

  function getEffectiveAllowRead(config: SandboxConfig): string[] {
    return [...config.filesystem.allowRead, ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(config: SandboxConfig): string[] {
    return [...config.filesystem.allowWrite, ...sessionAllowedWritePaths];
  }

  function getEffectiveAllowedDomains(config: SandboxConfig): string[] {
    return [...config.network.allowedDomains, ...sessionAllowedDomains];
  }

  function allowanceKey(callID: string, kind: SandboxPermissionKind, resource: string): string {
    return `${callID}:${kind}:${resource}`;
  }

  function rememberCallAllowance(
    callID: string | undefined,
    decision: SandboxPermissionDecision,
  ): void {
    if (!callID || decision.status === 'deny') return;
    callAllowances.add(allowanceKey(callID, decision.kind, decision.resource));
  }

  function hasCallAllowance(callID: string, decision: SandboxPermissionDecision): boolean {
    return callAllowances.has(allowanceKey(callID, decision.kind, decision.resource));
  }

  function enforcePermission(callID: string, decision: SandboxPermissionDecision): void {
    if (decision.status === 'allow' || hasCallAllowance(callID, decision)) return;
    client.tui
      ?.showToast?.({
        body: {
          title: 'Sandbox blocked',
          message: decision.message.slice(0, 120),
          variant: 'error',
        },
      })
      ?.catch?.(() => undefined);
    throw errorWithConfigPaths(directory, decision.message);
  }

  function pushCommandText(
    input: { sessionID: string },
    output: { parts: unknown[] },
    text: string,
  ): void {
    output.parts.push({
      type: 'text',
      text,
      id: '',
      sessionID: input.sessionID,
      messageID: '',
    });
  }

  function sandboxSummary(config: SandboxConfig): string {
    const { globalPath, projectPath } = getConfigPaths(directory);
    const networkMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';
    const allowed = getEffectiveAllowedDomains(config).join(', ') || '(none)';
    const denied = config.network.deniedDomains.join(', ') || '(none)';
    const denyRead = config.filesystem.denyRead.join(', ') || '(none)';
    const allowRead = getEffectiveAllowRead(config).join(', ') || '(none)';
    const allowWrite = getEffectiveAllowWrite(config).join(', ') || '(none)';
    const denyWrite = config.filesystem.denyWrite.join(', ') || '(none)';

    return [
      '# Sandbox Configuration',
      '',
      `Status: ${sandboxDisabled ? 'disabled for this session' : 'active'}`,
      `landstrip package binary: ${landstripBinaryPath()}`,
      '',
      'Config files:',
      `- project: ${projectPath}`,
      `- global: ${globalPath}`,
      '',
      `Network (${networkMode}):`,
      `- allow network: ${config.network.allowNetwork ? 'yes' : 'no'}`,
      `- allowed: ${allowed}`,
      `- denied: ${denied}`,
      '',
      'Filesystem:',
      `- deny read: ${denyRead}`,
      `- allow read: ${allowRead}`,
      `- allow write: ${allowWrite}`,
      `- deny write: ${denyWrite}`,
    ].join('\n');
  }

  client.app
    ?.log?.({
      body: {
        service: 'opencode-landstrip',
        level: 'info',
        message: `plugin loaded for ${directory}`,
      },
      query: { directory },
    })
    ?.catch?.(() => undefined);

  client.tui
    ?.showToast?.({
      body: {
        title: 'Sandbox',
        message: `Loaded for ${directory}`,
        variant: 'info',
        duration: 5000,
      },
    })
    ?.catch?.(() => undefined);

  const notifyGate = new Map<string, Promise<void>>();

  async function notifyOnce(key: string, message: string, variant: ToastVariant): Promise<void> {
    if (notified.has(key)) return;
    const pending = notifyGate.get(key);
    if (pending) return pending;

    const promise = (async () => {
      notified.add(key);

      await client.tui
        ?.showToast?.({
          body: { title: 'opencode-landstrip', message, variant },
          query: { directory },
        })
        ?.catch?.(() => undefined);

      await client.app
        ?.log?.({
          body: {
            service: 'opencode-landstrip',
            level: variant === 'error' ? 'error' : variant === 'warning' ? 'warn' : 'info',
            message,
          },
          query: { directory },
        })
        ?.catch?.(() => undefined);

      notifyGate.delete(key);
    })();

    notifyGate.set(key, promise);
    return promise;
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

    let version: string | null;
    try {
      version = landstripVersion();
    } catch (error) {
      landstripCheck = {
        ok: false,
        reason: error instanceof Error ? error.message : String(error),
      };
      return landstripCheck;
    }

    if (!version) {
      landstripCheck = {
        ok: false,
        reason: `landstrip was not found. Reinstall with: npm install @landstrip/landstrip`,
      };
      return landstripCheck;
    }

    if (!hasMinimumVersion(version, LANDSTRIP_VERSION)) {
      landstripCheck = {
        ok: false,
        reason: `landstrip ${REQUIRED_LANDSTRIP_VERSION} or newer is required; found: ${version}`,
      };
      return landstripCheck;
    }

    landstripCheck = { ok: true, version };
    return landstripCheck;
  }

  async function activeConfig(): Promise<SandboxConfig | null> {
    if (sandboxDisabled) return null;

    const config = loadConfig(directory, optionOverrides);
    if (!config.enabled) {
      await notifyOnce(
        `not-configured:${directory}`,
        'Sandbox is not configured — no sandbox.json5 found',
        'info',
      );
      return null;
    }

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

    if (isGeneratedWrappedCommand(args.command as string)) {
      const policyMatch = (args.command as string).match(/\s'-p'\s+'([^']+)'/);
      if (policyMatch && existsSync(policyMatch[1])) {
        if (typeof args.description === 'string')
          args.description = landstripDescription(args.description);
        return;
      }
      if (activeBash.has(callID)) await cleanupBash(callID);
      const original = extractOriginalCommand(args.command as string);
      if (original) {
        args.command = original;
      }
    }

    const allowNetwork = config.network.allowNetwork;
    const callAllowedDomains: string[] = [];
    const effectiveConfig = {
      ...config,
      network: { ...config.network, allowedDomains: getEffectiveAllowedDomains(config) },
    };

    if (!allowNetwork) {
      for (const domain of extractDomainsFromCommand(args.command as string)) {
        const decision = evaluateDomainPermission(domain, effectiveConfig);
        if (decision.status === 'allow') continue;
        if (decision.status === 'ask' && hasCallAllowance(callID, decision)) {
          callAllowedDomains.push(domain);
          continue;
        }
        throw errorWithConfigPaths(directory, decision.message);
      }
    }

    if (callAllowedDomains.length > 0) {
      effectiveConfig.network = {
        ...effectiveConfig.network,
        allowedDomains: [...effectiveConfig.network.allowedDomains, ...callAllowedDomains],
      };
    }

    const proxy = allowNetwork ? null : await startProxy(effectiveConfig);
    const proxyPort = proxy ? proxy.port : null;
    let policy: { dir: string; path: string };

    try {
      policy = writePolicyFile(effectiveConfig, directory, proxyPort);
    } catch (error) {
      if (proxy) await proxy.stop().catch(() => undefined);
      throw error;
    }

    const originalCommand = args.command as string;
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

  const hooks: Hooks = {
    config: async (config) => {
      configuredShell = configuredShellPath(config);
    },

    'permission.ask': async (input, output) => {
      const config = await activeConfig();
      if (!config) return;

      const request = input as Record<string, unknown>;
      const permission =
        typeof request.type === 'string'
          ? request.type
          : typeof request.permission === 'string'
            ? request.permission
            : typeof request.action === 'string'
              ? request.action
              : '';
      const metadata = isRecord(request.metadata) ? request.metadata : {};
      const tool = isRecord(request.tool) ? request.tool : undefined;
      const callID =
        typeof request.callID === 'string'
          ? request.callID
          : typeof tool?.callID === 'string'
            ? tool.callID
            : undefined;
      const patterns = Array.isArray(request.patterns)
        ? request.patterns.filter((item): item is string => typeof item === 'string')
        : typeof request.pattern === 'string'
          ? [request.pattern]
          : Array.isArray(request.resources)
            ? request.resources.filter((item): item is string => typeof item === 'string')
            : [];

      const decisions: SandboxPermissionDecision[] = [];
      const effectiveAllowRead = getEffectiveAllowRead(config);
      const effectiveAllowWrite = getEffectiveAllowWrite(config);

      if (permission === 'read') {
        for (const pattern of patterns) {
          decisions.push(evaluateReadPermission(pattern, config, directory, effectiveAllowRead));
        }
      }

      if (permission === 'glob' || permission === 'grep' || permission === 'list') {
        const searchPath = typeof metadata.path === 'string' ? metadata.path : '.';
        decisions.push(evaluateReadPermission(searchPath, config, directory, effectiveAllowRead));
      }

      if (permission === 'edit') {
        const filepath =
          typeof metadata.filepath === 'string'
            ? metadata.filepath
            : patterns.length === 1
              ? patterns[0]
              : undefined;
        if (filepath) {
          decisions.push(evaluateWritePermission(filepath, config, directory, effectiveAllowWrite));
        }
      }

      if (permission === 'bash') {
        const command = typeof metadata.command === 'string' ? metadata.command : patterns[0];
        if (typeof command === 'string' && !config.network.allowNetwork) {
          for (const domain of extractDomainsFromCommand(command)) {
            decisions.push(evaluateDomainPermission(domain, config));
          }
        }
      }

      const decision =
        decisions.find((item) => item.status === 'deny') ??
        decisions.find((item) => item.status === 'ask');
      if (!decision) return;

      output.status = decision.status;
      rememberCallAllowance(callID, decision);
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
        if (path)
          enforcePermission(
            input.callID,
            evaluateReadPermission(path, config, directory, effectiveAllowRead),
          );
        return;
      }

      if (input.tool === 'glob' || input.tool === 'grep' || input.tool === 'list') {
        enforcePermission(
          input.callID,
          evaluateReadPermission(getSearchPath(output.args), config, directory, effectiveAllowRead),
        );
        return;
      }

      if (input.tool === 'write' || input.tool === 'edit') {
        const path = getToolPath(output.args);
        if (path)
          enforcePermission(
            input.callID,
            evaluateWritePermission(path, config, directory, effectiveAllowWrite),
          );
        return;
      }

      if (input.tool === 'apply_patch' && typeof output.args.patchText === 'string') {
        for (const path of extractPatchPaths(output.args.patchText)) {
          enforcePermission(
            input.callID,
            evaluateWritePermission(path, config, directory, effectiveAllowWrite),
          );
        }
      }
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
          ?.showToast?.({
            body: { title: 'opencode-landstrip', message, variant: 'error' },
            query: { directory },
          })
          ?.catch?.(() => undefined);
        await client.app
          ?.log?.({
            body: {
              service: 'opencode-landstrip',
              level: 'error',
              message,
            },
            query: { directory },
          })
          ?.catch?.(() => undefined);
      }

      const blockedPath = extractBlockedWritePath(outputText, directory, state.originalCommand);
      if (blockedPath) {
        await notifyOnce(
          `blocked:${blockedPath}`,
          `Sandbox blocked access to "${blockedPath}". Approve the related OpenCode permission prompt and retry if needed.`,
          'warning',
        );
      }

      await cleanupBash(input.callID);
    },

    'command.execute.before': async (input, output) => {
      if (input.command.trim() === '/sandbox') {
        const config = loadConfig(directory, optionOverrides);
        pushCommandText(input, output, sandboxSummary(config));
        await client.tui
          ?.showToast?.({
            body: { title: 'Sandbox', message: `Config loaded for ${directory}`, variant: 'info' },
          })
          ?.catch?.(() => undefined);
        return;
      }

      if (input.command.trim() === '/sandbox-disable') {
        if (sandboxDisabled) {
          pushCommandText(
            input,
            output,
            'Sandbox is already disabled. Use /sandbox-enable to re-enable.',
          );
          return;
        }
        sandboxDisabled = true;
        pushCommandText(
          input,
          output,
          'Sandbox disabled for this session. Use /sandbox-enable to re-enable.',
        );
        await client.tui
          ?.showToast?.({
            body: {
              title: 'Sandbox',
              message: 'Sandbox disabled for this session. Use /sandbox-enable to re-enable.',
              variant: 'warning',
            },
          })
          ?.catch?.(() => undefined);
        return;
      }

      if (input.command.trim() === '/sandbox-enable') {
        if (!sandboxDisabled) {
          pushCommandText(
            input,
            output,
            'Sandbox is already enabled. Use /sandbox-disable to pause.',
          );
          return;
        }
        sandboxDisabled = false;
        const config = await activeConfig();
        if (!config) {
          pushCommandText(
            input,
            output,
            'Sandbox re-enabled but no sandbox.json5 found — no rules active.\nCreate sandbox.json5 to enforce sandboxing.',
          );
          await client.tui
            ?.showToast?.({
              body: {
                title: 'Sandbox',
                message: 'Sandbox re-enabled but no sandbox.json5 found — no rules active.',
                variant: 'warning',
              },
            })
            ?.catch?.(() => undefined);
        } else {
          pushCommandText(input, output, 'Sandbox re-enabled.');
          await client.tui
            ?.showToast?.({
              body: { title: 'Sandbox', message: 'Sandbox re-enabled.', variant: 'success' },
            })
            ?.catch?.(() => undefined);
        }
        return;
      }

      // Check domain and filesystem in user shell commands (commands starting with !)
      if (input.command.startsWith('!')) {
        const shellCommand = input.command.slice(1).trim();
        const config = await activeConfig();
        if (!config) return;

        const effectiveAllowRead = getEffectiveAllowRead(config);
        const effectiveAllowWrite = getEffectiveAllowWrite(config);

        for (const path of extractCandidatePaths(shellCommand)) {
          const readDecision = evaluateReadPermission(path, config, directory, effectiveAllowRead);
          if (readDecision.status === 'deny') {
            client.tui
              ?.showToast?.({
                body: {
                  title: 'Sandbox blocked',
                  message: readDecision.message.slice(0, 120),
                  variant: 'error',
                },
              })
              ?.catch?.(() => undefined);
            throw errorWithConfigPaths(directory, readDecision.message);
          }

          const writeDecision = evaluateWritePermission(
            path,
            config,
            directory,
            effectiveAllowWrite,
          );
          if (writeDecision.status === 'deny') {
            client.tui
              ?.showToast?.({
                body: {
                  title: 'Sandbox blocked',
                  message: writeDecision.message.slice(0, 120),
                  variant: 'error',
                },
              })
              ?.catch?.(() => undefined);
            throw errorWithConfigPaths(directory, writeDecision.message);
          }
        }

        if (!config.network.allowNetwork) {
          const effectiveConfig = {
            ...config,
            network: { ...config.network, allowedDomains: getEffectiveAllowedDomains(config) },
          };
          const blockedDomain = firstBlockedDomain(shellCommand, effectiveConfig);
          if (blockedDomain) {
            const reason =
              blockedDomain.reason === 'deniedDomains'
                ? 'is blocked by network.deniedDomains'
                : 'is not in network.allowedDomains';
            client.tui
              ?.showToast?.({
                body: {
                  title: 'Sandbox blocked',
                  message: `Network access denied for "${blockedDomain.domain}"`,
                  variant: 'error',
                },
              })
              ?.catch?.(() => undefined);
            throw errorWithConfigPaths(
              directory,
              `Sandbox: network access denied for "${blockedDomain.domain}" (${reason}).`,
            );
          }
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
