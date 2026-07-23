// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Hooks, Plugin, PluginInput, PluginOptions } from '@opencode-ai/plugin';

import { spawnSync } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import {
  type AddressInfo,
  BlockList,
  connect as connectNet,
  createServer,
  isIP,
  type Socket,
} from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { URL } from 'node:url';

import {
  type LandstripTrap,
  type SandboxConfig,
  type SandboxFilesystemConfig,
  controlResponseLine,
  decodeLandstripTrap,
  extractDomainsFromCommand,
  formatLandstripTraps,
  getConfigPaths,
  isRecord,
  landstripBinaryPath,
  loadConfig,
  normalizeOptions,
  parseLandstripTraps,
  permissionPatterns,
  permissionType,
  sandboxSummary,
  readDiscoveryPort,
  sessionScopeFor,
} from './shared.js';

type LandstripPolicy = {
  network: Omit<SandboxConfig['network'], 'allowedDomains' | 'deniedDomains'> & {
    httpProxyPort?: number;
  };
  filesystem: SandboxFilesystemConfig;
};

interface BashSandboxState {
  originalCommand: string;
  wrappedCommand: string;
  policyDir: string;
  port: number | null;
  stop: (() => Promise<void>) | null;
  trapServer: ReturnType<typeof createServer> | null;
  trapServerPort: number | null;
  trapLines: string[];
}

type SandboxPermissionKind = 'read' | 'write' | 'domain';

interface SandboxPermissionDecision {
  status: 'allow' | 'ask' | 'deny';
  kind: SandboxPermissionKind;
  resource: string;
  message: string;
}

type ToastVariant = 'info' | 'success' | 'warning' | 'error';

const LANDSTRIP_VERSION = [0, 17, 0] as const;
const REQUIRED_LANDSTRIP_VERSION = LANDSTRIP_VERSION.join('.');
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

function canonicalizeGlobPath(pattern: string, baseDirectory: string): string {
  const abs = expandPath(pattern, baseDirectory);
  const wildcardIndex = abs.indexOf('*');
  if (wildcardIndex === -1) return canonicalizePath(abs, baseDirectory);

  const prefixEnd = abs.lastIndexOf('/', wildcardIndex);
  const prefix = prefixEnd === 0 ? '/' : abs.slice(0, prefixEnd);
  return canonicalizePath(prefix, baseDirectory) + abs.slice(prefixEnd);
}

const globRegExpCache = new Map<string, RegExp>();

/**
 * Translates an absolute glob pattern to a regular expression using standard
 * path semantics: `**` crosses directory boundaries (and `**​/` may match zero
 * segments), while a single `*` is confined to one path segment.
 */
function globToRegExp(globPattern: string): RegExp {
  const cached = globRegExpCache.get(globPattern);
  if (cached) return cached;

  let regex = '';

  for (let i = 0; i < globPattern.length; i++) {
    const char = globPattern.charAt(i);
    if (char === '*') {
      if (globPattern.charAt(i + 1) === '*') {
        i++;
        if (globPattern.charAt(i + 1) === '/') {
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

  const result = new RegExp(`^${regex}$`);
  globRegExpCache.set(globPattern, result);
  return result;
}

// Component count of an absolute path; "/" is 0. Used to rank how specific a
// matching pattern is so the most specific allow/deny rule wins.
function pathDepth(absolutePath: string): number {
  return absolutePath.split('/').filter((segment) => segment.length > 0).length;
}

// The depth of the most specific pattern that matches `filePath`, or -1 when
// none match. A glob is anchored to the whole path, so it ranks at the path's
// own depth; a literal pattern ranks at the depth of the prefix it covers.
function matchDepth(filePath: string, patterns: string[], baseDirectory: string): number {
  const abs = canonicalizePath(filePath, baseDirectory);
  let depth = -1;

  for (const pattern of patterns) {
    if (pattern.includes('*')) {
      const absPattern = canonicalizeGlobPath(pattern, baseDirectory);
      if (globToRegExp(absPattern).test(abs)) depth = Math.max(depth, pathDepth(abs));
    } else {
      const absPattern = canonicalizePath(pattern, baseDirectory);
      const sep = absPattern.endsWith('/') ? '' : '/';
      if (abs === absPattern || abs.startsWith(absPattern + sep)) {
        depth = Math.max(depth, pathDepth(absPattern));
      }
    }
  }

  return depth;
}

function resolveFilesystemPatterns(patterns: string[], baseDirectory: string): string[] {
  return patterns.map((pattern) =>
    pattern.includes('*')
      ? canonicalizeGlobPath(pattern, baseDirectory)
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

function isDomainAllowed(domain: string, config: SandboxConfig): boolean {
  return (
    config.network.allowNetwork ||
    (!domainMatchesAny(domain, config.network.deniedDomains) &&
      domainMatchesAny(domain, config.network.allowedDomains))
  );
}

function isFilesystemAllowed(
  path: string,
  allowPatterns: string[],
  denyPatterns: string[],
  baseDirectory: string,
): boolean {
  const allowDepth = matchDepth(path, allowPatterns, baseDirectory);
  const denyDepth = matchDepth(path, denyPatterns, baseDirectory);
  return allowDepth >= 0 && allowDepth >= denyDepth;
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
  if (match?.[1]) return canonicalizePath(match[1], baseDirectory);

  // ls/cat/cp: cannot open/access/stat '/path': Permission denied
  match = output.match(
    /^[a-zA-Z0-9_-]+: cannot (?:open|access|stat|create)(?: directory)? '?([^'\n]+?)'?(?: for (?:reading|writing))?: Permission denied$/m,
  );
  if (match?.[1]) return canonicalizePath(match[1], baseDirectory);

  // Generic: cmd: /absolute/path: Permission denied or Operation not permitted
  match = output.match(
    /^[a-zA-Z0-9_-]+: (\/[^\n:]+): (?:Operation not permitted|Permission denied)$/m,
  );
  if (match?.[1]) return canonicalizePath(match[1], baseDirectory);

  // Landstrip structured trap format carrying a denied path
  const landstripTraps = parseLandstripTraps(output);
  for (const trap of landstripTraps) {
    if (trap.kind === 'filesystem') return canonicalizePath(trap.path, baseDirectory);
  }

  if (
    landstripTraps.some((trap) => trap.kind === 'filesystem' || trap.kind === 'internal') &&
    command
  ) {
    for (const candidate of extractCandidatePaths(command)) {
      const resolved = canonicalizePath(candidate, baseDirectory);
      return resolved;
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

  // Reads are interactive, so the read tool never hard-denies: a path covered by
  // allowRead at least as specifically as any denyRead is allowed silently;
  // everything else asks for approval (allow once/session/persist or reject)
  // rather than being blocked outright. denyRead still hard-applies to bash
  // through the landstrip binary policy, which has no way to prompt.
  if (
    isFilesystemAllowed(filePath, effectiveAllowRead, config.filesystem.denyRead, baseDirectory)
  ) {
    return { status: 'allow', kind: 'read', resource: filePath, message: '' };
  }

  return {
    status: 'ask',
    kind: 'read',
    resource: filePath,
    message: `Sandbox: read access requires approval for "${filePath}".`,
  };
}

function evaluateWritePermission(
  path: string,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowWrite: string[],
): SandboxPermissionDecision {
  const filePath = canonicalizePath(path, baseDirectory);
  const allowDepth = matchDepth(filePath, effectiveAllowWrite, baseDirectory);
  const denyDepth = matchDepth(filePath, config.filesystem.denyWrite, baseDirectory);

  if (denyDepth > allowDepth) {
    return {
      status: 'deny',
      kind: 'write',
      resource: filePath,
      message: `Sandbox: write access denied for "${filePath}" (denyWrite overrides allowWrite).`,
    };
  }

  if (
    isFilesystemAllowed(filePath, effectiveAllowWrite, config.filesystem.denyWrite, baseDirectory)
  ) {
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

  if (isDomainAllowed(domain, config)) {
    return { status: 'allow', kind: 'domain', resource: domain, message: '' };
  }

  return {
    status: 'ask',
    kind: 'domain',
    resource: domain,
    message: `Sandbox: network access requires approval for "${domain}" (not in network.allowedDomains).`,
  };
}

function evaluateCommandDomains(
  command: string,
  config: SandboxConfig,
): SandboxPermissionDecision[] {
  if (config.network.allowNetwork) return [];
  return extractDomainsFromCommand(command).map((domain) =>
    evaluateDomainPermission(domain, config),
  );
}

function landstripVersion(): string | null {
  const result = spawnSync(landstripBinaryPath(), ['--version'], {
    encoding: 'utf-8',
    shell: process.platform === 'win32',
  });
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
    const parsedPart = parsed[i];
    const minimumPart = minimum[i];
    if (parsedPart === undefined || minimumPart === undefined) return false;
    if (parsedPart > minimumPart) return true;
    if (parsedPart < minimumPart) return false;
  }

  return true;
}

function parseProxyPort(value: string | undefined, defaultPort: number): number | null {
  const rawPort = value ?? String(defaultPort);
  if (!/^\d+$/.test(rawPort)) return null;

  const port = Number(rawPort);
  return port >= 1 && port <= 65535 ? port : null;
}

function splitHostPort(target: string, defaultPort: number): { host: string; port: number } | null {
  const bracketMatch = target.match(/^\[([^\]]+)\](?::(.*))?$/);
  const host = bracketMatch?.[1];
  if (host) {
    const port = parseProxyPort(bracketMatch?.[2], defaultPort);
    return port === null ? null : { host, port };
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

function isPublicProxyAddress(address: string, family = isIP(address)): boolean {
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

  async function handleConnect(client: Socket, target: string, rest: Buffer): Promise<void> {
    const endpoint = splitHostPort(target, 443);
    if (!endpoint) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    if (!isDomainAllowed(endpoint.host, config)) {
      denyProxyRequest(client);
      return;
    }

    const resolved = await resolveProxyEndpoint(endpoint.host);
    let connected = false;
    const upstream = connectNet(
      { host: resolved.address, port: endpoint.port, family: resolved.family },
      () => {
        connected = true;
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pipeSockets(client, upstream, rest);
      },
    );
    upstream.on('error', () => {
      if (!connected) denyProxyRequest(client, '502 Bad Gateway');
    });
  }

  async function handleHttp(client: Socket, headerText: string, rest: Buffer): Promise<void> {
    const lines = headerText.split(/\r?\n/);
    const requestLine = lines[0];
    if (!requestLine) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    const [method, rawTarget, version] = requestLine.split(' ');

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

    if (!isDomainAllowed(url.hostname, config)) {
      denyProxyRequest(client);
      return;
    }

    const port = parseProxyPort(url.port || undefined, url.protocol === 'https:' ? 443 : 80);
    if (port === null) {
      denyProxyRequest(client, '400 Bad Request');
      return;
    }

    const path = `${url.pathname}${url.search}` || '/';
    lines[0] = `${method} ${path} ${version}`;

    const rewrittenHeader = lines
      .filter((line) => !line.toLowerCase().startsWith('proxy-connection:'))
      .join('\r\n');
    const resolved = await resolveProxyEndpoint(url.hostname);
    let connected = false;
    const upstream = connectNet({ host: resolved.address, port, family: resolved.family }, () => {
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
      const [method, target] = (firstLine ?? '').split(' ');

      const task =
        method?.toUpperCase() === 'CONNECT' && target
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

// Start a local TCP server that landstrip connects its trap fd to. Traps are
// handled in-process: query traps are answered immediately against the active
// config, and info traps are collected for post-execution error reporting.
function startTrapServer(
  effectiveAllowRead: string[],
  effectiveAllowWrite: string[],
  denyRead: string[],
  denyWrite: string[],
  baseDirectory: string,
  sessionAllowedReadPaths: Set<string>,
  sessionAllowedWritePaths: Set<string>,
  sessionAllowedTargets: Set<string>,
): Promise<{ server: ReturnType<typeof createServer>; port: number; trapLines: string[] }> {
  const trapLines: string[] = [];
  const server = createServer((trapSocket) => {
    let buffer = '';
    trapSocket.on('data', (data: Buffer) => {
      buffer += data.toString('utf8');
      let nl = buffer.indexOf('\n');
      while (nl !== -1) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        nl = buffer.indexOf('\n');
        if (line.length === 0) continue;
        let trap: LandstripTrap | null = null;
        try {
          trap = decodeLandstripTrap(JSON.parse(line));
        } catch {
          trap = null;
        }
        if (
          (trap?.kind === 'filesystem' || trap?.kind === 'network') &&
          trap.state === 'query' &&
          trap.query_id
        ) {
          const queryId = trap.query_id;
          if (trap.kind === 'filesystem') {
            const path = canonicalizePath(trap.path, baseDirectory);
            const operation = trap.operation;
            const allowed =
              operation === 'read'
                ? isFilesystemAllowed(path, effectiveAllowRead, denyRead, baseDirectory)
                : isFilesystemAllowed(path, effectiveAllowWrite, denyWrite, baseDirectory);
            if (allowed) {
              trapSocket.write(controlResponseLine(queryId, 'allow'));
            } else {
              // Auto-grant via session scope and allow so the command proceeds.
              const scope = sessionScopeFor(path, baseDirectory);
              if (operation === 'read') sessionAllowedReadPaths.add(scope);
              else sessionAllowedWritePaths.add(scope);
              trapSocket.write(controlResponseLine(queryId, 'deny'));
              trapLines.push(line);
            }
          } else if (
            trap.kind === 'network' &&
            (trap.operation === 'connect' || trap.operation === 'bind')
          ) {
            // No policy field expresses "allow this address:port" (allowedDomains
            // is hostname-based and enforced by the HTTP(S) proxy, not the broker),
            // so — matching the filesystem branch above — auto-grant, remember it
            // for the rest of the session, and surface it afterward rather than
            // hanging or hard-denying an already-approved command.
            const target = trap.target;
            if (!sessionAllowedTargets.has(target)) {
              sessionAllowedTargets.add(target);
              trapLines.push(line);
            }
            trapSocket.write(controlResponseLine(queryId, 'allow'));
          } else {
            trapLines.push(line);
          }
        } else {
          trapLines.push(line);
        }
      }
    });
    trapSocket.on('error', () => {});
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const address = server.address() as AddressInfo;
      resolve({ server, port: address.port, trapLines });
    });
  });
}

function buildWrappedCommand(
  policyPath: string,
  shell: string,
  command: string,
  trapPort: number | null,
): string {
  const baseArgs = ['-p', policyPath, ...shellArgs(shell, command)];
  const plain = [landstripBinaryPath(), ...baseArgs].map(shellQuote).join(' ');
  if (trapPort === null) return plain;

  // Connect fd 3 to the TUI's query-response socket BEFORE landstrip applies the
  // sandbox, so a denied filesystem access can be approved live instead of
  // forcing a re-run.
  //
  // /dev/tcp is a bash/ksh built-in — it does not work in zsh, dash, or fish.
  // We try the native redirect first (fast path when the host shell supports it)
  // and fall back to an explicit bash invocation that always speaks /dev/tcp.
  // If both fail (no bash, dead port, set -e in the outer shell) landstrip runs
  // without --trap-fd so the toast-notify path still works.
  const trapped = [landstripBinaryPath(), '--trap-fd', '3', ...baseArgs].map(shellQuote).join(' ');
  const bashTrap = `bash -c ${shellQuote(`exec 3<>/dev/tcp/127.0.0.1/${trapPort} 2>/dev/null && exec "$@"`)} bash ${trapped}`;
  return `{ exec 3<>/dev/tcp/127.0.0.1/${trapPort} ; } 2>/dev/null && ${trapped} || ${bashTrap} 2>/dev/null || ${plain}`;
}

function isGeneratedWrappedCommand(command: string): boolean {
  return (
    // `.includes` rather than `.startsWith`: the query-response form prefixes a
    // `{ exec 3<>/dev/tcp/...; } && ` redirect before the landstrip invocation.
    command.includes(`${shellQuote(landstripBinaryPath())} `) &&
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
      while (i < command.length) {
        if (command[i] === "'") {
          if (command[i + 1] === '\\' && command[i + 2] === "'" && command[i + 3] === "'") {
            arg += "'";
            i += 4;
            continue;
          }
          i++;
          break;
        }
        arg += command[i];
        i++;
      }
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
  const flagIdx = args.findIndex((arg, i) => i > pIdx && (arg === '-lc' || arg === '-c'));
  if (flagIdx === -1) return null;
  // The query-response form appends `|| <plain invocation>`; stop at that
  // separator so the fallback branch is not folded into the recovered command.
  const end = args.indexOf('||', flagIdx + 1);
  return (end === -1 ? args.slice(flagIdx + 1) : args.slice(flagIdx + 1, end)).join(' ');
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
    if (fileMatch?.[1]) {
      paths.push(fileMatch[1].trim());
      continue;
    }

    const moveMatch = line.match(/^\*\*\* Move to: (.+)$/);
    if (moveMatch?.[1]) paths.push(moveMatch[1].trim());
  }

  return paths;
}

function evaluateToolPermissions(
  tool: string,
  args: Record<string, unknown>,
  config: SandboxConfig,
  baseDirectory: string,
  effectiveAllowRead: string[],
  effectiveAllowWrite: string[],
): SandboxPermissionDecision[] {
  if (tool === 'read') {
    const paths = Array.isArray(args.paths)
      ? args.paths.filter((path): path is string => typeof path === 'string')
      : [getToolPath(args)].filter((path): path is string => path !== undefined);
    return paths.map((path) =>
      evaluateReadPermission(path, config, baseDirectory, effectiveAllowRead),
    );
  }

  if (tool === 'glob' || tool === 'grep' || tool === 'list') {
    return [evaluateReadPermission(getSearchPath(args), config, baseDirectory, effectiveAllowRead)];
  }

  if (tool === 'write' || tool === 'edit') {
    const path = getToolPath(args);
    return path ? [evaluateWritePermission(path, config, baseDirectory, effectiveAllowWrite)] : [];
  }

  if (tool === 'apply_patch' && typeof args.patchText === 'string') {
    return extractPatchPaths(args.patchText).map((path) =>
      evaluateWritePermission(path, config, baseDirectory, effectiveAllowWrite),
    );
  }

  if (tool === 'bash' && typeof args.command === 'string') {
    return evaluateCommandDomains(args.command, config);
  }

  return [];
}

function errorWithConfigPaths(baseDirectory: string, message: string): Error {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  return new Error(`${message}\n\nUpdate sandbox config in:\n  ${projectPath}\n  ${globalPath}`);
}

const plugin: Plugin = async ({ client, directory }: PluginInput, options?: PluginOptions) => {
  const optionOverrides = normalizeOptions(options);
  const activeBash = new Map<string, BashSandboxState>();
  const notified = new Set<string>();
  const callAllowances = new Set<string>();
  const sessionAllowedReadPaths = new Set<string>();
  const sessionAllowedWritePaths = new Set<string>();
  const sessionAllowedTargets = new Set<string>();

  function mergeAllowances(configured: string[], session: Set<string>): string[] {
    return [...configured, ...session];
  }

  function getEffectiveAllowRead(config: SandboxConfig): string[] {
    return mergeAllowances(config.filesystem.allowRead, sessionAllowedReadPaths);
  }

  function getEffectiveAllowWrite(config: SandboxConfig): string[] {
    return mergeAllowances(config.filesystem.allowWrite, sessionAllowedWritePaths);
  }
  let enabledNotified = false;
  let configuredShell: string | undefined;
  let landstripCheck: { ok: true; version: string } | { ok: false; reason: string } | undefined;

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

  function reportBlocked(decision: SandboxPermissionDecision): never {
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

  function enforcePermission(callID: string, decision: SandboxPermissionDecision): void {
    if (decision.status === 'allow' || hasCallAllowance(callID, decision)) return;
    reportBlocked(decision);
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

  function buildSandboxSummary(config: SandboxConfig): string {
    const { globalPath, projectPath } = getConfigPaths(directory);
    const report = sandboxSummary(config, globalPath, projectPath);
    return ['# Sandbox Configuration', '', report].join('\n');
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
    const config = loadConfig(directory, optionOverrides);
    if (!config.enabled) {
      await notifyOnce(
        `not-configured:${directory}`,
        'Sandbox is disabled by configuration',
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

    for (const key of callAllowances) {
      if (key.startsWith(`${callID}:`)) callAllowances.delete(key);
    }

    activeBash.delete(callID);
    if (state.stop) await state.stop().catch(() => undefined);
    if (state.trapServer) {
      await new Promise<void>((resolve) => {
        state.trapServer!.close(() => resolve());
      });
    }
    rmSync(state.policyDir, { recursive: true, force: true });
  }

  async function prepareBash(
    callID: string,
    args: Record<string, unknown>,
    config: SandboxConfig,
  ): Promise<void> {
    if (typeof args.command !== 'string') return;

    const rewriteDescription = (): void => {
      if (typeof args.description === 'string')
        args.description = landstripDescription(args.description);
    };

    const existing = activeBash.get(callID);
    if (existing) {
      if (args.command === existing.originalCommand || args.command === existing.wrappedCommand) {
        args.command = existing.wrappedCommand;
        rewriteDescription();
        return;
      }

      await cleanupBash(callID);
    }

    if (isGeneratedWrappedCommand(args.command as string)) {
      const policyMatch = (args.command as string).match(/\s'-p'\s+'([^']+)'/);
      if (policyMatch?.[1] && existsSync(policyMatch[1])) {
        rewriteDescription();
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
      network: { ...config.network },
      filesystem: {
        ...config.filesystem,
        allowRead: getEffectiveAllowRead(config),
        allowWrite: getEffectiveAllowWrite(config),
      },
    };

    if (!allowNetwork) {
      for (const decision of evaluateCommandDomains(args.command as string, effectiveConfig)) {
        if (decision.status === 'allow') continue;
        if (decision.status === 'ask' && hasCallAllowance(callID, decision)) {
          callAllowedDomains.push(decision.resource);
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

    // The TUI owns interactive query handling. Fall back to an in-process
    // broker when no TUI endpoint is available (for example, in headless mode).
    const tuiTrapPort = process.platform === 'linux' ? readDiscoveryPort(directory) : null;
    const trapServer =
      tuiTrapPort === null
        ? await startTrapServer(
            effectiveConfig.filesystem.allowRead,
            effectiveConfig.filesystem.allowWrite,
            effectiveConfig.filesystem.denyRead,
            effectiveConfig.filesystem.denyWrite,
            directory,
            sessionAllowedReadPaths,
            sessionAllowedWritePaths,
            sessionAllowedTargets,
          )
        : null;
    const trapPort = tuiTrapPort ?? trapServer?.port ?? null;

    const wrappedCommand = buildWrappedCommand(
      policy.path,
      configuredShell ?? process.env.SHELL ?? '/bin/sh',
      originalCommand,
      trapPort,
    );

    activeBash.set(callID, {
      originalCommand,
      wrappedCommand,
      policyDir: policy.dir,
      port: proxyPort,
      stop: proxy ? proxy.stop : null,
      trapServer: trapServer?.server ?? null,
      trapServerPort: trapPort,
      trapLines: trapServer?.trapLines ?? [],
    });

    args.command = wrappedCommand;
    rewriteDescription();
  }

  const hooks: Hooks = {
    config: async (config) => {
      configuredShell = configuredShellPath(config);
    },

    'permission.ask': async (input, output) => {
      const config = await activeConfig();
      if (!config) {
        output.status = 'allow';
        return;
      }

      const request = input as Record<string, unknown>;
      const permission = permissionType(request);
      const metadata = isRecord(request.metadata) ? request.metadata : {};
      const tool = isRecord(request.tool) ? request.tool : undefined;
      const callID =
        typeof request.callID === 'string'
          ? request.callID
          : typeof tool?.callID === 'string'
            ? tool.callID
            : undefined;
      const patterns = permissionPatterns(request);

      const effectiveAllowRead = getEffectiveAllowRead(config);
      const effectiveAllowWrite = getEffectiveAllowWrite(config);
      const args: Record<string, unknown> = { ...metadata };
      if (permission === 'read') args.paths = patterns;
      if (permission === 'edit') {
        args.path = typeof metadata.filepath === 'string' ? metadata.filepath : patterns[0];
      }
      if (permission === 'bash' && typeof args.command !== 'string') args.command = patterns[0];
      const decisions = evaluateToolPermissions(
        permission,
        args,
        config,
        directory,
        effectiveAllowRead,
        effectiveAllowWrite,
      );

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

      if (input.tool === 'bash') {
        await prepareBash(input.callID, output.args, config);
        return;
      }

      const decisions = evaluateToolPermissions(
        input.tool,
        output.args,
        config,
        directory,
        getEffectiveAllowRead(config),
        getEffectiveAllowWrite(config),
      );
      for (const decision of decisions) {
        enforcePermission(input.callID, decision);
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
      // Query traps were already resolved in-process by the local trap server;
      // only terminal (info) traps and trap-server-collected lines belong in
      // the after-the-fact toast.
      const serverTrapOutput = state.trapLines.join('\n');
      const combinedOutput = serverTrapOutput ? outputText + '\n' + serverTrapOutput : outputText;
      const errors = parseLandstripTraps(combinedOutput).filter(
        (trap: LandstripTrap) => !(trap.kind === 'filesystem' && trap.state === 'query'),
      );
      if (errors.length > 0) {
        const message = formatLandstripTraps(errors);
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

      const blockedPath = extractBlockedPath(outputText, directory, state.originalCommand);
      if (blockedPath) {
        let blockedOperation: 'read' | 'write' = 'read';
        for (const trap of errors) {
          if (trap.kind === 'filesystem') {
            blockedOperation = trap.operation;
            break;
          }
        }
        const scope = sessionScopeFor(blockedPath, directory);
        if (blockedOperation === 'read') sessionAllowedReadPaths.add(scope);
        else sessionAllowedWritePaths.add(scope);
        await notifyOnce(
          `blocked:${blockedPath}`,
          `Sandbox blocked ${blockedOperation} to "${blockedPath}". Added "${scope}" to session allowlist; retry the command.`,
          'warning',
        );
      }

      await cleanupBash(input.callID);
    },

    'command.execute.before': async (input, output) => {
      // OpenCode strips the leading slash before dispatching commands, so the
      // hook receives the bare name ("sandbox"); accept both forms so the
      // handler matches whether invoked by name or via tui.executeCommand.
      const command = input.command.trim().replace(/^\//, '');
      if (command === 'sandbox') {
        const config = loadConfig(directory, optionOverrides);
        pushCommandText(input, output, buildSandboxSummary(config));
        await client.tui
          ?.showToast?.({
            body: { title: 'Sandbox', message: `Config loaded for ${directory}`, variant: 'info' },
          })
          ?.catch?.(() => undefined);
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
          if (readDecision.status === 'deny') reportBlocked(readDecision);

          const writeDecision = evaluateWritePermission(
            path,
            config,
            directory,
            effectiveAllowWrite,
          );
          if (writeDecision.status === 'deny') reportBlocked(writeDecision);
        }

        for (const decision of evaluateCommandDomains(shellCommand, config)) {
          if (decision.status !== 'allow') reportBlocked(decision);
        }
      }
    },

    dispose: async () => {
      await Promise.all([...activeBash.keys()].map((callID) => cleanupBash(callID)));
    },
  };

  return hooks;
};

export default { server: plugin };
