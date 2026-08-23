// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Hooks, Plugin, PluginInput, PluginOptions } from '@opencode-ai/plugin';

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { type AddressInfo, connect as connectNet, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { startFilterProxy } from '@landstrip/landstrip-api/proxy';

import {
  type LandstripTrap,
  type SandboxConfig,
  type SandboxFilesystemConfig,
  allowsAllDomains,
  canonicalizeGlobPattern,
  canonicalizePath,
  controlResponseLine,
  decodeLandstripTrap,
  domainMatchesAny,
  extractDomainsFromCommand,
  formatLandstripTraps,
  getConfigPaths,
  globToRegExp,
  isRecord,
  landstripBinaryPath,
  loadConfig,
  normalizeOptions,
  normalizePathSeparators,
  parseLandstripTraps,
  permissionPatterns,
  permissionType,
  readDiscoveryPort,
  trapSessionHelloLine,
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
  sessionID: string | undefined;
  policyDir: string;
  port: number | null;
  proxyToken: string | null;
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
const DISCOVERY_CONNECT_TIMEOUT_MS = 250;

function configuredShellPath(config: unknown): string | undefined {
  if (!isRecord(config)) return undefined;
  return typeof config.shell === 'string' ? config.shell : undefined;
}

function normalizePathForMatch(filePath: string): string {
  return process.platform === 'win32' ? normalizePathSeparators(filePath).toLowerCase() : filePath;
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
  const abs = normalizePathForMatch(canonicalizePath(filePath, baseDirectory));
  let depth = -1;

  for (const pattern of patterns) {
    if (pattern.includes('*')) {
      const absPattern = normalizePathForMatch(canonicalizeGlobPattern(pattern, baseDirectory));
      if (globToRegExp(absPattern).test(abs)) depth = Math.max(depth, pathDepth(abs));
    } else {
      const absPattern = normalizePathForMatch(canonicalizePath(pattern, baseDirectory));
      const separator = absPattern.endsWith('/') ? '' : '/';
      if (abs === absPattern || abs.startsWith(absPattern + separator)) {
        depth = Math.max(depth, pathDepth(absPattern));
      }
    }
  }

  return depth;
}

function resolveFilesystemPatterns(patterns: string[], baseDirectory: string): string[] {
  return patterns.map((pattern) =>
    pattern.includes('*')
      ? canonicalizeGlobPattern(pattern, baseDirectory)
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
    const parsedPart = parsed[i];
    const minimumPart = minimum[i];
    if (parsedPart === undefined || minimumPart === undefined) return false;
    if (parsedPart > minimumPart) return true;
    if (parsedPart < minimumPart) return false;
  }

  return true;
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

function proxyEnv(
  port: number | null,
  proxyToken?: string | null,
): Record<string, string> | undefined {
  if (port === null) return undefined;
  const credentials = proxyToken ? `landstrip:${proxyToken}@` : '';
  const url = `http://${credentials}127.0.0.1:${port}`;

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
              trapSocket.write(controlResponseLine(queryId, 'deny'));
              trapLines.push(line);
            }
          } else if (
            trap.kind === 'network' &&
            (trap.operation === 'connect' || trap.operation === 'bind')
          ) {
            trapSocket.write(controlResponseLine(queryId, 'deny'));
            trapLines.push(line);
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

function trapPortAcceptsConnections(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connectNet({ host: '127.0.0.1', port });
    let settled = false;
    let timer: NodeJS.Timeout;
    const finish = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(ok);
    };
    timer = setTimeout(() => finish(false), DISCOVERY_CONNECT_TIMEOUT_MS);

    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

async function readLiveDiscoveryPort(baseDirectory: string): Promise<number | null> {
  const port = readDiscoveryPort(baseDirectory);
  if (port === null) return null;
  return (await trapPortAcceptsConnections(port)) ? port : null;
}

function buildWrappedCommand(
  policyPath: string,
  shell: string,
  command: string,
  trapPort: number | null,
  sessionID?: string,
): string {
  const baseArgs = ['run', '-p', policyPath, '--', ...shellArgs(shell, command)];
  const plain = [landstripBinaryPath(), ...baseArgs].map(shellQuote).join(' ');
  if (trapPort === null) return plain;

  // Open fd 3 before landstrip starts the command. The wrapper must never use
  // the command's exit status to select a fallback: by then the command may
  // already have changed the workspace. A failed socket setup therefore stops
  // without invoking landstrip, while every started command runs exactly once.
  const trapped = [
    landstripBinaryPath(),
    'run',
    '--trap-fd',
    '3',
    '-p',
    policyPath,
    '--',
    ...shellArgs(shell, command),
  ]
    .map(shellQuote)
    .join(' ');
  const identifySession = sessionID
    ? ` && printf '%s' ${shellQuote(trapSessionHelloLine(sessionID))} >&3`
    : '';
  const openTrap = `exec 3<>/dev/tcp/127.0.0.1/${trapPort}${identifySession} && exec "$@"`;
  return `bash -c ${shellQuote(openTrap)} bash ${trapped}`;
}

function isGeneratedWrappedCommand(command: string): boolean {
  return (
    // `.includes` rather than `.startsWith`: the query-response form prefixes
    // the landstrip invocation with a small bash fd-setup wrapper.
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
  // Old query-response wrappers appended `|| <fallback>`; stop there so
  // recovering an expired wrapper never folds a fallback into the command.
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
    const paths = Array.isArray(args.paths)
      ? args.paths.filter((path): path is string => typeof path === 'string')
      : [getToolPath(args)].filter((path): path is string => path !== undefined);
    return paths.map((path) =>
      evaluateWritePermission(path, config, baseDirectory, effectiveAllowWrite),
    );
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
  let enabledNotified = false;
  let configuredShell: string | undefined;
  let landstripCheck: { ok: true; version: string } | { ok: false; reason: string } | undefined;

  function allowanceKey(callID: string, kind: SandboxPermissionKind, resource: string): string {
    return `${callID}:${kind}:${resource}`;
  }

  function rememberCallAllowances(
    callID: string | undefined,
    approvals: readonly SandboxPermissionDecision[],
  ): void {
    if (!callID) return;
    for (const approval of approvals) {
      callAllowances.add(allowanceKey(callID, approval.kind, approval.resource));
    }
  }

  function clearCallAllowances(callID: string): void {
    for (const key of callAllowances) {
      if (key.startsWith(`${callID}:`)) callAllowances.delete(key);
    }
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
        reason: `landstrip was not found. Reinstall with: npm install @landstrip/landstrip-api`,
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
      const reason = check?.reason ?? 'Unknown Landstrip installation error';
      await notifyOnce(`broken-installation:${reason}`, reason, 'error');
      throw new Error(`Broken @landstrip/landstrip-api installation: ${reason}`);
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
    clearCallAllowances(callID);
    const state = activeBash.get(callID);
    if (!state) return;

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
    sessionID: string | undefined,
    args: Record<string, unknown>,
    config: SandboxConfig,
  ): Promise<void> {
    if (typeof args.command !== 'string') return;
    const normalizedSessionID = sessionID?.trim() || undefined;

    const rewriteDescription = (): void => {
      if (typeof args.description === 'string')
        args.description = landstripDescription(args.description);
    };

    const existing = activeBash.get(callID);
    if (existing) {
      if (
        existing.sessionID === normalizedSessionID &&
        (args.command === existing.originalCommand || args.command === existing.wrappedCommand)
      ) {
        args.command = existing.wrappedCommand;
        rewriteDescription();
        return;
      }

      await cleanupBash(callID);
    }

    if (isGeneratedWrappedCommand(args.command as string)) {
      if (activeBash.has(callID)) await cleanupBash(callID);
      const original = extractOriginalCommand(args.command as string);
      if (original) args.command = original;
    }

    const allowNetwork = config.network.allowNetwork;
    const callAllowedDomains: string[] = [];
    const effectiveConfig = {
      ...config,
      network: { ...config.network },
      filesystem: config.filesystem,
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

    const proxyToken = allowNetwork ? null : randomBytes(32).toString('base64url');
    const proxyAuthorization =
      proxyToken === null
        ? undefined
        : `Basic ${Buffer.from(`landstrip:${proxyToken}`).toString('base64')}`;
    const proxy = allowNetwork
      ? null
      : await startFilterProxy({
          isDomainAllowed: (domain) => isDomainAllowed(domain, effectiveConfig),
          ...(proxyAuthorization === undefined ? {} : { authorization: proxyAuthorization }),
        });
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
    // broker when no TUI endpoint or session identity is available.
    const interactiveSessionID = normalizedSessionID ?? '';
    const tuiTrapPort =
      process.platform === 'linux' && interactiveSessionID
        ? await readLiveDiscoveryPort(directory)
        : null;
    const trapServer =
      tuiTrapPort === null
        ? await startTrapServer(
            effectiveConfig.filesystem.allowRead,
            effectiveConfig.filesystem.allowWrite,
            effectiveConfig.filesystem.denyRead,
            effectiveConfig.filesystem.denyWrite,
            directory,
          )
        : null;
    const trapPort = tuiTrapPort ?? trapServer?.port ?? null;

    const wrappedCommand = buildWrappedCommand(
      policy.path,
      configuredShell ?? process.env.SHELL ?? '/bin/sh',
      originalCommand,
      trapPort,
      tuiTrapPort === null ? undefined : interactiveSessionID,
    );

    activeBash.set(callID, {
      originalCommand,
      wrappedCommand,
      sessionID: normalizedSessionID,
      policyDir: policy.dir,
      port: proxyPort,
      proxyToken,
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
      if (!config) return;

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

      const effectiveAllowRead = config.filesystem.allowRead;
      const effectiveAllowWrite = config.filesystem.allowWrite;
      const args: Record<string, unknown> = { ...metadata };
      if (permission === 'read') args.paths = patterns;
      if (permission === 'edit') {
        args.paths =
          patterns.length > 0
            ? patterns
            : [metadata.filepath].filter((path): path is string => typeof path === 'string');
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

      const denied = decisions.find((item) => item.status === 'deny');
      if (denied) {
        output.status = 'deny';
        return;
      }

      const approvals = decisions.filter((item) => item.status === 'ask');
      if (approvals.length === 0) return;

      output.status = 'ask';
      rememberCallAllowances(callID, approvals);
    },

    'tool.execute.before': async (input, output) => {
      if (!isRecord(output.args)) return;

      const config = await activeConfig();
      if (!config) return;

      if (input.tool === 'bash') {
        await prepareBash(input.callID, input.sessionID, output.args, config);
        return;
      }

      const decisions = evaluateToolPermissions(
        input.tool,
        output.args,
        config,
        directory,
        config.filesystem.allowRead,
        config.filesystem.allowWrite,
      );
      for (const decision of decisions) {
        enforcePermission(input.callID, decision);
      }
    },

    'shell.env': async (input, output) => {
      if (!input.callID) return;
      const state = activeBash.get(input.callID);
      if (!state) return;

      const envVars = proxyEnv(state.port, state.proxyToken);
      if (envVars) Object.assign(output.env, envVars);
    },

    'tool.execute.after': async (input, output) => {
      if (input.tool !== 'bash') {
        clearCallAllowances(input.callID);
        return;
      }

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
      const traps = parseLandstripTraps(combinedOutput);
      const errors = traps.filter(
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

      const blockedTrap = traps.find(
        (trap): trap is Extract<LandstripTrap, { kind: 'filesystem' }> =>
          trap.kind === 'filesystem' && trap.state === 'query',
      );
      const blockedPath = blockedTrap
        ? canonicalizePath(blockedTrap.path, directory)
        : extractBlockedPath(outputText, directory, state.originalCommand);
      if (blockedPath) {
        const blockedOperation = blockedTrap?.operation ?? 'read';
        await notifyOnce(
          `blocked:${blockedPath}`,
          `Sandbox blocked ${blockedOperation} to "${blockedPath}". No live TUI presenter was available, so access remains denied.`,
          'warning',
        );
      }

      await cleanupBash(input.callID);
    },

    dispose: async () => {
      await Promise.all([...activeBash.keys()].map((callID) => cleanupBash(callID)));
    },
  };

  return hooks;
};

export default { server: plugin };
