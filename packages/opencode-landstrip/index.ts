// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { Plugin } from '@opencode/plugin';

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

function normalizePathForMatch(filePath: string): string {
  return process.platform === 'win32' ? normalizePathSeparators(filePath).toLowerCase() : filePath;
}

// Component count of an absolute path; "/" is 0. Read rules use it to rank
// matching allow and deny patterns by specificity.
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
    if (/[*?[\]]/.test(pattern)) {
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
    /[*?[\]]/.test(pattern)
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

function isReadAllowed(
  path: string,
  allowPatterns: string[],
  denyPatterns: string[],
  baseDirectory: string,
): boolean {
  const allowDepth = matchDepth(path, allowPatterns, baseDirectory);
  const denyDepth = matchDepth(path, denyPatterns, baseDirectory);
  return allowDepth >= 0 && allowDepth >= denyDepth;
}

function writeAccess(
  path: string,
  allowPatterns: string[],
  denyPatterns: string[],
  baseDirectory: string,
): 'allow' | 'deny' | 'unlisted' {
  if (matchDepth(path, denyPatterns, baseDirectory) >= 0) return 'deny';
  return matchDepth(path, allowPatterns, baseDirectory) >= 0 ? 'allow' : 'unlisted';
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
  if (isReadAllowed(filePath, effectiveAllowRead, config.filesystem.denyRead, baseDirectory)) {
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
  const access = writeAccess(
    filePath,
    effectiveAllowWrite,
    config.filesystem.denyWrite,
    baseDirectory,
  );

  if (access === 'deny') {
    return {
      status: 'deny',
      kind: 'write',
      resource: filePath,
      message: `Sandbox: write access denied for "${filePath}" (denyWrite overrides allowWrite).`,
    };
  }

  if (access === 'allow') {
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
                ? isReadAllowed(path, effectiveAllowRead, denyRead, baseDirectory)
                : writeAccess(path, effectiveAllowWrite, denyWrite, baseDirectory) === 'allow';
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
    '--trap',
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
    const searchPath = typeof args.path === 'string' ? args.path : '.';
    return [evaluateReadPermission(searchPath, config, baseDirectory, effectiveAllowRead)];
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

const plugin: Plugin.Plugin = {
  id: 'opencode-landstrip',
  async setup(context: Plugin.Context) {
    const directory = context.location?.directory ?? process.cwd();
    const optionOverrides = normalizeOptions(context.options);
    const pendingCallIDByCommand = new Map<string, string>();
    const pendingSessionIDByCommand = new Map<string, string>();
    const activeBash = new Map<string, BashSandboxState>();
    const notified = new Set<string>();
    let enabledNotified = false;
    let landstripCheck: { ok: true; version: string } | { ok: false; reason: string } | undefined;
    function reportBlocked(decision: SandboxPermissionDecision): never {
      throw errorWithConfigPaths(directory, decision.message);
    }

    async function notifyOnce(key: string, message: string, variant: ToastVariant): Promise<void> {
      if (notified.has(key)) return;
      notified.add(key);
      const output =
        variant === 'error' ? console.error : variant === 'warning' ? console.warn : console.info;
      output(`opencode-landstrip: ${message}`);
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
        const result = spawnSync(landstripBinaryPath(), ['--version'], { encoding: 'utf-8' });
        version = result.status === 0 ? result.stdout.trim() : null;
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
      env?: Record<string, string | undefined>,
      overrideShell?: string,
    ): Promise<void> {
      if (typeof args.command !== 'string') return;
      const normalizedSessionID = sessionID?.trim() || undefined;

      const rewriteDescription = (): void => {
        if (typeof args.description === 'string' && !args.description.endsWith(' (landstrip)')) {
          args.description = `${args.description} (landstrip)`;
        }
      };

      const existing = activeBash.get(callID);
      if (existing) {
        if (
          existing.sessionID === normalizedSessionID &&
          (args.command === existing.originalCommand || args.command === existing.wrappedCommand)
        ) {
          args.command = existing.wrappedCommand;
          rewriteDescription();
          if (env) {
            const envVars = proxyEnv(existing.port, existing.proxyToken);
            if (envVars) Object.assign(env, envVars);
          }
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
      if (!allowNetwork) {
        for (const decision of evaluateCommandDomains(args.command as string, config)) {
          if (decision.status !== 'allow') throw errorWithConfigPaths(directory, decision.message);
        }
      }

      const proxyToken = allowNetwork ? null : randomBytes(32).toString('base64url');
      const proxyAuthorization =
        proxyToken === null
          ? undefined
          : `Basic ${Buffer.from(`landstrip:${proxyToken}`).toString('base64')}`;
      const proxy = allowNetwork
        ? null
        : await startFilterProxy({
            isDomainAllowed: (domain) => isDomainAllowed(domain, config),
            ...(proxyAuthorization === undefined ? {} : { authorization: proxyAuthorization }),
          });
      const proxyPort = proxy ? proxy.port : null;
      let policy: { dir: string; path: string };

      try {
        policy = writePolicyFile(config, directory, proxyPort);
      } catch (error) {
        if (proxy) await proxy.stop().catch(() => undefined);
        throw error;
      }

      const originalCommand = args.command as string;

      // The TUI owns interactive query handling. Fall back to an in-process
      // broker when no TUI endpoint or session identity is available.
      const interactiveSessionID = normalizedSessionID ?? '';
      const discoveredPort =
        process.platform === 'linux' && interactiveSessionID ? readDiscoveryPort(directory) : null;
      const tuiTrapPort =
        discoveredPort !== null && (await trapPortAcceptsConnections(discoveredPort))
          ? discoveredPort
          : null;
      const trapServer =
        tuiTrapPort === null
          ? await startTrapServer(
              config.filesystem.allowRead,
              config.filesystem.allowWrite,
              config.filesystem.denyRead,
              config.filesystem.denyWrite,
              directory,
            )
          : null;
      const trapPort = tuiTrapPort ?? trapServer?.port ?? null;

      const wrappedCommand = buildWrappedCommand(
        policy.path,
        overrideShell ?? process.env.SHELL ?? '/bin/sh',
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
      if (env) {
        const envVars = proxyEnv(proxyPort, proxyToken);
        if (envVars) Object.assign(env, envVars);
      }
    }

    context.permission.hook('evaluate', async (evaluation) => {
      if (evaluation.effect === 'deny') return;
      const config = await activeConfig();
      if (!config) return;

      const action = evaluation.action;
      const patterns = [...(evaluation.resources ?? [])];
      const effectiveAllowRead = config.filesystem.allowRead;
      const effectiveAllowWrite = config.filesystem.allowWrite;
      const args: Record<string, unknown> = { ...evaluation.metadata };
      if (action === 'read' || action === 'external_directory') args.paths = patterns;
      if (action === 'edit') {
        args.paths =
          patterns.length > 0
            ? patterns
            : [args.filepath].filter((path): path is string => typeof path === 'string');
      }
      if ((action === 'shell' || action === 'bash') && typeof args.command !== 'string') {
        args.command = patterns[0];
      }
      const toolName =
        action === 'shell' ? 'bash' : action === 'external_directory' ? 'read' : action;
      const decisions = evaluateToolPermissions(
        toolName,
        args,
        config,
        directory,
        effectiveAllowRead,
        effectiveAllowWrite,
      );

      const denied = decisions.find((item) => item.status === 'deny');
      if (denied) {
        evaluation.effect = 'deny';
        evaluation.message = denied.message;
        return;
      }

      const approvals = decisions.filter((item) => item.status === 'ask');
      if (approvals.length === 0) return;

      evaluation.effect = 'ask';
      evaluation.message = approvals.map((item) => item.message).join('\n');
    });

    context.tool.hook('execute.before', async (event) => {
      const config = await activeConfig();
      if (!config) return;

      const args = isRecord(event.input) ? event.input : {};

      if (event.tool === 'shell') {
        if (args.background === true) {
          throw new Error(
            'Background shell commands are not supported while the sandbox is enabled',
          );
        }
        if (typeof args.command === 'string') {
          await prepareBash(event.id, event.sessionID, args, config);
          pendingCallIDByCommand.set(args.command, event.id);
          pendingSessionIDByCommand.set(args.command, event.sessionID);
        }
        return;
      }

      const decisions = evaluateToolPermissions(
        event.tool,
        args,
        config,
        directory,
        config.filesystem.allowRead,
        config.filesystem.allowWrite,
      );
      for (const decision of decisions) {
        if (decision.status === 'allow') continue;
        if (decision.status === 'ask' && ['read', 'write', 'edit', 'patch'].includes(event.tool)) {
          // These host tools assert their own permission during execution.
          continue;
        }
        reportBlocked(decision);
      }
    });

    context.shell.hook('create.before', async (invocation) => {
      const config = await activeConfig();
      if (!config) return;

      let callID = pendingCallIDByCommand.get(invocation.command);
      let sessionID = pendingSessionIDByCommand.get(invocation.command);
      if (callID) {
        pendingCallIDByCommand.delete(invocation.command);
      } else {
        callID = `shell-${randomBytes(6).toString('hex')}`;
      }
      if (sessionID) {
        pendingSessionIDByCommand.delete(invocation.command);
      }

      await prepareBash(
        callID,
        sessionID,
        invocation as unknown as Record<string, unknown>,
        config,
        invocation.env,
        invocation.shell,
      );
    });

    context.tool.hook('execute.after', async (event) => {
      if (event.tool !== 'shell') return;

      const state = activeBash.get(event.id);
      if (!state) return;

      const outputText =
        event.status === 'completed'
          ? typeof event.result.output === 'string'
            ? event.result.output
            : typeof event.result.content === 'string'
              ? event.result.content
              : ''
          : '';
      const serverTrapOutput = state.trapLines.join('\n');
      const combinedOutput = serverTrapOutput ? outputText + '\n' + serverTrapOutput : outputText;
      const traps = parseLandstripTraps(combinedOutput);
      const errors = traps.filter(
        (trap: LandstripTrap) => !(trap.kind === 'filesystem' && trap.state === 'query'),
      );
      if (errors.length > 0) {
        console.error(`opencode-landstrip: ${formatLandstripTraps(errors)}`);
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

      await cleanupBash(event.id);
    });

    return async () => {
      await Promise.all([...activeBash.keys()].map((callID) => cleanupBash(callID)));
      activeBash.clear();
    };
  },
};

export { plugin };
export default plugin;
