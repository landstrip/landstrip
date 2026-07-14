// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripTrap,
} from '@landstrip/landstrip';

// Re-exported so index.ts/tui.ts can import the trap/response types from this
// module alongside the parsing functions that produce/consume them.
export type { LandstripControlResponse, LandstripTrap };

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export interface SandboxFilesystemConfig {
  denyRead: string[];
  allowRead: string[];
  allowWrite: string[];
  denyWrite: string[];
}

export interface SandboxNetworkConfig {
  allowNetwork: boolean;
  allowLocalBinding: boolean;
  allowAllUnixSockets: boolean;
  allowUnixSockets: string[];
  allowedDomains: string[];
  deniedDomains: string[];
}

export interface SandboxConfig {
  enabled: boolean;
  network: SandboxNetworkConfig;
  filesystem: SandboxFilesystemConfig;
}

export interface SandboxConfigOverrides {
  enabled?: boolean;
  network?: Partial<SandboxNetworkConfig>;
  filesystem?: Partial<SandboxFilesystemConfig>;
}

const packageDir = dirname(fileURLToPath(import.meta.url));

const LANDSTRIP_PACKAGE_NAMES = new Set([
  '@landstrip/landstrip',
  '@landstrip/landstrip-darwin-arm64',
  '@landstrip/landstrip-darwin-x64',
  '@landstrip/landstrip-linux-x64',
  '@landstrip/landstrip-win32-x64',
]);

// Breadth-first filesystem approval: a held read/write under a directory tree
// is approved for the broadest reasonable ancestor (e.g. `~/.cargo`, not each
// subcrate file), so a single approval covers sibling files under the same tree.
export function pathUnderDirectory(filePath: string, dir: string): boolean {
  if (filePath === dir) return true;
  const sep = dir.endsWith('/') ? '' : '/';
  return filePath.startsWith(dir + sep);
}

export function sessionAllows(prefixes: Set<string>, filePath: string): boolean {
  for (const prefix of prefixes) {
    if (pathUnderDirectory(filePath, prefix)) return true;
  }
  return false;
}

// The broadest ancestor worth approving in one click: the immediate child of
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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function list(values: string[]): string {
  return values.join(', ') || '(none)';
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

export function normalizeConfig(value: unknown): SandboxConfigOverrides {
  if (!isRecord(value)) return {};

  const config: SandboxConfigOverrides = {};
  if (typeof value.enabled === 'boolean') config.enabled = value.enabled;

  const network = normalizeNetworkConfig(value.network);
  if (network) config.network = network;

  const filesystem = normalizeFilesystemConfig(value.filesystem);
  if (filesystem) config.filesystem = filesystem;

  return config;
}

export function normalizeOptions(options: unknown): SandboxConfigOverrides {
  if (!isRecord(options)) return {};
  return normalizeConfig(isRecord(options.config) ? options.config : options);
}

function mergeArray(base: string[], override?: string[]): string[] {
  if (!override) return base;
  return [...new Set([...base, ...override])];
}

export function deepMerge(base: SandboxConfig, overrides: SandboxConfigOverrides): SandboxConfig {
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

export function getConfigPaths(baseDirectory: string): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(homedir(), '.config', 'opencode', 'sandbox.json'),
    projectPath: join(baseDirectory, '.opencode', 'sandbox.json'),
  };
}

// Returns `{}` when the file is absent and `null` when it exists but cannot be
// parsed, so callers can refuse to overwrite a corrupted config.
export function readConfigFile(configPath: string): SandboxConfigOverrides | null {
  if (!existsSync(configPath)) return {};

  try {
    return normalizeConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
  } catch {
    return null;
  }
}

export function loadConfig(
  baseDirectory: string,
  optionOverrides: SandboxConfigOverrides,
): SandboxConfig {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const templatePath = join(packageDir, 'sandbox.json');

  if (!existsSync(globalPath)) {
    mkdirSync(dirname(globalPath), { recursive: true });
    writeFileSync(globalPath, readFileSync(templatePath, 'utf-8'), 'utf-8');
  }

  const templateConfig: SandboxConfig = JSON.parse(readFileSync(templatePath, 'utf-8'));
  const globalOverrides = readConfigFile(globalPath) ?? {};
  const baseConfig = deepMerge(templateConfig, globalOverrides);

  return deepMerge(deepMerge(baseConfig, readConfigFile(projectPath) ?? {}), optionOverrides);
}

export function writeConfigFile(configPath: string, update: SandboxConfigOverrides): void {
  const current = readConfigFile(configPath);
  if (current === null) {
    throw new Error(`Config file ${configPath} is corrupted; refusing to overwrite`);
  }

  const templateConfig: SandboxConfig = JSON.parse(
    readFileSync(join(packageDir, 'sandbox.json'), 'utf-8'),
  );
  const next = deepMerge(deepMerge(templateConfig, current), update);

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(next, null, 2) + '\n');
}

let _landstripBinaryPath: string | undefined;
let _landstripBinaryPathError: unknown;

export function landstripBinaryPath(): string {
  if (_landstripBinaryPath !== undefined) return _landstripBinaryPath;
  if (_landstripBinaryPathError !== undefined) throw _landstripBinaryPathError;

  try {
    const filePath = realpathSync.native(binaryPath());
    let probe = dirname(filePath);

    while (true) {
      const manifestPath = join(probe, 'package.json');
      if (existsSync(manifestPath)) {
        try {
          const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as unknown;
          if (isRecord(manifest) && LANDSTRIP_PACKAGE_NAMES.has(String(manifest.name))) {
            _landstripBinaryPath = filePath;
            return filePath;
          }
        } catch {
          // malformed package.json — continue walking to parent
        }
      }

      const parent = dirname(probe);
      if (parent === probe) break;
      probe = parent;
    }

    throw new Error(
      `Refusing to use landstrip binary outside official @landstrip/landstrip packages: ${filePath}`,
    );
  } catch (error) {
    _landstripBinaryPathError = error;
    throw error;
  }
}

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([^\s/:?#'"]+)(?::\d+)?(?:[/?#]|\s|$)/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(command)) !== null) {
    if (match[1]) domains.add(match[1]);
  }

  return [...domains];
}

// Permission requests reach the plugin in slightly different shapes across the
// server hook and the TUI event bus, so the field-fallback parsing below is the
// single source of truth both entrypoints share.
export function permissionType(permission: Record<string, unknown>, fallback = ''): string {
  if (typeof permission.permission === 'string') return permission.permission;
  if (typeof permission.action === 'string') return permission.action;
  if (typeof permission.type === 'string') return permission.type;
  return fallback;
}

export function permissionPattern(permission: Record<string, unknown>): string | undefined {
  const patterns = permission.patterns;
  if (Array.isArray(patterns))
    return patterns.find((item): item is string => typeof item === 'string');

  const pattern = permission.pattern;
  if (typeof pattern === 'string') return pattern;
  if (Array.isArray(pattern))
    return pattern.find((item): item is string => typeof item === 'string');

  return undefined;
}

/**
 * Every string pattern a permission carries, in declaration order, read from
 * `patterns`, `pattern`, or `resources`. The plural complement to
 * {@link permissionPattern} for callers that must inspect all patterns.
 */
export function permissionPatterns(permission: Record<string, unknown>): string[] {
  const patterns = permission.patterns;
  if (Array.isArray(patterns))
    return patterns.filter((item): item is string => typeof item === 'string');

  const pattern = permission.pattern;
  if (typeof pattern === 'string') return [pattern];
  if (Array.isArray(pattern))
    return pattern.filter((item): item is string => typeof item === 'string');

  const resources = permission.resources;
  if (Array.isArray(resources))
    return resources.filter((item): item is string => typeof item === 'string');

  return [];
}

export function permissionLabel(permission: Record<string, unknown>): string {
  const type = permissionType(permission, 'permission');
  const title = typeof permission.title === 'string' ? permission.title : type;
  const pattern = permissionPattern(permission);
  return pattern ? `${title}: ${pattern}` : title;
}

// The concrete resource a permission concerns (a path or a domain), used to show
// the user exactly what they are approving and to persist the right allowlist.
export function permissionResource(permission: Record<string, unknown>): string | undefined {
  const metadata = isRecord(permission.metadata) ? permission.metadata : {};
  const type = permissionType(permission);
  const pattern = permissionPattern(permission);

  if (type === 'bash') {
    const command = typeof metadata.command === 'string' ? metadata.command : pattern;
    const domains = typeof command === 'string' ? extractDomainsFromCommand(command) : [];
    return domains.length > 0 ? domains.join(', ') : (command ?? pattern);
  }

  if (typeof metadata.filepath === 'string') return metadata.filepath;
  if (typeof metadata.path === 'string') return metadata.path;
  return pattern;
}

export function updateForPermission(
  permission: Record<string, unknown>,
): SandboxConfigOverrides | null {
  const metadata = isRecord(permission.metadata) ? permission.metadata : {};
  const type = permissionType(permission);
  const pattern = permissionPattern(permission);

  if (type === 'bash') {
    const command = typeof metadata.command === 'string' ? metadata.command : pattern;
    const domains = typeof command === 'string' ? extractDomainsFromCommand(command) : [];
    return domains.length > 0 ? { network: { allowedDomains: domains } } : null;
  }

  if (type === 'read' || type === 'glob' || type === 'grep' || type === 'list') {
    const filePath = typeof metadata.filepath === 'string' ? metadata.filepath : pattern;
    return filePath ? { filesystem: { allowRead: [filePath] } } : null;
  }

  if (type === 'edit' || type === 'write' || type === 'apply_patch') {
    const filePath = typeof metadata.filepath === 'string' ? metadata.filepath : pattern;
    return filePath ? { filesystem: { allowWrite: [filePath] } } : null;
  }

  return null;
}

// Landstrip emits one JSON trap per line on its trap fd/file. The `state` field
// distinguishes a terminal `info` trap from a `query` trap that holds a syscall
// pending until the host answers with the trap's `query_id`. Parsing lives here
// so the server hook and the TUI socket handler decode identically.
const LANDSTRIP_OPERATIONS = new Set<'read' | 'write'>(['read', 'write']);

function isLandstripOperation(value: unknown): value is 'read' | 'write' {
  return typeof value === 'string' && LANDSTRIP_OPERATIONS.has(value as 'read' | 'write');
}

// The declarations landstrip ships are compile-time only, so a runtime guard is
// still required — but it only has to validate the fields actually read below.
// Deliberately does not validate `state`: a missing or unknown state degrades to
// "informational", the safe direction. `query_id` must be a string on both
// filesystem and network traps — landstrip < 0.17 sent a number here, and a
// numeric id fails landstrip's own deserializer when echoed back, so treating
// it as undecodable (rather than coercing it) keeps a stale/mismatched trap
// from ever being answered with a shape the broker would reject.
function isLandstripTrap(value: unknown): value is LandstripTrap {
  if (!isRecord(value)) return false;

  switch (value.kind) {
    case 'filesystem':
      return (
        isLandstripOperation(value.operation) &&
        typeof value.path === 'string' &&
        typeof value.query_id === 'string'
      );
    case 'network':
      return (
        typeof value.operation === 'string' &&
        typeof value.target === 'string' &&
        typeof value.query_id === 'string'
      );
    case 'launch':
      return typeof value.program === 'string' && typeof value.message === 'string';
    case 'usage':
      return typeof value.message === 'string';
    case 'internal':
      return typeof value.code === 'string' && typeof value.message === 'string';
    default:
      return false;
  }
}

export function decodeLandstripTrap(value: unknown): LandstripTrap | null {
  return isLandstripTrap(value) ? value : null;
}

export function parseLandstripTraps(output: string): LandstripTrap[] {
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

export function formatLandstripTrap(trap: LandstripTrap): string {
  switch (trap.kind) {
    case 'filesystem':
      return `landstrip: filesystem ${trap.operation} denied (${trap.path})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'network':
      return `landstrip: network ${trap.operation} denied (${trap.target})${
        trap.mechanism ? ` [${trap.mechanism}]` : ''
      }`;
    case 'launch':
      return `landstrip: launch failed (${trap.program})${trap.message ? `: ${trap.message}` : ''}`;
    case 'usage':
      return `landstrip: usage error: ${trap.message}`;
    case 'internal': {
      const mechanism = trap.mechanism ? ` [${trap.mechanism}]` : '';
      return `landstrip: ${trap.code}${mechanism}: ${trap.message}`;
    }
  }
}

export function formatLandstripTraps(traps: LandstripTrap[]): string {
  return traps.map(formatLandstripTrap).join('\n');
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

// The TUI plugin runs the query-response socket server and publishes its port
// to a per-directory discovery file; the server plugin reads it to inject the
// fd-3 redirect. Namespacing by a hash of the realpath keeps concurrent
// opencode instances in different projects from colliding.
function discoveryDir(): string {
  const base = process.env.XDG_RUNTIME_DIR || tmpdir();
  return join(base, 'opencode-landstrip');
}

function directoryHash(baseDirectory: string): string {
  let key = baseDirectory;
  try {
    key = realpathSync.native(baseDirectory);
  } catch {
    // Directory not resolvable — hash the raw path instead.
  }
  return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

export function discoveryFilePath(baseDirectory: string): string {
  return join(discoveryDir(), `port-${directoryHash(baseDirectory)}.json`);
}

// /sandbox toggles the persisted `enabled` flag. Write it where the setting
// already lives — the project config if it sets `enabled`, otherwise the global
// config — and return the scope written so the UI can report it.
export function setSandboxConfigEnabled(
  baseDirectory: string,
  enabled: boolean,
): 'project' | 'global' {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const projectConfig = readConfigFile(projectPath);
  const useProject = projectConfig !== null && projectConfig.enabled !== undefined;
  const target = useProject ? projectPath : globalPath;
  writeConfigFile(target, { enabled });
  return useProject ? 'project' : 'global';
}

export function writeDiscoveryPort(baseDirectory: string, port: number): void {
  const dir = discoveryDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(
    discoveryFilePath(baseDirectory),
    JSON.stringify({ port, pid: process.pid, ts: Date.now() }) + '\n',
  );
}

export function removeDiscoveryFile(baseDirectory: string): void {
  rmSync(discoveryFilePath(baseDirectory), { force: true });
}

// Returns the live query-response port, or null when no fresh server is
// listening. A recorded writer pid that no longer exists marks the file stale.
export function readDiscoveryPort(baseDirectory: string): number | null {
  const path = discoveryFilePath(baseDirectory);
  if (!existsSync(path)) return null;

  try {
    const data: unknown = JSON.parse(readFileSync(path, 'utf-8'));
    if (!isRecord(data)) return null;

    const port = typeof data.port === 'number' ? data.port : NaN;
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;

    if (typeof data.pid === 'number') {
      try {
        process.kill(data.pid, 0);
      } catch (error) {
        // ESRCH: the writer is gone, so the file is stale. EPERM: alive but
        // owned by another user — still a live listener, so accept it.
        if ((error as NodeJS.ErrnoException).code === 'ESRCH') return null;
      }
    }

    return port;
  } catch {
    return null;
  }
}

/**
 * Human-readable sandbox configuration report consumed by both the server
 * command and the TUI inspector dialog.
 */
export function sandboxSummary(
  config: SandboxConfig,
  globalPath: string,
  projectPath: string,
  statusOverride?: string,
): string {
  const networkMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';
  const allowed = list(config.network.allowedDomains);
  const denied = list(config.network.deniedDomains);
  const unixSockets = config.network.allowAllUnixSockets
    ? 'all'
    : list(config.network.allowUnixSockets);
  const denyRead = list(config.filesystem.denyRead);
  const allowRead = list(config.filesystem.allowRead);
  const allowWrite = list(config.filesystem.allowWrite);
  const denyWrite = list(config.filesystem.denyWrite);

  const status = statusOverride ?? (config.enabled ? 'active' : 'disabled by config');
  let binary: string;
  try {
    binary = landstripBinaryPath();
  } catch {
    binary = '(unavailable)';
  }

  return [
    `Status: ${status}`,
    `landstrip package binary: ${binary}`,
    '',
    'Config files',
    `${projectPath} ${existsSync(projectPath) ? '(found)' : '(missing)'}`,
    `${globalPath} ${existsSync(globalPath) ? '(found)' : '(missing)'}`,
    '',
    `Network: ${networkMode}`,
    `allow network: ${config.network.allowNetwork ? 'yes' : 'no'}`,
    `allowed: ${allowed}`,
    `denied: ${denied}`,
    `unix sockets: ${unixSockets}`,
    '',
    'Filesystem',
    `deny read: ${denyRead}`,
    `allow read: ${allowRead}`,
    `allow write: ${allowWrite}`,
    `deny write: ${denyWrite}`,
  ].join('\n');
}
