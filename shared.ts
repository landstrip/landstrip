// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import { binaryPath } from '@landstrip/landstrip';

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
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

export const DEFAULT_CONFIG: SandboxConfig = {
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

const LANDSTRIP_PACKAGE_NAMES = new Set([
  '@landstrip/landstrip',
  '@landstrip/landstrip-darwin-arm64',
  '@landstrip/landstrip-darwin-x64',
  '@landstrip/landstrip-linux-x64',
  '@landstrip/landstrip-win32-x64',
]);

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
  return deepMerge(
    deepMerge(
      deepMerge(DEFAULT_CONFIG, readConfigFile(globalPath) ?? {}),
      readConfigFile(projectPath) ?? {},
    ),
    optionOverrides,
  );
}

export function writeConfigFile(configPath: string, update: SandboxConfigOverrides): void {
  const current = readConfigFile(configPath);
  if (current === null) {
    throw new Error(`Config file ${configPath} is corrupted; refusing to overwrite`);
  }

  const next = deepMerge(deepMerge(DEFAULT_CONFIG, current), update);

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(next, null, 2) + '\n');
}

export function landstripBinaryPath(): string {
  const filePath = realpathSync.native(binaryPath());
  let probe = dirname(filePath);

  while (true) {
    const manifestPath = join(probe, 'package.json');
    if (existsSync(manifestPath)) {
      try {
        const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as unknown;
        if (isRecord(manifest) && LANDSTRIP_PACKAGE_NAMES.has(String(manifest.name))) {
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
// (landstrip >= 0.15.4) distinguishes a terminal `info` trap from a `query`
// trap that holds a syscall pending until the host answers with `queryId`. It
// is absent on the static-profile platforms (macOS/Windows), so both fields are
// optional. Parsing lives here so the server hook and the TUI socket handler
// decode identically.
export type LandstripTrapState = 'query' | 'info';

export type LandstripTrap =
  | {
      kind: 'filesystem';
      operation: 'read' | 'write';
      path: string;
      mechanism: string;
      state?: LandstripTrapState;
      queryId?: number;
    }
  | { kind: 'network'; operation: string; target: string; mechanism: string }
  | { kind: 'launch'; program: string; message: string }
  | { kind: 'usage'; message: string }
  | { kind: 'internal'; detail: Record<string, string> };

const LANDSTRIP_OPERATIONS = new Set<'read' | 'write'>(['read', 'write']);

function isLandstripOperation(value: unknown): value is 'read' | 'write' {
  return typeof value === 'string' && LANDSTRIP_OPERATIONS.has(value as 'read' | 'write');
}

function decodeTrapState(value: unknown): LandstripTrapState | undefined {
  return value === 'query' || value === 'info' ? value : undefined;
}

export function decodeLandstripTrap(value: unknown): LandstripTrap | null {
  if (!isRecord(value)) return null;
  const mechanism = typeof value.mechanism === 'string' ? value.mechanism : '';

  switch (value.kind) {
    case 'filesystem': {
      const { operation, path } = value;
      if (!isLandstripOperation(operation) || typeof path !== 'string') return null;
      const trap: LandstripTrap = { kind: 'filesystem', operation, path, mechanism };
      const state = decodeTrapState(value.state);
      if (state) trap.state = state;
      if (typeof value.query_id === 'number') trap.queryId = value.query_id;
      return trap;
    }
    case 'network': {
      const { operation, target } = value;
      if (typeof operation !== 'string' || typeof target !== 'string') return null;
      return { kind: 'network', operation, target, mechanism };
    }
    case 'launch': {
      const { program, message } = value;
      if (typeof program !== 'string') return null;
      return { kind: 'launch', program, message: typeof message === 'string' ? message : '' };
    }
    case 'usage': {
      const { message } = value;
      if (typeof message !== 'string') return null;
      return { kind: 'usage', message };
    }
    case 'internal': {
      const detail: Record<string, string> = {};
      const payload = value.detail;
      if (isRecord(payload)) {
        for (const [key, val] of Object.entries(payload)) {
          detail[key] = typeof val === 'string' ? val : JSON.stringify(val);
        }
      }
      return { kind: 'internal', detail };
    }
    default:
      return null;
  }
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
      const detail = Object.entries(trap.detail)
        .map(([key, val]) => `${key}: ${val}`)
        .join(', ');
      return `landstrip: internal error${detail ? ` (${detail})` : ''}`;
    }
  }
}

export function formatLandstripTraps(traps: LandstripTrap[]): string {
  return traps.map(formatLandstripTrap).join('\n');
}

// The TUI plugin runs the query-response socket server and publishes its port
// to a per-directory discovery file; the server plugin reads it to inject the
// fd-3 redirect. Namespacing by a hash of the realpath keeps concurrent
// opencode instances in different projects from colliding.
function discoveryDir(): string {
  const base = process.env.XDG_RUNTIME_DIR || tmpdir();
  return join(base, 'opencode-landstrip');
}

export function discoveryFilePath(baseDirectory: string): string {
  let key = baseDirectory;
  try {
    key = realpathSync.native(baseDirectory);
  } catch {
    // Directory not resolvable — hash the raw path instead.
  }
  const hash = createHash('sha256').update(key).digest('hex').slice(0, 16);
  return join(discoveryDir(), `port-${hash}.json`);
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
