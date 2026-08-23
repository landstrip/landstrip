// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import {
  binaryPath,
  type LandstripControlResponse,
  type LandstripTrap,
} from '@landstrip/landstrip-api';

import {
  allowsAllDomains,
  canonicalizeGlobPattern,
  canonicalizePath,
  controlResponseLine,
  decodeLandstripTrap,
  domainMatchesAny,
  domainMatchesPattern,
  expandHomePath,
  expandPath,
  globToRegExp,
  formatLandstripTrap,
  formatLandstripTraps,
  isRecord,
  normalizePathSeparators,
  parseLandstripTraps,
  pathUnderDirectory,
  sessionAllows,
  sessionScopeFor,
} from '@landstrip/landstrip-api/shared';

export {
  allowsAllDomains,
  canonicalizeGlobPattern,
  canonicalizePath,
  controlResponseLine,
  decodeLandstripTrap,
  domainMatchesAny,
  domainMatchesPattern,
  expandHomePath,
  expandPath,
  globToRegExp,
  formatLandstripTrap,
  formatLandstripTraps,
  isRecord,
  normalizePathSeparators,
  parseLandstripTraps,
  pathUnderDirectory,
  sessionAllows,
  sessionScopeFor,
};

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
  '@landstrip/landstrip-api',
  '@landstrip/landstrip-darwin-arm64',
  '@landstrip/landstrip-darwin-x64',
  '@landstrip/landstrip-linux-x64',
  '@landstrip/landstrip-linux-arm64',
  '@landstrip/landstrip-win32-x64',
  '@landstrip/landstrip-win32-arm64',
]);

export function list(values: string[]): string {
  return values.join(', ') || '(none)';
}

function rejectUnknownFields(
  value: Record<string, unknown>,
  fields: readonly string[],
  prefix = '',
): void {
  for (const field of Object.keys(value)) {
    if (!fields.includes(field)) throw new Error(`unknown sandbox field ${prefix}${field}`);
  }
}

function booleanValue(value: unknown, field: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new Error(`${field} must be a boolean`);
  return value;
}

function stringArray(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || [...value].some((item) => typeof item !== 'string')) {
    throw new Error(`${field} must be an array of strings`);
  }
  return [...value];
}

function normalizeNetworkConfig(value: unknown): Partial<SandboxNetworkConfig> | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error('network must be an object');
  rejectUnknownFields(
    value,
    [
      'allowNetwork',
      'allowLocalBinding',
      'allowAllUnixSockets',
      'allowUnixSockets',
      'allowedDomains',
      'deniedDomains',
    ],
    'network.',
  );

  const config: Partial<SandboxNetworkConfig> = {};
  const allowNetwork = booleanValue(value.allowNetwork, 'network.allowNetwork');
  if (allowNetwork !== undefined) config.allowNetwork = allowNetwork;
  const allowLocalBinding = booleanValue(value.allowLocalBinding, 'network.allowLocalBinding');
  if (allowLocalBinding !== undefined) config.allowLocalBinding = allowLocalBinding;
  const allowAllUnixSockets = booleanValue(
    value.allowAllUnixSockets,
    'network.allowAllUnixSockets',
  );
  if (allowAllUnixSockets !== undefined) config.allowAllUnixSockets = allowAllUnixSockets;

  const allowUnixSockets = stringArray(value.allowUnixSockets, 'network.allowUnixSockets');
  if (allowUnixSockets) config.allowUnixSockets = allowUnixSockets;

  const allowedDomains = stringArray(value.allowedDomains, 'network.allowedDomains');
  if (allowedDomains) config.allowedDomains = allowedDomains;

  const deniedDomains = stringArray(value.deniedDomains, 'network.deniedDomains');
  if (deniedDomains) config.deniedDomains = deniedDomains;

  return config;
}

function normalizeFilesystemConfig(value: unknown): Partial<SandboxFilesystemConfig> | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error('filesystem must be an object');
  rejectUnknownFields(value, ['denyRead', 'allowRead', 'allowWrite', 'denyWrite'], 'filesystem.');

  const config: Partial<SandboxFilesystemConfig> = {};
  const denyRead = stringArray(value.denyRead, 'filesystem.denyRead');
  if (denyRead) config.denyRead = denyRead;

  const allowRead = stringArray(value.allowRead, 'filesystem.allowRead');
  if (allowRead) config.allowRead = allowRead;

  const allowWrite = stringArray(value.allowWrite, 'filesystem.allowWrite');
  if (allowWrite) config.allowWrite = allowWrite;

  const denyWrite = stringArray(value.denyWrite, 'filesystem.denyWrite');
  if (denyWrite) config.denyWrite = denyWrite;

  return config;
}

export function normalizeConfig(value: unknown): SandboxConfigOverrides {
  if (!isRecord(value)) throw new Error('sandbox config must be an object');
  rejectUnknownFields(value, ['enabled', 'network', 'filesystem']);

  const config: SandboxConfigOverrides = {};
  const enabled = booleanValue(value.enabled, 'enabled');
  if (enabled !== undefined) config.enabled = enabled;

  const network = normalizeNetworkConfig(value.network);
  if (network) config.network = network;

  const filesystem = normalizeFilesystemConfig(value.filesystem);
  if (filesystem) config.filesystem = filesystem;

  return config;
}

export function normalizeOptions(options: unknown): SandboxConfigOverrides {
  if (!isRecord(options)) return {};
  if (options.config === undefined) return normalizeConfig(options);
  if (!isRecord(options.config)) throw new Error('config must be an object');
  return normalizeConfig(options.config);
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

export function readConfigFile(configPath: string): SandboxConfigOverrides {
  if (!existsSync(configPath)) return {};

  try {
    return normalizeConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
  } catch (error) {
    throw new Error(
      `Could not load ${configPath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
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
  const globalOverrides = readConfigFile(globalPath);
  const baseConfig = deepMerge(templateConfig, globalOverrides);

  return deepMerge(deepMerge(baseConfig, readConfigFile(projectPath)), optionOverrides);
}

export function writeConfigFile(configPath: string, update: SandboxConfigOverrides): void {
  const current = readConfigFile(configPath);

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
      `Refusing to use landstrip binary outside official @landstrip/landstrip-api packages: ${filePath}`,
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

export interface TrapSessionHello {
  kind: 'opencode-landstrip-session';
  sessionID: string;
}

export interface SessionAllowances {
  readPaths: Set<string>;
  writePaths: Set<string>;
  targets: Set<string>;
}

export function trapSessionHelloLine(sessionID: string): string {
  const normalized = sessionID.trim();
  if (!normalized) throw new Error('OpenCode session ID must not be empty');
  const hello: TrapSessionHello = { kind: 'opencode-landstrip-session', sessionID: normalized };
  return JSON.stringify(hello) + '\n';
}

export function decodeTrapSessionHello(line: string): TrapSessionHello | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isRecord(value) || value.kind !== 'opencode-landstrip-session') return null;
  if (typeof value.sessionID !== 'string') return null;
  const sessionID = value.sessionID.trim();
  return sessionID ? { kind: 'opencode-landstrip-session', sessionID } : null;
}

export function sessionAllowancesFor(
  sessions: Map<string, SessionAllowances>,
  sessionID: string,
): SessionAllowances {
  const existing = sessions.get(sessionID);
  if (existing) return existing;
  const created: SessionAllowances = {
    readPaths: new Set(),
    writePaths: new Set(),
    targets: new Set(),
  };
  sessions.set(sessionID, created);
  return created;
}

export function rootSessionIDFor(
  sourceSessionID: string,
  session: (sessionID: string) => { parentID?: string } | undefined,
): string | undefined {
  let current = sourceSessionID;
  const seen = new Set<string>();
  while (!seen.has(current)) {
    seen.add(current);
    const value = session(current);
    if (!value) return undefined;
    if (!value.parentID) return current;
    current = value.parentID;
  }
  return undefined;
}

export function nextSandboxPermissionIndex<T extends { sessionID: string }>(
  queue: readonly T[],
  routeSessionID: string,
  blocked: (entry: T) => boolean,
): number {
  const entry = queue[0];
  return entry && entry.sessionID === routeSessionID && !blocked(entry) ? 0 : -1;
}

export function shouldRenderSandboxPermission(
  requestSessionID: string,
  routeSessionID: string,
  hostPromptActive: boolean,
): boolean {
  return requestSessionID === routeSessionID && !hostPromptActive;
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

// /landstrip toggles the persisted `enabled` flag. Write it where the setting
// already lives — the project config if it sets `enabled`, otherwise the global
// config — and return the scope written so the UI can report it.
export function sandboxConfigTarget(baseDirectory: string): {
  scope: 'project' | 'global';
  path: string;
} {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const useProject = readConfigFile(projectPath).enabled !== undefined;
  return useProject
    ? { scope: 'project', path: projectPath }
    : { scope: 'global', path: globalPath };
}

export function setSandboxConfigEnabled(
  baseDirectory: string,
  enabled: boolean,
  optionOverrides: SandboxConfigOverrides = {},
): 'project' | 'global' {
  if (optionOverrides.enabled !== undefined) {
    throw new Error('Sandbox state is managed by plugin options');
  }

  const target = sandboxConfigTarget(baseDirectory);
  writeConfigFile(target.path, { enabled });
  return target.scope;
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
