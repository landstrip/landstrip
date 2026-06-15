// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import { binaryPath } from '@jarkkojs/landstrip';

import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
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
    allowRead: ['.', '~/.gitconfig', '/dev/null'],
    allowWrite: ['.', '/dev/null'],
    denyWrite: ['**/.env', '**/.env.*', '**/*.pem', '**/*.key'],
  },
};

const LANDSTRIP_PACKAGE_NAMES = new Set([
  '@jarkkojs/landstrip',
  '@jarkkojs/landstrip-darwin-arm64',
  '@jarkkojs/landstrip-darwin-x64',
  '@jarkkojs/landstrip-linux-x64',
  '@jarkkojs/landstrip-win32-x64',
]);

export function isRecord(value: unknown): value is Record<string, unknown> {
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
    `Refusing to use landstrip binary outside official @jarkkojs/landstrip packages: ${filePath}`,
  );
}

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([^\s/:?#'"]+)(?::\d+)?(?:[/?#]|\s|$)/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1]);
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
