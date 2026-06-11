// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin } from '@opencode-ai/plugin/tui';

import { binaryPath } from '@jarkkojs/landstrip';

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

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

interface SandboxConfigOverrides {
  enabled?: boolean;
  network?: Partial<SandboxNetworkConfig>;
  filesystem?: Partial<SandboxFilesystemConfig>;
}

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

function normalizeOptions(options: unknown): SandboxConfigOverrides {
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
  } catch {
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

function list(values: string[]): string {
  return values.join(', ') || '(none)';
}

function configPathLine(label: string, filePath: string): string {
  return `${label}: ${filePath} ${existsSync(filePath) ? '(found)' : '(missing)'}`;
}

function sandboxSummary(baseDirectory: string, optionOverrides: SandboxConfigOverrides): string {
  const config = loadConfig(baseDirectory, optionOverrides);
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const networkMode = config.network.allowNetwork ? 'unrestricted' : 'proxied';

  return [
    `Status: ${config.enabled ? 'active' : 'disabled by config'}`,
    `landstrip: ${binaryPath()}`,
    '',
    'Config files',
    configPathLine('project', projectPath),
    configPathLine('global', globalPath),
    '',
    `Network: ${networkMode}`,
    `allow network: ${config.network.allowNetwork ? 'yes' : 'no'}`,
    `allowed: ${list(config.network.allowedDomains)}`,
    `denied: ${list(config.network.deniedDomains)}`,
    `unix sockets: ${config.network.allowAllUnixSockets ? 'all' : list(config.network.allowUnixSockets)}`,
    '',
    'Filesystem',
    `deny read: ${list(config.filesystem.denyRead)}`,
    `allow read: ${list(config.filesystem.allowRead)}`,
    `allow write: ${list(config.filesystem.allowWrite)}`,
    `deny write: ${list(config.filesystem.denyWrite)}`,
    '',
    'esc or any key to close',
  ].join('\n');
}

const tui: TuiPlugin = async (api, options) => {
  const showSandbox = () => {
    const directory = api.state.path.directory || process.cwd();
    const message = sandboxSummary(directory, normalizeOptions(options));

    api.ui.dialog.replace(
      () =>
        api.ui.DialogAlert({
          title: 'Sandbox Configuration',
          message,
          onConfirm: () => api.ui.dialog.clear(),
        }),
      () => api.ui.dialog.clear(),
    );
  };

  api.keymap.registerLayer({
    commands: [
      {
        namespace: 'palette',
        name: 'landstrip.sandbox.show',
        title: 'Show sandbox configuration',
        desc: 'Show landstrip sandbox status and rules',
        description: 'Show landstrip sandbox status and rules',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox',
        run: showSandbox,
      },
    ],
  });

  api.command?.register(() => [
    {
      title: 'Sandbox',
      value: 'landstrip.sandbox.show',
      description: 'Show sandbox configuration',
      category: 'Sandbox',
      suggested: true,
      slash: { name: 'sandbox' },
      onSelect: showSandbox,
    },
  ]);
};

export { tui };
export default { tui };
