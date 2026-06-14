// SPDX-License-Identifier: MIT
// Copyright (C) Jarkko Sakkinen 2026

import type { TuiPlugin } from '@opencode-ai/plugin/tui';

import { binaryPath } from '@jarkkojs/landstrip';

import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

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

function mergeArray(base: string[], override?: string[]): string[] {
  if (!override) return base;
  return [...new Set([...base, ...override])];
}

function deepMerge(base: SandboxConfig, overrides: SandboxConfigOverrides): SandboxConfig {
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

function getConfigPaths(baseDirectory: string): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(homedir(), '.config', 'opencode', 'sandbox.json'),
    projectPath: join(baseDirectory, '.opencode', 'sandbox.json'),
  };
}

function readConfigFile(configPath: string): SandboxConfigOverrides | null {
  if (!existsSync(configPath)) return {};

  try {
    return normalizeConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
  } catch {
    return null;
  }
}

function landstripBinaryPath(): string {
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

function writeConfigFile(configPath: string, update: SandboxConfigOverrides): void {
  const current = readConfigFile(configPath);
  if (current === null) {
    throw new Error(`Config file ${configPath} is corrupted; refusing to overwrite`);
  }

  const next = deepMerge(deepMerge(DEFAULT_CONFIG, current), update);

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(next, null, 2) + '\n');
}

function loadConfig(baseDirectory: string, optionOverrides: SandboxConfigOverrides): SandboxConfig {
  const { globalPath, projectPath } = getConfigPaths(baseDirectory);
  const globalConfig = readConfigFile(globalPath);
  const projectConfig = readConfigFile(projectPath);
  return deepMerge(
    deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig ?? {}), projectConfig ?? {}),
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
    `landstrip package binary: ${landstripBinaryPath()}`,
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

type PermissionChoice = 'once' | 'session' | 'project' | 'global' | 'reject';

function permissionType(permission: Record<string, unknown>, fallback = ''): string {
  if (typeof permission.permission === 'string') return permission.permission;
  if (typeof permission.action === 'string') return permission.action;
  if (typeof permission.type === 'string') return permission.type;
  return fallback;
}

function permissionPattern(permission: Record<string, unknown>): string | undefined {
  const patterns = permission.patterns;
  if (Array.isArray(patterns))
    return patterns.find((item): item is string => typeof item === 'string');

  const pattern = permission.pattern;
  if (typeof pattern === 'string') return pattern;
  if (Array.isArray(pattern))
    return pattern.find((item): item is string => typeof item === 'string');

  return undefined;
}

function domainsFromCommand(command: string): string[] {
  const domains = new Set<string>();
  const urlRegex = /https?:\/\/([^\s/:?#'"]+)(?::\d+)?(?:[/?#]|\s|$)/g;
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(command)) !== null) domains.add(match[1]);

  return [...domains];
}

function updateForPermission(permission: Record<string, unknown>): SandboxConfigOverrides | null {
  const metadata = isRecord(permission.metadata) ? permission.metadata : {};
  const type = permissionType(permission);
  const pattern = permissionPattern(permission);

  if (type === 'bash') {
    const command = typeof metadata.command === 'string' ? metadata.command : pattern;
    const domains = typeof command === 'string' ? domainsFromCommand(command) : [];
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

function permissionLabel(permission: Record<string, unknown>): string {
  const type = permissionType(permission, 'permission');
  const title = typeof permission.title === 'string' ? permission.title : type;
  const pattern = permissionPattern(permission);
  return pattern ? `${title}: ${pattern}` : title;
}

const tui: TuiPlugin = async (api, options) => {
  const handledPermissions = new Set<string>();

  async function replyPermission(
    permission: Record<string, unknown>,
    choice: PermissionChoice,
  ): Promise<void> {
    const id = typeof permission.id === 'string' ? permission.id : undefined;
    if (!id || typeof permission.sessionID !== 'string') return;

    const directory = api.state.path.directory || process.cwd();
    const { globalPath, projectPath } = getConfigPaths(directory);

    try {
      if (choice === 'project' || choice === 'global') {
        const update = updateForPermission(permission);
        if (update) writeConfigFile(choice === 'project' ? projectPath : globalPath, update);
      }

      await api.client.permission.reply({
        requestID: id,
        reply: choice === 'reject' ? 'reject' : choice === 'once' ? 'once' : 'always',
      });

      api.ui.toast({
        title: 'Sandbox',
        message: choice === 'reject' ? 'Permission rejected' : `Permission allowed for ${choice}`,
        variant: choice === 'reject' ? 'warning' : 'success',
      });
    } catch {
      api.ui.toast({
        title: 'Sandbox',
        message: 'Permission was already handled or could not be updated',
        variant: 'warning',
      });
    } finally {
      api.ui.dialog.clear();
    }
  }

  function showPermission(permission: Record<string, unknown>): void {
    const id = typeof permission.id === 'string' ? permission.id : undefined;
    if (!id || handledPermissions.has(id)) return;
    handledPermissions.add(id);

    api.ui.dialog.replace(
      () =>
        api.ui.DialogSelect<PermissionChoice>({
          title: 'Sandbox Permission',
          placeholder: permissionLabel(permission),
          options: [
            { title: 'Allow once', value: 'once', description: 'Approve only this request' },
            {
              title: 'Allow for session',
              value: 'session',
              description: 'Use OpenCode session approval for matching requests',
            },
            {
              title: 'Allow for project',
              value: 'project',
              description: 'Persist to .opencode/sandbox.json and approve this session',
            },
            {
              title: 'Allow globally',
              value: 'global',
              description: 'Persist to ~/.config/opencode/sandbox.json and approve this session',
            },
            { title: 'Reject', value: 'reject', description: 'Deny this request' },
          ],
          onSelect: (option) => {
            void replyPermission(permission, option.value);
          },
        }),
      () => api.ui.dialog.clear(),
    );
  }

  api.event.on('permission.asked', (event) => {
    showPermission(event.properties as Record<string, unknown>);
  });

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

  const executeServerCommand = async (command: string): Promise<boolean> => {
    await api.client.tui.executeCommand({ command });
    return true;
  };

  api.keymap.registerLayer({
    commands: [
      {
        namespace: 'palette',
        name: 'sandbox',
        title: 'Sandbox',
        desc: 'Show sandbox configuration',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox',
        run: showSandbox,
      },
      {
        namespace: 'palette',
        name: 'sandbox-disable',
        title: 'Disable sandbox',
        desc: 'Disable sandbox for this session',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox-disable',
        run: () => executeServerCommand('sandbox-disable'),
      },
      {
        namespace: 'palette',
        name: 'sandbox-enable',
        title: 'Enable sandbox',
        desc: 'Re-enable sandbox for this session',
        category: 'Sandbox',
        suggested: true,
        slashName: 'sandbox-enable',
        run: () => executeServerCommand('sandbox-enable'),
      },
    ],
  });
};

export { tui };
export default { tui };
