// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { binaryPath } from '@landstrip/landstrip-api';
import {
  deepMergeSandboxConfig,
  isRecord,
  mergeArray,
  parseSandboxConfig,
} from '@landstrip/landstrip-api/shared';
import type { SandboxConfig, SandboxConfigOverrides } from '@landstrip/landstrip-api/shared';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, isAbsolute, join } from 'node:path';

const packageDir = dirname(fileURLToPath(import.meta.url));

export function normalizeOptions(options: unknown): SandboxConfigOverrides {
  if (!isRecord(options)) return {};
  if (options.config === undefined) return parseSandboxConfig(options);
  if (!isRecord(options.config)) throw new Error('config must be an object');
  return parseSandboxConfig(options.config);
}
export function getConfigPaths(baseDirectory: string): { globalPath: string; projectPath: string } {
  const configHome = process.env.XDG_CONFIG_HOME;
  const configDirectory =
    configHome && isAbsolute(configHome) ? configHome : join(homedir(), '.config');
  return {
    globalPath: join(configDirectory, 'opencode', 'sandbox.json'),
    projectPath: join(baseDirectory, '.opencode', 'sandbox.json'),
  };
}

export function readConfigFile(configPath: string): SandboxConfigOverrides {
  if (!existsSync(configPath)) return {};

  try {
    return parseSandboxConfig(JSON.parse(readFileSync(configPath, 'utf-8')));
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
  templateConfig.filesystem.denyWrite.push(globalPath);
  const globalOverrides = readConfigFile(globalPath);
  const baseConfig = deepMergeSandboxConfig(templateConfig, globalOverrides);

  return deepMergeSandboxConfig(
    deepMergeSandboxConfig(baseConfig, readConfigFile(projectPath)),
    optionOverrides,
  );
}

export function writeConfigFile(configPath: string, update: SandboxConfigOverrides): void {
  const next: Record<string, unknown> = { ...readConfigFile(configPath) };
  for (const [key, value] of Object.entries(parseSandboxConfig(update))) {
    if (!isRecord(value)) {
      next[key] = value;
      continue;
    }

    const previous = next[key];
    const section: Record<string, unknown> = isRecord(previous) ? { ...previous } : {};
    for (const [field, fieldValue] of Object.entries(value)) {
      if (fieldValue === undefined) continue;
      const existing = section[field];
      section[field] = Array.isArray(fieldValue)
        ? mergeArray(Array.isArray(existing) ? existing : [], fieldValue)
        : fieldValue;
    }
    next[key] = section;
  }

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(next, null, 2) + '\n');
}

let _landstripBinaryPath: string | undefined;
let _landstripBinaryPathError: unknown;

export function landstripBinaryPath(): string {
  if (_landstripBinaryPath !== undefined) return _landstripBinaryPath;
  if (_landstripBinaryPathError !== undefined) throw _landstripBinaryPathError;

  try {
    _landstripBinaryPath = binaryPath();
    return _landstripBinaryPath;
  } catch (error) {
    _landstripBinaryPathError = error;
    throw error;
  }
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
