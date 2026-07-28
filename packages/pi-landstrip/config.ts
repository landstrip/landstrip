// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getAgentDir, withFileMutationQueue } from '@earendil-works/pi-coding-agent';

import { expandFileReferences, formatError, isRecord } from './util.ts';

export type ConfigObject = Record<string, unknown>;

export const MAX_SUBAGENTS = 16;

export type AgentSource = 'built-in' | 'global' | 'local';

type ConfigScope = 'built-in' | 'global' | 'project';

export interface OpenCodeConfig {
  showGlobalAgents: boolean;
  showLocalAgents: boolean;
}

export interface LandstripConfigFile {
  maxSubagents?: number;
  subagents?: ConfigObject;
}

export interface LandstripConfig extends LandstripConfigFile {
  maxSubagents: number;
  opencode: OpenCodeConfig;
  subagents: ConfigObject;
  agentSources: ReadonlyMap<string, AgentSource>;
}

const packageDir = dirname(fileURLToPath(import.meta.url));

const DEFAULT_OPENCODE: OpenCodeConfig = {
  showGlobalAgents: true,
  showLocalAgents: true,
};

const OPENCODE_KEYS = new Set(['showGlobalAgents', 'showLocalAgents']);

function readBooleanField(
  section: Record<string, unknown>,
  key: string,
  path: string,
): boolean | undefined {
  if (!(key in section)) return undefined;
  const value = section[key];
  if (typeof value === 'boolean') return value;
  throw new Error(`${path}.${key} must be a boolean`);
}

function normalizeOpenCode(value: unknown, path: string): Partial<OpenCodeConfig> {
  if (value === undefined) return {};
  if (!isRecord(value)) throw new Error(`${path} must be a JSON object`);
  for (const key of Object.keys(value)) {
    if (!OPENCODE_KEYS.has(key)) {
      throw new Error(`${path}: unknown field ${key}`);
    }
  }
  const result: Partial<OpenCodeConfig> = {};
  const showGlobalAgents = readBooleanField(value, 'showGlobalAgents', path);
  if (showGlobalAgents !== undefined) result.showGlobalAgents = showGlobalAgents;
  const showLocalAgents = readBooleanField(value, 'showLocalAgents', path);
  if (showLocalAgents !== undefined) result.showLocalAgents = showLocalAgents;
  return result;
}

function readOpenCodeSettings(path: string): Partial<OpenCodeConfig> {
  if (!existsSync(path)) return {};
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${path}: ${formatError(error)}`);
  }
  if (!isRecord(value)) throw new Error(`${path} must contain a JSON object`);
  if (value.landstrip === undefined) return {};
  if (!isRecord(value.landstrip)) throw new Error(`${path}: landstrip must be a JSON object`);
  return normalizeOpenCode(value.landstrip.opencode, `${path}: landstrip.opencode`);
}

function expandAgentPromptReferences(config: LandstripConfigFile, path: string): void {
  if (!isRecord(config.subagents) || !isRecord(config.subagents.agent)) return;
  const baseDir = dirname(path);
  for (const [name, value] of Object.entries(config.subagents.agent)) {
    if (!isRecord(value) || typeof value.prompt !== 'string') continue;
    if (!value.prompt.includes('{file:')) continue;
    try {
      value.prompt = expandFileReferences(value.prompt, baseDir);
    } catch (error) {
      throw new Error(`${path}: agent ${name}: ${formatError(error)}`);
    }
  }
}

function readConfig(path: string, scope: ConfigScope = 'project'): LandstripConfigFile {
  if (!existsSync(path)) return {};
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    const message = formatError(error);
    throw new Error(`${path}: ${message}`);
  }
  if (!isRecord(value)) throw new Error(`${path} must contain a JSON object`);
  if ('opencode' in value) {
    const settingsPath = join(dirname(path), 'settings.json');
    throw new Error(
      `${path}: opencode has moved; set landstrip.opencode in ${settingsPath} and remove it from subagents.json`,
    );
  }
  for (const key of Object.keys(value)) {
    if (key !== 'maxSubagents' && key !== 'subagents') {
      throw new Error(`${path}: unknown top-level field ${key}`);
    }
  }
  if (scope === 'project' && 'maxSubagents' in value) {
    throw new Error(`${path}: maxSubagents is only allowed in global subagents.json`);
  }
  const config: LandstripConfigFile = {};
  if ('maxSubagents' in value) {
    if (typeof value.maxSubagents !== 'number') {
      throw new Error(`${path}: maxSubagents must be a number`);
    }
    config.maxSubagents = value.maxSubagents;
  }
  if ('subagents' in value) {
    if (!isRecord(value.subagents)) {
      throw new Error(`${path}: subagents must be an object`);
    }
    config.subagents = value.subagents;
  }
  expandAgentPromptReferences(config, path);
  return config;
}

function mergeValue(base: unknown, override: unknown): unknown {
  if (override === undefined) return base;
  if (Array.isArray(override)) return [...override];
  if (isRecord(base) && isRecord(override)) {
    const result: ConfigObject = { ...base };
    for (const [key, value] of Object.entries(override)) {
      const merged = mergeValue(result[key], value);
      delete result[key];
      result[key] = merged;
    }
    return result;
  }
  return override;
}

function recordAgentSources(
  sources: Map<string, AgentSource>,
  config: LandstripConfigFile,
  source: AgentSource,
): void {
  if (!isRecord(config.subagents) || !isRecord(config.subagents.agent)) return;
  for (const name of Object.keys(config.subagents.agent)) sources.set(name, source);
}

export function getPiConfigPaths(
  cwd: string,
  fileName: string,
  agentDir = getAgentDir(),
): { globalPath: string; projectPath: string } {
  return {
    globalPath: join(agentDir, fileName),
    projectPath: join(cwd, '.pi', fileName),
  };
}

export async function setMaxSubagentsConfig(
  cwd: string,
  maxSubagents: number,
  _includeProject = true,
  agentDir = getAgentDir(),
): Promise<'global'> {
  await setMaxSubagentsConfigForScope(cwd, maxSubagents, 'global', agentDir);
  return 'global';
}

export async function setMaxSubagentsConfigForScope(
  cwd: string,
  maxSubagents: number,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  if (scope !== 'global') {
    throw new Error('maxSubagents is only allowed in global subagents.json');
  }
  if (!Number.isInteger(maxSubagents) || maxSubagents < 0 || maxSubagents > MAX_SUBAGENTS) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  const { globalPath } = getPiConfigPaths(cwd, 'subagents.json', agentDir);
  await withFileMutationQueue(globalPath, async () => {
    const config = readConfig(globalPath, 'global');
    config.maxSubagents = maxSubagents;
    mkdirSync(dirname(globalPath), { recursive: true });
    writeFileSync(globalPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  });
}

export function loadLandstripConfig(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): LandstripConfig {
  const subagentPaths = getPiConfigPaths(cwd, 'subagents.json', agentDir);
  const settingsPaths = getPiConfigPaths(cwd, 'settings.json', agentDir);
  const builtInConfig = readConfig(join(packageDir, 'subagents.json'), 'built-in');
  const globalConfig = readConfig(subagentPaths.globalPath, 'global');
  const projectConfig = includeProject
    ? readConfig(subagentPaths.projectPath, 'project')
    : undefined;
  const globalOpenCode = readOpenCodeSettings(settingsPaths.globalPath);
  const projectOpenCode = includeProject
    ? readOpenCodeSettings(settingsPaths.projectPath)
    : undefined;
  const agentSources = new Map<string, AgentSource>();
  recordAgentSources(agentSources, builtInConfig, 'built-in');
  recordAgentSources(agentSources, globalConfig, 'global');
  if (projectConfig) recordAgentSources(agentSources, projectConfig, 'local');
  let config = mergeValue(builtInConfig, globalConfig) as LandstripConfigFile;
  if (projectConfig) config = mergeValue(config, projectConfig) as LandstripConfigFile;
  const maxSubagents = config.maxSubagents ?? 0;
  if (!Number.isInteger(maxSubagents) || maxSubagents < 0 || maxSubagents > MAX_SUBAGENTS) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  if (!isRecord(config.subagents)) throw new Error('subagents must be an object');
  const opencode: OpenCodeConfig = {
    ...DEFAULT_OPENCODE,
    ...globalOpenCode,
    ...projectOpenCode,
  };
  return { ...config, maxSubagents, opencode, agentSources } as LandstripConfig;
}
