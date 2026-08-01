// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { getAgentDir, withFileMutationQueue } from '@earendil-works/pi-coding-agent';

import { BUILT_IN_LANDSTRIP_CONFIG } from './built-in-agents.ts';
import { expandFileReferences, formatError, isRecord } from './util.ts';

export type ConfigObject = Record<string, unknown>;

export const MAX_SUBAGENTS = 16;

export type AgentSource = 'built-in' | 'global' | 'local';

export interface OpenCodeConfig {
  showGlobalAgents: boolean;
  showLocalAgents: boolean;
}

export interface LandstripConfigFile {
  maxSubagents?: number;
  agent?: ConfigObject;
  permission?: unknown;
  opencode?: Partial<OpenCodeConfig>;
}

export interface LandstripConfig extends LandstripConfigFile {
  maxSubagents: number;
  agent: ConfigObject;
  opencode: OpenCodeConfig;
  agentSources: ReadonlyMap<string, AgentSource>;
}

export interface MaxSubagentsSettings {
  readonly global: number;
  readonly project?: number;
}

const DEFAULT_OPENCODE: OpenCodeConfig = {
  showGlobalAgents: true,
  showLocalAgents: true,
};

const LANDSTRIP_KEYS = new Set(['maxSubagents', 'agent', 'permission', 'opencode']);
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
    if (!OPENCODE_KEYS.has(key)) throw new Error(`${path}: unknown field ${key}`);
  }
  const result: Partial<OpenCodeConfig> = {};
  const showGlobalAgents = readBooleanField(value, 'showGlobalAgents', path);
  if (showGlobalAgents !== undefined) result.showGlobalAgents = showGlobalAgents;
  const showLocalAgents = readBooleanField(value, 'showLocalAgents', path);
  if (showLocalAgents !== undefined) result.showLocalAgents = showLocalAgents;
  return result;
}

function readJsonObject(path: string): ConfigObject {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`${path}: ${formatError(error)}`);
  }
  if (!isRecord(value)) throw new Error(`${path} must contain a JSON object`);
  return value;
}

function expandAgentPromptReferences(config: LandstripConfigFile, path: string): void {
  if (!isRecord(config.agent)) return;
  const baseDir = dirname(path);
  for (const [name, value] of Object.entries(config.agent)) {
    if (!isRecord(value) || typeof value.prompt !== 'string' || !value.prompt.includes('{file:')) {
      continue;
    }
    try {
      value.prompt = expandFileReferences(value.prompt, baseDir);
    } catch (error) {
      throw new Error(`${path}: agent ${name}: ${formatError(error)}`);
    }
  }
}

function readLandstripSettings(path: string): LandstripConfigFile {
  if (!existsSync(path)) return {};
  const settings = readJsonObject(path);
  if (settings.landstrip === undefined) return {};
  if (!isRecord(settings.landstrip)) throw new Error(`${path}: landstrip must be a JSON object`);
  for (const key of Object.keys(settings.landstrip)) {
    if (!LANDSTRIP_KEYS.has(key)) throw new Error(`${path}: landstrip has an unknown field ${key}`);
  }

  const config: LandstripConfigFile = {};
  if ('maxSubagents' in settings.landstrip) {
    if (typeof settings.landstrip.maxSubagents !== 'number') {
      throw new Error(`${path}: landstrip.maxSubagents must be a number`);
    }
    config.maxSubagents = settings.landstrip.maxSubagents;
  }
  if ('agent' in settings.landstrip) {
    if (!isRecord(settings.landstrip.agent)) {
      throw new Error(`${path}: landstrip.agent must be an object`);
    }
    config.agent = settings.landstrip.agent;
  }
  if ('permission' in settings.landstrip) config.permission = settings.landstrip.permission;
  config.opencode = normalizeOpenCode(settings.landstrip.opencode, `${path}: landstrip.opencode`);
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
  if (!isRecord(config.agent)) return;
  for (const name of Object.keys(config.agent)) sources.set(name, source);
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
  includeProject = true,
  agentDir = getAgentDir(),
): Promise<'global' | 'project'> {
  const scope = includeProject ? 'project' : 'global';
  await setMaxSubagentsConfigForScope(cwd, maxSubagents, scope, agentDir);
  return scope;
}

async function updateLandstripSettingsForScope(
  cwd: string,
  scope: 'global' | 'project',
  agentDir: string,
  update: (landstrip: ConfigObject) => void,
): Promise<void> {
  const paths = getPiConfigPaths(cwd, 'settings.json', agentDir);
  const path = scope === 'global' ? paths.globalPath : paths.projectPath;
  await withFileMutationQueue(path, async () => {
    const settings = existsSync(path) ? readJsonObject(path) : {};
    if (settings.landstrip !== undefined && !isRecord(settings.landstrip)) {
      throw new Error(`${path}: landstrip must be a JSON object`);
    }
    const landstrip = isRecord(settings.landstrip) ? { ...settings.landstrip } : {};
    update(landstrip);
    if (Object.keys(landstrip).length === 0) delete settings.landstrip;
    else settings.landstrip = landstrip;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
  });
}

async function writeMaxSubagentsConfigForScope(
  cwd: string,
  maxSubagents: number | undefined,
  scope: 'global' | 'project',
  agentDir: string,
): Promise<void> {
  await updateLandstripSettingsForScope(cwd, scope, agentDir, (landstrip) => {
    if (maxSubagents === undefined) delete landstrip.maxSubagents;
    else landstrip.maxSubagents = maxSubagents;
  });
}

export async function setMaxSubagentsConfigForScope(
  cwd: string,
  maxSubagents: number,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  if (!Number.isInteger(maxSubagents) || maxSubagents < 0 || maxSubagents > MAX_SUBAGENTS) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  await writeMaxSubagentsConfigForScope(cwd, maxSubagents, scope, agentDir);
}

export async function clearMaxSubagentsConfigForScope(
  cwd: string,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  await writeMaxSubagentsConfigForScope(cwd, undefined, scope, agentDir);
}

export async function setAgentDisabledForScope(
  cwd: string,
  name: string,
  disabled: boolean,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  await updateLandstripSettingsForScope(cwd, scope, agentDir, (landstrip) => {
    if (landstrip.agent !== undefined && !isRecord(landstrip.agent)) {
      throw new Error('landstrip.agent must be an object');
    }
    const agents = isRecord(landstrip.agent) ? { ...landstrip.agent } : {};
    const configured = agents[name];
    if (configured !== undefined && !isRecord(configured)) {
      throw new Error(`agent ${name} must be an object`);
    }
    agents[name] = { ...(isRecord(configured) ? configured : {}), disable: disabled };
    landstrip.agent = agents;
  });
}

export async function clearAgentDisabledForScope(
  cwd: string,
  name: string,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  await updateLandstripSettingsForScope(cwd, scope, agentDir, (landstrip) => {
    if (!isRecord(landstrip.agent)) return;
    const agents = { ...landstrip.agent };
    const configured = agents[name];
    if (!isRecord(configured)) return;
    const agent = { ...configured };
    delete agent.disable;
    if (Object.keys(agent).length === 0) delete agents[name];
    else agents[name] = agent;
    if (Object.keys(agents).length === 0) delete landstrip.agent;
    else landstrip.agent = agents;
  });
}

export function loadAgentDisabledOverrides(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): { global: ReadonlyMap<string, boolean>; project: ReadonlyMap<string, boolean> } {
  const paths = getPiConfigPaths(cwd, 'settings.json', agentDir);
  const read = (path: string): ReadonlyMap<string, boolean> => {
    const result = new Map<string, boolean>();
    const agents = readLandstripSettings(path).agent;
    if (!isRecord(agents)) return result;
    for (const [name, configured] of Object.entries(agents)) {
      if (isRecord(configured) && typeof configured.disable === 'boolean') {
        result.set(name, configured.disable);
      }
    }
    return result;
  };
  return {
    global: read(paths.globalPath),
    project: includeProject ? read(paths.projectPath) : new Map(),
  };
}

export function loadLandstripConfig(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): LandstripConfig {
  const settingsPaths = getPiConfigPaths(cwd, 'settings.json', agentDir);

  const builtInConfig = BUILT_IN_LANDSTRIP_CONFIG as LandstripConfigFile;
  const globalConfig = readLandstripSettings(settingsPaths.globalPath);
  const projectConfig = includeProject
    ? readLandstripSettings(settingsPaths.projectPath)
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
  if (!isRecord(config.agent)) throw new Error('landstrip.agent must be an object');
  const opencode: OpenCodeConfig = { ...DEFAULT_OPENCODE, ...config.opencode };
  return { ...config, maxSubagents, agent: config.agent, opencode, agentSources };
}

export function loadMaxSubagentsSettings(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): MaxSubagentsSettings {
  const global = loadLandstripConfig(cwd, false, agentDir).maxSubagents;
  if (!includeProject) return { global };

  const paths = getPiConfigPaths(cwd, 'settings.json', agentDir);
  const project = readLandstripSettings(paths.projectPath).maxSubagents;
  if (
    project !== undefined &&
    (!Number.isInteger(project) || project < 0 || project > MAX_SUBAGENTS)
  ) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  return { global, project };
}
