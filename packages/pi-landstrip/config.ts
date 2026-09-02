// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { getAgentDir, withFileMutationQueue } from '@earendil-works/pi-coding-agent';
import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import {
  applyEdits,
  modify,
  parse as parseJsonc,
  printParseErrorCode,
  type ParseError,
} from 'jsonc-parser';

import { BUILT_IN_LANDSTRIP_CONFIG } from './built-in-agents.ts';
import { expandFileReferences, formatError, isRecord } from './util.ts';

export type ConfigObject = Record<string, unknown>;

export function isProjectTrusted(ctx: ExtensionContext): boolean {
  const trustContext = ctx as ExtensionContext & { isProjectTrusted?: () => boolean };
  return trustContext.isProjectTrusted?.() ?? false;
}

export const MAX_SUBAGENTS = 16;

export type AgentSource = 'built-in' | 'global' | 'local';
export type ToolFilesystemPolicy = 'host' | 'sandbox';
export type LandstripConfigKind = 'dedicated' | 'settings';

export interface LandstripConfigTarget {
  readonly path: string;
  readonly kind: LandstripConfigKind;
}

export interface LandstripConfigFile {
  maxSubagents?: number;
  agent?: ConfigObject;
  permission?: unknown;
  toolFilesystemPolicy?: ToolFilesystemPolicy;
}

export interface LandstripConfig extends LandstripConfigFile {
  maxSubagents: number;
  agent: ConfigObject;
  toolFilesystemPolicy: ToolFilesystemPolicy;
  agentSources: ReadonlyMap<string, AgentSource>;
  agentPaths: ReadonlyMap<string, string>;
}

export interface MaxSubagentsSettings {
  readonly global: number;
  readonly project?: number;
}

export interface ToolFilesystemPolicySettings {
  readonly global: ToolFilesystemPolicy;
  readonly project?: ToolFilesystemPolicy;
}

interface LandstripConfigSource extends LandstripConfigTarget {
  readonly config: LandstripConfigFile;
}

const LANDSTRIP_KEYS = ['maxSubagents', 'agent', 'permission', 'toolFilesystemPolicy'] as const;
const JSON_FORMAT = { formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' } };

function ensureFinalNewline(content: string): string {
  return content.endsWith('\n') ? content : `${content}\n`;
}

function readJsonObject(path: string): ConfigObject {
  let content: string;
  try {
    content = readFileSync(path, 'utf8');
  } catch (error) {
    throw new Error(`${path}: ${formatError(error)}`);
  }
  const errors: ParseError[] = [];
  const value: unknown = parseJsonc(content, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    const error = errors[0]!;
    throw new Error(`${path}: ${printParseErrorCode(error.error)} at offset ${error.offset}`);
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

function parseLandstripConfig(
  value: unknown,
  path: string,
  kind: LandstripConfigKind,
): LandstripConfigFile {
  const label = kind === 'settings' ? 'landstrip' : 'configuration';
  if (!isRecord(value)) throw new Error(`${path}: ${label} must be a JSON object`);
  for (const key of Object.keys(value)) {
    if (!(LANDSTRIP_KEYS as readonly string[]).includes(key)) {
      throw new Error(`${path}: ${label} has an unknown field ${key}`);
    }
  }

  const field = (name: string): string => (kind === 'settings' ? `landstrip.${name}` : name);
  const config: LandstripConfigFile = {};
  if ('maxSubagents' in value) {
    if (typeof value.maxSubagents !== 'number') {
      throw new Error(`${path}: ${field('maxSubagents')} must be a number`);
    }
    config.maxSubagents = value.maxSubagents;
  }
  if ('agent' in value) {
    if (!isRecord(value.agent)) throw new Error(`${path}: ${field('agent')} must be an object`);
    config.agent = value.agent;
  }
  if ('permission' in value) config.permission = value.permission;
  if ('toolFilesystemPolicy' in value) {
    if (value.toolFilesystemPolicy !== 'host' && value.toolFilesystemPolicy !== 'sandbox') {
      throw new Error(`${path}: ${field('toolFilesystemPolicy')} must be host or sandbox`);
    }
    config.toolFilesystemPolicy = value.toolFilesystemPolicy;
  }
  return config;
}

function readLandstripConfigSource(
  cwd: string,
  scope: 'global' | 'project',
  agentDir: string,
): LandstripConfigSource {
  const settingsPaths = getPiConfigPaths(cwd, 'settings.json', agentDir);
  const dedicatedPaths = getPiConfigPaths(cwd, 'landstrip.json', agentDir);
  const settingsPath = scope === 'global' ? settingsPaths.globalPath : settingsPaths.projectPath;
  const dedicatedPath = scope === 'global' ? dedicatedPaths.globalPath : dedicatedPaths.projectPath;
  const settings = existsSync(settingsPath) ? readJsonObject(settingsPath) : undefined;
  const hasSettingsConfig = settings?.landstrip !== undefined;
  const hasDedicatedConfig = existsSync(dedicatedPath);

  if (hasSettingsConfig && hasDedicatedConfig) {
    throw new Error(
      `Landstrip configuration is defined in both ${settingsPath} and ${dedicatedPath}`,
    );
  }
  if (hasDedicatedConfig) {
    return {
      path: dedicatedPath,
      kind: 'dedicated',
      config: parseLandstripConfig(readJsonObject(dedicatedPath), dedicatedPath, 'dedicated'),
    };
  }
  if (hasSettingsConfig) {
    return {
      path: settingsPath,
      kind: 'settings',
      config: parseLandstripConfig(settings!.landstrip, settingsPath, 'settings'),
    };
  }
  return { path: dedicatedPath, kind: 'dedicated', config: {} };
}

export function getLandstripConfigTarget(
  cwd: string,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): LandstripConfigTarget {
  const { path, kind } = readLandstripConfigSource(cwd, scope, agentDir);
  return { path, kind };
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
  paths: Map<string, string>,
  config: LandstripConfigFile,
  source: AgentSource,
  path?: string,
): void {
  if (!isRecord(config.agent)) return;
  for (const name of Object.keys(config.agent)) {
    sources.set(name, source);
    if (path) paths.set(name, path);
    else paths.delete(name);
  }
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

async function updateLandstripConfigForScope(
  cwd: string,
  scope: 'global' | 'project',
  agentDir: string,
  update: (landstrip: ConfigObject) => void,
): Promise<void> {
  const target = getLandstripConfigTarget(cwd, scope, agentDir);
  await withFileMutationQueue(target.path, async () => {
    const source = readLandstripConfigSource(cwd, scope, agentDir);
    if (source.path !== target.path || source.kind !== target.kind) {
      throw new Error(`Landstrip ${scope} configuration source changed while updating it`);
    }

    const landstrip = { ...source.config };
    update(landstrip);
    const empty = Object.keys(landstrip).length === 0;
    if (source.kind === 'dedicated' && empty) {
      if (existsSync(source.path)) unlinkSync(source.path);
      return;
    }

    let content = existsSync(source.path) ? readFileSync(source.path, 'utf8') : '{}\n';
    if (source.kind === 'settings' && empty) {
      content = applyEdits(content, modify(content, ['landstrip'], undefined, JSON_FORMAT));
    } else {
      const root = source.kind === 'settings' ? ['landstrip'] : [];
      for (const key of LANDSTRIP_KEYS) {
        if (source.config[key] === landstrip[key]) continue;
        content = applyEdits(content, modify(content, [...root, key], landstrip[key], JSON_FORMAT));
      }
    }
    mkdirSync(dirname(source.path), { recursive: true });
    writeFileSync(source.path, ensureFinalNewline(content), { mode: 0o600 });
  });
}

async function writeMaxSubagentsConfigForScope(
  cwd: string,
  maxSubagents: number | undefined,
  scope: 'global' | 'project',
  agentDir: string,
): Promise<void> {
  await updateLandstripConfigForScope(cwd, scope, agentDir, (landstrip) => {
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

async function writeToolFilesystemPolicyConfigForScope(
  cwd: string,
  policy: ToolFilesystemPolicy | undefined,
  scope: 'global' | 'project',
  agentDir: string,
): Promise<void> {
  await updateLandstripConfigForScope(cwd, scope, agentDir, (landstrip) => {
    if (policy === undefined) delete landstrip.toolFilesystemPolicy;
    else landstrip.toolFilesystemPolicy = policy;
  });
}

export async function setToolFilesystemPolicyConfigForScope(
  cwd: string,
  policy: ToolFilesystemPolicy,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  if (policy !== 'host' && policy !== 'sandbox') {
    throw new Error('toolFilesystemPolicy must be host or sandbox');
  }
  await writeToolFilesystemPolicyConfigForScope(cwd, policy, scope, agentDir);
}

export async function clearToolFilesystemPolicyConfigForScope(
  cwd: string,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  await writeToolFilesystemPolicyConfigForScope(cwd, undefined, scope, agentDir);
}

export async function setAgentDisabledForScope(
  cwd: string,
  name: string,
  disabled: boolean,
  scope: 'global' | 'project',
  agentDir = getAgentDir(),
): Promise<void> {
  await updateLandstripConfigForScope(cwd, scope, agentDir, (landstrip) => {
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
  await updateLandstripConfigForScope(cwd, scope, agentDir, (landstrip) => {
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
  const read = (scope: 'global' | 'project'): ReadonlyMap<string, boolean> => {
    const result = new Map<string, boolean>();
    const agents = readLandstripConfigSource(cwd, scope, agentDir).config.agent;
    if (!isRecord(agents)) return result;
    for (const [name, configured] of Object.entries(agents)) {
      if (isRecord(configured) && typeof configured.disable === 'boolean') {
        result.set(name, configured.disable);
      }
    }
    return result;
  };
  return {
    global: read('global'),
    project: includeProject ? read('project') : new Map(),
  };
}

export function loadLandstripConfig(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): LandstripConfig {
  const globalSource = readLandstripConfigSource(cwd, 'global', agentDir);
  const projectSource = includeProject
    ? readLandstripConfigSource(cwd, 'project', agentDir)
    : undefined;
  const builtInConfig = BUILT_IN_LANDSTRIP_CONFIG as LandstripConfigFile;
  const globalConfig = globalSource.config;
  const projectConfig = projectSource?.config;
  expandAgentPromptReferences(globalConfig, globalSource.path);
  if (projectConfig && projectSource)
    expandAgentPromptReferences(projectConfig, projectSource.path);

  const agentSources = new Map<string, AgentSource>();
  const agentPaths = new Map<string, string>();
  recordAgentSources(agentSources, agentPaths, builtInConfig, 'built-in');
  recordAgentSources(agentSources, agentPaths, globalConfig, 'global', globalSource.path);
  if (projectConfig && projectSource) {
    recordAgentSources(agentSources, agentPaths, projectConfig, 'local', projectSource.path);
  }

  let config = mergeValue(builtInConfig, globalConfig) as LandstripConfigFile;
  if (projectConfig) config = mergeValue(config, projectConfig) as LandstripConfigFile;
  const maxSubagents = config.maxSubagents ?? 0;
  const toolFilesystemPolicy = config.toolFilesystemPolicy ?? 'host';
  if (!Number.isInteger(maxSubagents) || maxSubagents < 0 || maxSubagents > MAX_SUBAGENTS) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  if (!isRecord(config.agent)) throw new Error('landstrip.agent must be an object');
  return {
    ...config,
    maxSubagents,
    agent: config.agent,
    toolFilesystemPolicy,
    agentSources,
    agentPaths,
  };
}

export function loadMaxSubagentsSettings(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): MaxSubagentsSettings {
  const global = loadLandstripConfig(cwd, false, agentDir).maxSubagents;
  if (!includeProject) return { global };

  const project = readLandstripConfigSource(cwd, 'project', agentDir).config.maxSubagents;
  if (
    project !== undefined &&
    (!Number.isInteger(project) || project < 0 || project > MAX_SUBAGENTS)
  ) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  return { global, project };
}

export function loadToolFilesystemPolicySettings(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): ToolFilesystemPolicySettings {
  const global = loadLandstripConfig(cwd, false, agentDir).toolFilesystemPolicy;
  if (!includeProject) return { global };

  const project = readLandstripConfigSource(cwd, 'project', agentDir).config.toolFilesystemPolicy;
  if (project !== undefined && project !== 'host' && project !== 'sandbox') {
    throw new Error('toolFilesystemPolicy must be host or sandbox');
  }
  return { global, project };
}
