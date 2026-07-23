// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getAgentDir, withFileMutationQueue } from '@earendil-works/pi-coding-agent';

import { formatError, isRecord } from './util.ts';

export type ConfigObject = Record<string, unknown>;

export const MAX_SUBAGENTS = 16;

export type AgentSource = 'built-in' | 'global' | 'local';

export interface LandstripConfigFile {
  maxSubagents?: number;
  subagents?: ConfigObject;
}

export interface LandstripConfig extends LandstripConfigFile {
  maxSubagents: number;
  subagents: ConfigObject;
  agentSources: ReadonlyMap<string, AgentSource>;
}

const packageDir = dirname(fileURLToPath(import.meta.url));

function readConfig(path: string): LandstripConfigFile {
  if (!existsSync(path)) return {};
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    const message = formatError(error);
    throw new Error(`${path}: ${message}`);
  }
  if (!isRecord(value)) throw new Error(`${path} must contain a JSON object`);
  for (const key of Object.keys(value)) {
    if (key !== 'maxSubagents' && key !== 'subagents') {
      throw new Error(`${path}: unknown top-level field ${key}`);
    }
  }
  return value;
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
  includeProject = true,
  agentDir = getAgentDir(),
): Promise<'global' | 'project'> {
  const { projectPath } = getPiConfigPaths(cwd, 'subagents.json', agentDir);
  const scope = includeProject && existsSync(projectPath) ? 'project' : 'global';
  await setMaxSubagentsConfigForScope(cwd, maxSubagents, scope, agentDir);
  return scope;
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
  const { globalPath, projectPath } = getPiConfigPaths(cwd, 'subagents.json', agentDir);
  const path = scope === 'project' ? projectPath : globalPath;
  await withFileMutationQueue(path, async () => {
    const config = readConfig(path);
    config.maxSubagents = maxSubagents;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  });
}

export function loadLandstripConfig(
  cwd: string,
  includeProject = true,
  agentDir = getAgentDir(),
): LandstripConfig {
  const { globalPath, projectPath } = getPiConfigPaths(cwd, 'subagents.json', agentDir);
  const builtInConfig = readConfig(join(packageDir, 'subagents.json'));
  const globalConfig = readConfig(globalPath);
  const projectConfig = includeProject ? readConfig(projectPath) : undefined;
  const agentSources = new Map<string, AgentSource>();
  recordAgentSources(agentSources, builtInConfig, 'built-in');
  recordAgentSources(agentSources, globalConfig, 'global');
  if (projectConfig) recordAgentSources(agentSources, projectConfig, 'local');
  let config = mergeValue(builtInConfig, globalConfig) as LandstripConfigFile;
  if (projectConfig) config = mergeValue(config, projectConfig) as LandstripConfigFile;
  if (
    !Number.isInteger(config.maxSubagents) ||
    (config.maxSubagents ?? -1) < 0 ||
    (config.maxSubagents ?? MAX_SUBAGENTS + 1) > MAX_SUBAGENTS
  ) {
    throw new Error(`maxSubagents must be an integer from 0 to ${MAX_SUBAGENTS}`);
  }
  if (!isRecord(config.subagents)) throw new Error('subagents must be an object');
  return { ...config, agentSources } as LandstripConfig;
}
