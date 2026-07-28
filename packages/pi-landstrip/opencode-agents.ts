// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, extname, join, relative, sep } from 'node:path';

import { parse as parseYaml } from 'yaml';
import { parse as parseJsonc, printParseErrorCode, type ParseError } from 'jsonc-parser';

import type { AgentSource, ConfigObject } from './config.ts';
import { expandFileReferences, formatError, isRecord } from './util.ts';

export interface OpenCodeAgentRaw {
  readonly name: string;
  readonly source: AgentSource;
  readonly path: string;
  readonly raw: ConfigObject;
}

export interface OpenCodeAgentLoadResult {
  readonly agents: ReadonlyMap<string, OpenCodeAgentRaw>;
  readonly diagnostics: readonly string[];
}

const AGENT_DIR_PREFIXES = ['agent/', 'agents/'] as const;

function openCodeGlobalConfigDir(): string {
  if (process.env.OPENCODE_CONFIG_DIR) return process.env.OPENCODE_CONFIG_DIR;
  const xdg = process.env.XDG_CONFIG_HOME;
  return join(xdg && xdg.length > 0 ? xdg : join(homedir(), '.config'), 'opencode');
}

function listMarkdownFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const results: string[] = [];
  const visit = (dir: string): void => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(dir, entry);
      let stats;
      try {
        stats = statSync(path);
      } catch {
        continue;
      }
      if (stats.isDirectory()) visit(path);
      else if (stats.isFile() && extname(entry).toLowerCase() === '.md') results.push(path);
    }
  };
  visit(root);
  return results;
}

function agentNameFromPath(dir: string, filePath: string): string {
  const relativePath = relative(dir, filePath).split(sep).join('/');
  for (const prefix of AGENT_DIR_PREFIXES) {
    if (relativePath.startsWith(prefix)) {
      const candidate = relativePath.slice(prefix.length);
      const extension = extname(candidate);
      return extension.length > 0 ? candidate.slice(0, -extension.length) : candidate;
    }
  }
  const extension = extname(relativePath);
  return extension.length > 0 ? relativePath.slice(0, -extension.length) : relativePath;
}

function parseFrontmatter(content: string): { data: ConfigObject; body: string } {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n([\s\S]*))?$/);
  if (!match) return { data: {}, body: content };
  const parsed: unknown = parseYaml(match[1] ?? '');
  if (parsed === null || parsed === undefined) return { data: {}, body: match[2] ?? '' };
  if (!isRecord(parsed)) throw new Error('frontmatter must be a YAML mapping');
  return { data: { ...parsed }, body: match[2] ?? '' };
}

function convertToolsToPermission(tools: unknown): ConfigObject {
  if (!isRecord(tools)) throw new Error('tools must be a map of booleans');
  const permission: ConfigObject = {};
  for (const [tool, enabled] of Object.entries(tools)) {
    if (typeof enabled !== 'boolean') {
      throw new Error(`tools.${tool} must be a boolean`);
    }
    const action = enabled ? 'allow' : 'deny';
    if (tool === 'write' || tool === 'edit' || tool === 'patch') {
      permission.edit = action;
      continue;
    }
    permission[tool] = action;
  }
  return permission;
}

/** Normalize OpenCode markdown agent fields into pi-landstrip agent shape. */
export function normalizeOpenCodeAgentRaw(data: ConfigObject, prompt: string): ConfigObject {
  const known = new Set([
    'name',
    'model',
    'variant',
    'prompt',
    'description',
    'temperature',
    'top_p',
    'mode',
    'hidden',
    'color',
    'steps',
    'maxSteps',
    'options',
    'permission',
    'disable',
    'tools',
  ]);

  const options: ConfigObject = isRecord(data.options) ? { ...data.options } : {};
  for (const [key, value] of Object.entries(data)) {
    if (!known.has(key)) options[key] = value;
  }

  let permission: ConfigObject = {};
  if (data.tools !== undefined) {
    permission = convertToolsToPermission(data.tools);
  }
  if (data.permission !== undefined) {
    if (!isRecord(data.permission)) throw new Error('permission must be an object');
    permission = { ...permission, ...data.permission };
  }

  const steps = data.steps ?? data.maxSteps;
  const raw: ConfigObject = {
    description: data.description,
    prompt,
    mode: data.mode,
    model: data.model,
    variant: data.variant,
    hidden: data.hidden,
    disable: data.disable,
    color: data.color,
    temperature: data.temperature,
    top_p: data.top_p,
  };
  if (steps !== undefined) raw.steps = steps;
  if (Object.keys(permission).length > 0) raw.permission = permission;
  if (Object.keys(options).length > 0) raw.options = options;

  for (const key of Object.keys(raw)) {
    if (raw[key] === undefined) delete raw[key];
  }
  return raw;
}

function parseOpenCodeConfig(path: string): ConfigObject {
  const errors: ParseError[] = [];
  const value: unknown = parseJsonc(readFileSync(path, 'utf8'), errors, {
    allowTrailingComma: true,
  });
  if (errors.length > 0) {
    const error = errors[0];
    throw new Error(`${printParseErrorCode(error.error)} at offset ${error.offset}`);
  }
  if (!isRecord(value)) throw new Error('config must contain a JSON object');
  return value;
}

function loadAgentsFromConfigFile(
  path: string,
  source: AgentSource,
  agents: Map<string, OpenCodeAgentRaw>,
  diagnostics: string[],
): void {
  if (!existsSync(path)) return;
  try {
    const config = parseOpenCodeConfig(path);
    if (config.agent === undefined) return;
    if (!isRecord(config.agent)) throw new Error('agent must be a JSON object');
    for (const [name, value] of Object.entries(config.agent)) {
      try {
        if (!name) throw new Error('agent name is empty');
        if (!isRecord(value)) throw new Error(`agent ${name} must be a JSON object`);
        if (value.prompt !== undefined && typeof value.prompt !== 'string') {
          throw new Error(`agent ${name} prompt must be a string`);
        }
        const prompt =
          typeof value.prompt === 'string' ? expandFileReferences(value.prompt, dirname(path)) : '';
        const raw = normalizeOpenCodeAgentRaw(value, prompt);
        agents.set(name, { name, source, path, raw });
      } catch (error) {
        diagnostics.push(`${path}: ${formatError(error)}`);
      }
    }
  } catch (error) {
    diagnostics.push(`${path}: ${formatError(error)}`);
  }
}

function loadConfigAgentsFromDir(
  dir: string,
  source: AgentSource,
  agents: Map<string, OpenCodeAgentRaw>,
  diagnostics: string[],
): void {
  for (const file of ['opencode.json', 'opencode.jsonc']) {
    loadAgentsFromConfigFile(join(dir, file), source, agents, diagnostics);
  }
}

function loadAgentsFromRoot(
  root: string,
  nameRoot: string,
  source: AgentSource,
  agents: Map<string, OpenCodeAgentRaw>,
  diagnostics: string[],
): void {
  for (const filePath of listMarkdownFiles(root)) {
    try {
      const content = readFileSync(filePath, 'utf8');
      const { data, body } = parseFrontmatter(content);
      const name = agentNameFromPath(nameRoot, filePath);
      if (!name) {
        diagnostics.push(`${filePath}: agent name is empty`);
        continue;
      }
      const raw = normalizeOpenCodeAgentRaw(data, body.trim());
      agents.set(name, { name, source, path: filePath, raw });
    } catch (error) {
      diagnostics.push(`${filePath}: ${formatError(error)}`);
    }
  }
}

function loadAgentsFromDir(
  dir: string,
  source: AgentSource,
  agents: Map<string, OpenCodeAgentRaw>,
  diagnostics: string[],
): void {
  for (const subdir of ['agent', 'agents']) {
    loadAgentsFromRoot(join(dir, subdir), dir, source, agents, diagnostics);
  }
}

export function loadPiMarkdownAgents(options: {
  directories: readonly { path: string; source: AgentSource }[];
}): OpenCodeAgentLoadResult {
  const agents = new Map<string, OpenCodeAgentRaw>();
  const diagnostics: string[] = [];
  for (const directory of options.directories) {
    loadAgentsFromRoot(directory.path, directory.path, directory.source, agents, diagnostics);
  }
  return { agents, diagnostics };
}

export function loadOpenCodeAgents(options: {
  cwd: string;
  includeGlobal: boolean;
  includeProject: boolean;
  globalConfigDir?: string;
}): OpenCodeAgentLoadResult {
  const agents = new Map<string, OpenCodeAgentRaw>();
  const diagnostics: string[] = [];
  if (options.includeGlobal) {
    const globalDir = options.globalConfigDir ?? openCodeGlobalConfigDir();
    loadConfigAgentsFromDir(globalDir, 'global', agents, diagnostics);
    loadAgentsFromDir(globalDir, 'global', agents, diagnostics);
  }
  if (options.includeProject) {
    loadConfigAgentsFromDir(options.cwd, 'local', agents, diagnostics);
    const projectDir = join(options.cwd, '.opencode');
    loadConfigAgentsFromDir(projectDir, 'local', agents, diagnostics);
    loadAgentsFromDir(projectDir, 'local', agents, diagnostics);
  }
  return { agents, diagnostics };
}
