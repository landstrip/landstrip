// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, extname, join, relative, sep } from 'node:path';

import { parse as parseYaml } from 'yaml';

import type { AgentSource, ConfigObject } from './config.ts';
import { formatError, isRecord } from './util.ts';

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
  const base = basename(filePath);
  const extension = extname(base);
  return extension.length > 0 ? base.slice(0, -extension.length) : base;
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

function loadAgentsFromDir(
  dir: string,
  source: AgentSource,
  agents: Map<string, OpenCodeAgentRaw>,
  diagnostics: string[],
): void {
  for (const subdir of ['agent', 'agents']) {
    const root = join(dir, subdir);
    for (const filePath of listMarkdownFiles(root)) {
      try {
        const content = readFileSync(filePath, 'utf8');
        const { data, body } = parseFrontmatter(content);
        const name = agentNameFromPath(dir, filePath);
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
    loadAgentsFromDir(
      options.globalConfigDir ?? openCodeGlobalConfigDir(),
      'global',
      agents,
      diagnostics,
    );
  }
  if (options.includeProject) {
    loadAgentsFromDir(join(options.cwd, '.opencode'), 'local', agents, diagnostics);
  }
  return { agents, diagnostics };
}
