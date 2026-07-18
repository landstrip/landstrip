// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { minimatch } from 'minimatch';
import { getAgentDir } from '@earendil-works/pi-coding-agent';

import { loadLandstripConfig, type ConfigObject } from './config.ts';
import { expandHomePath, formatError, isRecord } from './util.ts';

export type PermissionAction = 'allow' | 'ask' | 'deny';

export interface PermissionRule {
  readonly permission: string;
  readonly pattern: string;
  readonly action: PermissionAction;
}

export type PermissionRules = readonly PermissionRule[];

export interface AgentDefinition {
  readonly name: string;
  readonly description?: string;
  readonly prompt: string;
  readonly mode: 'primary' | 'subagent' | 'all';
  readonly model?: string;
  readonly variant?: string;
  readonly hidden: boolean;
  readonly steps?: number;
  readonly permissions: PermissionRules;
  readonly providerOptions: Readonly<Record<string, unknown>>;
}

export interface AgentCatalog {
  readonly agents: ReadonlyMap<string, AgentDefinition>;
  readonly permissions: PermissionRules;
  readonly diagnostics: readonly string[];
  readonly warnings: readonly string[];
  readonly maxSubagents: number;
}

const AGENT_FIELDS = new Set([
  'name',
  'description',
  'prompt',
  'mode',
  'model',
  'variant',
  'hidden',
  'disable',
  'steps',
  'permission',
  'temperature',
  'top_p',
  'options',
  'color',
]);

function normalizeAbsolutePath(value: string): string {
  return /^(?:[A-Za-z]:[\\/]|\\\\)/.test(value) ? value.replaceAll('\\', '/') : value;
}

function expandPattern(pattern: string): string {
  return normalizeAbsolutePath(expandHomePath(pattern));
}

function permissionEntries(permission: string, value: unknown): PermissionRule[] {
  if (value === 'allow' || value === 'ask' || value === 'deny') {
    return [{ permission, pattern: '*', action: value }];
  }
  if (!isRecord(value)) {
    throw new Error(`permission ${permission} must be allow, ask, deny, or a map`);
  }
  return Object.entries(value).map(([pattern, action]) => {
    if (action !== 'allow' && action !== 'ask' && action !== 'deny') {
      throw new Error(`permission ${permission} pattern ${pattern} has an invalid action`);
    }
    return { permission, pattern: expandPattern(pattern), action };
  });
}

function normalizePermissions(value: unknown): PermissionRules {
  if (value === 'allow' || value === 'ask' || value === 'deny') {
    return [{ permission: '*', pattern: '*', action: value }];
  }
  if (value === undefined) return [];
  if (!isRecord(value)) throw new Error('permission must be allow, ask, deny, or a map');
  return Object.entries(value).flatMap(([permission, rules]) =>
    permissionEntries(permission, rules),
  );
}

function legacyConfigWarnings(piAgentDir: string): string[] {
  const path = join(piAgentDir, 'settings.json');
  if (!existsSync(path)) return [];
  try {
    const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!isRecord(value)) return [];
    const fields = ['agent', 'permission', 'subagents', 'maxSubagents'].filter(
      (field) => value[field] !== undefined,
    );
    if (fields.length === 0) return [];
    return [
      `${path}: legacy ${fields.join(', ')} configuration is ignored; move it to subagents.json`,
    ];
  } catch {
    return [];
  }
}

function normalizeAgent(name: string, raw: ConfigObject): AgentDefinition | undefined {
  for (const field of ['description', 'prompt', 'model', 'variant'] as const) {
    if (raw[field] !== undefined && typeof raw[field] !== 'string') {
      throw new Error(`agent ${name} ${field} must be a string`);
    }
  }
  for (const field of ['hidden', 'disable'] as const) {
    if (raw[field] !== undefined && typeof raw[field] !== 'boolean') {
      throw new Error(`agent ${name} ${field} must be a boolean`);
    }
  }
  for (const key of Object.keys(raw)) {
    if (!AGENT_FIELDS.has(key)) throw new Error(`agent ${name} has an unknown field ${key}`);
  }
  if (raw.options !== undefined && !isRecord(raw.options)) {
    throw new Error(`agent ${name} options must be an object`);
  }
  for (const field of ['temperature', 'top_p'] as const) {
    if (raw[field] !== undefined && typeof raw[field] !== 'number') {
      throw new Error(`agent ${name} ${field} must be a number`);
    }
  }
  if (raw.disable === true) return undefined;
  if (
    raw.mode !== undefined &&
    raw.mode !== 'primary' &&
    raw.mode !== 'subagent' &&
    raw.mode !== 'all'
  ) {
    throw new Error(`agent ${name} has an invalid mode`);
  }
  const providerOptions: Record<string, unknown> = isRecord(raw.options) ? { ...raw.options } : {};
  if (typeof raw.temperature === 'number') providerOptions.temperature = raw.temperature;
  if (typeof raw.top_p === 'number') providerOptions.top_p = raw.top_p;
  if (raw.steps !== undefined && (!Number.isInteger(raw.steps) || (raw.steps as number) <= 0)) {
    throw new Error(`agent ${name} steps must be a positive number`);
  }
  return {
    name,
    description: typeof raw.description === 'string' ? raw.description : undefined,
    prompt: typeof raw.prompt === 'string' ? raw.prompt : '',
    mode: raw.mode ?? 'all',
    model: typeof raw.model === 'string' ? raw.model : undefined,
    variant: typeof raw.variant === 'string' ? raw.variant : undefined,
    hidden: raw.hidden === true,
    steps: typeof raw.steps === 'number' ? raw.steps : undefined,
    permissions: normalizePermissions(raw.permission),
    providerOptions,
  };
}

export function loadAgentCatalog(
  cwd: string,
  piAgentDir = getAgentDir(),
  includeProject = true,
): AgentCatalog {
  const warnings = [
    ...legacyConfigWarnings(piAgentDir),
    ...(includeProject ? legacyConfigWarnings(join(cwd, '.pi')) : []),
  ];
  const diagnostics: string[] = [];
  let maxSubagents = 0;
  let subagents: ConfigObject = {};
  try {
    const config = loadLandstripConfig(cwd, includeProject, piAgentDir);
    maxSubagents = config.maxSubagents;
    subagents = config.subagents;
  } catch (error) {
    diagnostics.push(formatError(error));
  }

  const normalized = new Map<string, AgentDefinition>();
  if (subagents.agent !== undefined && !isRecord(subagents.agent)) {
    diagnostics.push('subagents.agent must be an object');
  } else if (isRecord(subagents.agent)) {
    for (const name of Object.keys(subagents.agent).sort()) {
      const value = subagents.agent[name];
      if (!isRecord(value)) {
        diagnostics.push(`agent ${name} must be an object`);
        continue;
      }
      try {
        const agent = normalizeAgent(name, value);
        if (agent) normalized.set(name, agent);
      } catch (error) {
        diagnostics.push(formatError(error));
      }
    }
  }

  let permissions: PermissionRules = [];
  for (const key of Object.keys(subagents)) {
    if (key !== 'agent' && key !== 'permission') {
      diagnostics.push(`subagents has an unknown field ${key}`);
    }
  }
  try {
    permissions = normalizePermissions(subagents.permission);
  } catch (error) {
    diagnostics.push(formatError(error));
  }
  return { agents: normalized, permissions, diagnostics, warnings, maxSubagents };
}

export function permissionDecision(
  rules: PermissionRules,
  permission: string,
  resource = '*',
): PermissionAction {
  let decision: PermissionAction = 'ask';
  for (const rule of rules) {
    const matchesPermission =
      rule.permission === '*' || minimatch(permission, rule.permission, { dot: true });
    const matchesResource =
      rule.pattern === '*' ||
      minimatch(normalizeAbsolutePath(resource), normalizeAbsolutePath(rule.pattern), {
        dot: true,
        matchBase: false,
      });
    if (matchesPermission && matchesResource) decision = rule.action;
  }
  return decision;
}

export function mergePermissionRules(...values: PermissionRules[]): PermissionRules {
  return values.flatMap((value) => value);
}

export function availableSubagents(catalog: AgentCatalog): AgentDefinition[] {
  return [...catalog.agents.values()].filter((agent) => agent.mode !== 'primary');
}

export function availablePrimaryAgents(catalog: AgentCatalog): AgentDefinition[] {
  return [...catalog.agents.values()].filter((agent) => agent.mode !== 'subagent' && !agent.hidden);
}
