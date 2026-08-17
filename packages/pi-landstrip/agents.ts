// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { join } from 'node:path';
import { minimatch } from 'minimatch';
import { getAgentDir } from '@earendil-works/pi-coding-agent';

import {
  loadLandstripConfig,
  type AgentSource,
  type ConfigObject,
  type ToolFilesystemPolicy,
} from './config.ts';
import { loadPiMarkdownAgents } from './opencode-agents.ts';
import { expandHomePath, formatError, isAgentColor, isRecord } from './util.ts';

export type PermissionAction = 'allow' | 'ask' | 'deny';

export interface PermissionRule {
  readonly permission: string;
  readonly pattern: string;
  readonly action: PermissionAction;
}

export type PermissionRules = readonly PermissionRule[];

export interface AgentOrigin {
  readonly kind: 'built-in' | 'config' | 'pi-markdown';
  readonly source: AgentSource;
  readonly path?: string;
}

export interface AgentDefinition {
  readonly name: string;
  readonly source: AgentSource;
  readonly description?: string;
  readonly prompt: string;
  readonly mode: 'primary' | 'subagent' | 'all';
  readonly model?: string;
  readonly variant?: string;
  readonly hidden: boolean;
  readonly disabled: boolean;
  readonly color?: string;
  readonly steps?: number;
  readonly permissions: PermissionRules;
  readonly providerOptions: Readonly<Record<string, unknown>>;
  readonly origin?: AgentOrigin;
  readonly raw?: Readonly<ConfigObject>;
}

export interface AgentCatalog {
  readonly agents: ReadonlyMap<string, AgentDefinition>;
  readonly permissions: PermissionRules;
  readonly diagnostics: readonly string[];
  readonly maxSubagents: number;
  readonly toolFilesystemPolicy: ToolFilesystemPolicy;
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

function normalizeAgent(
  name: string,
  raw: ConfigObject,
  source: AgentSource,
  origin: AgentOrigin,
): AgentDefinition {
  for (const field of ['description', 'prompt', 'model', 'variant', 'color'] as const) {
    if (raw[field] !== undefined && typeof raw[field] !== 'string') {
      throw new Error(`agent ${name} ${field} must be a string`);
    }
  }
  if (typeof raw.color === 'string' && !isAgentColor(raw.color)) {
    throw new Error(
      `agent ${name} color must be #RRGGBB or one of primary, secondary, accent, success, warning, error, info`,
    );
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
    source,
    description: typeof raw.description === 'string' ? raw.description : undefined,
    prompt: typeof raw.prompt === 'string' ? raw.prompt : '',
    mode: raw.mode ?? 'all',
    model: typeof raw.model === 'string' ? raw.model : undefined,
    variant: typeof raw.variant === 'string' ? raw.variant : undefined,
    hidden: raw.hidden === true,
    disabled: raw.disable === true,
    color: typeof raw.color === 'string' ? raw.color : undefined,
    steps: typeof raw.steps === 'number' ? raw.steps : undefined,
    permissions: normalizePermissions(raw.permission),
    providerOptions,
    origin,
    raw: { ...raw },
  };
}

export function validateAgentRaw(name: string, raw: ConfigObject): void {
  normalizeAgent(name, raw, 'local', { kind: 'config', source: 'local' });
}

export function loadAgentCatalog(
  cwd: string,
  piAgentDir = getAgentDir(),
  includeProject = true,
): AgentCatalog {
  const diagnostics: string[] = [];
  let maxSubagents = 0;
  let toolFilesystemPolicy: ToolFilesystemPolicy = 'host';
  let configuredAgents: ConfigObject = {};
  let configuredPermission: unknown;
  let agentSources = new Map<string, AgentSource>();
  let agentPaths = new Map<string, string>();
  try {
    const config = loadLandstripConfig(cwd, includeProject, piAgentDir);
    maxSubagents = config.maxSubagents;
    toolFilesystemPolicy = config.toolFilesystemPolicy;
    configuredAgents = config.agent;
    configuredPermission = config.permission;
    agentSources = new Map(config.agentSources);
    agentPaths = new Map(config.agentPaths);
  } catch (error) {
    diagnostics.push(formatError(error));
  }

  const normalized = new Map<string, AgentDefinition>();
  const piMarkdown = loadPiMarkdownAgents({
    directories: [
      { path: join(piAgentDir, 'agents'), source: 'global' },
      ...(includeProject ? ([{ path: join(cwd, '.pi', 'agents'), source: 'local' }] as const) : []),
    ],
  });
  diagnostics.push(...piMarkdown.diagnostics);
  for (const imported of piMarkdown.agents.values()) {
    try {
      normalized.set(
        imported.name,
        normalizeAgent(imported.name, imported.raw, imported.source, {
          kind: 'pi-markdown',
          source: imported.source,
          path: imported.path,
        }),
      );
    } catch (error) {
      diagnostics.push(`${imported.path}: ${formatError(error)}`);
    }
  }

  for (const name of Object.keys(configuredAgents).sort()) {
    const value = configuredAgents[name];
    if (!isRecord(value)) {
      diagnostics.push(`agent ${name} must be an object`);
      continue;
    }
    const imported = normalized.get(name);
    if (imported) {
      try {
        const source = agentSources.get(name) ?? imported.source;
        normalized.set(
          name,
          normalizeAgent(
            name,
            { ...imported.raw, ...value },
            source,
            imported.origin ?? {
              kind: 'pi-markdown',
              source: imported.source,
            },
          ),
        );
      } catch (error) {
        diagnostics.push(formatError(error));
      }
      continue;
    }
    if (Object.keys(value).every((key) => key === 'disable')) continue;
    try {
      const source = agentSources.get(name) ?? 'built-in';
      normalized.set(
        name,
        normalizeAgent(name, value, source, {
          kind: source === 'built-in' ? 'built-in' : 'config',
          source,
          path: agentPaths.get(name),
        }),
      );
    } catch (error) {
      diagnostics.push(formatError(error));
    }
  }

  let permissions: PermissionRules = [];
  try {
    permissions = normalizePermissions(configuredPermission);
  } catch (error) {
    diagnostics.push(formatError(error));
  }
  return { agents: normalized, permissions, diagnostics, maxSubagents, toolFilesystemPolicy };
}

function permissionMatches(pattern: string, permission: string): boolean {
  return pattern === '*' || minimatch(permission, pattern, { dot: true });
}

export function permissionDecision(
  rules: PermissionRules,
  permission: string,
  resource = '*',
): PermissionAction {
  let decision: PermissionAction = 'ask';
  for (const rule of rules) {
    const matchesResource =
      rule.pattern === '*' ||
      minimatch(normalizeAbsolutePath(resource), normalizeAbsolutePath(rule.pattern), {
        dot: true,
        matchBase: false,
      });
    if (permissionMatches(rule.permission, permission) && matchesResource) decision = rule.action;
  }
  return decision;
}

export function permissionAlwaysDenied(rules: PermissionRules, permission: string): boolean {
  let denied = false;
  for (const rule of rules) {
    if (!permissionMatches(rule.permission, permission)) continue;
    if (rule.pattern === '*') denied = rule.action === 'deny';
    else if (rule.action !== 'deny') denied = false;
  }
  return denied;
}

export function mergePermissionRules(...values: PermissionRules[]): PermissionRules {
  return values.flatMap((value) => value);
}

export function availableAgents(catalog: AgentCatalog): AgentDefinition[] {
  return [...catalog.agents.values()].filter((agent) => !agent.hidden && !agent.disabled);
}

export function isPrimaryAgent(agent: AgentDefinition): boolean {
  return agent.mode === 'primary';
}

export function agentSupportsMode(agent: AgentDefinition, mode: 'primary' | 'subagent'): boolean {
  return agent.mode === mode || agent.mode === 'all';
}
