// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, relative, sep } from 'node:path';

import { getAgentDir, withFileMutationQueue } from '@earendil-works/pi-coding-agent';
import {
  applyEdits,
  modify,
  parse as parseJsonc,
  printParseErrorCode,
  type ParseError,
} from 'jsonc-parser';

import { type AgentDefinition, validateAgentRaw } from './agents.ts';
import { type ConfigObject, getPiConfigPaths, loadLandstripConfig } from './config.ts';
import { normalizeOpenCodeAgentRaw, parseMarkdownAgentRaw } from './opencode-agents.ts';
import { expandFileReferences, isRecord } from './util.ts';

const JSON_FORMAT = {
  formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' },
};

type JsonAgentKind = 'landstrip' | 'opencode';
type JsonPath = (string | number)[];

export interface AgentEditorDocument {
  readonly title: string;
  readonly content: string;
  save(content: string): Promise<void>;
}

function parseJsonDocument(content: string, label: string): ConfigObject {
  const errors: ParseError[] = [];
  const value: unknown = parseJsonc(content, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    const error = errors[0]!;
    throw new Error(`${label}: ${printParseErrorCode(error.error)} at offset ${error.offset}`);
  }
  if (!isRecord(value)) throw new Error(`${label} must contain a JSON object`);
  return value;
}

function valueAtPath(root: unknown, path: JsonPath): unknown {
  let value = root;
  for (const segment of path) {
    if (typeof segment !== 'string' || !isRecord(value)) return undefined;
    value = value[segment];
  }
  return value;
}

function agentJsonPath(kind: JsonAgentKind, name: string): JsonPath {
  return kind === 'landstrip' ? ['landstrip', 'agent', name] : ['agent', name];
}

function agentContainerPath(kind: JsonAgentKind): JsonPath {
  return kind === 'landstrip' ? ['landstrip', 'agent'] : ['agent'];
}

function editorSnippet(kind: JsonAgentKind, name: string, raw: ConfigObject): string {
  const value =
    kind === 'landstrip' ? { landstrip: { agent: { [name]: raw } } } : { agent: { [name]: raw } };
  return `${JSON.stringify(value, null, 2)}\n`;
}

function parseEditorSnippet(content: string, kind: JsonAgentKind, name: string): ConfigObject {
  const root = parseJsonDocument(content, 'Edited agent');
  const parent = kind === 'landstrip' ? valueAtPath(root, ['landstrip']) : root;
  const container = valueAtPath(root, agentContainerPath(kind));
  const rootKey = kind === 'landstrip' ? 'landstrip' : 'agent';
  if (
    Object.keys(root).length !== 1 ||
    root[rootKey] === undefined ||
    !isRecord(parent) ||
    Object.keys(parent).length !== 1 ||
    parent.agent === undefined ||
    !isRecord(container) ||
    Object.keys(container).length !== 1 ||
    !isRecord(container[name])
  ) {
    throw new Error(`Edited JSON must contain only agent ${name}`);
  }
  return container[name];
}

function validateEditedAgent(kind: JsonAgentKind, name: string, raw: ConfigObject): void {
  if (kind === 'landstrip') {
    validateAgentRaw(name, raw);
    return;
  }
  const prompt = raw.prompt;
  if (prompt !== undefined && typeof prompt !== 'string') {
    throw new Error(`agent ${name} prompt must be a string`);
  }
  validateAgentRaw(name, normalizeOpenCodeAgentRaw(raw, typeof prompt === 'string' ? prompt : ''));
}

function ensureFinalNewline(content: string): string {
  return content.endsWith('\n') ? content : `${content}\n`;
}

async function writeJsonNode(path: string, nodePath: JsonPath, value: ConfigObject): Promise<void> {
  await withFileMutationQueue(path, async () => {
    const content = existsSync(path) ? readFileSync(path, 'utf8') : '{}\n';
    parseJsonDocument(content, path);
    const edited = applyEdits(content, modify(content, nodePath, value, JSON_FORMAT));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, ensureFinalNewline(edited), { mode: 0o600 });
  });
}

async function deleteJsonNode(
  path: string,
  nodePath: JsonPath,
  containerPaths: readonly JsonPath[],
): Promise<boolean> {
  if (!existsSync(path)) return false;
  let deleted = false;
  await withFileMutationQueue(path, async () => {
    let content = readFileSync(path, 'utf8');
    const root = parseJsonDocument(content, path);
    if (valueAtPath(root, nodePath) === undefined) return;
    content = applyEdits(content, modify(content, nodePath, undefined, JSON_FORMAT));
    for (const containerPath of containerPaths) {
      const parsed = parseJsonDocument(content, path);
      const container = valueAtPath(parsed, containerPath);
      if (isRecord(container) && Object.keys(container).length === 0) {
        content = applyEdits(content, modify(content, containerPath, undefined, JSON_FORMAT));
      }
    }
    writeFileSync(path, ensureFinalNewline(content), { mode: 0o600 });
    deleted = true;
  });
  return deleted;
}

function readAgentNode(path: string, kind: JsonAgentKind, name: string): ConfigObject | undefined {
  if (!existsSync(path)) return undefined;
  const root = parseJsonDocument(readFileSync(path, 'utf8'), path);
  const value = valueAtPath(root, agentJsonPath(kind, name));
  return isRecord(value) ? { ...value } : undefined;
}

function permissionConfig(agent: AgentDefinition): ConfigObject | undefined {
  if (agent.permissions.length === 0) return undefined;
  const permissions: ConfigObject = {};
  for (const rule of agent.permissions) {
    const configured = permissions[rule.permission];
    const patterns = isRecord(configured) ? { ...configured } : {};
    patterns[rule.pattern] = rule.action;
    permissions[rule.permission] = patterns;
  }
  return permissions;
}

function normalizedAgentRaw(agent: AgentDefinition): ConfigObject {
  const raw: ConfigObject = {
    description: agent.description,
    prompt: agent.prompt,
    mode: agent.mode,
    model: agent.model,
    variant: agent.variant,
    hidden: agent.hidden || undefined,
    disable: agent.disabled || undefined,
    color: agent.color,
    steps: agent.steps,
    permission: permissionConfig(agent),
    options:
      Object.keys(agent.providerOptions).length > 0 ? { ...agent.providerOptions } : undefined,
  };
  for (const key of Object.keys(raw)) {
    if (raw[key] === undefined) delete raw[key];
  }
  return raw;
}

function relocateGlobalPrompt(raw: ConfigObject, agent: AgentDefinition): ConfigObject {
  if (agent.origin?.source !== 'global' || !agent.origin.path || typeof raw.prompt !== 'string') {
    return raw;
  }
  return { ...raw, prompt: expandFileReferences(raw.prompt, dirname(agent.origin.path)) };
}

function safeRelative(root: string, path: string): string | undefined {
  const value = relative(root, path);
  return value && value !== '..' && !value.startsWith(`..${sep}`) ? value : undefined;
}

function projectMarkdownPath(cwd: string, agentDir: string, agent: AgentDefinition): string {
  const origin = agent.origin!;
  if (origin.source === 'local' && origin.path) return origin.path;
  if (origin.kind === 'pi-markdown' && origin.path) {
    const suffix = safeRelative(join(agentDir, 'agents'), origin.path) ?? `${agent.name}.md`;
    return join(cwd, '.pi', 'agents', suffix);
  }
  if (origin.kind === 'opencode-markdown' && origin.path) {
    return join(cwd, '.opencode', 'agents', `${agent.name}.md`);
  }
  throw new Error(`Agent ${agent.name} has no Markdown source`);
}

function openCodeProjectPath(cwd: string, sourcePath: string): string {
  return join(cwd, '.opencode', basename(sourcePath));
}

function projectSettingsPath(cwd: string, agentDir: string): string {
  return getPiConfigPaths(cwd, 'settings.json', agentDir).projectPath;
}

function projectSettingsHasAgent(cwd: string, name: string, agentDir: string): boolean {
  return readAgentNode(projectSettingsPath(cwd, agentDir), 'landstrip', name) !== undefined;
}

export function canDeleteProjectAgent(
  cwd: string,
  agent: AgentDefinition,
  agentDir = getAgentDir(),
): boolean {
  try {
    if (projectSettingsHasAgent(cwd, agent.name, agentDir)) return true;
  } catch {
    return false;
  }
  const origin = agent.origin;
  return Boolean(
    origin?.source === 'local' &&
    origin.path &&
    (origin.kind === 'pi-markdown' ||
      origin.kind === 'opencode-markdown' ||
      origin.kind === 'opencode-json'),
  );
}

export async function deleteProjectAgent(
  cwd: string,
  agent: AgentDefinition,
  agentDir = getAgentDir(),
): Promise<boolean> {
  const settingsPath = projectSettingsPath(cwd, agentDir);
  const deletedOverride = await deleteJsonNode(
    settingsPath,
    agentJsonPath('landstrip', agent.name),
    [['landstrip', 'agent'], ['landstrip']],
  );

  const origin = agent.origin;
  if (origin?.source !== 'local' || !origin.path) return deletedOverride;
  if (origin.kind === 'opencode-json') {
    const deletedSource = await deleteJsonNode(origin.path, agentJsonPath('opencode', agent.name), [
      ['agent'],
    ]);
    return deletedOverride || deletedSource;
  }
  if (origin.kind !== 'pi-markdown' && origin.kind !== 'opencode-markdown') {
    return deletedOverride;
  }
  if (!existsSync(origin.path)) return deletedOverride;
  await withFileMutationQueue(origin.path, async () => unlinkSync(origin.path!));
  return true;
}

export function prepareProjectAgentEditor(
  cwd: string,
  agent: AgentDefinition,
  agentDir = getAgentDir(),
): AgentEditorDocument {
  const origin = agent.origin;
  const openCodeProjectEnabled = loadLandstripConfig(cwd, true, agentDir).opencode.showLocalAgents;
  if (origin?.path && (origin.kind === 'pi-markdown' || origin.kind === 'opencode-markdown')) {
    const useMarkdown =
      origin.kind === 'pi-markdown' || origin.source === 'local' || openCodeProjectEnabled;
    const target = useMarkdown
      ? projectMarkdownPath(cwd, agentDir, agent)
      : projectSettingsPath(cwd, agentDir);
    const projectOverride = useMarkdown
      ? undefined
      : readAgentNode(target, 'landstrip', agent.name);
    const disabledOverride =
      projectOverride &&
      Object.keys(projectOverride).length === 1 &&
      typeof projectOverride.disable === 'boolean'
        ? projectOverride.disable
        : undefined;
    return {
      title: `Edit @${agent.name}`,
      content: readFileSync(origin.path, 'utf8'),
      async save(content) {
        const edited = parseMarkdownAgentRaw(content);
        const raw =
          !useMarkdown && edited.disable === undefined && disabledOverride !== undefined
            ? { ...edited, disable: disabledOverride }
            : edited;
        validateAgentRaw(agent.name, raw);
        if (!useMarkdown) {
          await writeJsonNode(target, agentJsonPath('landstrip', agent.name), raw);
          return;
        }
        await withFileMutationQueue(target, async () => {
          mkdirSync(dirname(target), { recursive: true });
          writeFileSync(target, ensureFinalNewline(content), { mode: 0o600 });
        });
      },
    };
  }
  const useOpenCode =
    origin?.kind === 'opencode-json' &&
    origin.path !== undefined &&
    (origin.source === 'local' || openCodeProjectEnabled);
  const kind: JsonAgentKind = useOpenCode ? 'opencode' : 'landstrip';
  const sourcePath = origin?.path;
  const sourceKind: JsonAgentKind = origin?.kind === 'opencode-json' ? 'opencode' : 'landstrip';
  const sourceRaw = sourcePath ? readAgentNode(sourcePath, sourceKind, agent.name) : undefined;
  const raw = relocateGlobalPrompt(
    sourceKind === kind && sourceRaw
      ? sourceRaw
      : agent.raw
        ? { ...agent.raw }
        : normalizedAgentRaw(agent),
    agent,
  );
  const target =
    kind === 'opencode' && sourcePath
      ? origin?.source === 'local'
        ? sourcePath
        : openCodeProjectPath(cwd, sourcePath)
      : projectSettingsPath(cwd, agentDir);

  return {
    title: `Edit @${agent.name}`,
    content: editorSnippet(kind, agent.name, raw),
    async save(content) {
      const edited = parseEditorSnippet(content, kind, agent.name);
      validateEditedAgent(kind, agent.name, edited);
      await writeJsonNode(target, agentJsonPath(kind, agent.name), edited);
    },
  };
}
