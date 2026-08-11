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
import {
  type ConfigObject,
  getLandstripConfigTarget,
  type LandstripConfigKind,
  type LandstripConfigTarget,
} from './config.ts';
import { parseMarkdownAgentRaw } from './opencode-agents.ts';
import { expandFileReferences, isRecord } from './util.ts';

const JSON_FORMAT = {
  formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' },
};

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

function configKindForPath(path: string): LandstripConfigKind {
  return basename(path) === 'landstrip.json' ? 'dedicated' : 'settings';
}

function agentJsonPath(kind: LandstripConfigKind, name: string): JsonPath {
  return kind === 'settings' ? ['landstrip', 'agent', name] : ['agent', name];
}

function editorSnippet(name: string, raw: ConfigObject, kind: LandstripConfigKind): string {
  const agent = { agent: { [name]: raw } };
  return `${JSON.stringify(kind === 'settings' ? { landstrip: agent } : agent, null, 2)}\n`;
}

function parseEditorSnippet(
  content: string,
  name: string,
  kind: LandstripConfigKind,
): ConfigObject {
  const root = parseJsonDocument(content, 'Edited agent');
  const parentPath = kind === 'settings' ? ['landstrip'] : [];
  const parent = valueAtPath(root, parentPath);
  const container = valueAtPath(root, [...parentPath, 'agent']);
  const expectedRootKey = kind === 'settings' ? 'landstrip' : 'agent';
  if (
    Object.keys(root).length !== 1 ||
    root[expectedRootKey] === undefined ||
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

function ensureFinalNewline(content: string): string {
  return content.endsWith('\n') ? content : `${content}\n`;
}

async function writeJsonNode(
  path: string,
  nodePath: JsonPath,
  value: ConfigObject,
  validate?: () => void,
): Promise<void> {
  await withFileMutationQueue(path, async () => {
    validate?.();
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
  validate?: () => void,
  removeEmptyFile = false,
): Promise<boolean> {
  if (!existsSync(path)) return false;
  let deleted = false;
  await withFileMutationQueue(path, async () => {
    validate?.();
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
    if (removeEmptyFile && Object.keys(parseJsonDocument(content, path)).length === 0) {
      unlinkSync(path);
      deleted = true;
      return;
    }
    writeFileSync(path, ensureFinalNewline(content), { mode: 0o600 });
    deleted = true;
  });
  return deleted;
}

function readAgentNode(
  path: string,
  kind: LandstripConfigKind,
  name: string,
): ConfigObject | undefined {
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
  throw new Error(`Agent ${agent.name} has no Markdown source`);
}

function projectConfigTarget(cwd: string, agentDir: string): LandstripConfigTarget {
  return getLandstripConfigTarget(cwd, 'project', agentDir);
}

function assertProjectConfigTarget(
  cwd: string,
  agentDir: string,
  target: LandstripConfigTarget,
): void {
  const current = projectConfigTarget(cwd, agentDir);
  if (current.path !== target.path || current.kind !== target.kind) {
    throw new Error('Landstrip project configuration source changed while updating it');
  }
}

function projectConfigHasAgent(cwd: string, name: string, agentDir: string): boolean {
  const target = projectConfigTarget(cwd, agentDir);
  return readAgentNode(target.path, target.kind, name) !== undefined;
}

export function canDeleteProjectAgent(
  cwd: string,
  agent: AgentDefinition,
  agentDir = getAgentDir(),
): boolean {
  try {
    if (projectConfigHasAgent(cwd, agent.name, agentDir)) return true;
  } catch {
    return false;
  }
  const origin = agent.origin;
  return Boolean(origin?.source === 'local' && origin.path && origin.kind === 'pi-markdown');
}

export async function deleteProjectAgent(
  cwd: string,
  agent: AgentDefinition,
  agentDir = getAgentDir(),
): Promise<boolean> {
  const target = projectConfigTarget(cwd, agentDir);
  const containers: readonly JsonPath[] =
    target.kind === 'settings' ? [['landstrip', 'agent'], ['landstrip']] : [['agent']];
  const deletedOverride = await deleteJsonNode(
    target.path,
    agentJsonPath(target.kind, agent.name),
    containers,
    () => assertProjectConfigTarget(cwd, agentDir, target),
    target.kind === 'dedicated',
  );

  const origin = agent.origin;
  if (origin?.source !== 'local' || !origin.path || origin.kind !== 'pi-markdown') {
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
  if (origin?.path && origin.kind === 'pi-markdown') {
    const target = projectMarkdownPath(cwd, agentDir, agent);
    return {
      title: `Edit @${agent.name}`,
      content: readFileSync(origin.path, 'utf8'),
      async save(content) {
        validateAgentRaw(agent.name, parseMarkdownAgentRaw(content));
        await withFileMutationQueue(target, async () => {
          mkdirSync(dirname(target), { recursive: true });
          writeFileSync(target, ensureFinalNewline(content), { mode: 0o600 });
        });
      },
    };
  }
  const sourcePath = origin?.path;
  const sourceRaw =
    origin?.kind === 'config' && sourcePath
      ? readAgentNode(sourcePath, configKindForPath(sourcePath), agent.name)
      : undefined;
  const raw = relocateGlobalPrompt(
    sourceRaw ? sourceRaw : agent.raw ? { ...agent.raw } : normalizedAgentRaw(agent),
    agent,
  );
  const target = projectConfigTarget(cwd, agentDir);

  return {
    title: `Edit @${agent.name}`,
    content: editorSnippet(agent.name, raw, target.kind),
    async save(content) {
      const edited = parseEditorSnippet(content, agent.name, target.kind);
      validateAgentRaw(agent.name, edited);
      await writeJsonNode(target.path, agentJsonPath(target.kind, agent.name), edited, () =>
        assertProjectConfigTarget(cwd, agentDir, target),
      );
    },
  };
}
