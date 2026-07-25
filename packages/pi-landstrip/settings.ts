// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { getAgentDir } from '@earendil-works/pi-coding-agent';

import { isRecord } from './util.ts';

export interface OpenCodeSettings {
  readonly showGlobalAgents: boolean;
  readonly showLocalAgents: boolean;
}

export interface LandstripSettings {
  readonly opencode: OpenCodeSettings;
}

export interface LandstripSettingsResult {
  readonly settings: LandstripSettings;
  readonly warnings: readonly string[];
}

const DEFAULT_OPENCODE_SETTINGS: OpenCodeSettings = {
  showGlobalAgents: false,
  showLocalAgents: false,
};

const LANDSTRIP_SETTING_KEYS = new Set(['opencode']);
const OPENCODE_SETTING_KEYS = new Set(['showGlobalAgents', 'showLocalAgents']);

function readJsonObject(path: string): { value?: Record<string, unknown>; warning?: string } {
  if (!existsSync(path)) return {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!isRecord(parsed)) {
      return { warning: `${path}: settings.json must contain a JSON object` };
    }
    return { value: parsed };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { warning: `${path}: ${message}` };
  }
}

function readBoolean(
  section: Record<string, unknown>,
  key: string,
  path: string,
  source: string,
  warnings: string[],
): boolean | undefined {
  if (!(key in section)) return undefined;
  const value = section[key];
  if (typeof value === 'boolean') return value;
  warnings.push(`${source}: ${path} must be a boolean`);
  return undefined;
}

function readOpenCodeSection(
  section: Record<string, unknown>,
  source: string,
  warnings: string[],
): Partial<OpenCodeSettings> {
  if (!('opencode' in section)) return {};
  if (!isRecord(section.opencode)) {
    warnings.push(`${source}: landstrip.opencode must be a JSON object`);
    return {};
  }

  const opencode = section.opencode;
  for (const key of Object.keys(opencode)) {
    if (!OPENCODE_SETTING_KEYS.has(key)) {
      warnings.push(`${source}: unknown landstrip.opencode setting ${key}`);
    }
  }

  const settings: {
    showGlobalAgents?: boolean;
    showLocalAgents?: boolean;
  } = {};
  const showGlobalAgents = readBoolean(
    opencode,
    'showGlobalAgents',
    'landstrip.opencode.showGlobalAgents',
    source,
    warnings,
  );
  if (showGlobalAgents !== undefined) settings.showGlobalAgents = showGlobalAgents;
  const showLocalAgents = readBoolean(
    opencode,
    'showLocalAgents',
    'landstrip.opencode.showLocalAgents',
    source,
    warnings,
  );
  if (showLocalAgents !== undefined) settings.showLocalAgents = showLocalAgents;
  return settings;
}

function readLandstripSection(
  root: Record<string, unknown> | undefined,
  source: string,
  warnings: string[],
): Partial<OpenCodeSettings> {
  if (!root || !('landstrip' in root)) return {};
  if (!isRecord(root.landstrip)) {
    warnings.push(`${source}: landstrip must be a JSON object`);
    return {};
  }

  const section = root.landstrip;
  for (const key of Object.keys(section)) {
    if (!LANDSTRIP_SETTING_KEYS.has(key)) {
      warnings.push(`${source}: unknown landstrip setting ${key}`);
    }
  }

  return readOpenCodeSection(section, source, warnings);
}

export function resolveLandstripSettings(
  cwd: string,
  includeProject = true,
  piAgentDir = getAgentDir(),
): LandstripSettingsResult {
  const warnings: string[] = [];
  const globalPath = join(piAgentDir, 'settings.json');
  const projectPath = join(cwd, '.pi', 'settings.json');

  const globalFile = readJsonObject(globalPath);
  if (globalFile.warning) warnings.push(globalFile.warning);
  const projectFile = includeProject ? readJsonObject(projectPath) : {};
  if (projectFile.warning) warnings.push(projectFile.warning);

  const settings: LandstripSettings = {
    opencode: {
      ...DEFAULT_OPENCODE_SETTINGS,
      ...readLandstripSection(globalFile.value, globalPath, warnings),
      ...(includeProject ? readLandstripSection(projectFile.value, projectPath, warnings) : {}),
    },
  };

  return { settings, warnings };
}
