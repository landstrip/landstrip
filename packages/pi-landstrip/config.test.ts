// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { loadLandstripConfig } from './config.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-opencode-config-');
}

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('OpenCode settings', () => {
  test('defaults both OpenCode agent imports to true', () => {
    const config = loadLandstripConfig(temporaryDirectory(), true, temporaryDirectory());
    expect(config.opencode).toEqual({ showGlobalAgents: true, showLocalAgents: true });
  });

  test('merges global and trusted-project settings', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        opencode: { showGlobalAgents: false, showLocalAgents: false },
      },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: { opencode: { showLocalAgents: true } },
    });

    expect(loadLandstripConfig(cwd, true, agentDir).opencode).toEqual({
      showGlobalAgents: false,
      showLocalAgents: true,
    });
    expect(loadLandstripConfig(cwd, false, agentDir).opencode).toEqual({
      showGlobalAgents: false,
      showLocalAgents: false,
    });
  });

  test('rejects invalid and unknown OpenCode settings', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        opencode: { showGlobalAgents: 'yes', showLocalAgents: true, extra: 1 },
      },
    });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      /unknown field extra|must be a boolean/,
    );
  });

  test('reports subagents.json as a migration error', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'subagents.json');
    write(path, { maxSubagents: 2 });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      `${path} is no longer supported; move its values to landstrip.maxSubagents, landstrip.agent, landstrip.permission, and landstrip.opencode in ${join(agentDir, 'settings.json')}`,
    );
  });

  test('reports project subagents.json only for trusted projects', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const path = join(cwd, '.pi', 'subagents.json');
    write(path, { subagents: { agent: {} } });

    expect(() => loadLandstripConfig(cwd, true, agentDir)).toThrow(
      `${path} is no longer supported`,
    );
    expect(() => loadLandstripConfig(cwd, false, agentDir)).not.toThrow();
  });

  test('rejects unknown landstrip settings', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { unknown: true },
    });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'landstrip has an unknown field unknown',
    );
  });
});
