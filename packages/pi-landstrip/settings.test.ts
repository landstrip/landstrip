// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { resolveLandstripSettings } from './settings.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-settings-');
}

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('landstrip settings', () => {
  test('defaults both OpenCode agent imports to false', () => {
    const result = resolveLandstripSettings(temporaryDirectory(), true, temporaryDirectory());
    expect(result.settings).toEqual({
      opencode: { showGlobalAgents: false, showLocalAgents: false },
    });
    expect(result.warnings).toEqual([]);
  });

  test('merges global and project landstrip.opencode settings', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      packages: ['npm:pi-landstrip'],
      landstrip: { opencode: { showGlobalAgents: true, showLocalAgents: false } },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: { opencode: { showLocalAgents: true } },
    });

    const result = resolveLandstripSettings(cwd, true, agentDir);
    expect(result.settings).toEqual({
      opencode: { showGlobalAgents: true, showLocalAgents: true },
    });
    expect(result.warnings).toEqual([]);
  });

  test('ignores project settings when the project is untrusted', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { opencode: { showGlobalAgents: true } },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: { opencode: { showGlobalAgents: false, showLocalAgents: true } },
    });

    const result = resolveLandstripSettings(cwd, false, agentDir);
    expect(result.settings).toEqual({
      opencode: { showGlobalAgents: true, showLocalAgents: false },
    });
  });

  test('warns about invalid and unknown landstrip.opencode settings', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'settings.json');
    write(path, {
      landstrip: {
        opencode: { showGlobalAgents: 'yes', showLocalAgents: true, extra: 1 },
        extra: 1,
      },
    });

    const result = resolveLandstripSettings(temporaryDirectory(), true, agentDir);
    expect(result.settings.opencode.showLocalAgents).toBe(true);
    expect(result.settings.opencode.showGlobalAgents).toBe(false);
    expect(result.warnings.join('\n')).toContain(
      'landstrip.opencode.showGlobalAgents must be a boolean',
    );
    expect(result.warnings.join('\n')).toContain('unknown landstrip.opencode setting extra');
    expect(result.warnings.join('\n')).toContain('unknown landstrip setting extra');
  });
});
