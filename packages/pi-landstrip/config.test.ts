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

describe('opencode config in subagents.json', () => {
  test('defaults both OpenCode agent imports to false', () => {
    const config = loadLandstripConfig(temporaryDirectory(), true, temporaryDirectory());
    expect(config.opencode).toEqual({ showGlobalAgents: false, showLocalAgents: false });
  });

  test('merges global and project opencode settings', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      opencode: { showGlobalAgents: true, showLocalAgents: false },
    });
    write(join(cwd, '.pi', 'subagents.json'), {
      opencode: { showLocalAgents: true },
    });

    const config = loadLandstripConfig(cwd, true, agentDir);
    expect(config.opencode).toEqual({ showGlobalAgents: true, showLocalAgents: true });
  });

  test('ignores project opencode settings when the project is untrusted', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      opencode: { showGlobalAgents: true },
    });
    write(join(cwd, '.pi', 'subagents.json'), {
      opencode: { showGlobalAgents: false, showLocalAgents: true },
    });

    const config = loadLandstripConfig(cwd, false, agentDir);
    expect(config.opencode).toEqual({ showGlobalAgents: true, showLocalAgents: false });
  });

  test('rejects invalid and unknown opencode settings', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'subagents.json');
    write(path, {
      opencode: { showGlobalAgents: 'yes', showLocalAgents: true, extra: 1 },
    });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      /unknown field extra|must be a boolean/,
    );
  });
});
