// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { loadLandstripConfig } from './config.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-config-');
}

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('Landstrip settings', () => {
  test('rejects unknown landstrip settings', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { unknown: true },
    });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'landstrip has an unknown field unknown',
    );
  });

  test('accepts landstrip.opencode settings object', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        opencode: { showGlobalAgents: false, showLocalAgents: false },
      },
    });

    const config = loadLandstripConfig(temporaryDirectory(), true, agentDir);
    expect(config.opencode).toEqual({ showGlobalAgents: false, showLocalAgents: false });
  });
});
