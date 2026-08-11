// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  loadLandstripConfig,
  setAgentDisabledForScope,
  setMaxSubagentsConfigForScope,
} from './config.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-config-');
}

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('Landstrip configuration', () => {
  test('defaults filesystem tools to host policy', () => {
    expect(
      loadLandstripConfig(temporaryDirectory(), false, temporaryDirectory()).toolFilesystemPolicy,
    ).toBe('host');
  });
  test('accepts equivalent settings and dedicated files', () => {
    const cwd = temporaryDirectory();
    const settingsAgentDir = temporaryDirectory();
    const dedicatedAgentDir = temporaryDirectory();
    const value = {
      maxSubagents: 3,
      toolFilesystemPolicy: 'sandbox',
      agent: { review: { mode: 'subagent', prompt: '{file:review.txt}' } },
      permission: { task: { review: 'allow' } },
    };
    writeFileSync(join(settingsAgentDir, 'review.txt'), 'Review from file.\n');
    writeFileSync(join(dedicatedAgentDir, 'review.txt'), 'Review from file.\n');
    write(join(settingsAgentDir, 'settings.json'), { landstrip: value });
    write(join(dedicatedAgentDir, 'landstrip.json'), value);

    const settings = loadLandstripConfig(cwd, false, settingsAgentDir);
    const dedicated = loadLandstripConfig(cwd, false, dedicatedAgentDir);
    expect({
      maxSubagents: dedicated.maxSubagents,
      agent: dedicated.agent.review,
      permission: dedicated.permission,
      toolFilesystemPolicy: dedicated.toolFilesystemPolicy,
    }).toEqual({
      maxSubagents: settings.maxSubagents,
      agent: settings.agent.review,
      permission: settings.permission,
      toolFilesystemPolicy: settings.toolFilesystemPolicy,
    });
    expect(dedicated.agent.review).toMatchObject({ prompt: 'Review from file.' });
  });

  test('merges mixed global and project forms with existing precedence', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const projectPath = join(cwd, '.pi', 'landstrip.json');
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        maxSubagents: 2,
        toolFilesystemPolicy: 'sandbox',
        agent: { review: { mode: 'subagent', prompt: 'Review globally.' } },
      },
    });
    write(projectPath, {
      maxSubagents: 4,
      toolFilesystemPolicy: 'host',
      agent: { review: { description: 'Project review' } },
    });

    const config = loadLandstripConfig(cwd, true, agentDir);
    expect(config.maxSubagents).toBe(4);
    expect(config.toolFilesystemPolicy).toBe('host');
    expect(config.agent.review).toEqual({
      mode: 'subagent',
      prompt: 'Review globally.',
      description: 'Project review',
    });
    expect(config.agentSources.get('review')).toBe('local');
    expect(config.agentPaths.get('review')).toBe(projectPath);
  });

  test('rejects both configuration forms at one scope', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), { landstrip: {} });
    write(join(agentDir, 'landstrip.json'), {});

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'Landstrip configuration is defined in both',
    );
  });

  test('rejects both project configuration forms', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(cwd, '.pi', 'settings.json'), { landstrip: {} });
    write(join(cwd, '.pi', 'landstrip.json'), {});

    expect(() => loadLandstripConfig(cwd, true, agentDir)).toThrow(
      'Landstrip configuration is defined in both',
    );
  });

  test('rejects unknown settings fields', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), { landstrip: { unknown: true } });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'landstrip has an unknown field unknown',
    );
  });

  test('rejects unknown dedicated fields', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'landstrip.json'), { unknown: true });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'configuration has an unknown field unknown',
    );
  });

  test('rejects invalid filesystem tool policy modes', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'landstrip.json'), { toolFilesystemPolicy: 'prompt' });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'toolFilesystemPolicy must be host or sandbox',
    );
  });

  test('rejects the removed landstrip.opencode settings object', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        opencode: { showGlobalAgents: false, showLocalAgents: false },
      },
    });

    expect(() => loadLandstripConfig(temporaryDirectory(), true, agentDir)).toThrow(
      'landstrip has an unknown field opencode',
    );
  });

  test('serializes mutations in existing settings without replacing siblings', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const path = join(cwd, '.pi', 'settings.json');
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      '{\n  // Keep Pi settings intact.\n  "theme": "dark",\n  "landstrip": { "permission": { "bash": "ask" } }\n}\n',
    );

    await Promise.all([
      setMaxSubagentsConfigForScope(cwd, 6, 'project', agentDir),
      setAgentDisabledForScope(cwd, 'build', true, 'project', agentDir),
    ]);

    const content = readFileSync(path, 'utf8');
    expect(content).toContain('// Keep Pi settings intact.');
    expect(content).toContain('"theme": "dark"');
    const config = loadLandstripConfig(cwd, true, agentDir);
    expect(config.maxSubagents).toBe(6);
    expect(config.agent.build).toMatchObject({ disable: true });
    expect(existsSync(join(cwd, '.pi', 'landstrip.json'))).toBe(false);
  });

  test('defaults concurrent mutations to one dedicated file', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const path = join(cwd, '.pi', 'landstrip.json');

    await Promise.all([
      setMaxSubagentsConfigForScope(cwd, 5, 'project', agentDir),
      setAgentDisabledForScope(cwd, 'build', true, 'project', agentDir),
    ]);

    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({
      maxSubagents: 5,
      agent: { build: { disable: true } },
    });
    expect(existsSync(join(cwd, '.pi', 'settings.json'))).toBe(false);
  });
});
