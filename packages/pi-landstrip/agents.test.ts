// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import {
  availablePrimaryAgents,
  availableSubagents,
  loadAgentCatalog,
  mergePermissionRules,
  permissionDecision,
  type PermissionRules,
} from './agents.ts';
import { MAX_SUBAGENTS, setMaxSubagentsConfig, setMaxSubagentsConfigForScope } from './config.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-agents-');
}

function write(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('landstrip agent configuration', () => {
  let previousOpenCodeConfigDir: string | undefined;

  beforeEach(() => {
    previousOpenCodeConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = temporaryDirectory();
  });

  afterEach(() => {
    if (previousOpenCodeConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = previousOpenCodeConfigDir;
  });
  test('provides default primary agents and subagents', () => {
    const catalog = loadAgentCatalog(temporaryDirectory(), temporaryDirectory());

    expect(catalog.maxSubagents).toBe(0);
    expect(availablePrimaryAgents(catalog).map((agent) => agent.name)).toEqual(['build', 'plan']);
    expect(availableSubagents(catalog).map((agent) => agent.name)).toEqual([
      'explore',
      'general',
      'scout',
    ]);
    expect(catalog.agents.get('scout')).toMatchObject({
      source: 'built-in',
      mode: 'subagent',
    });
    expect(permissionDecision(catalog.permissions, 'bash')).toBe('allow');
    expect(permissionDecision(catalog.agents.get('plan')?.permissions ?? [], 'edit')).toBe('ask');
    expect(permissionDecision(catalog.agents.get('plan')?.permissions ?? [], 'task')).toBe('ask');
    expect(catalog.agents.get('build')?.color).toBe('#034cff');
    expect(catalog.agents.get('plan')?.color).toBe('#a753ae');

    const explore = catalog.agents.get('explore');
    const exploreRules = mergePermissionRules(catalog.permissions, explore?.permissions ?? []);
    expect(permissionDecision(exploreRules, 'read', 'src/index.ts')).toBe('allow');
    expect(permissionDecision(exploreRules, 'read', '.env')).toBe('ask');
    expect(permissionDecision(exploreRules, 'read', '.env.local')).toBe('ask');
    expect(permissionDecision(exploreRules, 'read', '.env.example')).toBe('allow');
    expect(permissionDecision(exploreRules, 'bash')).toBe('allow');
    expect(permissionDecision(exploreRules, 'webfetch')).toBe('allow');
    expect(permissionDecision(exploreRules, 'websearch')).toBe('allow');
    expect(permissionDecision(exploreRules, 'edit')).toBe('deny');
    expect(permissionDecision(exploreRules, 'task')).toBe('deny');
  });

  test('merges global and project subagents.json sections', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      maxSubagents: 2,
      subagents: {
        agent: { review: { mode: 'subagent', prompt: 'Review globally.' } },
        permission: { bash: { 'git status': 'deny', '*': 'ask' } },
      },
    });
    write(join(cwd, '.pi', 'subagents.json'), {
      subagents: {
        agent: { review: { description: 'Project review' } },
        permission: { bash: { 'git status': 'allow' } },
      },
    });

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.maxSubagents).toBe(2);
    expect(catalog.agents.get('review')).toMatchObject({
      description: 'Project review',
      prompt: 'Review globally.',
      mode: 'subagent',
    });
    expect(catalog.agents.get('review')?.source).toBe('local');
    expect(permissionDecision(catalog.permissions, 'bash', 'rm -rf build')).toBe('ask');
    expect(permissionDecision(catalog.permissions, 'bash', 'git status')).toBe('allow');
  });

  test('tracks the effective built-in, global, and local agent sources', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      subagents: {
        agent: {
          global: { mode: 'subagent' },
          general: { description: 'Customized globally' },
        },
      },
    });
    write(join(cwd, '.pi', 'subagents.json'), {
      subagents: {
        agent: {
          local: { mode: 'subagent' },
          global: { description: 'Customized locally' },
        },
      },
    });

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.get('explore')?.source).toBe('built-in');
    expect(catalog.agents.get('general')?.source).toBe('global');
    expect(catalog.agents.get('global')?.source).toBe('local');
    expect(catalog.agents.get('local')?.source).toBe('local');
  });

  test('ignores project subagents.json when the project is untrusted', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(cwd, '.pi', 'subagents.json'), {
      subagents: { agent: { project: { mode: 'subagent' } } },
    });

    const catalog = loadAgentCatalog(cwd, agentDir, false);
    expect(catalog.maxSubagents).toBe(0);
    expect(catalog.agents.has('project')).toBe(false);
  });

  test('allows maxSubagents zero without removing primary agents', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), { maxSubagents: 0 });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.maxSubagents).toBe(0);
    expect(availablePrimaryAgents(catalog).map((agent) => agent.name)).toEqual(['build', 'plan']);
  });

  test('rejects maxSubagents above the supported limit', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), { maxSubagents: MAX_SUBAGENTS + 1 });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.diagnostics.join('\n')).toContain(`integer from 0 to ${MAX_SUBAGENTS}`);
  });

  test('updates maxSubagents in global config without replacing other global settings', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'subagents.json');
    write(path, { maxSubagents: 2, subagents: { permission: { bash: 'ask' } } });

    await expect(setMaxSubagentsConfig(cwd, 6, true, agentDir)).resolves.toBe('global');
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({
      maxSubagents: 6,
      subagents: { permission: { bash: 'ask' } },
    });
  });

  test('rejects setting maxSubagents in project scope', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();

    await setMaxSubagentsConfigForScope(cwd, 3, 'global', agentDir);
    await expect(setMaxSubagentsConfigForScope(cwd, 5, 'project', agentDir)).rejects.toThrow(
      'maxSubagents is only allowed in global subagents.json',
    );

    expect(JSON.parse(readFileSync(join(agentDir, 'subagents.json'), 'utf8')).maxSubagents).toBe(3);
  });

  test('reports malformed agent permissions', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      subagents: { agent: { unsafe: { permission: { bash: { '*': false } } } } },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.has('unsafe')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain('invalid action');
  });

  test('rejects unknown agent fields instead of treating typos as provider options', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      subagents: { agent: { unsafe: { permissions: { bash: 'deny' } } } },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.has('unsafe')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain('unknown field permissions');
  });

  test('keeps agent color and rejects invalid colors', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), {
      subagents: {
        agent: {
          build: { color: 'accent' },
          plan: { color: '#FF00FF' },
          bad: { color: 'not-a-color' },
        },
      },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.get('build')?.color).toBe('accent');
    expect(catalog.agents.get('plan')?.color).toBe('#FF00FF');
    expect(catalog.agents.has('bad')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain('color must be');
  });

  test('does not read subagent configuration from settings.json', () => {
    const agentDir = temporaryDirectory();
    const cwd = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      agent: { legacy: { mode: 'subagent', prompt: 'Do not load.' } },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      permission: { bash: 'deny' },
    });

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.has('legacy')).toBe(false);
    expect(catalog.warnings.join('\n')).toContain('legacy agent configuration is ignored');
    expect(catalog.warnings.join('\n')).toContain(join(cwd, '.pi', 'settings.json'));
  });

  test('rejects sandbox fields in subagents.json', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'subagents.json'), { sandbox: { enabled: false } });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.diagnostics.join('\n')).toContain('unknown top-level field sandbox');
  });

  test('includes the source path in malformed JSON diagnostics', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'subagents.json');
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, '{');

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.diagnostics.join('\n')).toContain(path);
  });

  test('expands {file:path} prompt references relative to subagents.json', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    writeFileSync(join(agentDir, 'review-prompt.txt'), 'Review from file.\n');
    write(join(agentDir, 'subagents.json'), {
      subagents: {
        agent: {
          review: {
            mode: 'subagent',
            prompt: 'Prefix {file:./review-prompt.txt} suffix',
          },
        },
      },
    });

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.get('review')?.prompt).toBe('Prefix Review from file. suffix');
  });

  test('reports a diagnostic for missing {file:path} prompt references', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'subagents.json');
    write(path, {
      subagents: {
        agent: {
          review: {
            mode: 'subagent',
            prompt: '{file:./missing-prompt.txt}',
          },
        },
      },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.has('review')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain(path);
    expect(catalog.diagnostics.join('\n')).toContain('bad file reference');
  });
});

describe('permissions', () => {
  test('uses the last matching rule', () => {
    const globalRules: PermissionRules = [
      { permission: '*', pattern: '*', action: 'allow' },
      { permission: 'bash', pattern: '*', action: 'ask' },
    ];
    const agentRules: PermissionRules = [
      { permission: 'bash', pattern: 'git status', action: 'allow' },
    ];
    const rules = mergePermissionRules(globalRules, agentRules);

    expect(permissionDecision(rules, 'bash', 'rm -rf build')).toBe('ask');
    expect(permissionDecision(rules, 'bash', 'git status')).toBe('allow');
  });

  test('matches absolute Windows paths', () => {
    const rules: PermissionRules = [
      { permission: '*', pattern: '*', action: 'allow' },
      { permission: 'read', pattern: 'C:\\Users\\alice\\secrets\\**', action: 'deny' },
    ];

    expect(permissionDecision(rules, 'read', 'C:\\Users\\alice\\secrets\\token.txt')).toBe('deny');
  });
});
