// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import {
  agentSupportsMode,
  availableAgents,
  loadAgentCatalog,
  mergePermissionRules,
  permissionDecision,
  type PermissionRules,
} from './agents.ts';
import {
  clearAgentDisabledForScope,
  clearMaxSubagentsConfigForScope,
  loadAgentDisabledOverrides,
  loadMaxSubagentsSettings,
  MAX_SUBAGENTS,
  setAgentDisabledForScope,
  setMaxSubagentsConfig,
  setMaxSubagentsConfigForScope,
} from './config.ts';
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
  test('provides one default agent catalog with mode capabilities', () => {
    const catalog = loadAgentCatalog(temporaryDirectory(), temporaryDirectory());

    expect(catalog.maxSubagents).toBe(1);
    const agents = availableAgents(catalog);
    expect(agents.map((agent) => agent.name)).toEqual([
      'build',
      'explore',
      'general',
      'plan',
      'scout',
    ]);
    expect(
      agents.filter((agent) => agentSupportsMode(agent, 'primary')).map((agent) => agent.name),
    ).toEqual(['build', 'plan']);
    expect(
      agents.filter((agent) => agentSupportsMode(agent, 'subagent')).map((agent) => agent.name),
    ).toEqual(['explore', 'general', 'scout']);
    expect(catalog.agents.get('scout')).toMatchObject({
      source: 'built-in',
      mode: 'subagent',
    });
    expect(permissionDecision(catalog.permissions, 'bash')).toBe('allow');
    expect(permissionDecision(catalog.agents.get('plan')?.permissions ?? [], 'edit')).toBe('ask');
    expect(permissionDecision(catalog.agents.get('plan')?.permissions ?? [], 'task')).toBe('ask');
    expect(catalog.agents.get('build')?.color).toBe('success');
    expect(catalog.agents.get('plan')?.color).toBe('warning');

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

  test('loads global and trusted-project Pi markdown agents', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const advisorPath = join(agentDir, 'agents', 'advisor.md');
    const localPath = join(cwd, '.pi', 'agents', 'local-review.md');
    mkdirSync(dirname(advisorPath), { recursive: true });
    mkdirSync(dirname(localPath), { recursive: true });
    writeFileSync(
      advisorPath,
      '---\ndescription: Stronger reviewer\nmode: subagent\nhidden: true\n---\nAdvise.\n',
    );
    writeFileSync(localPath, '---\ndescription: Local reviewer\nmode: subagent\n---\nReview.\n');

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.diagnostics).toEqual([]);
    expect(catalog.agents.get('advisor')).toMatchObject({
      source: 'global',
      description: 'Stronger reviewer',
      prompt: 'Advise.',
      hidden: true,
    });
    expect(availableAgents(catalog).map((agent) => agent.name)).not.toContain('advisor');
    expect(catalog.agents.get('local-review')?.source).toBe('local');

    const untrustedCatalog = loadAgentCatalog(cwd, agentDir, false);
    expect(untrustedCatalog.agents.has('advisor')).toBe(true);
    expect(untrustedCatalog.agents.has('local-review')).toBe(false);
  });

  test('merges global and trusted-project landstrip settings', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        maxSubagents: 2,
        agent: { review: { mode: 'subagent', prompt: 'Review globally.' } },
        permission: { bash: { 'git status': 'deny', '*': 'ask' } },
      },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: {
        maxSubagents: 3,
        agent: { review: { description: 'Project review' } },
        permission: { bash: { 'git status': 'allow' } },
      },
    });

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.maxSubagents).toBe(3);
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
    write(join(agentDir, 'settings.json'), {
      landstrip: {
        agent: {
          global: { mode: 'subagent' },
          general: { description: 'Customized globally' },
        },
      },
    });
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: {
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

  test('ignores project landstrip settings when the project is untrusted', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(join(cwd, '.pi', 'settings.json'), {
      landstrip: {
        maxSubagents: 8,
        agent: { project: { mode: 'subagent' } },
        opencode: { showGlobalAgents: false },
      },
    });

    const catalog = loadAgentCatalog(cwd, agentDir, false);
    expect(catalog.maxSubagents).toBe(1);
    expect(catalog.agents.has('project')).toBe(false);
  });

  test('allows maxSubagents zero without removing primary agents', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), { landstrip: { maxSubagents: 0 } });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.maxSubagents).toBe(0);
    expect(
      availableAgents(catalog)
        .filter((agent) => agentSupportsMode(agent, 'primary'))
        .map((agent) => agent.name),
    ).toEqual(['build', 'plan']);
  });

  test('keeps disabled agents in the composed catalog while excluding them from execution', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();

    await setAgentDisabledForScope(cwd, 'build', true, 'global', agentDir);
    let catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.get('build')).toMatchObject({ disabled: true, source: 'global' });
    expect(availableAgents(catalog).map((agent) => agent.name)).not.toContain('build');

    await setAgentDisabledForScope(cwd, 'build', false, 'project', agentDir);
    catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.get('build')).toMatchObject({ disabled: false, source: 'local' });
    expect(loadAgentDisabledOverrides(cwd, true, agentDir).project.get('build')).toBe(false);

    await clearAgentDisabledForScope(cwd, 'build', 'project', agentDir);
    catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.get('build')?.disabled).toBe(true);
    expect(loadAgentDisabledOverrides(cwd, true, agentDir).project.has('build')).toBe(false);
  });

  test('rejects maxSubagents above the supported limit', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { maxSubagents: MAX_SUBAGENTS + 1 },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.diagnostics.join('\n')).toContain(`integer from 0 to ${MAX_SUBAGENTS}`);
  });

  test('updates maxSubagents in global settings without replacing other settings', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'settings.json');
    write(path, {
      theme: 'dark',
      landstrip: { maxSubagents: 2, permission: { bash: 'ask' } },
    });

    await expect(setMaxSubagentsConfig(cwd, 6, true, agentDir)).resolves.toBe('global');
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({
      theme: 'dark',
      landstrip: { maxSubagents: 6, permission: { bash: 'ask' } },
    });
  });

  test('updates maxSubagents in trusted-project settings', async () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const globalPath = join(agentDir, 'settings.json');
    const projectPath = join(cwd, '.pi', 'settings.json');

    await setMaxSubagentsConfigForScope(cwd, 3, 'global', agentDir);
    expect(loadMaxSubagentsSettings(cwd, true, agentDir)).toEqual({
      global: 3,
      project: undefined,
    });
    await setMaxSubagentsConfigForScope(cwd, 5, 'project', agentDir);
    expect(loadMaxSubagentsSettings(cwd, true, agentDir)).toEqual({ global: 3, project: 5 });

    expect(JSON.parse(readFileSync(globalPath, 'utf8')).landstrip.maxSubagents).toBe(3);
    expect(JSON.parse(readFileSync(projectPath, 'utf8')).landstrip.maxSubagents).toBe(5);
    expect(loadAgentCatalog(cwd, agentDir).maxSubagents).toBe(5);

    await clearMaxSubagentsConfigForScope(cwd, 'project', agentDir);
    expect(loadMaxSubagentsSettings(cwd, true, agentDir)).toEqual({
      global: 3,
      project: undefined,
    });
    expect(JSON.parse(readFileSync(projectPath, 'utf8')).landstrip).toBeUndefined();
  });

  test('reports malformed agent permissions', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { agent: { unsafe: { permission: { bash: { '*': false } } } } },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.has('unsafe')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain('invalid action');
  });

  test('rejects unknown agent fields instead of treating typos as provider options', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: { agent: { unsafe: { permissions: { bash: 'deny' } } } },
    });

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.agents.has('unsafe')).toBe(false);
    expect(catalog.diagnostics.join('\n')).toContain('unknown field permissions');
  });

  test('keeps agent color and rejects invalid colors', () => {
    const agentDir = temporaryDirectory();
    write(join(agentDir, 'settings.json'), {
      landstrip: {
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

  test('includes the source path in malformed settings JSON diagnostics', () => {
    const agentDir = temporaryDirectory();
    const path = join(agentDir, 'settings.json');
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, '{');

    const catalog = loadAgentCatalog(temporaryDirectory(), agentDir);
    expect(catalog.diagnostics.join('\n')).toContain(path);
  });

  test('expands {file:path} prompt references relative to settings.json', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    writeFileSync(join(agentDir, 'review-prompt.txt'), 'Review from file.\n');
    write(join(agentDir, 'settings.json'), {
      landstrip: {
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
    const path = join(agentDir, 'settings.json');
    write(path, {
      landstrip: {
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
