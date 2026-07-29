// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import {
  canDeleteProjectAgent,
  deleteProjectAgent,
  prepareProjectAgentEditor,
} from './agent-files.ts';
import { loadAgentCatalog } from './agents.ts';
import { temporaryDirectory } from './test-util.ts';

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

describe('project agent files', () => {
  let previousOpenCodeConfigDir: string | undefined;

  beforeEach(() => {
    previousOpenCodeConfigDir = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = temporaryDirectory('pi-landstrip-opencode-');
  });

  afterEach(() => {
    if (previousOpenCodeConfigDir === undefined) delete process.env.OPENCODE_CONFIG_DIR;
    else process.env.OPENCODE_CONFIG_DIR = previousOpenCodeConfigDir;
  });

  test('edits a built-in through a project settings snippet without replacing sibling settings', async () => {
    const cwd = temporaryDirectory('pi-landstrip-agent-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-agent-dir-');
    const settingsPath = join(cwd, '.pi', 'settings.json');
    write(
      settingsPath,
      `${JSON.stringify({ theme: 'dark', landstrip: { maxSubagents: 3 } }, null, 2)}\n`,
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('build')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    const snippet = JSON.parse(document.content);
    expect(Object.keys(snippet.landstrip.agent)).toEqual(['build']);
    snippet.landstrip.agent.build.description = 'Project build';
    await document.save(`${JSON.stringify(snippet, null, 2)}\n`);

    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    expect(settings.theme).toBe('dark');
    expect(settings.landstrip.maxSubagents).toBe(3);
    expect(settings.landstrip.agent.build.description).toBe('Project build');
    expect(loadAgentCatalog(cwd, agentDir).agents.get('build')).toMatchObject({
      source: 'local',
      description: 'Project build',
    });

    expect(canDeleteProjectAgent(cwd, agent, agentDir)).toBe(true);
    await expect(deleteProjectAgent(cwd, agent, agentDir)).resolves.toBe(true);
    const deleted = JSON.parse(readFileSync(settingsPath, 'utf8'));
    expect(deleted.landstrip.agent).toBeUndefined();
    expect(deleted.landstrip.maxSubagents).toBe(3);
  });

  test('copies a global Markdown agent to the project and deletes only the project copy', async () => {
    const cwd = temporaryDirectory('pi-landstrip-markdown-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-markdown-dir-');
    const globalPath = join(agentDir, 'agents', 'review.md');
    const projectPath = join(cwd, '.pi', 'agents', 'review.md');
    write(globalPath, '---\ndescription: Global review\nmode: subagent\n---\nReview globally.\n');
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    expect(document.content).toContain('Global review');
    await document.save(document.content.replace('Global review', 'Project review'));

    expect(readFileSync(globalPath, 'utf8')).toContain('Global review');
    expect(readFileSync(projectPath, 'utf8')).toContain('Project review');
    const projectAgent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;
    expect(projectAgent).toMatchObject({ source: 'local', description: 'Project review' });
    expect(canDeleteProjectAgent(cwd, projectAgent, agentDir)).toBe(true);
    await expect(deleteProjectAgent(cwd, projectAgent, agentDir)).resolves.toBe(true);
    expect(existsSync(projectPath)).toBe(false);
    expect(loadAgentCatalog(cwd, agentDir).agents.get('review')).toMatchObject({
      source: 'global',
      description: 'Global review',
    });
  });

  test('preserves a nested global OpenCode Markdown agent name in the project', async () => {
    const cwd = temporaryDirectory('pi-landstrip-opencode-markdown-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-opencode-markdown-agent-');
    const globalPath = join(
      process.env.OPENCODE_CONFIG_DIR!,
      'agents',
      'team',
      'agent',
      'review.md',
    );
    const projectPath = join(cwd, '.opencode', 'agents', 'team', 'agent', 'review.md');
    write(globalPath, '---\ndescription: Global review\nmode: subagent\n---\nReview globally.\n');
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('team/agent/review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    await document.save(document.content.replace('Global review', 'Project review'));

    expect(readFileSync(projectPath, 'utf8')).toContain('Project review');
    expect(loadAgentCatalog(cwd, agentDir).agents.get('team/agent/review')).toMatchObject({
      source: 'local',
      description: 'Project review',
    });
  });

  test('saves global OpenCode Markdown into Pi settings when local OpenCode is disabled', async () => {
    const cwd = temporaryDirectory('pi-landstrip-disabled-opencode-markdown-');
    const agentDir = temporaryDirectory('pi-landstrip-disabled-opencode-markdown-agent-');
    const globalPath = join(process.env.OPENCODE_CONFIG_DIR!, 'agents', 'review.md');
    const settingsPath = join(cwd, '.pi', 'settings.json');
    write(
      join(agentDir, 'settings.json'),
      `${JSON.stringify({ landstrip: { opencode: { showLocalAgents: false } } })}\n`,
    );
    write(globalPath, '---\ndescription: Global review\nmode: subagent\n---\nReview globally.\n');
    write(
      settingsPath,
      `${JSON.stringify({ landstrip: { agent: { review: { disable: true } } } })}\n`,
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    await document.save(document.content.replace('Global review', 'Project review'));

    const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
    expect(settings.landstrip.agent.review.description).toBe('Project review');
    expect(settings.landstrip.agent.review.disable).toBe(true);
    expect(existsSync(join(cwd, '.opencode', 'agents', 'review.md'))).toBe(false);
    expect(loadAgentCatalog(cwd, agentDir).agents.get('review')).toMatchObject({
      source: 'local',
      description: 'Project review',
      disabled: true,
    });
  });

  test('allows a project override to enable a globally disabled OpenCode Markdown agent', async () => {
    const cwd = temporaryDirectory('pi-landstrip-enable-opencode-markdown-');
    const agentDir = temporaryDirectory('pi-landstrip-enable-opencode-markdown-agent-');
    const globalPath = join(process.env.OPENCODE_CONFIG_DIR!, 'agents', 'enable-me.md');
    const settingsPath = join(cwd, '.pi', 'settings.json');
    write(
      join(agentDir, 'settings.json'),
      `${JSON.stringify({ landstrip: { opencode: { showLocalAgents: false } } })}\n`,
    );
    write(
      globalPath,
      '---\ndescription: Disabled globally\nmode: subagent\ndisable: true\n---\nReview globally.\n',
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('enable-me')!;
    expect(agent.disabled).toBe(true);

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    await document.save(document.content.replace('disable: true\n', ''));

    const saved = JSON.parse(readFileSync(settingsPath, 'utf8')).landstrip.agent['enable-me'];
    expect(saved.disable).toBeUndefined();
    expect(loadAgentCatalog(cwd, agentDir).agents.get('enable-me')).toMatchObject({
      source: 'local',
      disabled: false,
    });
  });

  test('substitutes and deletes one agent node in a project OpenCode JSONC file', async () => {
    const cwd = temporaryDirectory('pi-landstrip-opencode-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-opencode-agent-');
    const path = join(cwd, '.opencode', 'opencode.jsonc');
    write(
      path,
      '{\n  // keep this comment\n  "agent": {\n    "review": { "description": "Review", "prompt": "Review.", "mode": "subagent" },\n    "keep": { "description": "Keep", "prompt": "Keep.", "mode": "subagent" }\n  }\n}\n',
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    const snippet = JSON.parse(document.content);
    expect(Object.keys(snippet.agent)).toEqual(['review']);
    snippet.agent.review.description = 'Edited review';
    await document.save(`${JSON.stringify(snippet, null, 2)}\n`);

    let content = readFileSync(path, 'utf8');
    expect(content).toContain('// keep this comment');
    expect(content).toContain('Edited review');
    expect(content).toContain('"keep"');
    const settingsPath = join(cwd, '.pi', 'settings.json');
    write(
      settingsPath,
      `${JSON.stringify({ landstrip: { agent: { review: { disable: true } } } })}\n`,
    );

    const edited = loadAgentCatalog(cwd, agentDir).agents.get('review')!;
    await expect(deleteProjectAgent(cwd, edited, agentDir)).resolves.toBe(true);
    expect(JSON.parse(readFileSync(settingsPath, 'utf8')).landstrip).toBeUndefined();
    content = readFileSync(path, 'utf8');
    expect(content).toContain('// keep this comment');
    expect(content).not.toContain('"review"');
    expect(content).toContain('"keep"');
  });

  test('edits a global OpenCode JSON agent into a project OpenCode config', async () => {
    const cwd = temporaryDirectory('pi-landstrip-global-opencode-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-global-opencode-agent-');
    const globalPath = join(process.env.OPENCODE_CONFIG_DIR!, 'opencode.json');
    const projectPath = join(cwd, '.opencode', 'opencode.json');
    write(join(process.env.OPENCODE_CONFIG_DIR!, 'review.txt'), 'Review instructions.\n');
    write(
      globalPath,
      `${JSON.stringify({
        agent: {
          review: { description: 'Global review', prompt: '{file:review.txt}', mode: 'subagent' },
        },
      })}\n`,
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    const snippet = JSON.parse(document.content);
    expect(snippet.agent.review.prompt).toBe('Review instructions.');
    snippet.agent.review.description = 'Project review';
    await document.save(`${JSON.stringify(snippet, null, 2)}\n`);

    expect(readFileSync(globalPath, 'utf8')).toContain('Global review');
    expect(readFileSync(projectPath, 'utf8')).toContain('Project review');
    expect(loadAgentCatalog(cwd, agentDir).agents.get('review')).toMatchObject({
      source: 'local',
      description: 'Project review',
    });
  });

  test('uses project Pi settings when project OpenCode agents are disabled', async () => {
    const cwd = temporaryDirectory('pi-landstrip-global-opencode-settings-');
    const agentDir = temporaryDirectory('pi-landstrip-global-opencode-settings-agent-');
    const globalPath = join(process.env.OPENCODE_CONFIG_DIR!, 'opencode.json');
    const settingsPath = join(cwd, '.pi', 'settings.json');
    write(
      join(agentDir, 'settings.json'),
      `${JSON.stringify({ landstrip: { opencode: { showLocalAgents: false } } })}\n`,
    );
    write(
      globalPath,
      `${JSON.stringify({
        agent: {
          review: {
            description: 'Global review',
            prompt: 'Review.',
            mode: 'subagent',
            tools: { bash: false },
          },
        },
      })}\n`,
    );
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('review')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    const snippet = JSON.parse(document.content);
    expect(snippet.landstrip.agent.review).toBeDefined();
    expect(snippet.landstrip.agent.review.permission.bash).toBe('deny');
    snippet.landstrip.agent.review.description = 'Project review';
    await document.save(`${JSON.stringify(snippet, null, 2)}\n`);

    expect(JSON.parse(readFileSync(settingsPath, 'utf8')).landstrip.agent.review.description).toBe(
      'Project review',
    );
    expect(existsSync(join(cwd, '.opencode', 'opencode.json'))).toBe(false);
  });
});
