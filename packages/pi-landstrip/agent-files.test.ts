// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

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

  test('edits a built-in through a dedicated project configuration', async () => {
    const cwd = temporaryDirectory('pi-landstrip-agent-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-agent-dir-');
    const path = join(cwd, '.pi', 'landstrip.json');
    write(path, `${JSON.stringify({ maxSubagents: 3 }, null, 2)}\n`);
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('build')!;

    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    const snippet = JSON.parse(document.content);
    expect(Object.keys(snippet.agent)).toEqual(['build']);
    snippet.agent.build.description = 'Dedicated build';
    await document.save(`${JSON.stringify(snippet, null, 2)}\n`);

    const config = JSON.parse(readFileSync(path, 'utf8'));
    expect(config.maxSubagents).toBe(3);
    expect(config.agent.build.description).toBe('Dedicated build');
    const projectAgent = loadAgentCatalog(cwd, agentDir).agents.get('build')!;
    expect(projectAgent).toMatchObject({ source: 'local', description: 'Dedicated build' });

    expect(canDeleteProjectAgent(cwd, projectAgent, agentDir)).toBe(true);
    await expect(deleteProjectAgent(cwd, projectAgent, agentDir)).resolves.toBe(true);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ maxSubagents: 3 });
  });

  test('removes an empty dedicated file after deleting its last agent', async () => {
    const cwd = temporaryDirectory('pi-landstrip-agent-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-agent-dir-');
    const path = join(cwd, '.pi', 'landstrip.json');
    write(path, `${JSON.stringify({ agent: { build: { description: 'Project build' } } })}\n`);
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('build')!;

    await expect(deleteProjectAgent(cwd, agent, agentDir)).resolves.toBe(true);
    expect(existsSync(path)).toBe(false);
  });

  test('rejects an editor save after the project configuration source changes', async () => {
    const cwd = temporaryDirectory('pi-landstrip-agent-edit-');
    const agentDir = temporaryDirectory('pi-landstrip-agent-dir-');
    const dedicatedPath = join(cwd, '.pi', 'landstrip.json');
    const agent = loadAgentCatalog(cwd, agentDir).agents.get('build')!;
    const document = prepareProjectAgentEditor(cwd, agent, agentDir);
    write(join(cwd, '.pi', 'settings.json'), `${JSON.stringify({ landstrip: {} }, null, 2)}\n`);

    await expect(document.save(document.content)).rejects.toThrow(
      'configuration source changed while updating it',
    );
    expect(existsSync(dedicatedPath)).toBe(false);
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
});
