// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { loadAgentCatalog } from './agents.ts';
import { loadOpenCodeAgents, normalizeOpenCodeAgentRaw } from './opencode-agents.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-opencode-');
}

function write(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value);
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

describe('OpenCode agent import', () => {
  test('normalizes tools booleans and unknown fields into permission/options', () => {
    const raw = normalizeOpenCodeAgentRaw(
      {
        description: 'Reviewer',
        mode: 'subagent',
        tools: { write: false, read: true },
        stuff: 'extra',
        maxSteps: 3,
      },
      'Review carefully.',
    );

    expect(raw).toEqual({
      description: 'Reviewer',
      mode: 'subagent',
      prompt: 'Review carefully.',
      steps: 3,
      permission: { edit: 'deny', read: 'allow' },
      options: { stuff: 'extra' },
    });
  });

  test('loads global and project OpenCode markdown agents', () => {
    const cwd = temporaryDirectory();
    const globalDir = temporaryDirectory();
    write(
      join(globalDir, 'agents', 'review.md'),
      `---\ndescription: Global review\nmode: subagent\n---\nGlobal prompt.\n`,
    );
    write(
      join(cwd, '.opencode', 'agent', 'deep', 'scout.md'),
      `---\ndescription: Nested scout\nmode: subagent\npermission:\n  bash: deny\n---\nNested prompt.\n`,
    );

    const result = loadOpenCodeAgents({
      cwd,
      includeGlobal: true,
      includeProject: true,
      globalConfigDir: globalDir,
    });

    expect(result.diagnostics).toEqual([]);
    expect(result.agents.get('review')).toMatchObject({
      source: 'global',
      raw: {
        description: 'Global review',
        mode: 'subagent',
        prompt: 'Global prompt.',
      },
    });
    expect(result.agents.get('deep/scout')).toMatchObject({
      source: 'local',
      raw: {
        description: 'Nested scout',
        mode: 'subagent',
        prompt: 'Nested prompt.',
        permission: { bash: 'deny' },
      },
    });
  });

  test('project OpenCode agents override global OpenCode agents', () => {
    const cwd = temporaryDirectory();
    const globalDir = temporaryDirectory();
    write(
      join(globalDir, 'agent', 'review.md'),
      `---\ndescription: Global\nmode: subagent\n---\nGlobal.\n`,
    );
    write(
      join(cwd, '.opencode', 'agents', 'review.md'),
      `---\ndescription: Project\nmode: subagent\n---\nProject.\n`,
    );

    const result = loadOpenCodeAgents({
      cwd,
      includeGlobal: true,
      includeProject: true,
      globalConfigDir: globalDir,
    });

    expect(result.agents.get('review')?.source).toBe('local');
    expect(result.agents.get('review')?.raw.description).toBe('Project');
  });

  test('imports OpenCode agents into the catalog when settings enable them', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const globalDir = temporaryDirectory();
    writeJson(join(agentDir, 'subagents.json'), {
      opencode: { showGlobalAgents: true, showLocalAgents: true },
    });
    write(
      join(globalDir, 'agents', 'review.md'),
      `---\ndescription: OpenCode review\nmode: subagent\ntools:\n  edit: false\n  read: true\n---\nReview the code.\n`,
    );
    write(
      join(cwd, '.opencode', 'agent', 'local-only.md'),
      `---\ndescription: Local OpenCode agent\nmode: subagent\n---\nLocal only.\n`,
    );

    const previous = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalDir;
    try {
      const catalog = loadAgentCatalog(cwd, agentDir);
      expect(catalog.diagnostics).toEqual([]);
      expect(catalog.agents.get('review')).toMatchObject({
        source: 'global',
        description: 'OpenCode review',
        prompt: 'Review the code.',
        mode: 'subagent',
      });
      expect(catalog.agents.get('local-only')).toMatchObject({
        source: 'local',
        description: 'Local OpenCode agent',
      });
      // Built-in agents still present.
      expect(catalog.agents.get('explore')?.source).toBe('built-in');
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = previous;
    }
  });

  test('Pi agent definitions win silently over OpenCode agents with the same name', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const globalDir = temporaryDirectory();
    writeJson(join(agentDir, 'subagents.json'), {
      opencode: { showGlobalAgents: true, showLocalAgents: true },
      subagents: {
        agent: {
          review: { description: 'Pi review', mode: 'subagent', prompt: 'From Pi.' },
        },
      },
    });
    write(
      join(globalDir, 'agents', 'review.md'),
      `---\ndescription: OpenCode review\nmode: subagent\n---\nFrom OpenCode.\n`,
    );
    write(
      join(cwd, '.opencode', 'agent', 'explore.md'),
      `---\ndescription: OpenCode explore override\nmode: subagent\n---\nShould not win.\n`,
    );

    const previous = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalDir;
    try {
      const catalog = loadAgentCatalog(cwd, agentDir);
      expect(catalog.agents.get('review')).toMatchObject({
        source: 'global',
        description: 'Pi review',
        prompt: 'From Pi.',
      });
      // Built-in explore wins silently over OpenCode project explore.
      expect(catalog.agents.get('explore')).toMatchObject({
        source: 'built-in',
      });
      expect(catalog.agents.get('explore')?.description).not.toBe('OpenCode explore override');
      expect(catalog.diagnostics).toEqual([]);
      expect(catalog.warnings.filter((warning) => warning.includes('conflict'))).toEqual([]);
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = previous;
    }
  });

  test('does not import OpenCode agents when settings are disabled', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    const globalDir = temporaryDirectory();
    write(
      join(globalDir, 'agents', 'review.md'),
      `---\ndescription: OpenCode review\nmode: subagent\n---\nReview.\n`,
    );

    const previous = process.env.OPENCODE_CONFIG_DIR;
    process.env.OPENCODE_CONFIG_DIR = globalDir;
    try {
      const catalog = loadAgentCatalog(cwd, agentDir);
      expect(catalog.agents.has('review')).toBe(false);
    } finally {
      if (previous === undefined) delete process.env.OPENCODE_CONFIG_DIR;
      else process.env.OPENCODE_CONFIG_DIR = previous;
    }
  });

  test('skips project OpenCode agents when the project is untrusted', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    writeJson(join(agentDir, 'subagents.json'), {
      opencode: { showLocalAgents: true },
    });
    write(
      join(cwd, '.opencode', 'agent', 'local-only.md'),
      `---\ndescription: Local\nmode: subagent\n---\nLocal.\n`,
    );

    const catalog = loadAgentCatalog(cwd, agentDir, false);
    expect(catalog.agents.has('local-only')).toBe(false);
  });
});
