// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describe, expect, test } from 'vitest';

import { loadAgentCatalog } from './agents.ts';
import { loadPiMarkdownAgents, normalizeMarkdownAgentRaw } from './opencode-agents.ts';
import { temporaryDirectory as makeTemporaryDirectory } from './test-util.ts';

function temporaryDirectory(): string {
  return makeTemporaryDirectory('pi-landstrip-markdown-');
}

function write(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value);
}

describe('Pi markdown agents', () => {
  test('normalizes tools booleans and unknown fields into permission/options', () => {
    const raw = normalizeMarkdownAgentRaw(
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

  test('loads nested Pi markdown agents', () => {
    const root = temporaryDirectory();
    write(join(root, 'team', 'scout.md'), `---\ndescription: Scout\nmode: subagent\n---\nScout.\n`);

    const result = loadPiMarkdownAgents({
      directories: [{ path: root, source: 'global' }],
    });

    expect(result.diagnostics).toEqual([]);
    expect(result.agents.get('team/scout')).toMatchObject({
      name: 'team/scout',
      source: 'global',
      raw: {
        description: 'Scout',
        mode: 'subagent',
        prompt: 'Scout.',
      },
    });
  });

  test('does not import OpenCode agents into the catalog', () => {
    const cwd = temporaryDirectory();
    const agentDir = temporaryDirectory();
    write(
      join(cwd, '.opencode', 'agent', 'local-only.md'),
      `---\ndescription: Local OpenCode agent\nmode: subagent\n---\nLocal only.\n`,
    );
    write(
      join(cwd, 'opencode.json'),
      `${JSON.stringify({
        agent: {
          review: { description: 'OpenCode review', prompt: 'Review.', mode: 'subagent' },
        },
      })}\n`,
    );

    const catalog = loadAgentCatalog(cwd, agentDir);
    expect(catalog.agents.has('local-only')).toBe(false);
    expect(catalog.agents.has('review')).toBe(false);
  });
});
