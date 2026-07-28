// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

export const BUILT_IN_LANDSTRIP_CONFIG = {
  maxSubagents: 1,
  agent: {
    build: {
      description: 'Default primary agent with full development access',
      mode: 'primary',
      color: 'success',
      prompt: 'Work in build mode. Implement, test, and complete the requested changes.',
    },
    plan: {
      description: 'Planning agent that asks before shell commands and file edits',
      mode: 'primary',
      color: 'warning',
      prompt:
        'Work in plan mode. Analyze the problem and produce a clear plan before making changes.',
      permission: { edit: 'ask', bash: 'ask', task: 'ask' },
    },
    general: {
      description: 'General-purpose agent for complex tasks',
      mode: 'subagent',
      prompt: 'Complete the delegated task autonomously. Return one concise result to the parent.',
      permission: { todowrite: 'deny' },
    },
    scout: {
      description: 'Fast codebase reconnaissance',
      mode: 'subagent',
      prompt:
        'Scout the codebase without modifying it. Return concise findings with exact file references, key code, architecture, and a recommended starting point.',
      permission: {
        '*': 'deny',
        read: {
          '*': 'allow',
          '**/*.env': 'ask',
          '**/*.env.*': 'ask',
          '**/*.env.example': 'allow',
        },
        glob: 'allow',
        grep: 'allow',
        list: 'allow',
      },
    },
    explore: {
      description: 'Fast codebase exploration',
      mode: 'subagent',
      prompt:
        'Explore the codebase without modifying it. Report findings with file references. Use bash and network fetch tools when needed for git, PR metadata, or remote docs; do not edit files.',
      permission: {
        '*': 'deny',
        read: {
          '*': 'allow',
          '**/*.env': 'ask',
          '**/*.env.*': 'ask',
          '**/*.env.example': 'allow',
        },
        glob: 'allow',
        grep: 'allow',
        list: 'allow',
        bash: 'allow',
        webfetch: 'allow',
        websearch: 'allow',
      },
    },
  },
  permission: {
    '*': 'allow',
    read: {
      '**/*.env': 'ask',
      '**/*.env.*': 'ask',
      '**/*.env.example': 'allow',
    },
  },
} satisfies Record<string, unknown>;
