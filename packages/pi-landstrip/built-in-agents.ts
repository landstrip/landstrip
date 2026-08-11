// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

export const BUILT_IN_LANDSTRIP_CONFIG = {
  maxSubagents: 1,
  toolFilesystemPolicy: 'host',
  agent: {
    build: {
      description: 'Implement and test requested changes',
      mode: 'primary',
      color: 'success',
      prompt: 'Implement, test, and complete the request.',
    },
    plan: {
      description: 'Plan before running commands or editing files',
      mode: 'primary',
      color: 'warning',
      prompt: 'Analyze the request and produce a clear plan before making changes.',
      permission: { edit: 'ask', bash: 'ask', task: 'ask' },
    },
    general: {
      description: 'General-purpose agent for complex tasks',
      mode: 'subagent',
      prompt: 'Complete the task and return a concise result.',
      permission: { todowrite: 'deny' },
    },
    scout: {
      description: 'Read-only codebase reconnaissance',
      mode: 'subagent',
      prompt:
        'Inspect the codebase without editing. Return concise findings with exact file references and a recommended starting point.',
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
      description: 'Codebase research with shell and web access',
      mode: 'subagent',
      prompt:
        'Explore without editing. Use shell or web tools when needed, then return concise findings with file references.',
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
