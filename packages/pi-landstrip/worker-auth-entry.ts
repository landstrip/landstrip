// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { Socket } from 'node:net';
import { resolve } from 'node:path';

import { InMemoryCredentialStore } from '@earendil-works/pi-ai';
import {
  createAgentSessionFromServices,
  createAgentSessionRuntime,
  createAgentSessionServices,
  getAgentDir,
  ModelRuntime,
  parseArgs,
  runRpcMode,
  SessionManager,
  SettingsManager,
} from '@earendil-works/pi-coding-agent';
import { EnvHttpProxyAgent, install, setGlobalDispatcher } from 'undici';

import { WORKER_AUTH_FD, WorkerAuthClient } from './worker-auth-channel.ts';
import { createWorkerAuthRuntime } from './worker-auth-runtime.ts';

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (
    args.mode !== 'rpc' ||
    !args.provider ||
    !args.model ||
    args.apiKey ||
    args.messages.length ||
    args.fileArgs.length
  ) {
    throw new Error('Invalid authenticated worker invocation');
  }
  if (args.offline) {
    process.env.PI_OFFLINE = '1';
    process.env.PI_SKIP_VERSION_CHECK = '1';
  }
  process.env.AI_AGENT = 'pi';
  process.env.PI_CODING_AGENT = 'true';
  const client = new WorkerAuthClient(
    new Socket({ fd: WORKER_AUTH_FD, readable: true, writable: true }),
  );
  let dispatcher: EnvHttpProxyAgent | undefined;
  try {
    // The SDK does not configure CLI HTTP proxy support. Use public Undici APIs
    // so provider fetches obey the sandbox's authenticated proxy environment.
    dispatcher = new EnvHttpProxyAgent({ allowH2: false });
    setGlobalDispatcher(dispatcher);
    install();
    const initial = await client.request();
    if (
      initial.model.provider !== args.provider ||
      `${initial.model.provider}/${initial.model.id}` !== args.model
    ) {
      throw new Error('Authenticated worker model mismatch');
    }
    const cwd = process.cwd();
    const agentDir = getAgentDir();
    const sessionManager = args.session
      ? SessionManager.open(args.session, args.sessionDir)
      : args.noSession
        ? SessionManager.inMemory(cwd)
        : SessionManager.create(cwd, args.sessionDir);
    const absolutePaths = (paths: string[] | undefined) => paths?.map((path) => resolve(cwd, path));
    const runtime = await createAgentSessionRuntime(
      async ({ cwd, sessionManager, sessionStartEvent }) => {
        const catalog = await ModelRuntime.create({
          credentials: new InMemoryCredentialStore(),
          allowModelNetwork: false,
          refreshOnCreate: false,
        });
        const services = await createAgentSessionServices({
          cwd,
          agentDir,
          modelRuntime: catalog,
          settingsManager: SettingsManager.create(cwd, agentDir, {
            projectTrusted: args.projectTrustOverride === true,
          }),
          extensionFlagValues: args.unknownFlags,
          resourceLoaderOptions: {
            additionalExtensionPaths: absolutePaths(args.extensions),
            additionalSkillPaths: absolutePaths(args.skills),
            additionalPromptTemplatePaths: absolutePaths(args.promptTemplates),
            additionalThemePaths: absolutePaths(args.themes),
            noExtensions: args.noExtensions,
            noSkills: args.noSkills,
            noPromptTemplates: args.noPromptTemplates,
            noThemes: args.noThemes,
            noContextFiles: args.noContextFiles,
            systemPrompt: args.systemPrompt,
            appendSystemPrompt: args.appendSystemPrompt,
          },
        });
        if (
          services.diagnostics.some((diagnostic) => diagnostic.type === 'error') ||
          services.resourceLoader.getExtensions().errors.length
        ) {
          throw new Error('Authenticated worker initialization failed');
        }
        services.modelRuntime = await createWorkerAuthRuntime(
          catalog,
          initial.model,
          async (signal) => {
            const result = await client.request(signal);
            if (
              result.model.provider !== initial.model.provider ||
              result.model.id !== initial.model.id
            ) {
              throw new Error('Authenticated worker model mismatch');
            }
            return result.auth;
          },
        );
        return {
          ...(await createAgentSessionFromServices({
            services,
            sessionManager,
            sessionStartEvent,
            model: initial.model,
            thinkingLevel: args.thinking,
            tools: args.tools,
            excludeTools: args.excludeTools,
            noTools: args.noTools ? 'all' : args.noBuiltinTools ? 'builtin' : undefined,
          })),
          services,
          diagnostics: services.diagnostics,
        };
      },
      { cwd, agentDir, sessionManager },
    );
    try {
      await runRpcMode(runtime);
    } finally {
      await runtime.dispose();
    }
  } finally {
    client.dispose();
    await dispatcher?.destroy();
  }
}

void main().catch(() => {
  // Startup failures can contain auth or model metadata. Never print their causes.
  console.error('Authenticated subagent worker failed to initialize');
  process.exitCode = 1;
});
