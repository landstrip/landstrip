// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { AuthResult, Model } from '@earendil-works/pi-ai';
import type { ExtensionContext } from '@earendil-works/pi-coding-agent';
import { canonicalizeHost } from '@landstrip/landstrip-api/shared';

export interface WorkerAuthSnapshot {
  model: Model<any>;
  auth: AuthResult;
}

// Pi 0.84.4 request implementations read these values from options.env. Never
// copy a provider prefix (or process.env) wholesale into the private snapshot.
const PROVIDER_ENVIRONMENT_KEYS: Readonly<Record<string, readonly string[]>> = {
  'amazon-bedrock': [
    'AWS_REGION',
    'AWS_DEFAULT_REGION',
    'AWS_PROFILE',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'AWS_BEARER_TOKEN_BEDROCK',
    'AWS_BEDROCK_SKIP_AUTH',
    'AWS_BEDROCK_FORCE_HTTP1',
    'AWS_BEDROCK_FORCE_CACHE',
  ],
  'google-vertex': [
    'GOOGLE_CLOUD_PROJECT',
    'GCLOUD_PROJECT',
    'GOOGLE_CLOUD_LOCATION',
    'GOOGLE_APPLICATION_CREDENTIALS',
  ],
  'azure-openai-responses': [
    'AZURE_OPENAI_BASE_URL',
    'AZURE_OPENAI_RESOURCE_NAME',
    'AZURE_OPENAI_API_VERSION',
    'AZURE_OPENAI_DEPLOYMENT_NAME_MAP',
  ],
};

class UnsupportedWorkerAuthError extends Error {}

function providerRequestAuth(provider: string, result: AuthResult, model?: Model<any>): AuthResult {
  const implementation = model?.api === 'bedrock-converse-stream' ? 'amazon-bedrock' : model?.api;
  const selected =
    implementation && Object.hasOwn(PROVIDER_ENVIRONMENT_KEYS, implementation)
      ? implementation
      : provider;
  const ambient: Record<string, string> = {};
  const keys = Object.hasOwn(PROVIDER_ENVIRONMENT_KEYS, selected)
    ? PROVIDER_ENVIRONMENT_KEYS[selected]
    : [];
  for (const name of keys) {
    const value = process.env[name];
    if (value !== undefined) ambient[name] = value;
  }
  const env = { ...ambient, ...result.env };

  if (selected === 'amazon-bedrock') {
    const directAuth =
      result.auth.apiKey || env.AWS_BEARER_TOKEN_BEDROCK || env.AWS_BEDROCK_SKIP_AUTH === '1';
    const staticKeys = env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && !env.AWS_PROFILE;
    if (!directAuth && !staticKeys) {
      // These are read by the AWS default chain from process.env, NOT options.env.
      // Do not silently use a different profile, file, or instance role in the worker.
      const unsupported = ['AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE'];
      if (!env.AWS_PROFILE || unsupported.some((name) => result.env?.[name] ?? process.env[name])) {
        throw new UnsupportedWorkerAuthError(
          'Subagent AWS credential-chain environment is unsupported in isolated workers; use scoped access keys or a Bedrock bearer token',
        );
      }
    }
    // Unlike scoped profiles, ambient profiles make the SDK load the profile's
    // region. That process.env-only behavior cannot survive worker isolation.
    // Defer this check until model selection so ARN-pinned regions still work.
    if (
      model &&
      process.env.AWS_PROFILE &&
      !env.AWS_REGION &&
      !env.AWS_DEFAULT_REGION &&
      !/^arn:aws(?:-[a-z0-9-]+)?:bedrock:([a-z0-9-]+):/.test(model.id)
    ) {
      throw new UnsupportedWorkerAuthError(
        'Subagent ambient AWS profiles require AWS_REGION or AWS_DEFAULT_REGION for non-ARN models in isolated workers',
      );
    }
  }

  // Azure's request env takes precedence over model.baseUrl. Surface that same
  // endpoint during the parent's initial grant and subsequent host validation.
  const baseUrl =
    selected === 'azure-openai-responses'
      ? env.AZURE_OPENAI_BASE_URL?.trim() ||
        (env.AZURE_OPENAI_RESOURCE_NAME
          ? `https://${env.AZURE_OPENAI_RESOURCE_NAME}.openai.azure.com/openai/v1`
          : undefined)
      : undefined;
  return {
    auth: baseUrl ? { ...result.auth, baseUrl } : result.auth,
    env: Object.keys(env).length ? env : undefined,
  };
}

/** Never include provider exceptions, source labels, or credential objects in diagnostics. */
export async function resolveWorkerAuth(
  registry: ExtensionContext['modelRegistry'],
  provider: string,
  signal: AbortSignal,
  model?: Model<any>,
): Promise<AuthResult | undefined> {
  if (signal.aborted) throw new Error('Task cancelled');
  let abort = () => {};
  let timer: ReturnType<typeof setTimeout> | undefined;
  const interrupted = new Promise<never>((_resolve, reject) => {
    abort = () => reject(new Error('Task cancelled'));
    signal.addEventListener('abort', abort, { once: true });
    timer = setTimeout(
      () => reject(new Error('Subagent provider authentication lookup timed out after 30 seconds')),
      30_000,
    );
  });
  try {
    // ModelRegistry's public facade does not accept a signal (Pi 0.82–0.84).
    // Race the wait, never modify its private runtime or copy OAuth refresh tokens.
    const resolve = async (): Promise<AuthResult | undefined> => {
      try {
        const providerAuth = await registry.getProviderAuth(provider);
        if (signal.aborted || !providerAuth) return undefined;
        if (model && typeof registry.getApiKeyAndHeaders === 'function') {
          // The model facade also resolves configured per-model headers. It can
          // report ok with no credential, so first verify provider auth exists.
          const result = await registry.getApiKeyAndHeaders(model);
          if (!result.ok) throw new Error();
          return {
            auth: { apiKey: result.apiKey, headers: result.headers, baseUrl: result.baseUrl },
            env: result.env,
          };
        }
        return { auth: providerAuth.auth, env: providerAuth.env };
      } catch {
        throw new Error('Could not resolve subagent provider authentication');
      }
    };
    const result = await Promise.race([resolve(), interrupted]);
    if (signal.aborted) throw new Error('Task cancelled');
    try {
      return result ? providerRequestAuth(provider, result, model) : undefined;
    } catch (error) {
      if (error instanceof UnsupportedWorkerAuthError) throw error;
      throw new Error('Could not resolve subagent provider authentication');
    }
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', abort);
  }
}

export function workerAuthHost(baseUrl: unknown): string | undefined {
  if (baseUrl === undefined || baseUrl === '') return undefined;
  try {
    if (
      typeof baseUrl !== 'string' ||
      !/^https?:\/\/[^/?#]/i.test(baseUrl) ||
      /[\s\\\p{Cc}]/u.test(baseUrl)
    ) {
      throw new Error();
    }
    const url = new URL(baseUrl);
    const host = canonicalizeHost(url.hostname);
    if (!host || (url.protocol !== 'https:' && url.protocol !== 'http:')) throw new Error();
    return host;
  } catch {
    throw new Error('Invalid subagent provider endpoint');
  }
}

/** Each request resolves afresh in the parent, retaining its OAuth locking/refresh behavior. */
export function workerAuthResolver(
  registry: ExtensionContext['modelRegistry'],
  selected: Model<any>,
  domains: readonly string[],
): (signal: AbortSignal) => Promise<WorkerAuthSnapshot> {
  // The selected model is pinned before any asynchronous auth work.
  const model = structuredClone(selected);
  return async (signal) => {
    const result = await resolveWorkerAuth(registry, model.provider, signal, model);
    if (!result) throw new Error('Subagent provider authentication is unavailable');
    const baseUrl = result.auth.baseUrl || model.baseUrl;
    const host = workerAuthHost(baseUrl);
    if (!host || !domains.includes(host)) {
      throw new Error('Subagent provider endpoint changed; start a new task');
    }
    const { headers: _headers, ...metadata } = model;
    return {
      // RPC get_state exposes model metadata. Auth-bearing paths/headers stay private.
      model: { ...metadata, baseUrl: new URL(baseUrl).origin },
      auth: { auth: { ...result.auth, baseUrl }, env: result.env },
    };
  };
}
