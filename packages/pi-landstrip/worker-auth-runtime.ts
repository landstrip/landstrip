// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { AuthResult, Model } from '@earendil-works/pi-ai';
import type { ModelRuntime } from '@earendil-works/pi-coding-agent';

/**
 * Compose the worker's existing stream implementation with parent-owned auth.
 * The second runtime deliberately has no models.json overlay: credentials and
 * authHeader/header interpolation have already been resolved by the parent.
 */
export async function createWorkerAuthRuntime(
  catalog: ModelRuntime,
  runtime: ModelRuntime,
  model: Model<any>,
  resolveAuth: (signal: AbortSignal) => Promise<AuthResult>,
): Promise<ModelRuntime> {
  if (!catalog.getProvider(model.provider)) {
    // Runtime-only SDK models using a standard Pi API need not exist in models.json.
    catalog.registerProvider(model.provider, {
      baseUrl: model.baseUrl,
      api: model.api,
      models: [model],
    });
  }
  const provider = catalog.getProvider(model.provider);
  if (!provider) throw new Error('Subagent provider is unavailable in the worker');
  runtime.registerNativeProvider({
    id: provider.id,
    name: provider.name,
    // No resolved auth belongs in provider/model metadata (RPC exposes models).
    getModels: () => [model],
    auth: {
      apiKey: {
        name: 'Supervisor authentication',
        check: async () => ({ type: 'api_key' }),
        resolve: ({ signal }) => resolveAuth(signal),
      },
    },
    // Bind the original provider, preserving custom stream implementations.
    stream: (requestModel, context, options) => provider.stream(requestModel, context, options),
    streamSimple: (requestModel, context, options) =>
      provider.streamSimple(requestModel, context, options),
  });
  await runtime.refresh({ allowNetwork: false });
  return runtime;
}
