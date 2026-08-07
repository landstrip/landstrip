// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { createHash } from 'node:crypto';

import { clampThinkingLevel, complete, completeSimple } from '@earendil-works/pi-ai/compat';
import type { AssistantMessage, Model, ThinkingLevel, UserMessage } from '@earendil-works/pi-ai';
import type { ExtensionContext } from '@earendil-works/pi-coding-agent';

import { REVIEWER_POLICY_PROMPT } from './policy.ts';

export type ReviewDecision = {
  decision: 'allow' | 'block';
  tier: 'hard_deny' | 'soft_deny' | 'allow' | 'explicit_intent' | 'none';
  reason: string;
};

export type ReviewReasoningLevel = 'off' | ThinkingLevel;

export type ReviewConfig = {
  enabled: boolean;
  model?: string;
  reasoning: ReviewReasoningLevel;
  timeoutMs: number;
  policy: string;
  maxConsecutiveDenials: number;
  maxDenialsInWindow: number;
  denialWindowSize: number;
};

export type ReviewerCompletionFn = (
  model: Model<any>,
  options: { systemPrompt: string; messages: UserMessage[] },
  callOptions: {
    apiKey?: string;
    headers?: Record<string, string>;
    signal?: AbortSignal;
    maxTokens: number;
    temperature?: number;
    reasoning?: Exclude<ReviewReasoningLevel, 'off'>;
    sessionId?: string;
    cacheRetention?: 'none' | 'short' | 'long';
  },
) => Promise<AssistantMessage>;

const FAST_INSTRUCTION =
  'Return exactly one digit and nothing else: 0 only when the action is clearly allowed by the policy; 1 when it may need blocking or you are uncertain. Err on 1.';

const DETAILED_INSTRUCTION = `Return only JSON exactly matching:
{"decision":"allow"|"block","tier":"hard_deny"|"soft_deny"|"allow"|"explicit_intent"|"none","reason":"brief concrete reason"}
Do not use Markdown, code fences, prose, or any wrapper. The first character must be { and the last character must be }.
Valid decision/tier combinations:
- allow: allow, explicit_intent, or none
- block: hard_deny, soft_deny, or none`;

const DEFAULT_FAST_MAX_TOKENS = 512;
const DEFAULT_DETAILED_MAX_TOKENS = 1200;

function parseModelSpec(spec: string): { provider: string; id: string } | undefined {
  const slashIndex = spec.indexOf('/');
  if (slashIndex <= 0 || slashIndex === spec.length - 1) return undefined;
  return { provider: spec.slice(0, slashIndex), id: spec.slice(slashIndex + 1) };
}

function extractAssistantText(message: AssistantMessage, trim = true): string {
  const text = message.content
    .filter((block): block is { type: 'text'; text: string } => block.type === 'text')
    .map((block) => block.text)
    .join('\n');
  return trim ? text.trim() : text;
}

export function parseReviewDecision(
  message: AssistantMessage,
): ReviewDecision | undefined {
  const text = extractAssistantText(message);
  const validTiers = new Set<ReviewDecision['tier']>([
    'hard_deny',
    'soft_deny',
    'allow',
    'explicit_intent',
    'none',
  ]);
  try {
    for (const key of ['decision', 'tier', 'reason']) {
      const occurrences = text.match(new RegExp(`"${key}"\\s*:`, 'g'))?.length ?? 0;
      if (occurrences !== 1) return undefined;
    }
    const parsed = JSON.parse(text) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined;
    }
    const keys = Object.keys(parsed).sort();
    if (keys.join(',') !== 'decision,reason,tier') return undefined;
    if (parsed.decision !== 'allow' && parsed.decision !== 'block') {
      return undefined;
    }
    if (!validTiers.has(parsed.tier as ReviewDecision['tier'])) {
      return undefined;
    }
    const tier = parsed.tier as ReviewDecision['tier'];
    if (
      (parsed.decision === 'allow' &&
        !['allow', 'explicit_intent', 'none'].includes(tier)) ||
      (parsed.decision === 'block' &&
        !['hard_deny', 'soft_deny', 'none'].includes(tier))
    ) {
      return undefined;
    }
    if (typeof parsed.reason !== 'string' || parsed.reason.trim() === '') {
      return undefined;
    }
    return { decision: parsed.decision, tier, reason: parsed.reason };
  } catch {
    return undefined;
  }
}

function stageMessage(text: string): UserMessage {
  return {
    role: 'user',
    content: [{ type: 'text', text }],
    timestamp: Date.now(),
  };
}

function classifierFailure(
  response: AssistantMessage,
  label: string,
  retryLength = false,
): ReviewDecision | undefined {
  if (
    response.stopReason === 'stop' ||
    (retryLength && response.stopReason === 'length')
  ) {
    return undefined;
  }
  const fallback =
    response.stopReason === 'aborted'
      ? 'Reviewer model request was aborted.'
      : response.stopReason === 'error'
        ? 'Reviewer model returned an error response.'
        : `${label} response did not stop cleanly (${response.stopReason}).`;
  return {
    decision: 'block',
    tier: 'none',
    reason: `${label} failed; review fails closed: ${response.errorMessage ?? fallback}`,
  };
}

export function buildSystemPrompt(config: ReviewConfig): string {
  if (config.policy === 'default' || !config.policy) {
    return REVIEWER_POLICY_PROMPT;
  }
  return config.policy;
}

type ClassifierResolution = {
  classifier?: {
    model: Model<any>;
    apiKey?: string;
    headers?: Record<string, string>;
  };
  completionFn: ReviewerCompletionFn;
  reasoningLevel?: Exclude<ReviewReasoningLevel, 'off'>;
};

export async function resolveReviewer(
  ctx: ExtensionContext,
  config: ReviewConfig,
): Promise<ClassifierResolution> {
  const configured = config.model;
  const model = configured
    ? (() => {
        const parsed = parseModelSpec(configured);
        return parsed ? ctx.modelRegistry.find(parsed.provider, parsed.id) : undefined;
      })()
    : ctx.model;
  if (!model) {
    return { completionFn: complete };
  }

  const effectiveLevel = clampThinkingLevel(model, config.reasoning);
  const completionFn = effectiveLevel === 'off' ? completeSimple : completeSimple;
  const reasoningLevel = effectiveLevel === 'off' ? undefined : effectiveLevel;

  const auth = await ctx.modelRegistry.getApiKeyAndHeaders(model);
  if (!auth.ok) return { completionFn, reasoningLevel };

  return {
    classifier: { model, apiKey: auth.apiKey, headers: auth.headers },
    completionFn,
    reasoningLevel,
  };
}

export function reviewerCacheSessionId(ctx: ExtensionContext): string {
  const source =
    ctx.sessionManager.getSessionId?.() ??
    ctx.sessionManager.getSessionFile?.() ??
    ctx.cwd;
  const digest = createHash('sha256').update(source).digest('hex').slice(0, 32);
  return `pi-landstrip-review-${digest}`;
}

async function classifyWithRetry(
  completeFn: ReviewerCompletionFn,
  classifier: {
    model: Model<any>;
    apiKey?: string;
    headers?: Record<string, string>;
  },
  prompt: { systemPrompt: string; messages: UserMessage[] },
  signal: AbortSignal | undefined,
  options: {
    maxTokens?: number;
    reasoningLevel?: Exclude<ReviewReasoningLevel, 'off'>;
    sessionId: string;
    timeoutMs: number;
  },
): Promise<ReviewDecision> {
  const maxAttempts = 2;
  const maxTokens = options.maxTokens ?? DEFAULT_DETAILED_MAX_TOKENS;
  let lastReason =
    'Reviewer response was not valid decision JSON; review fails closed.';
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const timeoutController = new AbortController();
    const timeout = setTimeout(
      () => timeoutController.abort(),
      options.timeoutMs,
    );
    const combinedSignal = signal
      ? AbortSignal.any([signal, timeoutController.signal])
      : timeoutController.signal;
    let response: AssistantMessage;
    try {
      response = await completeFn(
        classifier.model,
        prompt,
        {
          apiKey: classifier.apiKey,
          headers: classifier.headers,
          signal: combinedSignal,
          maxTokens,
          ...(options.reasoningLevel === undefined
            ? {}
            : { reasoning: options.reasoningLevel }),
          sessionId: options.sessionId,
          cacheRetention: 'short',
        },
      );
    } catch (error) {
      clearTimeout(timeout);
      const message = error instanceof Error ? error.message : String(error);
      return {
        decision: 'block',
        tier: 'none',
        reason: `Reviewer failed; review fails closed: ${message}`,
      };
    }
    clearTimeout(timeout);
    const failure = classifierFailure(response, 'Reviewer', true);
    const decision =
      response.stopReason === 'stop' ? parseReviewDecision(response) : undefined;
    if (failure) return failure;
    if (decision) return decision;
    lastReason =
      response.stopReason === 'length'
        ? 'Reviewer response was truncated before producing valid decision JSON; review fails closed.'
        : 'Reviewer response was not valid decision JSON; review fails closed.';
  }
  return { decision: 'block', tier: 'none', reason: lastReason };
}

export async function classifyInStages(
  completeFn: ReviewerCompletionFn,
  classifier: {
    model: Model<any>;
    apiKey?: string;
    headers?: Record<string, string>;
  },
  prompt: { systemPrompt: string; contextMessage: UserMessage },
  signal: AbortSignal | undefined,
  options: {
    fastMaxTokens?: number;
    reasoningLevel?: Exclude<ReviewReasoningLevel, 'off'>;
    sessionId: string;
    timeoutMs: number;
  },
): Promise<ReviewDecision> {
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort(), options.timeoutMs);
  const combinedSignal = signal
    ? AbortSignal.any([signal, timeoutController.signal])
    : timeoutController.signal;

  let fastResponse: AssistantMessage;
  try {
    fastResponse = await completeFn(
      classifier.model,
      {
        systemPrompt: prompt.systemPrompt,
        messages: [prompt.contextMessage, stageMessage(FAST_INSTRUCTION)],
      },
      {
        apiKey: classifier.apiKey,
        headers: classifier.headers,
        signal: combinedSignal,
        maxTokens: options.fastMaxTokens ?? DEFAULT_FAST_MAX_TOKENS,
        ...(options.reasoningLevel === undefined
          ? {}
          : { reasoning: options.reasoningLevel }),
        sessionId: options.sessionId,
        cacheRetention: 'short',
      },
    );
  } catch (error) {
    clearTimeout(timeout);
    const message = error instanceof Error ? error.message : String(error);
    return {
      decision: 'block',
      tier: 'none',
      reason: `Fast reviewer failed; review fails closed: ${message}`,
    };
  }
  clearTimeout(timeout);

  const fastText = extractAssistantText(fastResponse, false).trim();
  const failure = classifierFailure(fastResponse, 'Fast reviewer');
  if (failure) return failure;
  if (fastText === '0') {
    return {
      decision: 'allow',
      tier: 'none',
      reason: 'Fast reviewer found no policy-relevant risk.',
    };
  }
  if (fastText !== '1') {
    return {
      decision: 'block',
      tier: 'none',
      reason:
        'Fast reviewer response was not 0 or 1 after trimming whitespace; review fails closed.',
    };
  }

  return classifyWithRetry(
    completeFn,
    classifier,
    {
      systemPrompt: prompt.systemPrompt,
      messages: [prompt.contextMessage, stageMessage(DETAILED_INSTRUCTION)],
    },
    signal,
    {
      maxTokens: DEFAULT_DETAILED_MAX_TOKENS,
      reasoningLevel: options.reasoningLevel,
      sessionId: options.sessionId,
      timeoutMs: options.timeoutMs,
    },
  );
}

export type ReviewAction = (
  ctx: ExtensionContext,
  config: ReviewConfig,
  action: string,
) => Promise<ReviewDecision>;

export const defaultReviewAction: ReviewAction = async (
  ctx,
  config,
  action,
): Promise<ReviewDecision> => {
  const resolution = await resolveReviewer(ctx, config);
  if (!resolution.classifier) {
    return {
      decision: 'block',
      tier: 'none',
      reason: 'No reviewer model/API key available; review fails closed.',
    };
  }

  const systemPrompt = buildSystemPrompt(config);
  const contextText = `Latest action to classify:\n${action}`;
  const contextMessage: UserMessage = {
    role: 'user',
    content: [{ type: 'text', text: contextText }],
    timestamp: Date.now(),
  };

  return classifyInStages(
    resolution.completionFn,
    resolution.classifier,
    { systemPrompt, contextMessage },
    ctx.signal,
    {
      fastMaxTokens: DEFAULT_FAST_MAX_TOKENS,
      reasoningLevel: resolution.reasoningLevel,
      sessionId: reviewerCacheSessionId(ctx),
      timeoutMs: config.timeoutMs,
    },
  );
};