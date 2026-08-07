// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { expect, test } from 'vitest';

import type { AssistantMessage } from '@earendil-works/pi-ai';

import { parseReviewDecision } from './classifier.ts';

function mockAssistant(text: string, stopReason: AssistantMessage['stopReason'] = 'stop'): AssistantMessage {
  return {
    role: 'assistant',
    content: [{ type: 'text', text }],
    api: 'test',
    provider: 'test',
    model: 'test',
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason,
    timestamp: Date.now(),
  };
}

test('parses a valid allow decision', () => {
  const msg = mockAssistant('{"decision":"allow","tier":"allow","reason":"safe action"}');
  const result = parseReviewDecision(msg);
  expect(result).toEqual({
    decision: 'allow',
    tier: 'allow',
    reason: 'safe action',
  });
});

test('parses a valid block decision', () => {
  const msg = mockAssistant('{"decision":"block","tier":"soft_deny","reason":"risky action"}');
  const result = parseReviewDecision(msg);
  expect(result).toEqual({
    decision: 'block',
    tier: 'soft_deny',
    reason: 'risky action',
  });
});

test('parses allow with explicit_intent tier', () => {
  const msg = mockAssistant('{"decision":"allow","tier":"explicit_intent","reason":"user authorized"}');
  const result = parseReviewDecision(msg);
  expect(result?.decision).toBe('allow');
  expect(result?.tier).toBe('explicit_intent');
});

test('parses allow with none tier', () => {
  const msg = mockAssistant('{"decision":"allow","tier":"none","reason":"no risk"}');
  const result = parseReviewDecision(msg);
  expect(result?.decision).toBe('allow');
  expect(result?.tier).toBe('none');
});

test('parses block with hard_deny tier', () => {
  const msg = mockAssistant('{"decision":"block","tier":"hard_deny","reason":"exfiltration"}');
  const result = parseReviewDecision(msg);
  expect(result?.decision).toBe('block');
  expect(result?.tier).toBe('hard_deny');
});

test('rejects extra fields', () => {
  const msg = mockAssistant('{"decision":"allow","tier":"allow","reason":"ok","extra":"field"}');
  expect(parseReviewDecision(msg)).toBeUndefined();
});

test('rejects missing fields', () => {
  expect(parseReviewDecision(mockAssistant('{"decision":"allow","tier":"allow"}'))).toBeUndefined();
  expect(parseReviewDecision(mockAssistant('{"decision":"allow","reason":"ok"}'))).toBeUndefined();
  expect(parseReviewDecision(mockAssistant('{"tier":"allow","reason":"ok"}'))).toBeUndefined();
});

test('rejects invalid decision values', () => {
  expect(
    parseReviewDecision(mockAssistant('{"decision":"maybe","tier":"allow","reason":"?"}')),
  ).toBeUndefined();
});

test('rejects invalid tier values', () => {
  expect(
    parseReviewDecision(mockAssistant('{"decision":"allow","tier":"maybe","reason":"?"}')),
  ).toBeUndefined();
});

test('rejects allow with block-only tier', () => {
  expect(
    parseReviewDecision(mockAssistant('{"decision":"allow","tier":"hard_deny","reason":"?"}')),
  ).toBeUndefined();
});

test('rejects block with allow-only tier', () => {
  expect(
    parseReviewDecision(mockAssistant('{"decision":"block","tier":"allow","reason":"?"}')),
  ).toBeUndefined();
});

test('rejects empty reason', () => {
  expect(
    parseReviewDecision(mockAssistant('{"decision":"allow","tier":"allow","reason":""}')),
  ).toBeUndefined();
  expect(
    parseReviewDecision(mockAssistant('{"decision":"allow","tier":"allow","reason":"  "}')),
  ).toBeUndefined();
});

test('rejects markdown-wrapped JSON', () => {
  expect(
    parseReviewDecision(
      mockAssistant('```json\n{"decision":"allow","tier":"allow","reason":"ok"}\n```'),
    ),
  ).toBeUndefined();
});

test('rejects non-JSON text', () => {
  expect(parseReviewDecision(mockAssistant('not json at all'))).toBeUndefined();
  expect(parseReviewDecision(mockAssistant(''))).toBeUndefined();
});

test('rejects duplicate keys', () => {
  expect(
    parseReviewDecision(
      mockAssistant('{"decision":"allow","tier":"allow","reason":"ok","decision":"block"}'),
    ),
  ).toBeUndefined();
});