// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { highlightCode, keyHint } from '@earendil-works/pi-coding-agent';
import {
  type Component,
  Markdown,
  type MarkdownTheme,
  truncateToWidth,
  visibleWidth,
  wrapTextWithAnsi,
} from '@earendil-works/pi-tui';

export interface MarkdownRenderTheme {
  fg(color: any, text: string): string;
  bg?(color: any, text: string): string;
  bold(text: string): string;
  italic?(text: string): string;
  underline?(text: string): string;
  strikethrough?(text: string): string;
}

export interface KeyHintSource {
  keyHint?: (keybinding: any, description: string) => string;
}

const DEFAULT_FALLBACK_WIDTH = 80;
const LOG_TOOL_RESULT_PREVIEW_LINES = 8;

const TASK_ENVELOPE_RE =
  /^(?:([^\n]*)\n\n)?<task id="([^"]*)" state="([^"]*)">\n<(task_result|task_error)>\n([\s\S]*)\n<\/\4>\n<\/task>\s*$/;

const STREAM_STATUS_PLACEHOLDER_RE =
  /^(?:\(no output\)|Queued|Starting subagent|Subagent running|Running [^\n]+|Retry \d+)$/;

export interface ParsedTaskEnvelope {
  preamble?: string;
  taskId?: string;
  state?: string;
  isError: boolean;
  isCommand: boolean;
  body: string;
}

export function normalizeRenderWidth(width: unknown, fallback = DEFAULT_FALLBACK_WIDTH): number {
  return typeof width === 'number' && Number.isFinite(width) && width > 0
    ? Math.floor(width)
    : fallback;
}

export function clampLineToWidth(line: string, width: number): string {
  return visibleWidth(line) <= width ? line : truncateToWidth(line, width);
}

export function formatExpandHint(source?: KeyHintSource): string {
  if (typeof source?.keyHint === 'function') {
    const formatted = source.keyHint('app.tools.expand', 'to expand');
    if (formatted && formatted !== 'to expand') return formatted;
  }
  try {
    const fallback = keyHint('app.tools.expand', 'to expand');
    if (fallback && fallback !== 'to expand') return fallback;
  } catch {}
  return 'Ctrl+O to expand';
}

export function isStreamStatusPlaceholder(text: string): boolean {
  return STREAM_STATUS_PLACEHOLDER_RE.test(text.trim());
}

export function parseTaskEnvelope(raw: string): ParsedTaskEnvelope | undefined {
  const match = TASK_ENVELOPE_RE.exec(raw);
  if (!match) return undefined;
  const [, preamble, taskId, state, tag, body] = match;
  return {
    preamble: preamble || undefined,
    taskId: taskId || undefined,
    state: state || undefined,
    isError: tag === 'task_error',
    isCommand: Boolean(preamble?.startsWith('Background command ')),
    body: body ?? '',
  };
}

export function markdownThemeFrom(theme: MarkdownRenderTheme): MarkdownTheme {
  const fg =
    typeof theme?.fg === 'function' ? theme.fg.bind(theme) : (_color: any, text: string) => text;
  const bold = typeof theme?.bold === 'function' ? theme.bold.bind(theme) : (text: string) => text;
  const italic =
    typeof theme?.italic === 'function' ? theme.italic.bind(theme) : (text: string) => text;
  const underline =
    typeof theme?.underline === 'function' ? theme.underline.bind(theme) : (text: string) => text;
  const strikethrough =
    typeof theme?.strikethrough === 'function'
      ? theme.strikethrough.bind(theme)
      : (text: string) => text;

  return {
    heading: (text) => fg('mdHeading', text),
    link: (text) => fg('mdLink', text),
    linkUrl: (text) => fg('mdLinkUrl', text),
    code: (text) => fg('mdCode', text),
    codeBlock: (text) => fg('mdCodeBlock', text),
    codeBlockBorder: (text) => fg('mdCodeBlockBorder', text),
    quote: (text) => fg('mdQuote', text),
    quoteBorder: (text) => fg('mdQuoteBorder', text),
    hr: (text) => fg('mdHr', text),
    listBullet: (text) => fg('mdListBullet', text),
    bold,
    italic,
    underline,
    strikethrough,
    highlightCode: (code, lang) => {
      if (!lang) return code.split('\n').map((line) => fg('mdCodeBlock', line));
      try {
        return highlightCode(code, lang);
      } catch {
        return code.split('\n').map((line) => fg('mdCodeBlock', line));
      }
    },
  };
}

function cleanMarkdownOutputLines(rawLines: readonly string[], width: number): string[] {
  const cleaned = rawLines.map((line) => clampLineToWidth(line.replace(/ +$/, ''), width));
  while (cleaned.length > 0 && cleaned[cleaned.length - 1] === '') {
    cleaned.pop();
  }
  return cleaned;
}

export function renderMarkdownLines(
  markdown: string,
  width: number,
  theme: MarkdownRenderTheme,
  colorToken = 'toolOutput',
): string[] {
  const trimmed = markdown.trimEnd();
  if (!trimmed) return [];
  const normalized = normalizeRenderWidth(width);
  const fg =
    typeof theme?.fg === 'function' ? theme.fg.bind(theme) : (_color: any, text: string) => text;
  const md = new Markdown(trimmed, 0, 0, markdownThemeFrom(theme), {
    color: (text) => fg(colorToken, text),
  });
  return cleanMarkdownOutputLines(md.render(normalized), normalized);
}

export function renderPlainLines(
  text: string,
  width: number,
  theme: MarkdownRenderTheme,
  colorToken = 'toolOutput',
): string[] {
  const trimmed = text.trimEnd();
  if (!trimmed) return [];
  const normalized = normalizeRenderWidth(width);
  const fg =
    typeof theme?.fg === 'function' ? theme.fg.bind(theme) : (_color: any, value: string) => value;
  const out: string[] = [];
  for (const rawLine of trimmed.split('\n')) {
    const wrapped = wrapTextWithAnsi(fg(colorToken, rawLine), normalized);
    if (wrapped.length === 0) {
      out.push('');
      continue;
    }
    for (const line of wrapped) out.push(clampLineToWidth(line, normalized));
  }
  return out;
}

export interface SubagentLogMessagePart {
  type: 'text' | 'toolCall';
  text: string;
}

export interface SubagentLogEntry {
  role: 'user' | 'assistant' | 'toolResult' | string;
  toolName?: string;
  parts: SubagentLogMessagePart[];
}

export function extractLogMessageParts(message: Record<string, unknown>): SubagentLogMessagePart[] {
  const content = message.content;
  if (typeof content === 'string') {
    return content ? [{ type: 'text', text: content }] : [];
  }
  if (!Array.isArray(content)) return [];
  const parts: SubagentLogMessagePart[] = [];
  for (const item of content) {
    if (typeof item !== 'object' || item === null) continue;
    const record = item as Record<string, unknown>;
    if (record.type === 'text' && typeof record.text === 'string' && record.text) {
      parts.push({ type: 'text', text: record.text });
    } else if (record.type === 'toolCall' && typeof record.name === 'string' && record.name) {
      parts.push({ type: 'toolCall', text: record.name });
    }
  }
  return parts;
}

export function renderSubagentSessionLog(
  entries: readonly SubagentLogEntry[],
  width: number,
  theme: MarkdownRenderTheme,
  agentLabel = 'assistant',
): string[] {
  const normalized = normalizeRenderWidth(width);
  const fg =
    typeof theme?.fg === 'function' ? theme.fg.bind(theme) : (_color: any, value: string) => value;
  const bold =
    typeof theme?.bold === 'function' ? theme.bold.bind(theme) : (value: string) => value;
  const bodyWidth = Math.max(1, normalized - 2);
  const indent = normalized > 4 ? '  ' : '';
  const indentWidth = indent.length;
  const innerWidth = Math.max(1, normalized - indentWidth);
  const lines: string[] = [];

  for (const entry of entries) {
    if (entry.parts.length === 0) continue;
    if (lines.length > 0) lines.push('');

    if (entry.role === 'toolResult') {
      const label = entry.toolName ? `tool:${entry.toolName}` : 'tool';
      lines.push(clampLineToWidth(fg('dim', label), normalized));
      const rawText = entry.parts
        .filter((part) => part.type === 'text')
        .map((part) => part.text)
        .join('\n')
        .trimEnd();
      if (!rawText) continue;
      const wrapped = renderPlainLines(rawText, innerWidth, theme, 'dim');
      const shown = wrapped.slice(0, LOG_TOOL_RESULT_PREVIEW_LINES);
      for (const line of shown) {
        lines.push(clampLineToWidth(`${indent}${line}`, normalized));
      }
      const hidden = wrapped.length - shown.length;
      if (hidden > 0) {
        lines.push(
          clampLineToWidth(
            `${indent}${fg('muted', `… +${hidden} line${hidden === 1 ? '' : 's'}`)}`,
            normalized,
          ),
        );
      }
      continue;
    }

    const header =
      entry.role === 'user'
        ? fg('accent', bold('user'))
        : entry.role === 'assistant'
          ? fg('success', bold(agentLabel))
          : fg('muted', bold(entry.role));
    lines.push(clampLineToWidth(header, normalized));

    const colorToken = entry.role === 'user' ? 'text' : 'toolOutput';
    for (const part of entry.parts) {
      if (part.type === 'toolCall') {
        lines.push(clampLineToWidth(`${indent}${fg('muted', `→ ${part.text}`)}`, normalized));
        continue;
      }
      const mdLines = renderMarkdownLines(
        part.text,
        indentWidth > 0 ? innerWidth : bodyWidth,
        theme,
        colorToken,
      );
      for (const mdLine of mdLines) {
        lines.push(mdLine ? clampLineToWidth(`${indent}${mdLine}`, normalized) : '');
      }
    }
  }

  return lines;
}

export interface SubagentReportComponentOptions {
  headerLines?: string[];
  body?: string;
  bodyKind?: 'markdown' | 'plain' | 'error';
  expanded: boolean;
  previewLines?: number;
  expandHint?: string;
  footerLines?: string[];
  theme: MarkdownRenderTheme;
  fallbackWidth?: number;
}

export class SubagentReportComponent implements Component {
  private options: SubagentReportComponentOptions;
  private md: Markdown | undefined;
  private mdThemeRef: MarkdownRenderTheme | undefined;
  private mdBody = '';
  private cachedWidth: number | undefined;
  private cachedLines: string[] | undefined;

  constructor(options: SubagentReportComponentOptions) {
    this.options = options;
  }

  update(options: SubagentReportComponentOptions): void {
    this.options = options;
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
  }

  invalidate(): void {
    this.cachedWidth = undefined;
    this.cachedLines = undefined;
    this.md?.invalidate();
  }

  private renderMarkdownBody(text: string, width: number): string[] {
    const fg =
      typeof this.options.theme?.fg === 'function'
        ? this.options.theme.fg.bind(this.options.theme)
        : (_color: any, value: string) => value;
    if (!this.md || this.mdThemeRef !== this.options.theme) {
      this.md = new Markdown(text, 0, 0, markdownThemeFrom(this.options.theme), {
        color: (value) => fg('toolOutput', value),
      });
      this.mdThemeRef = this.options.theme;
      this.mdBody = text;
    } else if (this.mdBody !== text) {
      this.md.setText(text);
      this.mdBody = text;
    }
    return cleanMarkdownOutputLines(this.md.render(width), width);
  }

  render(width: number): string[] {
    const normalized = normalizeRenderWidth(width, this.options.fallbackWidth);
    if (this.cachedLines && this.cachedWidth === normalized) {
      return this.cachedLines;
    }

    const fg =
      typeof this.options.theme?.fg === 'function'
        ? this.options.theme.fg.bind(this.options.theme)
        : (_color: any, value: string) => value;
    const out: string[] = [];

    for (const header of this.options.headerLines ?? []) {
      for (const rawLine of header.split('\n')) {
        for (const wrapped of wrapTextWithAnsi(rawLine, normalized)) {
          out.push(clampLineToWidth(wrapped, normalized));
        }
      }
    }

    const trimmedBody = (this.options.body ?? '').trimEnd();
    if (trimmedBody) {
      const bodyKind = this.options.bodyKind ?? 'markdown';
      const renderedBody =
        bodyKind === 'markdown'
          ? this.renderMarkdownBody(trimmedBody, normalized)
          : renderPlainLines(
              trimmedBody,
              normalized,
              this.options.theme,
              bodyKind === 'error' ? 'error' : 'toolOutput',
            );

      if (renderedBody.length > 0) {
        if (this.options.expanded) {
          if (out.length > 0 && bodyKind === 'markdown' && renderedBody.length > 1) {
            out.push('');
          }
          out.push(...renderedBody);
          if (
            (this.options.footerLines?.length ?? 0) > 0 &&
            bodyKind === 'markdown' &&
            renderedBody.length > 1
          ) {
            out.push('');
          }
        } else {
          const previewLimit = Math.max(1, this.options.previewLines ?? 3);
          const shown = renderedBody.slice(0, previewLimit);
          const hidden = renderedBody.length > shown.length;
          if (hidden) {
            while (shown.length > 1 && shown[shown.length - 1] === '') {
              shown.pop();
            }
          }
          out.push(...shown);
          if (hidden) {
            const hint = this.options.expandHint || formatExpandHint();
            out.push(clampLineToWidth(fg('muted', `… ${hint}`), normalized));
          }
        }
      }
    }

    for (const footer of this.options.footerLines ?? []) {
      for (const rawLine of footer.split('\n')) {
        out.push(clampLineToWidth(rawLine, normalized));
      }
    }

    this.cachedWidth = normalized;
    this.cachedLines = out;
    return out;
  }
}

export function upsertSubagentReportComponent(
  lastComponent: unknown,
  options: SubagentReportComponentOptions,
): SubagentReportComponent {
  if (lastComponent instanceof SubagentReportComponent) {
    lastComponent.update(options);
    return lastComponent;
  }
  return new SubagentReportComponent(options);
}
