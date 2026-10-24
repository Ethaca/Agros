import Anthropic from '@anthropic-ai/sdk';
import { config } from './config.ts';

export interface ChatMessage { role: 'system' | 'user' | 'assistant'; content: string }

export const llmEnabled = () => !!config.claude.apiKey;

/**
 * Anthropic Claude Messages API (https://api.anthropic.com/v1/messages).
 * `system` messages are lifted into the top-level `system` field (Anthropic keeps
 * them separate from the user/assistant turns). `temperature` is intentionally
 * not sent — the Messages API rejects it (400) on current models. The SDK retries
 * 429/5xx/network errors itself (maxRetries), so no manual retry loop here.
 */
export async function chat(messages: ChatMessage[], { maxTokens = 8000 } = {}): Promise<string> {
  const client = new Anthropic({ apiKey: config.claude.apiKey });

  const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n');
  const turns: Anthropic.MessageParam[] = messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({ role: m.role as 'user' | 'assistant', content: m.content }));

  const res = await client.messages.create({
    model: config.claude.model,
    max_tokens: maxTokens,
    // Keep thinking shallow: these are extraction/classification calls, and
    // thinking tokens share the max_tokens budget with the JSON output.
    output_config: { effort: 'low' },
    ...(system ? { system } : {}),
    messages: turns,
  });

  const content = res.content
    .filter((b): b is Anthropic.TextBlock => b.type === 'text')
    .map((b) => b.text)
    .join('');
  if (!content) throw new Error('Claude 응답에 text 가 없습니다');
  return content;
}

/** 코드펜스나 앞뒤 설명이 섞여 있어도 첫 JSON 객체를 꺼낸다 */
export function extractJson<T>(text: string): T {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  const candidate = fenced?.[1] ?? text;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('LLM 응답에서 JSON 을 찾지 못했습니다');
  return JSON.parse(candidate.slice(start, end + 1)) as T;
}
