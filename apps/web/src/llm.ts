import { config } from './config.ts';

export interface ChatMessage { role: 'system' | 'user' | 'assistant'; content: string }

export const llmEnabled = () => !!config.poe.apiKey;

/** Poe OpenAI 호환 API (https://api.poe.com/v1/chat/completions) */
export async function chat(messages: ChatMessage[], { temperature = 0.1, maxTokens = 8000 } = {}): Promise<string> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(`${config.poe.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${config.poe.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: config.poe.model, messages, temperature, max_tokens: maxTokens, stream: false }),
        signal: AbortSignal.timeout(180_000),
      });
      if (res.status === 429 || res.status >= 500) {
        lastError = new Error(`Poe API ${res.status}: ${(await res.text()).slice(0, 300)}`);
        await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
        continue;
      }
      if (!res.ok) throw new Error(`Poe API ${res.status}: ${(await res.text()).slice(0, 300)}`);
      const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
      const content = data.choices?.[0]?.message?.content;
      if (!content) throw new Error('Poe API 응답에 content 가 없습니다');
      return content;
    } catch (err) {
      lastError = err;
      if (err instanceof Error && /Poe API 4\d\d/.test(err.message) && !err.message.includes('429')) throw err;
    }
  }
  throw lastError;
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
