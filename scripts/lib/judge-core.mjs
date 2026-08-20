// The judging call itself, shared by the scoring run (judge.mjs) and by the judge's
// own validation against DeepSource's published verdicts (validate-judge.mjs). Both
// must send byte-identical prompts or the validation says nothing about the judge we
// actually score with.

import { readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..')

export const DEFAULT_MODEL = 'gpt-5.6-terra'
export const DEFAULT_EFFORT = 'high'
const API_VERSION = process.env.AZURE_OPENAI_API_VERSION ?? '2025-03-01-preview'

// The Foundry project endpoint carries an /api/projects/<name> suffix that the
// deployments path does not sit under; strip it so either form of the env var works.
export const endpoint = () => (process.env.AZURE_OPENAI_ENDPOINT ?? '')
  .replace(/\/api\/projects\/[^/]+\/?$/, '').replace(/\/$/, '')

export const systemPrompt = () => readFile(join(ROOT, 'prompts/judge.md'), 'utf8')

/** Render reported issues identically no matter which tool produced them. */
export function renderIssues(issues) {
  if (!issues?.length) return '(the reviewer reported no issues)'
  return issues.map((f, i) => {
    const line = f.line ?? f.position?.begin?.line
    const where = `${f.file ?? 'n/a'}${line ? `:${line}` : ''}`
    const text = f.explanation ?? f.body ?? ''
    return `[${i}] file: ${where}\n${f.severity ? `severity: ${f.severity}\n` : ''}` +
      `${f.title ? `title: ${f.title}\n` : ''}explanation: ${String(text).slice(0, 4000)}`
  }).join('\n\n')
}

export const buildUser = ({ cve, description, variant, issues }) =>
  `CVE: ${cve}\nCVE description: ${description}\n\nVariant: ${variant}\n\n` +
  `Reported issues (${issues?.length ?? 0}):\n\n${renderIssues(issues)}`

export async function judgeOnce({ cve, description, variant, issues, model = DEFAULT_MODEL, effort = DEFAULT_EFFORT, system }) {
  const key = process.env.AZURE_OPENAI_API_KEY
  const base = endpoint()
  if (!key || !base) throw new Error('AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT are not set')
  const url = `${base}/openai/deployments/${model}/chat/completions?api-version=${API_VERSION}`
  const body = {
    max_completion_tokens: 4000,
    response_format: { type: 'json_object' },
    // Reasoning tokens bill as output, so effort is pinned rather than left to drift
    // between calls — a judge that varies its own depth is not one verdict standard.
    reasoning_effort: effort,
    messages: [
      { role: 'system', content: system ?? await systemPrompt() },
      { role: 'user', content: buildUser({ cve, description, variant, issues }) },
    ],
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'api-key': key, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (res.status === 429 || res.status >= 500) {
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)))
      continue
    }
    if (!res.ok) throw new Error(`judge ${res.status}: ${(await res.text()).slice(0, 300)}`)
    const json = await res.json()
    const choice = json.choices?.[0]
    // A reasoning model can burn the whole allowance before emitting the verdict; that
    // comes back as a well-formed response with an empty message, which must not be
    // read as "no match".
    if (choice?.finish_reason === 'length') throw new Error('judge truncated before answering')
    const text = choice?.message?.content ?? ''
    const m = text.match(/\{[\s\S]*\}/)
    if (!m) throw new Error(`judge returned no JSON: ${text.slice(0, 200)}`)
    const parsed = JSON.parse(m[0])
    return { ...parsed, usage: json.usage ?? null }
  }
  throw new Error('judge: retries exhausted')
}

/** Price per 1M tokens, OpenAI first-party list. Azure is assumed to match. */
export const PRICES = {
  'gpt-5.6-sol': { in: 5.0, out: 30.0 },
  'gpt-5.6-terra': { in: 2.0, out: 12.0 },
  'gpt-5.6-luna': { in: 0.2, out: 1.2 },
  'gpt-5.5': { in: 5.0, out: 30.0 },
  'gpt-5.4-nano': { in: 0.2, out: 1.25 },
}

export function costOf(model, usage) {
  const p = PRICES[model]
  if (!p || !usage) return 0
  return ((usage.prompt_tokens ?? 0) * p.in + (usage.completion_tokens ?? 0) * p.out) / 1e6
}
