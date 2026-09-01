// The judging call itself, shared by the scoring run (judge.mjs), the competitor
// re-judge (rejudge-baselines.mjs) and the judge's own validation against DeepSource's
// published verdicts (validate-judge.mjs). All three must send byte-identical prompts
// or the validation says nothing about the judge we actually score with.
//
// Two providers, chosen by model name:
//   gpt-*     Azure OpenAI chat completions (the original grader)
//   claude-*  Anthropic Messages API, either first-party (ANTHROPIC_API_KEY) or the
//             same Azure Foundry resource that hosts the GPT deployments (AZURE_* vars)
//
// The published grading uses gpt-5.6-terra, which is also the model Ozone reviews
// with. The judge never sees code or a tool's name, and it was checked row by row
// against DeepSource's Claude Opus 4.5 verdicts (validate-judge.mjs), but it is not
// cross-family. The Claude provider is here so anyone can re-grade across families:
//   node scripts/judge.mjs --model claude-opus-5 --out results/claude/judged.jsonl

import { readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..')

export const DEFAULT_MODEL = 'gpt-5.6-terra'
export const DEFAULT_EFFORT = 'high'
const AZURE_API_VERSION = process.env.AZURE_OPENAI_API_VERSION ?? '2025-03-01-preview'
const ANTHROPIC_VERSION = '2023-06-01'

// The Foundry project endpoint carries an /api/projects/<name> suffix that the
// deployments path does not sit under; strip it so either form of the env var works.
export const endpoint = () => (process.env.AZURE_OPENAI_ENDPOINT ?? '')
  .replace(/\/api\/projects\/[^/]+\/?$/, '').replace(/\/$/, '')

export const providerOf = (model) => (model.startsWith('claude-') ? 'anthropic' : 'azure-openai')

/** Throw early, with the variable names, rather than 401 on the first row. */
export function assertCredentials(model) {
  if (providerOf(model) === 'azure-openai') {
    if (!process.env.AZURE_OPENAI_API_KEY || !endpoint()) throw new Error('AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT are not set')
    return
  }
  if (!process.env.ANTHROPIC_API_KEY && !(process.env.AZURE_OPENAI_API_KEY && endpoint())) {
    throw new Error('ANTHROPIC_API_KEY, or AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT with a Claude deployment, are not set')
  }
}

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

// The variant is deliberately NOT in the prompt. Telling the judge that a version is
// already patched tells it the answer: it then declines every finding on the fixed
// variant, no tool can record a false positive, and precision is 100% for everyone by
// construction. The judge decides only whether the reported issues describe the CVE;
// the variant maps that verdict onto the confusion matrix afterwards.
export const buildUser = ({ cve, description, issues }) =>
  `CVE: ${cve}\nCVE description: ${description}\n\n` +
  `Reported issues (${issues?.length ?? 0}):\n\n${renderIssues(issues)}`

const retryable = (status) => status === 429 || status === 529 || status >= 500

async function post(url, headers, body) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(url, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(body) })
    if (retryable(res.status)) {
      await new Promise((r) => setTimeout(r, 3000 * (attempt + 1)))
      continue
    }
    if (!res.ok) throw new Error(`judge ${res.status}: ${(await res.text()).slice(0, 300)}`)
    return res.json()
  }
  throw new Error('judge: retries exhausted')
}

function parseVerdict(text) {
  const m = text.match(/\{[\s\S]*\}/)
  if (!m) throw new Error(`judge returned no JSON: ${text.slice(0, 200)}`)
  return JSON.parse(m[0])
}

async function judgeAzureOpenAI({ model, effort, system, user }) {
  const url = `${endpoint()}/openai/deployments/${model}/chat/completions?api-version=${AZURE_API_VERSION}`
  const json = await post(url, { 'api-key': process.env.AZURE_OPENAI_API_KEY }, {
    max_completion_tokens: 4000,
    response_format: { type: 'json_object' },
    // Reasoning tokens bill as output, so effort is pinned rather than left to drift
    // between calls — a judge that varies its own depth is not one verdict standard.
    reasoning_effort: effort,
    messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
  })
  const choice = json.choices?.[0]
  // A reasoning model can burn the whole allowance before emitting the verdict; that
  // comes back as a well-formed response with an empty message, which must not be
  // read as "no match".
  if (choice?.finish_reason === 'length') throw new Error('judge truncated before answering')
  return { ...parseVerdict(choice?.message?.content ?? ''), usage: json.usage ?? null }
}

async function judgeAnthropic({ model, effort, system, user }) {
  // First-party key wins; otherwise the Foundry resource exposes the same Messages API
  // under /anthropic and accepts the Azure key in the same header.
  const firstParty = Boolean(process.env.ANTHROPIC_API_KEY)
  const url = firstParty ? 'https://api.anthropic.com/v1/messages' : `${endpoint()}/anthropic/v1/messages`
  const key = firstParty ? process.env.ANTHROPIC_API_KEY : process.env.AZURE_OPENAI_API_KEY
  const json = await post(url, { 'x-api-key': key, 'anthropic-version': ANTHROPIC_VERSION }, {
    model,
    max_tokens: 4000,
    system,
    // Adaptive thinking with pinned effort is the Claude equivalent of a fixed
    // reasoning_effort: the depth is set per run, not chosen per call.
    thinking: { type: 'adaptive' },
    output_config: { effort },
    messages: [{ role: 'user', content: user }],
  })
  if (json.stop_reason === 'max_tokens') throw new Error('judge truncated before answering')
  if (json.stop_reason === 'refusal') throw new Error(`judge refused: ${json.stop_details?.explanation ?? ''}`)
  const text = (json.content ?? []).filter((b) => b.type === 'text').map((b) => b.text).join('')
  const u = json.usage ?? {}
  // Normalise to the OpenAI usage shape so costOf and the callers stay provider-blind.
  const usage = { prompt_tokens: (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0), completion_tokens: u.output_tokens ?? 0 }
  return { ...parseVerdict(text), usage }
}

export async function judgeOnce({ cve, description, variant, issues, model = DEFAULT_MODEL, effort = DEFAULT_EFFORT, system }) {
  assertCredentials(model)
  const args = { model, effort, system: system ?? await systemPrompt(), user: buildUser({ cve, description, variant, issues }) }
  return providerOf(model) === 'anthropic' ? judgeAnthropic(args) : judgeAzureOpenAI(args)
}

/** Price per 1M tokens, first-party list. Azure and Foundry are assumed to match. */
export const PRICES = {
  'gpt-5.6-sol': { in: 5.0, out: 30.0 },
  'gpt-5.6-terra': { in: 2.0, out: 12.0 },
  'gpt-5.6-luna': { in: 0.2, out: 1.2 },
  'gpt-5.5': { in: 5.0, out: 30.0 },
  'gpt-5.4-nano': { in: 0.2, out: 1.25 },
  'claude-opus-5': { in: 5.0, out: 25.0 },
  'claude-opus-4-8': { in: 5.0, out: 25.0 },
  'claude-opus-4-6': { in: 5.0, out: 25.0 },
  'claude-sonnet-5': { in: 2.0, out: 10.0 },
}

export function costOf(model, usage) {
  const p = PRICES[model]
  if (!p || !usage) return 0
  return ((usage.prompt_tokens ?? 0) * p.in + (usage.completion_tokens ?? 0) * p.out) / 1e6
}
