#!/usr/bin/env node
// Judge each run's findings against the known CVE, blind to which tool produced them.
//
// The judgment is the same one DeepSource applied to the eight tools already published
// on this dataset: does any reported issue match the exact CVE — same impact, same
// attack pattern, same instance — rather than merely the same category. The prompt is
// in prompts/judge.md and every verdict is written out with its reasoning.
//
// CVE descriptions come from OSV, matching the published run, and are cached so a
// re-judge does not depend on the network.
//
// Usage: ANTHROPIC_API_KEY=… node scripts/judge.mjs [--model claude-opus-4-5-20251101]
//                                                   [--only CVE-ID,...] [--force]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = parseArgs(process.argv.slice(2))
const MODEL = args.model ?? 'claude-opus-4-5-20251101'
const KEY = process.env.ANTHROPIC_API_KEY
if (!KEY) { console.error('ANTHROPIC_API_KEY is not set'); process.exit(2) }

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) continue
    const k = a.slice(2)
    const next = argv[i + 1]
    if (next && !next.startsWith('--')) { out[k] = next; i++ } else out[k] = true
  }
  return out
}

const readJson = async (p, fallback) => {
  try { return JSON.parse(await readFile(p, 'utf8')) } catch { return fallback }
}

const cachePath = join(ROOT, 'manifest/cve-descriptions.json')
const descriptions = await readJson(cachePath, {})

async function describe(cve) {
  if (descriptions[cve]) return descriptions[cve]
  let text = ''
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${cve}`)
    if (res.ok) {
      const v = await res.json()
      text = v.details || v.summary || ''
    }
  } catch { /* fall through to the dataset's own explanation */ }
  if (!text) {
    const cves = await readJson(join(ROOT, 'manifest/ossf-cves.json'), [])
    const entry = cves.find((c) => c.cve === cve)
    text = entry?.explanation || `${cve} in ${entry?.repo ?? 'the affected project'}`
  }
  descriptions[cve] = text
  await writeFile(cachePath, JSON.stringify(descriptions, null, 1))
  return text
}

const SYSTEM = await readFile(join(ROOT, 'prompts/judge.md'), 'utf8')

async function judge(record, description) {
  const issues = record.findings.map((f, i) =>
    `[${i}] file: ${f.file ?? 'n/a'}${f.line ? `:${f.line}` : ''}\nseverity: ${f.severity ?? 'n/a'}\n` +
    `title: ${f.title ?? ''}\nexplanation: ${(f.body ?? '').slice(0, 4000)}`).join('\n\n')
  const user = `CVE: ${record.cve}\nCVE description: ${description}\n\n` +
    `Variant: ${record.variant}\n\nReported issues (${record.findings.length}):\n\n` +
    (issues || '(the reviewer reported no issues)')

  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 1000,
        system: SYSTEM,
        messages: [{ role: 'user', content: user }],
      }),
    })
    if (res.status === 429 || res.status >= 500) {
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)))
      continue
    }
    if (!res.ok) throw new Error(`judge ${res.status}: ${(await res.text()).slice(0, 200)}`)
    const body = await res.json()
    const text = (body.content ?? []).filter((b) => b.type === 'text').map((b) => b.text).join('')
    const m = text.match(/\{[\s\S]*\}/)
    if (!m) throw new Error(`judge returned no JSON: ${text.slice(0, 200)}`)
    return JSON.parse(m[0])
  }
  throw new Error('judge: retries exhausted')
}

const runsPath = join(ROOT, 'results/runs.jsonl')
const raw = (await readFile(runsPath, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l))
// A re-run of the same fixture supersedes the earlier attempt; keep the last of each.
const latest = new Map()
for (const r of raw) if (r.status === 'completed') latest.set(`${r.cve}:${r.variant}`, r)
let records = [...latest.values()]
if (args.only) {
  const want = new Set(String(args.only).split(',').map((s) => s.trim()))
  records = records.filter((r) => want.has(r.cve))
}

const outPath = join(ROOT, 'results/judged.jsonl')
const existing = args.force ? [] : (await readFile(outPath, 'utf8').catch(() => ''))
  .split('\n').filter(Boolean).map((l) => JSON.parse(l))
const judged = new Map(existing.map((j) => [`${j.cve_id}:${j.variant}`, j]))

await mkdir(join(ROOT, 'results'), { recursive: true })
let n = 0
for (const record of records) {
  const key = `${record.cve}:${record.variant}`
  if (judged.has(key)) continue
  const description = await describe(record.cve)
  try {
    const verdict = await judge(record, description)
    // The confusion matrix follows directly from the variant: on unfixed code a match
    // is a true positive and a miss a false negative; on fixed code a match means the
    // reviewer flagged an already-patched flaw, which is a false positive.
    const matched = Boolean(verdict.match)
    const row = {
      cve_id: record.cve,
      variant: record.variant,
      run_id: record.run_id,
      cve_explanation: description,
      detected_issues: record.findings,
      TP: record.variant === 'unfixed' && matched ? 1 : 0,
      FN: record.variant === 'unfixed' && !matched ? 1 : 0,
      FP: record.variant === 'fixed' && matched ? 1 : 0,
      TN: record.variant === 'fixed' && !matched ? 1 : 0,
      judge_reasoning: verdict.reasoning,
      judge_model: MODEL,
      cost_usd: record.cost_usd,
    }
    judged.set(key, row)
    await writeFile(outPath, [...judged.values()].map((j) => JSON.stringify(j)).join('\n') + '\n')
    n++
    process.stdout.write(`${key} → ${matched ? 'match' : 'no match'}  (${n}/${records.length})\n`)
  } catch (e) {
    console.error(`${key} judge failed: ${e.message}`)
  }
}
console.log(`judged ${judged.size} rows → results/judged.jsonl`)
