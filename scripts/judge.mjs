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
// The judge defaults to gpt-5.6-terra, which reproduces the published grading. That
// is the same model family Ozone reviews with; pass --model claude-opus-5 and --out to
// produce a cross-family grading beside it without overwriting the published one.
//
// Usage: node scripts/judge.mjs [--model gpt-5.6-terra] [--effort high]
//          [--out results/judged.jsonl] [--only CVE-ID,...] [--force]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { judgeOnce, systemPrompt, costOf, assertCredentials, DEFAULT_MODEL, DEFAULT_EFFORT } from './lib/judge-core.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = parseArgs(process.argv.slice(2))
const MODEL = args.model ?? DEFAULT_MODEL
const EFFORT = args.effort ?? DEFAULT_EFFORT
try { assertCredentials(MODEL) } catch (e) { console.error(e.message); process.exit(2) }

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

const SYSTEM = await systemPrompt()

const judge = (record, description) => judgeOnce({
  cve: record.cve,
  description,
  variant: record.variant,
  issues: record.findings,
  model: MODEL,
  effort: EFFORT,
  system: SYSTEM,
})

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

const outPath = join(ROOT, args.out ?? 'results/judged.jsonl')
const existing = args.force ? [] : (await readFile(outPath, 'utf8').catch(() => ''))
  .split('\n').filter(Boolean).map((l) => JSON.parse(l))
const judged = new Map(existing.map((j) => [`${j.cve_id}:${j.variant}`, j]))

await mkdir(dirname(outPath), { recursive: true })
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
      judge_effort: EFFORT,
      judge_cost_usd: costOf(MODEL, verdict.usage),
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
console.log(`judged ${judged.size} rows → ${outPath}`)
