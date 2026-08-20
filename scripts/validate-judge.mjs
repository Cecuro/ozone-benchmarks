#!/usr/bin/env node
// Validate our judge against DeepSource's published verdicts before trusting it.
//
// DeepSource judged eight tools over the same 165 rows with Claude Opus 4.5 and
// published every verdict. Those rows carry the reviewer's raw findings, so our judge
// can be replayed over them and its agreement measured against a judge from a
// different model family that we did not write.
//
// This matters because the judge is the one component of the benchmark we control.
// If it agreed with nobody, our score would be our own opinion of ourselves.
//
// Rows are sampled stratified by DeepSource's own verdict, so agreement is measured on
// matches and non-matches alike rather than on the ~75% of rows where nothing was found.
//
// Usage: node scripts/validate-judge.mjs [--model gpt-5.6-terra] [--effort high]
//                                        [--sample 40] [--seed 20260820]

import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname, basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import { judgeOnce, costOf, DEFAULT_MODEL, DEFAULT_EFFORT, systemPrompt } from './lib/judge-core.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = {}
for (let i = 0; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (!a.startsWith('--')) continue
  const n = process.argv[i + 1]
  args[a.slice(2)] = n && !n.startsWith('--') ? n : true
}
const MODEL = args.model ?? DEFAULT_MODEL
const EFFORT = args.effort ?? DEFAULT_EFFORT
const SAMPLE = Number(args.sample ?? 40)
const SEED = Number(args.seed ?? 20260820)
const CONCURRENCY = Number(args.concurrency ?? 4)

function rng(seed) {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6D2B79F5) >>> 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const shuffle = (arr, rand) => {
  const out = [...arr]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out
}

const dir = args.baselines ?? join(ROOT, '../deepsource-benchmarks/benchmarks/judged-results')
const rows = []
for (const f of (await readdir(dir)).filter((f) => f.endsWith('.jsonl'))) {
  const tool = basename(f, '.jsonl')
  for (const line of (await readFile(join(dir, f), 'utf8')).split('\n').filter(Boolean)) {
    const r = JSON.parse(line)
    rows.push({ ...r, tool, theirs: (r.TP || 0) + (r.FP || 0) > 0 })
  }
}

// Stratify: half the sample from rows DeepSource judged a match, half from the rest.
const rand = rng(SEED)
const yes = shuffle(rows.filter((r) => r.theirs), rand)
const no = shuffle(rows.filter((r) => !r.theirs), rand)
const half = Math.floor(SAMPLE / 2)
const picked = shuffle([...yes.slice(0, half), ...no.slice(0, SAMPLE - half)], rand)

console.log(`${rows.length} published verdicts across ${new Set(rows.map((r) => r.tool)).size} tools`)
console.log(`sampling ${picked.length} (${Math.min(half, yes.length)} match / ${picked.length - Math.min(half, yes.length)} non-match), ` +
  `judge=${MODEL} effort=${EFFORT} seed=${SEED}\n`)

const system = await systemPrompt()
const results = []
let spend = 0
const queue = [...picked]

async function worker() {
  while (queue.length) {
    const r = queue.shift()
    try {
      const v = await judgeOnce({
        cve: r.cve_id,
        description: r.cve_explanation,
        variant: r.variant,
        issues: r.detected_issues,
        model: MODEL,
        effort: EFFORT,
        system,
      })
      spend += costOf(MODEL, v.usage)
      const ours = Boolean(v.match)
      results.push({ ...r, ours, agree: ours === r.theirs, ours_reasoning: v.reasoning, theirs_reasoning: r.judge_reasoning })
      process.stdout.write(ours === r.theirs ? '.' : 'X')
    } catch (e) {
      results.push({ ...r, error: e.message })
      process.stdout.write('!')
    }
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker))

const scored = results.filter((r) => !r.error)
const agree = scored.filter((r) => r.agree).length
// Cohen's kappa: raw agreement flatters a judge on an unbalanced set, where always
// answering "no match" would look competent.
const n = scored.length
const a = scored.filter((r) => r.ours && r.theirs).length
const b = scored.filter((r) => r.ours && !r.theirs).length
const c = scored.filter((r) => !r.ours && r.theirs).length
const d = scored.filter((r) => !r.ours && !r.theirs).length
const pe = (((a + b) * (a + c)) + ((c + d) * (b + d))) / (n * n)
const kappa = (agree / n - pe) / (1 - pe)

console.log(`\n\nagreement ${agree}/${n} = ${(100 * agree / n).toFixed(1)}%   Cohen's kappa ${kappa.toFixed(3)}`)
console.log(`  both match: ${a}   ours only: ${b}   theirs only: ${c}   both no-match: ${d}`)
console.log(`  errors: ${results.length - n}`)
console.log(`judge spend: $${spend.toFixed(2)} over ${n} calls ($${(spend / Math.max(1, n)).toFixed(3)}/call)`)
console.log(`  → projected for a 165-run scoring pass: $${(165 * spend / Math.max(1, n)).toFixed(2)}`)

const disagreements = scored.filter((r) => !r.agree)
if (disagreements.length) {
  console.log(`\ndisagreements (${disagreements.length}):`)
  for (const r of disagreements.slice(0, 12)) {
    console.log(`\n  ${r.cve_id}/${r.variant} [${r.tool}] ours=${r.ours} theirs=${r.theirs}`)
    console.log(`    ours:   ${String(r.ours_reasoning ?? '').slice(0, 190)}`)
    console.log(`    theirs: ${String(r.theirs_reasoning ?? '').slice(0, 190)}`)
  }
}

await mkdir(join(ROOT, 'results'), { recursive: true })
await writeFile(join(ROOT, 'results/judge-validation.json'), JSON.stringify({
  judge_model: MODEL, reasoning_effort: EFFORT, seed: SEED, sample: n,
  agreement: n ? agree / n : null, kappa, matrix: { both_match: a, ours_only: b, theirs_only: c, both_no_match: d },
  spend_usd: spend, rows: results,
}, null, 1))
console.log('\nwritten → results/judge-validation.json')
