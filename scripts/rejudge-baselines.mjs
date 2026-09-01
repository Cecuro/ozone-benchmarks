#!/usr/bin/env node
// Re-judge every published competitor row with OUR judge, so that all tools — theirs
// and ours — are scored by one standard.
//
// Validation (results/judge-validation.json) showed our judge is systematically
// stricter than the one DeepSource used: on an 80-row stratified sample it never
// credited a detection theirs rejected, but declined 10 that theirs accepted. Scoring
// Ozone with the strict judge while quoting competitors' figures from the lenient one
// would understate them and overstate the gap — in our favour. Re-judging removes the
// asymmetry, and the tool's identity is never shown to the judge.
//
// The output is written in the same shape score.mjs already reads, so:
//   node scripts/score.mjs --baselines results/baselines-rejudged
//
// Usage: node scripts/rejudge-baselines.mjs [--model gpt-5.6-terra] [--effort high]
//          [--out results/baselines-rejudged] [--concurrency 12] [--tool NAME]

import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname, basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import { judgeOnce, costOf, assertCredentials, DEFAULT_MODEL, DEFAULT_EFFORT, systemPrompt } from './lib/judge-core.mjs'

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
const CONCURRENCY = Number(args.concurrency ?? 12)
try { assertCredentials(MODEL) } catch (e) { console.error(e.message); process.exit(2) }
const srcDir = args.baselines ?? join(ROOT, '../deepsource-benchmarks/benchmarks/judged-results')
const outDir = join(ROOT, args.out ?? 'results/baselines-rejudged')
await mkdir(outDir, { recursive: true })

const system = await systemPrompt()
const tools = (await readdir(srcDir)).filter((f) => f.endsWith('.jsonl'))
  .map((f) => basename(f, '.jsonl'))
  .filter((t) => !args.tool || t === args.tool)

const work = []
const done = new Map()
for (const tool of tools) {
  const outPath = join(outDir, `${tool}.jsonl`)
  const prior = await readFile(outPath, 'utf8').catch(() => '')
  const seen = new Map()
  for (const line of prior.split('\n').filter(Boolean)) {
    const r = JSON.parse(line)
    seen.set(`${r.cve_id}:${r.variant}`, r)
  }
  done.set(tool, seen)
  for (const line of (await readFile(join(srcDir, `${tool}.jsonl`), 'utf8')).split('\n').filter(Boolean)) {
    const r = JSON.parse(line)
    if (seen.has(`${r.cve_id}:${r.variant}`)) continue
    work.push({ tool, row: r })
  }
}

console.log(`${tools.length} tools, ${work.length} rows to judge (already done: ` +
  `${[...done.values()].reduce((a, m) => a + m.size, 0)}), judge=${MODEL} effort=${EFFORT}, concurrency=${CONCURRENCY}`)

let spend = 0
let n = 0
let failures = 0
const queue = [...work]
const dirty = new Set()

const flush = async () => {
  for (const tool of dirty) {
    await writeFile(join(outDir, `${tool}.jsonl`),
      [...done.get(tool).values()].map((r) => JSON.stringify(r)).join('\n') + '\n')
  }
  dirty.clear()
}

async function worker() {
  while (queue.length) {
    const { tool, row } = queue.shift()
    try {
      const v = await judgeOnce({
        cve: row.cve_id,
        description: row.cve_explanation,
        variant: row.variant,
        issues: row.detected_issues,
        model: MODEL, effort: EFFORT, system,
      })
      spend += costOf(MODEL, v.usage)
      const matched = Boolean(v.match)
      done.get(tool).set(`${row.cve_id}:${row.variant}`, {
        cve_id: row.cve_id,
        variant: row.variant,
        TP: row.variant === 'unfixed' && matched ? 1 : 0,
        FN: row.variant === 'unfixed' && !matched ? 1 : 0,
        FP: row.variant === 'fixed' && matched ? 1 : 0,
        TN: row.variant === 'fixed' && !matched ? 1 : 0,
        judge_reasoning: v.reasoning,
        judge_model: MODEL,
        judge_effort: EFFORT,
        original_verdict_match: (row.TP || 0) + (row.FP || 0) > 0,
      })
      dirty.add(tool)
    } catch (e) {
      failures++
      if (failures <= 5) console.error(`\n${tool} ${row.cve_id}/${row.variant}: ${e.message}`)
    }
    n++
    if (n % 25 === 0) {
      await flush()
      console.log(`  ${n}/${work.length}  $${spend.toFixed(2)}  ${failures} failed`)
    }
  }
}

await Promise.all(Array.from({ length: CONCURRENCY }, worker))
await flush()

// How far the two judges diverge, across every row rather than the validation sample.
let agree = 0, total = 0, strictOnly = 0, lenientOnly = 0
for (const [, seen] of done) {
  for (const r of seen.values()) {
    if (r.original_verdict_match === undefined) continue
    total++
    const ours = (r.TP || 0) + (r.FP || 0) > 0
    if (ours === r.original_verdict_match) agree++
    else if (ours) lenientOnly++
    else strictOnly++
  }
}
console.log(`\ndone. ${n} judged, ${failures} failed, $${spend.toFixed(2)} spent`)
console.log(`judge agreement with DeepSource across ${total} rows: ${(100 * agree / total).toFixed(1)}%`)
console.log(`  ours stricter (they matched, we did not): ${strictOnly}`)
console.log(`  ours more lenient (we matched, they did not): ${lenientOnly}`)
console.log(`\nscore with:  node scripts/score.mjs --baselines ${outDir}`)
