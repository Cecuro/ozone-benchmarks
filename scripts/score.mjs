#!/usr/bin/env node
// Score the judged results and print them beside the eight tools DeepSource published
// on the same 165 rows.
//
// Two scorings are produced:
//   as-published  — every row, directly comparable with the published table
//   corrected     — excludes the fixed variants of the CVEs whose recorded vulnerable
//                   file is byte-identical before and after the patch, where a correct
//                   detection is scored as a false positive through no fault of the tool
//
// Usage: node scripts/score.mjs [--judged results/judged.jsonl] [--out results/scores.json]
//          [--baselines ../deepsource-benchmarks/benchmarks/judged-results]

import { readFile, readdir, writeFile } from 'node:fs/promises'
import { join, dirname, basename } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => {
  if (a.startsWith('--')) acc.push([a.slice(2), arr[i + 1] && !arr[i + 1].startsWith('--') ? arr[i + 1] : true])
  return acc
}, []))

const pct = (x) => (Number.isFinite(x) ? (x * 100).toFixed(2) : '—')

function metrics(rows) {
  const TP = rows.reduce((a, r) => a + (r.TP || 0), 0)
  const FP = rows.reduce((a, r) => a + (r.FP || 0), 0)
  const TN = rows.reduce((a, r) => a + (r.TN || 0), 0)
  const FN = rows.reduce((a, r) => a + (r.FN || 0), 0)
  const precision = TP + FP ? TP / (TP + FP) : NaN
  const recall = TP + FN ? TP / (TP + FN) : NaN
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : NaN
  const accuracy = TP + FP + TN + FN ? (TP + TN) / (TP + FP + TN + FN) : NaN
  return { TP, FP, TN, FN, precision, recall, f1, accuracy, n: rows.length }
}

const identical = new Set(JSON.parse(await readFile(join(ROOT, 'manifest/identical-variants.json'), 'utf8')))

async function load(path) {
  return (await readFile(path, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l))
}

const ours = await load(join(ROOT, args.judged ?? 'results/judged.jsonl'))
const baselineDir = args.baselines ?? join(ROOT, '../deepsource-benchmarks/benchmarks/judged-results')

const table = []
const corrected = []

const addRow = (name, rows) => {
  table.push({ tool: name, ...metrics(rows) })
  corrected.push({ tool: name, ...metrics(rows.filter((r) => !(r.variant === 'fixed' && identical.has(r.cve_id)))) })
}

addRow('Ozone', ours)

try {
  for (const f of (await readdir(baselineDir)).filter((f) => f.endsWith('.jsonl'))) {
    addRow(basename(f, '.jsonl'), await load(join(baselineDir, f)))
  }
} catch {
  console.error(`(no baselines found at ${baselineDir} — printing Ozone only)`)
}

const render = (rows, title) => {
  console.log(`\n${title}`)
  console.log('tool                 n    TP  FP  TN  FN   precision  recall   F1       accuracy')
  for (const r of [...rows].sort((a, b) => (b.f1 || 0) - (a.f1 || 0))) {
    console.log(
      `${r.tool.padEnd(20)} ${String(r.n).padStart(3)}  ${String(r.TP).padStart(3)} ${String(r.FP).padStart(3)} ` +
      `${String(r.TN).padStart(3)} ${String(r.FN).padStart(3)}   ${pct(r.precision).padStart(6)}%  ` +
      `${pct(r.recall).padStart(6)}%  ${pct(r.f1).padStart(6)}%  ${pct(r.accuracy).padStart(6)}%`)
  }
}

render(table, 'As published (all rows) — comparable with deepsource.com/benchmarks')
render(corrected, `Corrected (excludes fixed variants of ${identical.size} CVEs whose file is unchanged by the patch)`)

const outPath = join(ROOT, args.out ?? 'results/scores.json')
await writeFile(outPath,
  JSON.stringify({ generated_at: new Date().toISOString(), as_published: table, corrected}, null, 1))
console.log(`\nwritten → ${outPath}`)
