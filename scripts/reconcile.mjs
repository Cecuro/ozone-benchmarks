#!/usr/bin/env node
// Recover runs that completed on the server but never reached results/runs.jsonl.
//
// A run is started by POST /v1/runs and then polled. If the client loses the network
// between those two steps — or is killed — the run still executes and is still billed,
// but the local record never appears. Re-running those tasks would pay for the same
// work twice, so the sweep is reconciled against the server before anything is retried.
//
// Runs are matched back to a CVE and variant through the fixture manifest, by
// repository and pull-request number.
//
// Usage: OZONE_API_KEY=… node scripts/reconcile.mjs [--project prj_…] [--dry-run]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = {}
for (let i = 0; i < process.argv.length; i++) {
  const a = process.argv[i]
  if (!a.startsWith('--')) continue
  const n = process.argv[i + 1]
  args[a.slice(2)] = n && !n.startsWith('--') ? n : true
}
const BASE = (process.env.OZONE_BASE_URL ?? 'https://ozone.cecuro.ai').replace(/\/$/, '')
const KEY = process.env.OZONE_API_KEY
const PROJECT_NAME = args.project_name ?? 'Ozone benchmark — OpenSSF CVE'
if (!KEY) { console.error('OZONE_API_KEY is not set'); process.exit(2) }

const api = async (path) => {
  const res = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${KEY}` } })
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`)
  return res.json()
}

let projectId = args.project
if (!projectId) {
  const { projects = [] } = await api('/v1/projects')
  projectId = projects.find((p) => p.name === PROJECT_NAME)?.id
  if (!projectId) { console.error(`no project named ${PROJECT_NAME}`); process.exit(1) }
}

const fixtures = JSON.parse(await readFile(join(ROOT, 'manifest/fixtures.json'), 'utf8'))
// (repo, pr number) → which CVE and which variant that pull request represents
const index = new Map()
for (const [cve, fx] of Object.entries(fixtures)) {
  for (const [variant, pr] of Object.entries(fx.prs)) {
    index.set(`${fx.repo_full_name}#${pr}`, { cve, variant, files: fx.files, cwes: fx.cwes })
  }
}

const resultsPath = join(ROOT, 'results/runs.jsonl')
const existing = (await readFile(resultsPath, 'utf8').catch(() => ''))
  .split('\n').filter(Boolean).map((l) => JSON.parse(l))
const knownRunIds = new Set(existing.map((r) => r.run_id).filter(Boolean))
// Keyed by task, so a task already recorded as completed is not duplicated by a
// second server-side run of the same pull request.
const completedTasks = new Set(existing.filter((r) => r.status === 'completed').map((r) => `${r.cve}:${r.variant}`))

const { runs = [] } = await api(`/v1/runs?project_id=${projectId}&limit=200`)
const missing = runs.filter((r) => r.status === 'completed' && !knownRunIds.has(r.id))
console.log(`${runs.length} runs on the server, ${missing.length} not recorded locally`)

const recovered = []
let spend = 0
for (const run of missing) {
  const key = `${run.repo_full_name}#${run.pr_number}`
  const task = index.get(key)
  if (!task) { console.log(`  skip ${run.id}: ${key} is not a known fixture pull request`); continue }
  if (completedTasks.has(`${task.cve}:${task.variant}`)) {
    console.log(`  skip ${run.id}: ${task.cve}/${task.variant} already recorded`)
    continue
  }
  const full = await api(`/v1/runs/${run.id}`)
  const record = {
    cve: task.cve,
    variant: task.variant,
    repo_full_name: run.repo_full_name,
    pr_number: run.pr_number,
    run_id: run.id,
    status: run.status,
    cost_usd: run.cost_usd ?? null,
    duration_ms: run.duration_ms ?? null,
    error: run.error ?? null,
    files: task.files,
    cwes: task.cwes,
    summary: full.summary ?? null,
    recovered: true,
    findings: (full.findings ?? []).map((f) => ({
      id: f.id, title: f.title, severity: f.severity, file: f.file, line: f.line, body: f.body,
    })),
  }
  recovered.push(record)
  completedTasks.add(`${task.cve}:${task.variant}`)
  spend += Number(run.cost_usd ?? 0)
  console.log(`  recovered ${task.cve}/${task.variant} $${run.cost_usd} ${record.findings.length} findings`)
}

if (!args['dry-run'] && recovered.length) {
  await mkdir(join(ROOT, 'results/raw'), { recursive: true })
  for (const r of recovered) {
    await writeFile(join(ROOT, `results/raw/${r.cve}_${r.variant}.json`), JSON.stringify(r, null, 1))
  }
  await writeFile(resultsPath, recovered.map((r) => JSON.stringify(r)).join('\n') + '\n', { flag: 'a' })
}
console.log(`\nrecovered ${recovered.length} runs worth $${spend.toFixed(2)}${args['dry-run'] ? ' (dry run, nothing written)' : ''}`)
const serverSpend = runs.reduce((a, r) => a + (Number(r.cost_usd) || 0), 0)
console.log(`server-side spend on this project to date: $${serverSpend.toFixed(2)}`)
