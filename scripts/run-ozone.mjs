#!/usr/bin/env node
// Drive Ozone over its public REST API across the fixture PRs and record raw results.
//
// Every fixture repo is attached with trigger_mode 'off' and comment_mode
// 'dashboard_only', so nothing runs except what this script starts, and no benchmark
// review is ever posted to a PR.
//
// Spend is bounded twice: --max-spend stops the sweep once the accumulated cost_usd
// of finished runs crosses the cap, and --concurrency limits how much can be in
// flight (and therefore unbilled-but-committed) at any moment.
//
// Usage:
//   OZONE_API_KEY=oz_live_… node scripts/run-ozone.mjs \
//     [--limit N] [--only CVE-ID,...] [--variant unfixed|fixed] \
//     [--max-spend 120] [--concurrency 4] [--project "Ozone benchmark — OpenSSF CVE"]

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = parseArgs(process.argv.slice(2))
const BASE = (args.base ?? process.env.OZONE_BASE_URL ?? 'https://ozone.cecuro.ai').replace(/\/$/, '')
const KEY = process.env.OZONE_API_KEY
const INSTALLATION_ID = Number(args.installation ?? process.env.OZONE_INSTALLATION_ID ?? 149868650)
const PROJECT_NAME = args.project ?? 'Ozone benchmark — OpenSSF CVE'
const MAX_SPEND = Number(args['max-spend'] ?? 150)
const CONCURRENCY = Number(args.concurrency ?? 4)
const POLL_MS = 10_000
const RUN_TIMEOUT_MS = 45 * 60 * 1000

if (!KEY) {
  console.error('OZONE_API_KEY is not set. Create an org-scoped key with projects:write + runs:write')
  process.exit(2)
}

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

async function api(path, init = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${KEY}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  })
  const text = await res.text()
  let body
  try { body = text ? JSON.parse(text) : {} } catch { body = { raw: text } }
  if (!res.ok) {
    const err = new Error(`${init.method ?? 'GET'} ${path} → ${res.status} ${JSON.stringify(body).slice(0, 300)}`)
    err.status = res.status
    err.body = body
    throw err
  }
  return body
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function ensureProject() {
  const { projects = [] } = await api('/v1/projects')
  const found = projects.find((p) => p.name === PROJECT_NAME)
  if (found) return found.id
  const created = await api('/v1/projects', {
    method: 'POST',
    body: JSON.stringify({ name: PROJECT_NAME }),
  })
  return created.id ?? created.project?.id
}

// Attaching a repo is idempotent from this script's point of view: an already-attached
// repo comes back from the project read, and only a genuinely new one is POSTed. The
// PATCH that follows is what actually protects the budget, so it runs either way.
async function ensureRepo(projectId, fullName, attached) {
  let repo = attached.get(fullName)
  if (!repo) {
    await api(`/v1/projects/${projectId}/repos`, {
      method: 'POST',
      body: JSON.stringify({ repo_full_name: fullName, installation_id: INSTALLATION_ID }),
    })
    const project = await api(`/v1/projects/${projectId}`)
    for (const r of project.repos ?? []) attached.set(r.repo_full_name, r)
    repo = attached.get(fullName)
    if (!repo) throw new Error(`attached ${fullName} but it did not appear on the project`)
  }
  if (repo.trigger_mode !== 'off' || repo.comment_mode !== 'dashboard_only') {
    await api(`/v1/projects/${projectId}/repos/${repo.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ trigger_mode: 'off', comment_mode: 'dashboard_only' }),
    })
    repo.trigger_mode = 'off'
    repo.comment_mode = 'dashboard_only'
  }
  return repo.id
}

async function waitForRun(runId) {
  const deadline = Date.now() + RUN_TIMEOUT_MS
  for (;;) {
    const run = await api(`/v1/runs/${runId}`)
    if (['completed', 'failed', 'cancelled'].includes(run.status)) return run
    if (Date.now() > deadline) {
      await api(`/v1/runs/${runId}/cancel`, { method: 'POST' }).catch(() => {})
      return { ...run, status: 'timeout' }
    }
    await sleep(POLL_MS)
  }
}

const fixtures = JSON.parse(await readFile(join(ROOT, 'manifest/fixtures.json'), 'utf8'))
const cves = JSON.parse(await readFile(join(ROOT, 'manifest/ossf-cves.json'), 'utf8'))
const byCve = new Map(cves.map((c) => [c.cve, c]))

let tasks = []
for (const [cve, fx] of Object.entries(fixtures)) {
  for (const [variant, prNumber] of Object.entries(fx.prs)) {
    if (args.variant && args.variant !== variant) continue
    tasks.push({ cve, variant, prNumber, repo_full_name: fx.repo_full_name, files: fx.files, cwes: fx.cwes })
  }
}
if (args.only) {
  const want = new Set(String(args.only).split(',').map((s) => s.trim()))
  tasks = tasks.filter((t) => want.has(t.cve))
}

// Sampling is by CVE, never by run, so a sampled sweep still holds both variants of
// every CVE it covers and can report precision as well as recall. The order is a
// seeded shuffle rather than the manifest's (alphabetical, therefore roughly
// chronological) order, so a sweep cut short by the spend cap is still a random
// subset of the benchmark rather than its oldest CVEs. The seed is recorded with the
// results so the selection can be reproduced exactly.
const SEED = Number(args.seed ?? 20260820)
function shuffled(keys, seed) {
  // mulberry32 — small, deterministic, and identical across machines.
  let s = seed >>> 0
  const rand = () => {
    s = (s + 0x6D2B79F5) >>> 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  const out = [...keys]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out
}
const order = shuffled([...new Set(tasks.map((t) => t.cve))], SEED)
const rank = new Map(order.map((c, i) => [c, i]))
tasks.sort((a, b) => (rank.get(a.cve) - rank.get(b.cve)) || a.variant.localeCompare(b.variant))
if (args.sample) {
  const keep = new Set(order.slice(0, Number(args.sample)))
  tasks = tasks.filter((t) => keep.has(t.cve))
}
if (args.limit) tasks = tasks.slice(0, Number(args.limit))

const outDir = join(ROOT, 'results/raw')
await mkdir(outDir, { recursive: true })
const resultsPath = join(ROOT, 'results/runs.jsonl')
const done = new Set()
try {
  const prior = await readFile(resultsPath, 'utf8')
  for (const line of prior.split('\n').filter(Boolean)) {
    const r = JSON.parse(line)
    if (r.status === 'completed') done.add(`${r.cve}:${r.variant}`)
  }
} catch { /* first run */ }

const pending = tasks.filter((t) => !done.has(`${t.cve}:${t.variant}`))
console.log(`${tasks.length} tasks, ${done.size} already complete, ${pending.length} to run`)
console.log(`spend cap $${MAX_SPEND}, concurrency ${CONCURRENCY}, base ${BASE}`)

const projectId = await ensureProject()
const project = await api(`/v1/projects/${projectId}`)
const attached = new Map((project.repos ?? []).map((r) => [r.repo_full_name, r]))
console.log(`project ${projectId} (${(project.repos ?? []).length} repos attached)`)

let spent = 0
let stopped = false
const queue = [...pending]
const lines = []

async function worker(id) {
  while (queue.length && !stopped) {
    if (spent >= MAX_SPEND) {
      if (!stopped) console.log(`\nspend cap $${MAX_SPEND} reached (spent $${spent.toFixed(2)}) — stopping`)
      stopped = true
      return
    }
    const t = queue.shift()
    const tag = `${t.cve}/${t.variant}`
    try {
      const repoId = await ensureRepo(projectId, t.repo_full_name, attached)
      const started = await api('/v1/runs', {
        method: 'POST',
        body: JSON.stringify({ repo_id: repoId, pr_number: Number(t.prNumber) }),
      })
      const runId = started.id ?? started.run?.id
      const run = await waitForRun(runId)
      spent += Number(run.cost_usd ?? 0)
      const record = {
        cve: t.cve,
        variant: t.variant,
        repo_full_name: t.repo_full_name,
        pr_number: Number(t.prNumber),
        run_id: runId,
        status: run.status,
        cost_usd: run.cost_usd ?? null,
        duration_ms: run.duration_ms ?? null,
        error: run.error ?? null,
        files: t.files,
        cwes: t.cwes,
        summary: run.summary ?? null,
        findings: (run.findings ?? []).map((f) => ({
          id: f.id, title: f.title, severity: f.severity, file: f.file, line: f.line, body: f.body,
        })),
      }
      lines.push(record)
      await writeFile(join(outDir, `${t.cve}_${t.variant}.json`), JSON.stringify(record, null, 1))
      await writeFile(resultsPath, lines.map((l) => JSON.stringify(l)).join('\n') + '\n', { flag: 'a' })
      lines.length = 0
      console.log(`w${id} ${tag} ${run.status} $${Number(run.cost_usd ?? 0).toFixed(2)} ` +
        `${record.findings.length} findings (total $${spent.toFixed(2)})`)
    } catch (e) {
      console.error(`w${id} ${tag} ERROR ${e.message}`)
      await writeFile(resultsPath,
        JSON.stringify({ cve: t.cve, variant: t.variant, status: 'error', error: e.message }) + '\n',
        { flag: 'a' })
    }
  }
}

await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => worker(i + 1)))
console.log(`\ndone. spent $${spent.toFixed(2)} across this sweep. results → results/runs.jsonl`)
