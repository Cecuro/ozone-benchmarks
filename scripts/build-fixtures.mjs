#!/usr/bin/env node
// Build one GitHub fixture repo per CVE, replicating the DeepSource construction of
// the OpenSSF CVE Benchmark:
//
//   main            = the upstream tree at the pre-patch commit, MINUS the vulnerable file
//   pr/unfixed      = main + the vulnerable file as it was before the patch
//   pr/fixed        = main + the same file as it was after the patch
//
// Each branch is opened as a PR, so the security-relevant code arrives as an addition
// in the diff exactly as a contributor's change would. The unfixed PR measures TP/FN,
// the fixed PR measures TN/FP.
//
// Only the two needed commits are fetched (depth 1 each), and history is re-rooted, so
// a fixture repo is one snapshot rather than the upstream's full history.
//
// Usage: node scripts/build-fixtures.mjs --org Cecuro [--limit N] [--only CVE-ID,...]
//                                        [--visibility private|public] [--dry-run]

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdtemp, rm, readFile, writeFile, mkdir, cp, access } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const exec = promisify(execFile)
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const args = parseArgs(process.argv.slice(2))
const ORG = args.org ?? 'Cecuro'
const VISIBILITY = args.visibility ?? 'private'
const DRY = Boolean(args['dry-run'])

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

// git/gh calls are noisy on stderr even when they succeed; only the exit code matters.
async function run(cmd, cmdArgs, opts = {}) {
  try {
    const { stdout } = await exec(cmd, cmdArgs, { maxBuffer: 64 * 1024 * 1024, ...opts })
    return stdout.trim()
  } catch (e) {
    const detail = (e.stderr || e.stdout || e.message || '').toString().trim().split('\n').slice(-4).join(' | ')
    throw new Error(`${cmd} ${cmdArgs.slice(0, 4).join(' ')} failed: ${detail}`)
  }
}

async function exists(p) {
  try { await access(p); return true } catch { return false }
}

// A fixture is only useful if the vulnerable file is present at BOTH commits: the
// pre-patch version is what the unfixed PR adds, the post-patch version is what the
// fixed PR adds. A CVE whose patch deletes or renames the file is skipped loudly
// rather than silently producing a fixed PR identical to the unfixed one.
async function buildOne(cve, dir) {
  const repoUrl = cve.repo.replace(/\.git$/, '') + '.git'
  await run('git', ['init', '-q', '-b', 'main', dir])
  await run('git', ['remote', 'add', 'origin', repoUrl], { cwd: dir })
  for (const sha of [cve.pre, cve.post]) {
    await run('git', ['fetch', '-q', '--depth', '1', 'origin', sha], { cwd: dir })
  }
  await run('git', ['checkout', '-q', cve.pre], { cwd: dir })

  const snapshots = {}
  for (const [variant, sha] of [['unfixed', cve.pre], ['fixed', cve.post]]) {
    const stash = join(dir, '.fixture-cache', variant)
    for (const f of cve.files) {
      const src = join(dir, f)
      await run('git', ['checkout', '-q', sha, '--', f], { cwd: dir })
      if (!(await exists(src))) throw new Error(`${cve.cve}: ${f} missing at ${variant} commit ${sha}`)
      const dst = join(stash, f)
      await mkdir(dirname(dst), { recursive: true })
      await cp(src, dst)
    }
    snapshots[variant] = stash
  }

  // Re-root: one orphan commit holding the pre-patch tree minus the vulnerable files.
  await run('git', ['checkout', '-q', cve.pre], { cwd: dir })
  await run('git', ['checkout', '-q', '--orphan', 'main'], { cwd: dir })
  for (const f of cve.files) await run('git', ['rm', '-q', '--cached', '--ignore-unmatch', f], { cwd: dir })
  for (const f of cve.files) await rm(join(dir, f), { force: true })
  await rm(join(dir, '.fixture-cache'), { recursive: true, force: true }).catch(() => {})
  await writeFile(join(dir, 'BENCHMARK.md'), baselineNote(cve))
  await run('git', ['add', '-A'], { cwd: dir })
  await run('git', ['-c', 'user.email=bench@cecuro.ai', '-c', 'user.name=Ozone Benchmark',
    'commit', '-q', '-m', `Baseline: ${projectName(cve.repo)} at ${cve.pre.slice(0, 8)}`], { cwd: dir })

  // Rebuild the per-variant file snapshots (wiped by the orphan checkout) from git.
  for (const [variant, sha] of [['unfixed', cve.pre], ['fixed', cve.post]]) {
    await run('git', ['checkout', '-q', '-B', `pr/${variant}`, 'main'], { cwd: dir })
    for (const f of cve.files) {
      await run('git', ['checkout', '-q', sha, '--', f], { cwd: dir })
    }
    await run('git', ['add', '-A'], { cwd: dir })
    await run('git', ['-c', 'user.email=bench@cecuro.ai', '-c', 'user.name=Ozone Benchmark',
      'commit', '-q', '-m', prTitle(cve)], { cwd: dir })
  }
  await run('git', ['checkout', '-q', 'main'], { cwd: dir })
  void snapshots
}

const projectName = (url) => url.replace(/\.git$/, '').split('/').slice(-2).join('/')

// The PR title and body must not hint that this is a security benchmark, or a reviewer
// would be primed to look for a vulnerability. They read as an ordinary contribution.
const prTitle = (cve) => `Add ${cve.files.map((f) => f.split('/').pop()).join(', ')}`
const prBody = (cve) => `Adds \`${cve.files.join('`, `')}\` to ${projectName(cve.repo)}.\n\nPlease review.`
const baselineNote = (cve) => `# Benchmark fixture\n\nSource: ${projectName(cve.repo)} at \`${cve.pre}\`.\n\n` +
  `This repository is a fixture for an automated code-review evaluation built from the\n` +
  `[OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark).\n` +
  `The baseline branch is the upstream tree with \`${cve.files.join('`, `')}\` removed;\n` +
  `each pull request re-adds that file at one of the two commits recorded for ${cve.cve}.\n`

async function ensureRepo(slug) {
  const full = `${ORG}/${slug}`
  try {
    await run('gh', ['repo', 'view', full, '--json', 'name'])
    return { full, created: false }
  } catch {
    if (DRY) return { full, created: false }
    await run('gh', ['repo', 'create', full, `--${VISIBILITY}`,
      '--description', 'Fixture for the Ozone security-review benchmark (OpenSSF CVE Benchmark)'])
    return { full, created: true }
  }
}

async function openPr(full, cve, variant) {
  const existing = JSON.parse(await run('gh', ['pr', 'list', '--repo', full, '--state', 'all',
    '--head', `pr/${variant}`, '--json', 'number']))
  if (existing.length) return existing[0].number
  const url = await run('gh', ['pr', 'create', '--repo', full, '--base', 'main', '--head', `pr/${variant}`,
    '--title', prTitle(cve), '--body', prBody(cve)])
  return Number(url.trim().split('/').pop())
}

const manifest = JSON.parse(await readFile(join(ROOT, 'manifest/ossf-cves.json'), 'utf8'))
let targets = manifest
if (args.only) {
  const want = new Set(String(args.only).split(',').map((s) => s.trim()))
  targets = targets.filter((c) => want.has(c.cve))
}
if (args.limit) targets = targets.slice(0, Number(args.limit))

const outPath = join(ROOT, 'manifest/fixtures.json')
const built = (await exists(outPath)) ? JSON.parse(await readFile(outPath, 'utf8')) : {}
let ok = 0
const failures = []

for (const [i, cve] of targets.entries()) {
  const label = `[${i + 1}/${targets.length}] ${cve.cve}`
  if (built[cve.cve]?.prs && Object.keys(built[cve.cve].prs).length === cve.variants.length) {
    console.log(`${label} already built — skipping`)
    ok++
    continue
  }
  const dir = await mkdtemp(join(tmpdir(), 'ozbench-'))
  try {
    await buildOne(cve, dir)
    if (DRY) { console.log(`${label} built locally (dry run)`); ok++; continue }
    const { full } = await ensureRepo(cve.slug)
    await run('git', ['remote', 'remove', 'origin'], { cwd: dir }).catch(() => {})
    await run('git', ['remote', 'add', 'origin', `https://github.com/${full}.git`], { cwd: dir })
    await run('git', ['push', '-q', '--force', 'origin', 'main'], { cwd: dir })
    for (const v of cve.variants) await run('git', ['push', '-q', '--force', 'origin', `pr/${v}`], { cwd: dir })
    const prs = {}
    for (const v of cve.variants) prs[v] = await openPr(full, cve, v)
    built[cve.cve] = { repo_full_name: full, prs, files: cve.files, cwes: cve.cwes, source: projectName(cve.repo) }
    await writeFile(outPath, JSON.stringify(built, null, 1))
    console.log(`${label} ${full} → ${cve.variants.map((v) => `${v}#${prs[v]}`).join(' ')}`)
    ok++
  } catch (e) {
    console.error(`${label} FAILED: ${e.message}`)
    failures.push({ cve: cve.cve, error: e.message })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

await writeFile(join(ROOT, 'manifest/fixture-failures.json'), JSON.stringify(failures, null, 1))
console.log(`\nbuilt ${ok}/${targets.length}; ${failures.length} failed`)
if (failures.length) console.log('failures written to manifest/fixture-failures.json')
