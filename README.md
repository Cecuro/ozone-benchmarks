# Ozone benchmarks

Reproducible evaluation of [Ozone](https://ozone.cecuro.ai) on public security benchmarks,
with the harness, the fixtures, the raw model output and the judge's verdicts published
alongside the scores.

The point of this repository is that you do not have to take our number on trust. Every
figure we publish can be recomputed from what is here, and the tools we compare against
are scored by the same script from their own maintainers' published data.

## OpenSSF CVE Benchmark

[The OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) is
200+ real JavaScript and TypeScript CVEs, each with the commit that introduced the flaw
and the commit that fixed it. Because both commits exist, a tool can be measured for
false positives as well as detection: it should report the vulnerability in the first and
stay quiet on the second.

We evaluate on the 85-CVE / 165-run subset that DeepSource used when it
[published results](https://deepsource.com/benchmarks) for eight other tools
(filtered to CVEs with both commits, a CWE label, and an affected file under 1,000 lines),
so the comparison is like for like.

### How a run is constructed

Following DeepSource's method, each CVE becomes its own repository:

| Branch | Contents |
| --- | --- |
| `main` | the upstream tree at the pre-patch commit, with the vulnerable file removed |
| `pr/unfixed` | `main` + the vulnerable file as it was **before** the fix |
| `pr/fixed` | `main` + the same file as it was **after** the fix |

Each branch is opened as a pull request, so the security-relevant code appears as an
addition in the diff, the way a contributor's change would. Ozone reviews the pull
request through its ordinary PR path — no benchmark-specific prompt, no hint that a
vulnerability is present, and the PR title and body describe the change neutrally.

- The `unfixed` PR measures **true positives** and **false negatives**.
- The `fixed` PR measures **true negatives** and **false positives**.

Fixture repositories are attached with `trigger_mode: off` and
`comment_mode: dashboard_only`, so only the runs this harness starts ever execute, and no
benchmark review is posted to a pull request.

### Judging

Findings are judged by an LLM that is **not told which tool produced them**. A finding
counts as a detection only when it describes the same security impact, the same attack
pattern, and the same vulnerability instance as the CVE — not merely the same category in
the same file. The prompt is [`prompts/judge.md`](prompts/judge.md) and every verdict is
written to `results/judged.jsonl` with its reasoning, so any judgment can be disputed
against the record.

### A defect in the dataset, and how we report around it

In 8 of the 85 CVEs the file recorded as vulnerable is **byte-identical before and after
the patch** — the fix landed somewhere else, or the recorded location is not where the
change happened:

```
CVE-2017-16003  CVE-2018-1002204  CVE-2019-10090  CVE-2019-10759
CVE-2019-10776  CVE-2019-5483     CVE-2020-11021  CVE-2020-7763
```

For these, the `fixed` pull request is identical to the `unfixed` one, so a tool that
correctly finds the vulnerability is recorded as raising a false positive. This penalises
exactly the tools that detect the most, and the effect is not small: excluding those eight
`fixed` rows moves Cursor Bugbot's precision from 74.2% to 78.3% and GitLab Duo's from
92.9% to 97.5%.

`scripts/score.mjs` therefore prints two tables — **as published**, comparable with the
numbers already in circulation, and **corrected**, excluding those eight rows for every
tool equally. We report both. Anything we claim publicly quotes both.

### Baseline figures

Baselines are computed by our script from
[DeepSourceCorp/benchmarks](https://github.com/DeepSourceCorp/benchmarks), the maintainers'
own judged output, rather than transcribed from a marketing page. Note that for two tools
that published data does not agree with DeepSource's summary table: it yields CodeRabbit
82.61% precision with 4 false positives (the table says 100%) and Claude Code 88.89%
precision (the table says 90.7%). We score from the data.

## Reproducing

```bash
# 1. Build the fixture repositories and open their pull requests
node scripts/build-fixtures.mjs --org Cecuro --visibility private

# 2. Run Ozone over them (spend-capped, resumable, nothing auto-triggers)
OZONE_API_KEY=oz_live_… node scripts/run-ozone.mjs --max-spend 150 --concurrency 4

# 3. Judge the findings, blind to the tool
ANTHROPIC_API_KEY=… node scripts/judge.mjs

# 4. Score, against every published baseline
node scripts/score.mjs
```

Both `run-ozone.mjs` and `judge.mjs` resume: re-running skips work already recorded.
`run-ozone.mjs` stops as soon as accumulated `cost_usd` crosses `--max-spend`.

## What is in here

| Path | |
| --- | --- |
| `manifest/ossf-cves.json` | the 85 CVEs: upstream repo, both commits, affected file, CWEs |
| `manifest/identical-variants.json` | the 8 CVEs whose patch does not change the recorded file |
| `manifest/fixtures.json` | built fixture repositories and their PR numbers |
| `prompts/judge.md` | the judge prompt, verbatim |
| `results/runs.jsonl` | every run: status, cost, duration, and each finding as Ozone reported it |
| `results/judged.jsonl` | one verdict per run, with reasoning and the judge model |
| `results/scores.json` | the computed tables |

## Scope and limits

- JavaScript and TypeScript only. This benchmark says nothing about our coverage of other
  languages, and we do not extrapolate from it.
- The CVEs are public and predate current models, so memorisation cannot be excluded. It
  applies equally to every tool in the table, and it is the reason we treat post-cutoff
  evaluation as necessary rather than optional.
- Ozone is run at a pinned agent revision, recorded with each result set. Product changes
  move these numbers; we re-run rather than quote stale figures.
