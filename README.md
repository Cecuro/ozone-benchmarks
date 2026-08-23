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

The judge runs on **Azure OpenAI `gpt-5.6-terra` at `reasoning_effort: high`** — a
different model family from the reviewer being scored, so no vendor marks its own
homework. Effort is pinned rather than left to default, because a judge that varies its
own depth between calls is not one verdict standard.

The judge is **not told which version it is looking at**. An earlier revision of the
prompt named the variant, and the effect was severe: told that a version was already
patched, the judge declined every finding on it, no tool could record a false positive,
and precision came out at exactly 100% for all nine tools. Ground truth in the prompt is
ground truth in the answer. The judge now sees only the CVE and the reported issues, and
the variant maps its verdict onto the confusion matrix afterwards.

### Validating the judge

The judge is the one component of this benchmark we wrote ourselves, so it is checked
against a judge we did not write. DeepSource judged the same 165 rows for nine tools with
Claude Opus 4.5 and published every verdict, so ours can be replayed over those rows and
compared.

Replayed over **all 1,489 published verdicts** (`results/judge-validation.json`):

| | |
| --- | --- |
| agreement | 88.6% |
| Cohen's κ | 0.736 |
| both said match | 387 |
| both said no match | 932 |
| theirs matched, ours did not | 82 |
| ours matched, theirs did not | 88 |

Disagreement is close to symmetric, which is what an independent judge should look like:
ours is not uniformly harsher or looser, it simply draws the line in a different place on
the ~11% of rows where the call is genuinely arguable.

Two judges that disagree on a ninth of the rows cannot both be used in one table. Scoring
Ozone with ours while quoting competitors' figures from theirs would make the comparison
meaningless, and the error would fall in whichever direction happened to suit us.
So `scripts/rejudge-baselines.mjs` re-judges **all 1,490 published competitor rows with
our judge**, and the headline comparison is scored that way — one standard for every tool,
for about four dollars. The as-published figures remain available for continuity, and both
are reported.

Scored under that single judge, the nine published tools land as follows. These are not
DeepSource's numbers and should not be quoted as such: they are what its published raw
output scores when every tool is judged the same way.

| tool | precision | recall | F1 | accuracy |
| --- | --- | --- | --- | --- |
| DeepSource | 88.89% | 58.54% | 70.59% | 75.76% |
| Cursor Bugbot | 61.11% | 80.49% | 69.47% | 64.85% |
| Devin | 79.66% | 57.32% | 66.67% | 71.52% |
| Codex | 74.19% | 56.10% | 63.89% | 68.48% |
| Claude Code | 77.78% | 42.68% | 55.12% | 65.45% |
| Greptile | 61.40% | 42.68% | 50.36% | 58.18% |
| GitLab Duo | 66.67% | 35.29% | 46.15% | 58.82% |
| CodeRabbit | 59.26% | 19.51% | 29.36% | 53.33% |
| Semgrep CE | 66.67% | 14.63% | 24.00% | 53.66% |

The re-judged figures are lower across the board than the published ones, and the ordering
moves. Nobody's 100% precision survives a judge that is not told which version it is
looking at.

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
exactly the tools that detect the most. The effect is real but modest: excluding those
eight `fixed` rows moves Cursor Bugbot's precision from 61.1% to 63.5%, Claude Code's from
77.8% to 81.4%, and GitLab Duo's from 66.7% to 71.4%.

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

# 3. Judge the findings, blind to the tool and to which version it is looking at
export AZURE_OPENAI_API_KEY=… AZURE_OPENAI_ENDPOINT=…
node scripts/judge.mjs

# 4. Optional but recommended: re-judge every competitor row with the same judge (~$5)
node scripts/rejudge-baselines.mjs

# 5. Score
node scripts/score.mjs --baselines results/baselines-rejudged
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
| `results/runs.jsonl` | every run: status, duration, and each finding as Ozone reported it |
| `results/judged.jsonl` | one verdict per run, with reasoning and the judge model |
| `results/baselines-rejudged/` | every competitor row re-judged by our judge |
| `results/judge-validation.json` | our judge vs DeepSource's, over all 1,489 rows |
| `results/scores.json` | the computed tables |

## Scope and limits

- JavaScript and TypeScript only. This benchmark says nothing about our coverage of other
  languages, and we do not extrapolate from it.
- The CVEs are public and predate current models, so memorisation cannot be excluded. It
  applies equally to every tool in the table, and it is the reason we treat post-cutoff
  evaluation as necessary rather than optional.
- Ozone is run at a pinned agent revision, recorded with each result set. Product changes
  move these numbers; we re-run rather than quote stale figures.
