# The fixed variant is not always fixed

The benchmark measures false positives by showing a reviewer the patched version of a
file and expecting silence. That only works if the patched version is genuinely no longer
vulnerable. For a third of this dataset, it is not.

## The construction

Each CVE records a *vulnerable file*. The fixture — following DeepSource's method — puts
the repository at the pre-patch commit on `main` and adds that one file back, at the
pre-patch version for `unfixed` and the post-patch version for `fixed`.

If the real fix changed **only** that file, the fixed variant is correctly patched.
If the fix also changed other files, those changes are absent, and the "fixed" variant can
still be exploitable.

## How often

Of the 85 CVEs, **27 (32%)** have a fix commit that modified source files beyond the
recorded one (excluding tests, docs and lockfiles). Full data in
`manifest/multifile-fixes.json`.

## A worked example: CVE-2019-10750 (prototype pollution in `deeply`)

The recorded file is `lib/reduce_object.js`. The post-patch version adds a guard:

```js
var behaviors = require('../flags.js');
...
if (context.allowDangerousObjectKeys !== behaviors.allowDangerousObjectKeys && isUnsafeKey(key))
{
  return acc;   // drop __proto__
}
```

The real fix commit changed seven files, including `flags.js`, which is where
`allowDangerousObjectKeys` is defined. The fixture does not ship `flags.js`, so it stays at
the pre-patch version — where that flag does not exist.

`behaviors.allowDangerousObjectKeys` is therefore `undefined`, and for any ordinary call
`context.allowDangerousObjectKeys` is `undefined` too. The condition reduces to
`undefined !== undefined`, which is `false`. **The guard never runs, and the patched file
is still vulnerable to prototype pollution.**

A reviewer that reports prototype pollution against this "fixed" variant is correct, and
the benchmark records a false positive.

## What this does to the numbers

It penalises detection. A tool that finds the flaw is marked wrong; a tool that stays
quiet is marked right, including when it stayed quiet because it found nothing at all.
Precision is therefore understated for every tool, and understated most for the tools that
detect the most.

## How we report it

Two tables, both published:

- **as run** — every row, directly comparable with the figures already in circulation.
- **corrected** — dropping the `fixed` rows of CVEs whose fixture cannot be shown to carry
  the complete patch (the 27 multi-file fixes plus the 8 whose recorded file the patch
  never touched).

The correction is applied identically to all ten tools. It is a statement about the
fixture, not about any tool's answer, and it is deliberately mechanical — "the fix touched
files we do not ship" — rather than a per-finding judgement call about whether our own
false positives were really justified.

Only CVE-2019-10750 above has been verified by reading the patch. The other 26 are flagged
by the mechanical rule and should be read as *cannot be shown to be completely patched*,
not as *proven still vulnerable*.
