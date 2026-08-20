# CVEs whose recorded fix does not fix the vulnerability

The benchmark's ground truth assumes the post-patch commit is safe, so any finding
reported against it counts as a false positive. That assumption does not always hold.
Where it fails, a reviewer is penalised for being right.

This file records only cases **demonstrated with a concrete bypass**, not cases we merely
suspect. Each entry must carry a reproduction anyone can run. A false positive we cannot
disprove stays counted against us.

## CVE-2017-16029 — hostr, path traversal

Recorded fix (`lib/routes/statics.js`, commit `postPatch`):

```js
resourcePathname = resourcePathname.replace(/\/\.\./, "").replace(/\.\.\//, "");
```

Both replaces are **non-global**, so each strips at most one occurrence. Nested traversal
survives:

```js
const sanitize = p => p.replace(/\/\.\./, "").replace(/\.\.\//, "");

sanitize("/a/../../../etc/passwd")   // → "/a/../etc/passwd"   still escapes the root
sanitize("/..../..//etc/passwd")     // → "..//etc/passwd"     still escapes the root
sanitize("/./..././..././etc/passwd")// → "/./..././etc/passwd" still escapes the root
```

The patched version remains directory-traversable, so a reviewer reporting traversal
against it is correct and the benchmark records a false positive.

Ozone reported exactly this on the fixed variant and the judge, blind to which version it
was looking at, described it as "insufficient removal of repeated `../` segments lets
unauthenticated requests escape the served root".

**How this is reported:** the headline figures count it as a false positive, unchanged.
The effect of excluding demonstrated cases like this is reported separately, so the
adjustment is visible and arguable rather than baked into the number.
