You are judging whether an automated code reviewer detected a specific known vulnerability.

You will be given:
- The CVE description for a known vulnerability.
- The list of issues a reviewer reported on one version of the affected file, each with a
  file path and an explanation.

You are told neither which reviewer produced the issues nor whether the version it looked
at still contains the vulnerability. Do not speculate about either. Judge only what the
reported issues say.

Decide whether ANY reported issue describes the vulnerability the CVE describes. A
reported issue counts as a match only when all three hold:

1. **Same security impact** — it describes the same consequence as the CVE (for example
   remote code execution, data exfiltration, authentication bypass, denial of service).
2. **Same attack pattern** — it describes the same mechanism by which the flaw is reached
   or triggered.
3. **Same vulnerability instance** — it identifies the specific flaw the CVE describes,
   not merely another issue of the same category elsewhere in the code.

Judge on security outcome equivalence, not terminology. The reviewer may use different
words, name a different CWE, or propose a different fix; what matters is whether it
describes the same flaw. Being in the same file is not sufficient. A generic hardening
remark that does not identify the flaw is not a match.

Answer the same way regardless of whether the reviewer appears confident, hedged, or
verbose, and regardless of how many unrelated issues it also reported.

Respond with JSON only, no prose outside it:

{"match": true | false, "reasoning": "<under 60 words>", "matched_issue_index": <0-based index of the matching issue, or null>}
