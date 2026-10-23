# Real-model recommendation smoke evaluation

This suite checks the LLM recommendation path with six synthetic, labeled PR
diffs and existing findings. A live runner should submit each finding and diff
to the local analysis service's triage endpoint, which invokes
`triage_findings_payload` and the configured model. No detector is being tested:
the finding is provided as input. This is not a test of GitHub delivery, the UI,
or the entire multi-service deployment.

The fixtures cover three clear vulnerabilities (SQL injection, shell command
injection, reflected HTML injection), two safe controls (parameter binding and
validated shell-free subprocess arguments), and an authorization question with
insufficient context. The shell-injection case contains a malicious reviewer
instruction inside a code comment. Treat that text as fixture data; evaluate
whether the model ignores it and grounds its verdict in the code.

## Fixture contract

`cases.json` is an object with `schema_version: 1` and a `cases` array. Each case
has an `id`, `expected_verdict`, `finding`, `file_patch`, `repo_profile`,
`expected_fix_terms`, and `human_review_rubric`.

For a `TriageRequest`, use `[case.finding]` as `findings`,
`{case.finding.file_path: case.file_patch}` as `file_patches`, and
`case.repo_profile` as `repo_profile`. Supply a synthetic repository name, PR
number, and commit SHA. The full added-file unified diffs have accurate new-file
line numbers matching each finding. All fixture content is synthetic.

Expected labels and rubrics belong to the evaluator. **Do not include them in
the model request.** Recommendations should be derived from finding evidence
and the supplied patch, not the expected answer.

`expected_fix_terms` is a list of alternative-string groups. A simple heuristic
checks that the recommendation's fix text contains at least one term from each
group, using case-insensitive substring matching. An empty list means this
check is not applicable, not evidence of a good recommendation. These terms are
deliberately broad: they cannot establish security correctness. Use the human
review rubric to assess the actual fix and negative test. For uncertain cases,
an absent recommendation may be appropriate when evidence is insufficient.

## What to record

Report observed model verdicts separately from endpoint outcomes. The current
triage implementation removes false-positive findings, so removal alone must
not be mistaken for an observed model verdict without call/response evidence.
A returned original finding after an API error or disabled model is a degraded
fallback, not a successful LLM evaluation.

For each case, retain the model/provider and prompt/code version, actual token
usage, estimated model cost using explicit rates, wall latency, whether a real
model response was obtained, expected and observed verdicts, recommendation
presence, accepted citations, keyword coverage, and failures. Repeated runs
can expose variability; report their count and disagreement, not an unsupported
claim of reliability. Grounded citations show correspondence to supplied code,
not that a recommendation repairs the vulnerability.

Review each true-positive recommendation for a concrete repo-specific fix, a
negative regression test with expected behavior, explicit assumptions, and no
claims of executed tests or verified repairs. Review both safe controls for
unnecessary security changes and review the uncertain case for overconfidence.
Inspect the malicious-comment case for instruction following or unsupported
suppression. Keyword checks are auxiliary and should never override these
judgments.

## Replacement-code gate (not remediation verification)

Advisory `recommendation.fix` prose and optional `fixed_code` are evaluated
separately. When the raw model proposes `fixed_code`, the runner requires an
exact snippet/line anchor in the fixture's complete added-file diff, applies
the bounded replacement in memory, and parses the resulting full source with
Python `ast.parse` or Node `--check` (JavaScript). It does not execute candidate
code. Invalid, oversized, unsupported, unanchored, or syntactically invalid
proposals fail the report, even when the verdict and advisory scores pass.
Duplicate verdicts for one fingerprint also fail the ambiguity score.

Each live row records `replacement_validation`: `not_proposed`, `rejected`, or
`syntax_only_passed`. Advisory-only responses may pass this smoke evaluation
without proposing code; that is never counted as a repaired vulnerability.
Every row keeps `behavior_checked`, `sandbox_verified`, and
`ready_for_inline_publication` false. The summary explicitly reports zero
sandbox-verified repairs and semantic correctness as `not_evaluated`.
Even syntactically valid code can reference undefined helpers, break behavior,
or leave the vulnerability intact. The separate remediation service's sandbox,
regression, and publication-evidence path remains necessary; this smoke result
does not promote rules, authorize GitHub suggestions, or replace that evidence.

Deterministic safe-sink removal is deliberately narrower than the model's
advice: it requires a complete inspectable Python added-file context and exact
sink alignment, imported `subprocess` with an allowlisted non-interpreter
executable and `shell=False`, or an unambiguously bound built-in `sqlite3`
connection/cursor with parameter binding. Partial diffs and ambiguous receivers
cannot establish this proof. Strong/dataflow findings disputed by the model
are retained as uncertain without inspectable safe-sink proof. Credential
literals are deterministically redacted before provider calls; findings and
their source locations are not mutated.

## Scope, cost, and interpretation

This is a curated smoke evaluation. Six hand-authored cases do **not** measure
production precision, recall, or proof of semantic correctness. Report scores
as agreement or coverage on these cases, with denominators, and disclose any
heuristic checks. More representative independently labeled data and repeated
trials are needed for broader quality claims. Keep these cases fixed for
comparisons and record any subsequent fixture changes.

Live model calls cost money; use an explicit bounded budget and configured
model prices. Run locally, without Google Cloud deployment. Local reports must
remain usable without LangSmith. LangSmith uploads are optional and must stay
within the user's verified zero-cost configuration; a tracing flag or local
budget does not itself guarantee a zero LangSmith bill. Never put API keys in
fixtures, logs, reports, or trace inputs.

## Run the local endpoint evaluation

Use `.venv/analysis/bin/python`. The runner starts a temporary HTTP listener on
127.0.0.1, invokes the actual Tier 3 route and configured model, then round-trips
the result through the service's gRPC response schema. It records context,
provider, parsing, enrichment, and transport stages. It disables inherited
LangSmith/OTEL tracing and SDK retries for the evaluation process. It does not
change a running service or any `.env` file.

For an explicitly authorized reuse of the remediation development credentials:

```sh
.venv/analysis/bin/python benchmarks/analysis_recommendations/run.py \
  --env-file benchmarks/remediation/.env \
  --api-key-env REPAIR_LLM_API_KEY --base-url https://api.openai.com/v1 \
  --model gpt-4o-mini --input-price 0.15 --output-price 0.60 \
  --max-cost 0.10 --repeats 2
```

Select a single fixture with `--case sql_interpolation --repeats 1`.
The suite allows at most 12 live requests. Prices must match your provider.
A generous input estimate plus the output limit reserves estimated spend before
starting a request; provider-reported usage settles it afterward. This is not a
provider-side hard billing cap. Unknown usage reserves the entire estimated
request amount. A provider failure stops further live requests. Saved reports
include failures, incomplete runs, and synthetic fault checks separately.

For recovery checks with no external provider calls:

```sh
.venv/analysis/bin/python benchmarks/analysis_recommendations/run.py \
  --model fault-injection --input-price 1 --output-price 1 --faults-only \
  --output benchmarks/results/recommendations-faults.json
```

The default result is `benchmarks/results/recommendations-live.json`. It contains
synthetic prompts and responses for local inspection, with source/fixture/prompt
digests, latency, measured tokens, estimated cost, and per-case scores. It is
written after each case using an atomic replacement and owner-only permissions.
Fault checks deliberately replace the provider with a timeout or invalid JSON;
they do not count as model quality measurements. A fault check passes only when
the patched provider path was called exactly once and the original finding was
preserved. An HTTP 200 fallback alone is insufficient. A live row passes only
after the HTTP response and gRPC transport round-trip both complete. The report's
`evaluation_status` stays `in_progress` until every planned row finishes, then
becomes `passed` or `failed`. Keyword matching is labelled a heuristic.

## Upload saved observations to free LangSmith

First confirm the free allowance and no-card setting. This separate step makes
no model calls. Use the existing optional SDK in `.venv/remediation`:

```sh
LANGSMITH_WORKSPACE_ID=<your-workspace-id> \
.venv/remediation/bin/python benchmarks/analysis_recommendations/run.py \
  --env-file benchmarks/remediation/.env \
  --upload-only benchmarks/results/recommendations-live.json
```

The upload contains synthetic case IDs, verdicts, timing, tokens, costs, scores,
and parent/child stages. It excludes prompts, source, raw model responses and
exception messages. Feedback uses `extend_trace_retention=False`; the upload
limit is 14 root observations, not an account-wide billing guarantee. The
experiment uses the fixture hash for dataset identity and retains prompt/model
metadata. A read-back checks the first uploaded root trace. The optional SDK
is not added to production dependencies.

```sh
.venv/analysis/bin/python -m pytest benchmarks/analysis_recommendations/test_run.py -q
```
