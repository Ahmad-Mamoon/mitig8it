# Security curation datasets

This directory validates and optionally publishes two synthetic, source-backed evaluation
datasets:

- `mitig8it-application-security-v1`: application findings for the HTTP triage path.
- `mitig8it-ai-reviewer-security-v1`: prompt-injection, context, and agent-review cases for the
  same triage path. These cases do not claim to exercise remediation tool guards, autonomous
  merge, persistent memory, or RAG.
- Version 2 catalogs are named `mitig8it-application-security-v2` (120 planned cases) and
  `mitig8it-ai-reviewer-security-v2` (60 planned cases). They retain v1 seeds for comparison,
  add scenario and isolation metadata, and apply stronger pair and label-leakage checks.

Both files use `{ "schema_version": 1, "cases": [...] }`. Every case has an ID, finding
fingerprint, split, lineage, language, unified diff, expected outcome, and primary-source
references. Lineages may not cross splits, so near-copy variants remain in one split. The
validator checks exact finding-to-diff line mapping, duplicate IDs/fingerprints, URL shape,
Python syntax, and lightweight JavaScript/TypeScript delimiter plausibility. It never fetches
URLs, runs fixture code, installs dependencies, or invokes a model.

Application cases are 24 curated cases (8 true positives, 8 false positives, 8 uncertain) in
eight triplet lineages, split 12 development / 6 validation / 6 holdout. Agent cases are 12
triage cases split 6 / 4 / 2. These are curated challenges, not prevalence samples or
independently established production ground truth; labels should be peer-reviewed and any
disagreements recorded before using holdout results.

The v2 target is 40 application triplets (72 / 24 / 24 cases) and 30 agent pairs (36 / 12 / 12
cases). The v1 catalog remains frozen; v2 inherited seeds are normalized migrations identified
by `inherited_seed_ids`, and every v2 case requires `scenario_id` and `isolation_group`.
Agent pairs must keep the same finding,
repository profile, verdict, and executable patch semantics, with only a prose/comment line
changed. Normalized content reused across splits is reported for manual review rather than
silently treated as independent evidence. These counts and labels are targets until authored
files arrive and pass validation.

Run validation locally:

```sh
.venv/analysis/bin/python -m benchmarks.security_curation.validate path/to/cases.json
.venv/analysis/bin/python -m pytest benchmarks/security_curation/test_validate.py benchmarks/security_curation/test_publish.py -q
```

The publisher defaults to a dry run and makes no network calls:

```sh
.venv/analysis/bin/python -m benchmarks.security_curation.publish path/to/cases.json
```

Publishing is a separate, explicit action. It validates first, loads only the allowlisted
LangSmith variables from the specified remediation env file, requires workspace
`779b5011-7837-4605-bdfb-2057895981c9`, and writes examples only to the dedicated versioned
dataset. Existing examples with the same ID and digest are skipped; conflicting IDs are refused.
It creates no runs, projects, traces, or model calls, and never deletes or overwrites existing
fixtures. Do not use `--publish` until the coordinator explicitly authorizes the upload:

```sh
.venv/remediation/bin/python -m benchmarks.security_curation.publish path/to/cases.json \
  --env-file benchmarks/remediation/.env --publish
```

The current triage runner caps a live batch at 12 requests. Evaluating all 24 application cases
therefore requires selected batches (or repeated runs); do not silently change that cap. The
existing 63 remediation fixtures remain a separate repair/verification corpus and are not
counted as recommendation-quality cases. Neither catalog is CI-ready proof of precision or a
security guarantee: the validator checks fixture contracts offline, not model behavior, repair
correctness, production prevalence, or independent human-auditor agreement.
