# Development evaluation with optional LangSmith

This workflow exercises the local remediation pipeline with checked-in fixtures and a
scripted provider. It needs no model key, deployed service, or Google Cloud resources.
LangSmith is an optional destination for explicitly uploaded experiment results.

## Observe

Use the remediation Python environment created by `make deps`, or an existing environment
with `services/remediation-service/requirements-test.txt` installed. Run from the repository root:

```sh
make dev-eval

# Keep a baseline before changing the engine.
make dev-eval DEV_EVAL_ARGS='--output benchmarks/results/dev-baseline.json'

# Quick fixture-reference checks without importing the repair engine.
make dev-eval DEV_EVAL_ARGS='--adapter reference --limit 5'
```

The default adapter is `engine-local`. It runs the real repair engine with a scripted provider
and development subprocess verification. The `reference` adapter checks reviewed fixture
repairs. Neither measures a real model's ability to generate repairs. Reports record individual
outcomes, timing, verification levels, deterministic scores, and failures. Any token-derived
cost estimate from the fixture harness is synthetic, not a bill.

For engine runs, the command prefers the scanner already installed in `.venv/analysis/bin`,
disables scanner metrics/version checks, and uses temporary log/settings files when you have
not supplied your own. If no `SSL_CERT_FILE` is set and certifi is available, it uses certifi's
trusted CA bundle. TLS verification stays enabled. These environment changes are restored
after the run, and temporary scanner files are removed.

## Evaluate

```sh
make dev-eval DEV_EVAL_ARGS='--baseline benchmarks/results/dev-baseline.json --output benchmarks/results/dev-current.json'
```

Compare the same adapter and fixture content. Keep the original baseline; do not point
`--output` at it. A failure or regression produces a nonzero exit code. Incomparable baselines
must be investigated rather than interpreted as improvements. Known failures remain failures.

An executed regression test and a static assertion are different evidence. Reports preserve
that distinction; passing a static assertion does not imply a test ran. Executed local results
remain `development_unverified`, since ordinary subprocesses do not establish production
sandbox isolation. Authored fixture success is regression coverage, not a release certification.

If static-assertion cases fail, inspect `scanner_preflight` in the report. These cases need the
local `semgrep` executable used by the analysis service. The diagnostic distinguishes a missing
executable, startup timeout, certificate-store problem, and permission failure; it never turns
a failed case into a pass. Fix the local scanner environment before interpreting those failures
as an engine regression. The reference adapter can still check authored fixture repairs, but
does not substitute for exercising the engine's static-assertion path.

## Improve

1. Read the failing fixture IDs and reason codes in the report.
2. Reproduce a case with `--fixture FIXTURE_ID` and inspect its checked-in fixture and verifier.
3. Fix the cause or add a reviewed fixture for missing behavior. Do not weaken the expected
   verification level or hide a failure to improve a score.
4. Rerun the original fixture selection against the saved baseline, then run the full corpus.
5. Review the evidence before choosing a new baseline.

This loop surfaces regressions; it does not automatically edit code or promote a deployment.

## Real-model evaluation

`--adapter engine-live` runs the same engine against a real model and spends money with that
provider. It is never the default. Configure an OpenAI-compatible provider and that model's
current prices in the gitignored `benchmarks/remediation/.env`:

```sh
REPAIR_LLM_BASE_URL=https://api.openai.com/v1
REPAIR_LLM_API_KEY=...
REPAIR_LLM_MODEL=...
REPAIR_LLM_INPUT_USD_PER_MTOK=...
REPAIR_LLM_OUTPUT_USD_PER_MTOK=...
```

Live mode executes code a model wrote. The engine's local sandbox driver runs the proposed patch
and its generated regression test, and the trusted fixture check runs the candidate file, all as
ordinary subprocesses of your user with no network, kernel or filesystem isolation. The command
refuses to start without `--allow-host-execution`. Use it only on a development machine or a
disposable VM, never on a host holding production credentials, and never in CI.

Prices are required because the budget cannot be enforced without them. Start small, with a
repairable case, a case that must be refused, and an adversarial one:

```sh
make dev-eval DEV_EVAL_ARGS='--adapter engine-live --allow-host-execution --fixture python-sql-sqlite-001 --fixture ambiguous-sql-driver-001 --fixture adversarial-safe-comment-001 --output benchmarks/results/dev-live.json'
```

`--max-cost-usd` (default 1.00) caps the suite and `--max-case-cost-usd` (default 0.25) caps one
fixture. Both go into the engine's request policy, which reserves spend before each provider
call; a case the remaining budget cannot cover is not started and is reported as
`suite_budget_exhausted`. `--max-live-cases` (default 10) rejects a larger selection outright.
Reported cost is an estimate from provider-reported tokens at the configured prices, not a bill.
A case whose usage was lost is marked `cost_unknown` and charged its full cap against the suite.

A real model rarely reproduces the reference repair byte for byte. A candidate the engine
verified is therefore also run through the fixture's own trusted check, and passes on that
check (`graded_by: trusted_fixture_check`); `reference_match` stays a separate score. Refusal
cases are never upgraded. Live reports are labelled `live_model_development` and are not
comparable with scripted baselines. Verification is still `development_unverified`.

A deterministic template repair or an early refusal passes without any provider call. Each
live row records `model_invoked`, and the report counts `model_invoked_cases`; only those cases
say anything about the model.

A live pass at `static_assertion` comes from the engine's deterministic fallback after the agent
gave up. Rows record `model_repair`, and `model_repair_runs` counts only passes the model produced.

Live outcomes vary between identical runs. `--repeats N` runs each fixture N times (fixtures
times repeats counts against `--max-live-cases`) and the report's `repeat_agreement` gives passes
per fixture and whether it was stable. Repeated reports are not comparable with `--baseline`.

Use train fixtures while iterating, validation for comparisons, and holdout only occasionally.

## Optional LangSmith experiments

Install the optional development dependency separately:

```sh
.venv/remediation/bin/python -m pip install -r benchmarks/remediation/requirements-dev.txt
```

Set `LANGSMITH_API_KEY` in your shell using your own secret-management method, or put it in
`benchmarks/remediation/.env`, then explicitly request an upload:

```sh
make dev-eval DEV_EVAL_ARGS='--limit 5 --upload'
```

The env file is gitignored and optional; a missing file is not an error. It holds simple
`KEY=VALUE` lines: `LANGSMITH_API_KEY`, and optionally `LANGSMITH_WORKSPACE_ID`. Only keys
starting with `LANGSMITH_`, `LANGCHAIN_`, or `REPAIR_LLM_` are applied, a variable already set
in your shell is never replaced, and the environment is restored after the run. Tracing stays
disabled during evaluation whatever the file says. Reports list the applied key names under
`env_file_keys`, never the values. Use `--env-file PATH` to read a different file.

Uploads create a LangSmith dataset/experiment with fixture identifiers, expected outcomes,
sanitized results, and deterministic feedback. Experiment metadata describes the report:
adapter, provider kind, results and usage kind, fixture digest, and git revision. Token counts
and cost estimates are included only when the report recorded them. Source code, patches,
prompts, test output, and raw exception messages are excluded. Local results are saved before
uploading, so an upload failure does not lose the evaluation. Credentials alone do not enable
uploads.

To retry a failed upload without rerunning fixtures, upload the saved report:

```sh
make dev-eval DEV_EVAL_ARGS='--upload-only benchmarks/results/dev-eval.json'
```

This does not run fixtures or import the engine. It respects `--max-upload-cases`, writes the
upload status back into the same report, and cannot be combined with `--baseline`, `--fixture`,
`--split`, or `--limit`. Each upload creates a new experiment on the same dataset.

Uploaded experiments consume LangSmith usage. Start with a small selection and check your
account allowance; a per-run upload limit is not a monthly spending cap. No LLM judge is used,
and this command has no deployed-service adapter.

The optional SDK is not added to production requirements, Docker images, CI runs, or cloud
configuration. The existing production telemetry remains separate from this development tool.

LangSmith documents [uploading external experiments](https://docs.langchain.com/langsmith/upload-existing-experiments)
and [custom evaluation](https://docs.langchain.com/langsmith/evaluation-quickstart).
