# Mitig8it Model Benchmarks

Benchmark dataset for evaluating LLM models on security vulnerability detection. Use it to compare candidate models before integrating them into the Mitig8it analysis pipeline.

Rule publication is separately enforced by the [rule quality gate](../../benchmarks/rule-quality/README.md):
new, changed, or re-enabled rules require at least 100 reviewed holdout predictions,
no unresolved judgments, and a two-sided 95% Wilson lower precision bound of at
least 0.95. `make bench-rule-quality` runs the same check enforced in CI and before
publishing the release image. Existing rules are explicitly reported as legacy
exceptions, not statistically validated detections.

## Structure

```
benchmarks/
├── dataset/
│   ├── true_positives/    # Code with known vulnerabilities
│   │   ├── python.json
│   │   ├── javascript.json
│   │   ├── java.json
│   │   └── go.json
│   └── true_negatives/    # Safe code that looks suspicious
│       ├── python.json
│       ├── javascript.json
│       ├── java.json
│       └── go.json
├── eval.py                # Evaluation script
└── results/               # Generated results (gitignored)
```

## Dataset

- **24 true positives**: code with confirmed vulnerabilities, labeled with CWE and severity
- **15 true negatives**: safe code that naive scanners might flag (parameterized queries, safe loaders, etc.)
- Covers: Python, JavaScript/TypeScript, Java, Go
- Derived from Mitig8it's existing regex and OpenGrep rule sets

## Running

```bash
# Install the SDK for the provider you are explicitly evaluating.
pip install anthropic openai

# Run against an Anthropic model
export ANTHROPIC_API_KEY=sk-...
python benchmarks/eval.py --provider anthropic --model <pinned-model-id> \
  --input-price <usd-per-million> --output-price <usd-per-million>

# Run against an OpenAI model
export OPENAI_API_KEY=sk-...
python benchmarks/eval.py --provider openai --model <pinned-model-id> \
  --reasoning-effort medium \
  --input-price <usd-per-million> --output-price <usd-per-million>

# Reuse an existing gitignored development key without sourcing the file as shell code.
python benchmarks/eval.py --provider openai --model <pinned-model-id> \
  --env-file benchmarks/remediation/.env --api-key-env REPAIR_LLM_API_KEY \
  --input-price <usd-per-million> --output-price <usd-per-million>

# Limit samples for quick test
python benchmarks/eval.py --provider openai --model <pinned-model-id> --samples 5 \
  --max-requests 5 --input-price <usd-per-million> --output-price <usd-per-million>
```

## Metrics

The eval script measures:
- **Precision**: of flagged code, how much is actually vulnerable
- **Recall**: of all vulnerabilities, how many were caught
- **F1 Score**: harmonic mean of precision and recall
- **Latency**: p50 and p95 response time per snippet
- **Cost**: total and per-scan API cost

Provider and parse failures stay in the planned-sample denominator and make the
command exit nonzero. Prices are required inputs rather than stale constants.
Reports record dataset and prompt digests, Wilson intervals, valid-response rate,
and limitations. This 42-case synthetic snippet set compares candidate models; it
does not establish production detector or recommendation accuracy. Run candidates
on the same pinned inputs, then promote only a model that meets the product's
quality, latency, and cost thresholds on independently reviewed holdout traffic.

## Adding samples

Add entries to the relevant JSON file under `benchmarks/dataset/true_positives/` or `benchmarks/dataset/true_negatives/`. Each entry needs:

```json
{
  "id": "tp-py-009",
  "rule_source": "which rule this tests",
  "language": "python",
  "cwe": "CWE-XXX",
  "owasp": "A03:2021",
  "severity": "high",
  "expected_verdict": "vulnerable",
  "description": "what the vulnerability is",
  "code": "the code snippet"
}
```

For true negatives, add a `why_safe` field explaining why the code is not vulnerable despite looking suspicious.
