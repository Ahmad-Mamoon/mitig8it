# Rule publication criterion

Run `python -m benchmarks.rule_quality_gate` from the repository root (Python 3.11
and PyYAML), or `make bench-rule-quality`. The command exits 2 on failure. CI,
`make bench`, and the image release workflow enforce this check. The optional
`--output /tmp/rule-quality.json` writes the full machine-readable report.

Existing postable rules are recorded, by definition SHA-256, in
`legacy-posting.json`. This is a compatibility exception, explicitly reported as
`legacy_unvalidated`; it is not a precision claim. Do not extend that inventory to
approve a new or changed rule. Quarantined rules do not need promotion evidence
to continue running and being counted without publication.
Remove a legacy entry when its rule changes, is quarantined, or is removed; stale
entries fail the check. A later rollback or re-enabling must supply evidence too.

A new postable rule, changed legacy rule, or previously quarantined rule may
publish only when its exact definition digest has evidence in `evidence.json`
that meets every requirement below:

- A named frozen holdout corpus and a written sampling plan; training and
  validation observations cannot count toward promotion.
- At least 100 adjudicated predictions for that individual rule, with no
  unresolved judgments. Safe cases the rule does not flag do not enter a
  precision denominator.
- The lower endpoint of the two-sided 95% Wilson score interval for
  `true / (true + false)` is at least 0.95, using z = 1.959963984540054.
  The decision uses the unrounded bound. 100/100 passes (lower bound about
  0.9630); 99/100 fails (about 0.9455). A point precision of 0.95 alone cannot pass.
- Every observation identifies its source, reviewer, finding ID, and independent
  sampling unit. Finding IDs and sampling units must be unique within a rule's
  evaluation. Use one finding per independently sampled PR (or repository where
  PRs are correlated), not many copies of the same fixture or many findings from
  one PR. False and uncertain judgments must remain in the evidence.

Evidence shape (the example alone intentionally cannot pass):

```json
{
  "schema_version": "v1",
  "rules": {
    "example.rule": {
      "rule_digest": "<digest from load_rules() for the evaluated definition>",
      "corpus": "pinned-corpus-and-revision",
      "split": "holdout",
      "sampling_plan": "Frozen random PR sample, one finding per independent PR",
      "observations": [
        {
          "id": "stable-finding-fingerprint",
          "sampling_unit": "owner/repository/pull/123",
          "source": "pinned-source-or-review-record-reference",
          "reviewer": "independent-reviewer-id",
          "verdict": "true"
        }
      ]
    }
  }
}
```

Verdicts are `true`, `false`, or `uncertain`. Rule definitions include tier 1
matching options and exclusions, dependency patterns, tier 2 YAML definitions,
and the secret detector implementation. Formatting and posting/evidence prose
are excluded where possible; changing the shared secret implementation requires
revalidating both signals. Runtime matching code outside those definitions still
needs the existing detector, precision-regression, and integration tests.

The interval assumes representative independent observations and applies per
rule, not simultaneously across all rules. The checker rejects duplicate unit
identifiers, but cannot authenticate human judgments, prove corpus independence,
detect invented unit IDs, or prevent holdout reuse/cherry-picking. Reviewers must
audit the sampling plan and pinned sources and keep the holdout out of tuning.
This gate does not claim that the legacy inventory or authored regression
fixtures meet a production precision target.

The remediation release evaluator uses the same minimum of 100 holdout published
predictions and Wilson lower precision bound. An unsafe ready patch on a negative
or adversarial case counts as a false positive. All fixture results must be
present exactly once, and the manifest's holdout coverage floor also applies.
Existing corpus, external review signature, and production isolation requirements
still apply; the authored remediation seed remains non-promotable.

## Readiness, runtime admission, and audited shipping paths

`python -m benchmarks.production_readiness --output /tmp/readiness.json` emits a
machine-readable decision and exits 2 until the selected production component is
ready. `--component analysis` requires the promotion gate to pass, at least one
validated posting rule, and zero unvalidated legacy posting rules. Quarantined
rules are disabled and need not be promoted. The default `all` also requires
independent remediation release evidence. `--report-only` is for inspection;
`--compatibility` is restricted to staging and reports `production_ready: false`
even when compatibility admission passes.

The checked-in `services/analysis-service/src/publication-policy.json` is a
compiled allowlist, checked against the canonical evidence on every gate run.
After adding qualifying evidence or retiring legacy exceptions, regenerate it
with `python -m benchmarks.rule_quality_gate --refresh-runtime-policy`. Refresh
refuses if promotion evidence fails. Runtime code re-hashes each actual rule;
unknown IDs, changed definitions, invalid states, and missing IDs are withheld
even if somebody bypasses a normal workflow. A missing/stale allowlist that
approves no definitions prevents service startup. Tier 3 applies the same
admission before and after model triage, including caller-supplied findings.

Repair proposals remain available for development evaluation. Analysis responses
withhold candidate patches until release evidence exists. The API capability
policy disables fix publication and automatic generation for publication; feature
flags and development/static verification flags cannot override missing release
evidence. The GitHub service independently refuses fix-section publication and
suggestion blocks in generic review/comment transports. The Action skips repair
generation intended for publication and explains the withheld suggestions in its
review. Ordinary detection findings and remediation residual reports without
repair artifacts remain reportable.

| Path | Enforced decision |
| --- | --- |
| CI and `make bench-rule-quality` | Promotion evidence and exact packaged runtime allowlist; CI separately reports production readiness without claiming it passed. |
| Version/image release | Strict combined readiness before image push, tag changes, or GitHub release creation. |
| Analysis Cloud Run deployment | Strict analysis readiness for production; compatibility admission for staging. |
| Remediation Cloud Run deployment, including sandbox job image | Strict remediation readiness for production; compatibility admission for staging. |
| API, GitHub service, and Firebase deployments | Strict combined readiness for production; compatibility admission for staging. |
| Manual dispatch and reusable deployment workflows | Each leaf workflow invokes the local quality-readiness composite before cloud authentication and shipping. |
| Action source builds, local compose, and direct analysis calls | Packaged exact-definition runtime admission and independent publisher refusal still apply; a development build is not evidence of readiness. |
| LangSmith security-curation publisher | Publishes evaluation dataset examples only; it cannot approve a rule, enable repairs, publish product comments, or deploy a service. |

The Node services carry identical `quality-release.json` artifacts recording
`remediation_release_verified: false`. The readiness check rejects manual edits
that claim verification. No trust root or cryptographic review verifier is
configured, so no repair release can currently become production-ready. Enabling
that path requires implementing an audited verifier, binding approved evidence to
the evaluated engine/model/configuration and source revision, collecting the
required independently reviewed holdout corpus and production sandbox evidence,
and regenerating release artifacts through that verified process. A JSON flag,
reference fixture result, or provider self-assessment cannot substitute for it.

Remaining evidence work: independently adjudicate representative frozen holdout
samples for each posting rule (or quarantine/remove that rule), audit sampling
independence and provenance, supply the remediation manifest's full reviewed
corpus, configure approved review keys/signature verification, and record
production isolation and live-provider evaluation evidence. No external deployment
or evidence collection is performed by these offline checks.
