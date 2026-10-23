# External remediation release review

The standalone verifier is `python -m benchmarks.remediation.release_evidence`.
It authenticates external review evidence, **not production readiness**. It is not
yet connected to the release evaluator, packaged `quality-release.json` artifacts,
or deployment admission. Those gates stay closed; do not hand-edit a release flag.

## Owner/reviewer inputs

1. Appoint independent reviewers and approve their stable reviewer IDs and Ed25519
   public keys through a separately reviewed change to
   `benchmarks/remediation/release/trusted-keys.json`. Register `key_id`,
   `reviewer_id`, `algorithm: "ed25519"`, `status: "active"`, and the canonical base64
   encoding of the 32-byte raw public key as `public_key_base64`. Never put private
   keys in this repository, GitHub variables, receipts, or the evaluated service.
   The store is deliberately empty today. Revocation sets `status: "revoked"`;
   receipts signed by revoked keys fail, even before their expiry. Key rotations
   need a distinct key ID. Do not reuse one key under multiple reviewer IDs.
2. Independently review a frozen, representative corpus and its complete model
   evaluation. Statistical corpus/precision/coverage requirements remain in
   `benchmarks/remediation/release-manifest.json`; signatures cannot waive them.
   Audit sampling independence, held-out provenance, source/reference/check files,
   full result evidence, and actual live-provider/production-sandbox identities.
   A provider's declaration alone does not prove the model it used.
3. Pin the evaluated Git source SHA, provider/model version, non-secret effective
   configuration (including prompts, budgets, tools and policy), and the exact
   `registry/image@sha256:...` production sandbox image. Record secrets only by
   managed version identifier when needed, never by value. The current protocol
   requires `independent_sandbox`; `isolated_job`, development subprocess and static
   assertion results do not authenticate a production release.
4. Sign the complete receipt payload out of band with approved reviewer keys.
   The deployment job needs only public keys and signed evidence, **no signing
   secret**. Verify possession/ownership and independence of reviewers separately;
   cryptography authenticates an approved key, not a person's independence.

## Receipt protocol v1

Install the pinned quality-only dependency:

```sh
python -m pip install -r benchmarks/requirements-quality.txt
```

The JSON envelope has exactly `schema_version: "v1"`, `payload`, and `signatures`.
The payload contains exactly:

- `schema_version: "v1"`, `purpose: "mitig8it/remediation-release-evidence"`;
- all fields returned by `expected_bindings(...)`: current `source_revision`,
  `manifest_digest`, `fixtures_digest`, `results_digest`, `provider`, and `sandbox`;
- `issued_at` and `expires_at` as UTC `YYYY-MM-DDTHH:MM:SSZ`; the trust store caps
  both the validity interval and receipt age (currently seven days, never over 30);
- `reviews`: exactly one record for every current fixture, with `fixture_id`,
  authenticated `reviewer_id`, `verdict: "approved"`, `fixture_digest`, and
  `result_digest`. Compute individual digests with the module's `digest` function.

`fixture_inventory` hashes every fixture's metadata, source, reference repair,
and check file. The full result array is signed by digest, not a summary/count.
Changes to either inventory or any evidence/result field invalidate the receipt.
Reviewers sign the same complete payload; each signer must own at least one
fixture review. The configured minimum counts distinct authenticated reviewers.

Sign the exact bytes returned by `signing_bytes(payload)`: the UTF-8/ASCII domain
`mitig8it/remediation-release-evidence/v1` followed by one NUL byte, followed by
sorted-key, compact JSON with ASCII escapes and no NaN/infinity. Arrays retain
their order. This is the protocol's encoding, not a claim of RFC 8785 compliance.
Each signature record has exactly `algorithm: "ed25519"`, `key_id`, `reviewer_id`,
and `signature` (canonical base64 of the raw 64-byte Ed25519 signature). Embedded
public keys, unknown/revoked keys, duplicate key/signature/review IDs, malformed
JSON/base64, incomplete reviews and stale evidence are refused.

With a complete evaluation report and the independently recorded current identity:

```sh
python -m benchmarks.remediation.release_evidence \
  --receipt /path/to/external-review-receipt.json \
  --evaluation /path/to/full-evaluation.json \
  --identity /path/to/non-secret-evaluation-identity.json
```

The identity document contains exactly `provider_id`, `model_id`, `configuration`
(nonempty JSON object), and `sandbox_image_digest`. The CLI obtains the current
source SHA, manifest, corpus and checked-in trust policy itself. It refuses dirty
tracked engine/verifier/trust-policy files and untracked engine files; commit the evaluated implementation
before running an external review. Supply receipts out of band for that exact SHA;
do not create an extra evidence commit and pretend its SHA was evaluated. The
verifier never executes candidate code or calls a provider/cloud API.

Success returns an `external_review_authentication_only` receipt digest and
reviewer IDs. Failure exits 2. It does not return `passed`/`production_ready`, write
artifacts, deploy, or open any runtime publication gate.

## Remaining integration and deployment checklist

- Wire authenticated receipts into the release evaluator, recompute statistical
  gates from the same bound complete results, and independently verify the live
  production sandbox evidence/configuration. Reference/scripted/local evaluation
  cannot qualify. The authored seed still lacks the required release corpus.
- Generate packaged release admission artifacts only from that full verified
  decision; bind them to this source/model/config/sandbox identity and revalidate
  on every deployment. Reject manually edited booleans and stale receipts.
- Require production Environment approvals and protected release branches. The
  read-only GitHub audit on 2026-10-23 found `production` with no protection rules
  or branch policy and no environment-scoped variables/secrets; `staging` was
  absent. Approval settings are owner actions, not receipt signatures.
- Provision sandbox resources, dedicated identities/IAM, separate runtime DB
  credentials, and Secret Manager application-auth secrets using their existing
  runbooks. None is a substitute for cryptographic review or quality evidence.

No production keys, signatures, evidence approvals, or cloud changes are supplied
by this implementation. Tests generate private keys only in memory.
