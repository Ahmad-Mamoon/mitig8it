# Internal gRPC authentication

The API, GitHub service, and analysis service enforce the same shared-secret contract
over gRPC as over HTTP. Every application call carries exactly one `x-internal-secret`
metadata value. A missing or incorrect value returns `UNAUTHENTICATED` before GitHub
operations or analysis functions run. An unconfigured server returns `UNAVAILABLE`;
an unconfigured API client rejects before sending the request. Secrets must use printable
ASCII characters for gRPC metadata; the API rejects invalid values with a generic error
that does not include the credential. Secrets never enter the correlation context or
authentication error response.

| Boundary | API credential | Server credential |
|---|---|---|
| GitHub | `GITHUB_SERVICE_INTERNAL_SECRET` | `GITHUB_SERVICE_INTERNAL_SECRET` |
| Analysis | `ANALYSIS_SERVICE_INTERNAL_SECRET`, falling back to `GITHUB_SERVICE_INTERNAL_SECRET` | Same precedence |

Cloud Run IAM is an additional check. The API continues to send its audience-bound
identity token in `x-serverless-authorization` on TLS channels. An identity token alone
does not authorize an application call. Keep the GitHub and analysis services deployed
with `--no-allow-unauthenticated` and grant invoker access only to intended callers.
The containers' plaintext HTTP/2 listeners are intended for Cloud Run TLS termination
or isolated local development. Do not expose those ports directly on a public network.

Only `/grpc.health.v1.Health/Check` accepts requests without the application secret,
because Cloud Run's startup and liveness probes cannot attach it. This probe reports
process health; it does not prove that credentials or GitHub/analysis dependencies work.
The application `HealthCheck` methods require authentication.

## Deployment, smoke, and rollback

`deploy-production.yml` and `deploy-staging.yml` enforce the compatibility order: the
API client revision deploys first, GitHub and analysis servers deploy second, and the
reusable `smoke-internal-grpc.yml` runs before the frontend. All three services and the
smoke load `codesentry-internal-secret` (or its `-staging` variant) from Secret Manager.
There is no Actions-secret copy.

The smoke calls the API's protected `GET /internal/dependencies` endpoint. The API then
invokes each service's authenticated application `HealthCheck`, so this proves the
shared secret, Cloud Run identity path, gRPC transport, and both deployed dependencies;
the standard unauthenticated process probe alone does not prove any of those things.

For initial rollout, deploy the API client before the enforcing servers. For rollback,
roll back the receiving services before rolling the API back to a revision that omits
the metadata. Rotation still requires an ordered deployment because each participant
accepts one active value; rotating only one participant interrupts calls. Do not print
the value or place it in shell history.

Current live-state warning (read-only inspection, 2026-10-20): production still mounts
the previous internal value as a plain Cloud Run environment variable and does not yet
have `codesentry-internal-secret` in Secret Manager. Apply the owner steps in the
production-readiness runbook before running the new ordered workflow.

## Local verification

These tests use loopback gRPC listeners and mock the GitHub/analysis operations, so they
exercise the actual transport without needing production credentials or making GitHub
writes. They run as part of the existing CI test jobs.

```bash
cd services/api-service
npm test -- --runInBand tests/grpcInternalAuth.test.js tests/grpcMetadataToken.test.js
```

```bash
cd services/github-service
npm test -- --runInBand src/__tests__/grpcInternalAuth.test.js
```

```bash
cd services/analysis-service/src
python -m pip install -r requirements-test.txt
python -m pytest tests/test_grpc_internal_auth.py tests/test_grpc_contracts.py -q
```

Wire tests cover every application method, incorrect and duplicate credentials,
unconfigured secrets, analysis credential precedence/fallback, correlation metadata,
and the unauthenticated standard health probe. They establish application behavior;
live IAM, TLS termination, and the deployed secret values need the rollout checks above.
