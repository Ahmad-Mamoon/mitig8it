# Cloud Run Jobs sandbox runbook

The `isolated_job` verification level. It exists because the two levels either side of it are
not available to this deployment: `independent_sandbox` needs a GKE cluster with a gVisor node
pool that has never been applied, and `development_unverified` runs repository checks inside
the repair service's own container with no isolation of any kind. This level runs each half of
each check pair in its own Cloud Run job container, as an unprivileged user that holds none of
the job's credentials, on a network that the task's own probes measured as unreachable before
the check started.

Nothing here is applied automatically, and no step in this repository turns it on. The service
keeps running `SANDBOX_DRIVER=local` until an owner completes every step below in order.

Read [what this design cannot guarantee](#what-this-design-cannot-guarantee) before step 1. It
is the reason the level is called `isolated_job` and not `independent_sandbox`, and it is the
part an owner has to be able to repeat to whoever asks what the label means.

## The one thing step 4 might tell you

The control that denies the link-local metadata server at `169.254.169.254` is the private user
and network namespace the entrypoint creates. No VPC firewall rule reaches that address, and a
Cloud Run container holds neither `CAP_NET_ADMIN` nor `CAP_SYS_ADMIN`, so there is no second
mechanism behind it.

Whether an unprivileged user namespace can be created depends on the sandbox the platform runs
the container in, and that is not something this repository can assert from outside. It has been
observed unavailable under a restrictive seccomp profile: building the job image locally and
running one task body inside it reports `network_namespace: "unavailable"`. The task now
refuses the repository command before running probes or repository code, with
`sandbox_network_namespace_unavailable` and null probe measurements. A failed namespace
control never falls back to running the command on the container's original network.

So step 4 has two possible outcomes, and both are information:

* a completed smoke command with exit 0, probes all `false`, and `network_namespace: "applied"`:
  the level can be claimed, continue;
* an unavailable namespace or any probe `true` or `null`: stop at step 4. Do not flip the driver. The service keeps
  producing honest `development_unverified` evidence, which is what it produced before.

Running step 4 before step 5 exists precisely so this is discovered against a throwaway
execution rather than against every verification.

## Ordered owner steps

Every command names the project and region explicitly. Substitute the installation's own
values for `PROJECT`, `REGION`, `GAR_REPOSITORY`, and `ENVIRONMENT`; they are the same values
the deploy workflows read from `vars.GCP_PROJECT_ID`, `vars.GCP_REGION`, `vars.GAR_REPOSITORY`.

### 1. Apply the Terraform

```sh
cd infrastructure/remediation/terraform
```

Set these in the tfvars file, on top of the existing variables:

```hcl
enable_cloud_run_job_sandbox           = true
sandbox_bucket_prefix                 = "<globally unique prefix for this environment>"
sandbox_job_name                      = "codesentry-remediation-sandbox"
remediation_service_account_email     = "<the dedicated remediation runtime identity>"
sandbox_release_service_account_email = "<the deployment workflow identity>"
```

Both identities are required once the sandbox is enabled and must be different. The release
identity receives only `iam.serviceAccounts.getAccessToken` on this runtime identity so the
smoke exercises the runtime's actual authority. The workflow's deployment principal still
needs its existing image-push, job-update, service-deploy and service-account-use permissions.
The sandbox job has a third, separate identity that cannot access remediation credentials.

```sh
terraform init
terraform plan  -out=sandbox.tfplan
terraform apply sandbox.tfplan
```

The module needs Terraform >= 1.6. This apply creates:

* `<prefix>-snapshots` and `<prefix>-results`: two buckets, uniform access, public access
  prevention enforced, one-day lifecycle deletion, versioning off;
* `remediation-sandbox-<environment>`: the identity every sandbox task runs as. Its whole
  authority is `objectViewer` on the snapshots bucket, `objectCreator` on the results bucket,
  and `run.viewer` on this one job;
* `remediation-sandbox-<environment>`: a VPC and subnet with Private Google Access on, no Cloud
  NAT or peering, private DNS mapping `*.googleapis.com` to `private.googleapis.com`, a tcp/443
  egress allow rule for `199.36.153.8/30`, and deny-all egress at priority 65000. The default
  gateway route remains for Private Google Access; arbitrary VPC egress is blocked;
* the Cloud Run v2 job: two parallel tasks, 1 vCPU and 1 GiB per task, task timeout 600 s,
  `max_retries = 0`, explicit second generation environment, direct VPC egress with
  `ALL_TRAFFIC`, running as the sandbox identity;
* a custom role `remediation_sandbox_job_operator_<environment>` bound to the remediation
  service on this job: start, poll, and cancel executions, and nothing that can change the job's
  image or its service account. It includes `run.jobs.runWithOverrides`; `run.jobs.run` alone
  cannot launch the driver's environment and task-count overrides.

The job is created pointing at a placeholder digest and cannot run yet. That is expected.

Record the outputs; steps 3 and 5 need them.

```sh
terraform output -json sandbox_github_environment_variables
```

### 2. Build and push the first job image

The job image is built from the same `services/remediation-service/Dockerfile` as the service,
with `RUNTIME_UID=0`. The job entrypoint has to drop the repository's check to a *different*
unprivileged user (`sandboxcheck`, uid 65533, created in that Dockerfile), and only a process
that starts as root can change uid. Cloud Run offers no way to override a container's user, so
the difference lives in the image.

```sh
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

docker build \
  --build-arg RUNTIME_UID=0 \
  -f services/remediation-service/Dockerfile \
  -t "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)" \
  services/remediation-service

docker push "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)"
```

`.github/workflows/deploy-remediation-cloudrun.yml` builds this image on every release that
selects or preserves `cloud_run_job`. Bootstrap it once here to diagnose the platform before
requesting the first driver change.

### 3. Compute the digest and point the job at it

```sh
DIGEST=$(gcloud artifacts docker images describe \
  "${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job:$(git rev-parse --short HEAD)" \
  --project "${PROJECT}" --format='value(image_summary.digest)')

IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${GAR_REPOSITORY}/remediation-job@${DIGEST}"
echo "${IMAGE}"

gcloud run jobs update codesentry-remediation-sandbox \
  --image "${IMAGE}" \
  --region "${REGION}" --project "${PROJECT}"
```

`${IMAGE}` in full, registry path and all, is what `SANDBOX_IMAGE_DIGEST` must be set to. It is
not the bare `sha256:...`. The driver compares it, character for character, against the image
each task reads back from the Cloud Run Admin API, and returns `inconclusive` with
`sandbox_image_digest_mismatch` on any disagreement, including a task that could not read one.

Terraform ignores changes to the job's image on purpose (`ignore_changes` on the container
image), so a later `terraform plan` does not try to roll this back to the placeholder.

### 4. Run the live release smoke with the runtime identity

Install `services/remediation-service/requirements.txt` in a Python 3.12 virtual environment.
Authenticate Application Default Credentials as the release identity configured in step 1.
The following command impersonates the runtime identity with a short-lived token; it does
not pass the release identity's broader authority to the sandbox.

```sh
JOB=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_job_name)
SNAPSHOTS=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_snapshot_bucket)
RESULTS=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_result_bucket)
JOB_ACCOUNT=$(cd infrastructure/remediation/terraform && terraform output -raw sandbox_job_service_account)
RUNTIME_ACCOUNT='<remediation_service_account_email from step 1>'
WORK=$(mktemp -d)
python services/remediation-service/scripts/cloud_run_sandbox_release.py smoke \
  --project "$PROJECT" --region "$REGION" --job "$JOB" \
  --image "$IMAGE" --release-sha "$(git rev-parse HEAD)" \
  --snapshot-bucket "$SNAPSHOTS" --result-bucket "$RESULTS" \
  --runtime-service-account "$RUNTIME_ACCOUNT" --job-service-account "$JOB_ACCOUNT" \
  --receipt "$WORK/sandbox-release-receipt.json"
```

A `reached: true` means the network was not denied. A `reached: null` means the probe could not
run, which proves nothing and is refused exactly the same way. Either one stops the rollout
here: do not continue to step 5. `network_namespace: "unavailable"` means the kernel refused
the unprivileged user namespace and the task skipped the repository command. A reachable or
inconclusive probe also skips the command with `sandbox_network_not_denied`. Local regression
tests cover these refusals; they do not establish that the deployed Cloud Run kernel permits
the namespace or that the cloud smoke test passed.

The tool uses the real driver to package and digest-check a fresh generated fixture, launches
two tasks, checks each result MAC and its exact check/variant/execution/task binding, requires
the current challenge output from UID/GID 65533, and requires all three expected probe
endpoints to be denied. It checks the immutable execution's pinned image, identity, task
counts, limits, entrypoint and VPC settings, and refuses a job that changes during the smoke.
The tool attempts input deletion and cancellation of unfinished tasks; smoke result objects expire under the
one-day lifecycle. The receipt contains the generated fixture's results, never the MAC nonce.

### 5. Select the driver through the gated release workflow

Set every value from `sandbox_github_environment_variables` as a variable in the matching
GitHub `staging` or `production` environment. Also set its `GCP_PROJECT_ID`, `GCP_REGION`,
registry and deployment-auth variables. Use a separate Terraform installation, job, buckets
and identities for each environment. The workflow now selects that GitHub environment.

```sh
gh workflow run deploy-remediation-cloudrun.yml --ref main \
  -f environment=staging -f sandbox_driver=cloud_run_job
```

The release builds and pins its own image, runs a fresh live smoke, saves the receipt as a
30-day workflow artifact, then invokes the tool's `verify` command immediately before service
deployment. Verification requires a receipt no older than 15 minutes bound to this commit,
image, identities, buckets and unchanged job generation, and re-reads the immutable execution.
It deploys the service under the same runtime identity the smoke used. A refused smoke or
receipt check triggers restoration of the previous job image; a restoration error remains a
workflow failure. A prior manual receipt or
an environment flag cannot replace this live release check.

The input defaults to `preserve`: ordinary pushes retain the deployed driver and repeat the
live gate whenever it is `cloud_run_job`. First deployment needs an explicit driver because
there is no prior selection to preserve. Selecting `local` explicitly restores
`development_unverified` evidence. This workflow does not restrict an administrator making
out-of-band cloud changes; runtime per-task gates still refuse unsafe checks.

### 6. Confirm one real verification

Generate a fix on a test repository and read the evidence:

```
GET /api/remediations/:id/evidence
```

The `verification` record must carry `verification_level: "isolated_job"`, a `runner` with
`environment_kind: "cloud-run-job"`, `job_executions` naming each execution, and, on every
completed baseline and candidate result, `network_probes` with all three targets at
`reached: false`. The pull request comment reads "isolated sandbox (Cloud Run job, network
denied)". A run that instead comes back `inconclusive` with `sandbox_network_not_denied` or
`sandbox_image_digest_mismatch` is the driver refusing to claim the level, which is the
designed behaviour and not a bug to work around.

## Expected latency and cost

Order of magnitude only; measure the installation's own numbers before quoting any of this.

**Latency.** One check is one execution of two tasks running concurrently, so a check costs
container start plus the slower of its two variants. Cloud Run job task start is seconds, not
milliseconds: expect roughly 10-30 s before the check's first instruction, dominated by the
image pull on a cold start. Checks run one execution after another, so a verification with
three checks adds roughly 1-2 minutes of wall clock over the local driver, which has no start
cost at all. The driver allows a check its own timeout plus a 180 s start margin before it
calls the execution lost, and the job's own task timeout is 600 s.

**Cost.** A task is 1 vCPU and 1 GiB for its lifetime. At Cloud Run's per-second rates that is
on the order of $0.00003 per task-second, so a 60 s check pair is roughly half a US cent. A
verification of three checks is on the order of one to two cents; a month of a few hundred
verifications is single-digit dollars. The two buckets hold objects for at most a day and the
snapshot objects are deleted as each verification ends, so storage is rounding error. The
dominant cost of a repair remains the model call, not the sandbox.

No Cloud NAT is provisioned, which is both a control and the reason there is no per-GB egress
charge to account for.

## What this design cannot guarantee

Stated plainly, because the verification level's whole value is that it claims only what it
measured.

1. **The probes are one measurement at one moment, from one process.** They run from the
   check's own user, in the check's own isolation context, immediately before the check starts.
   They do not prove the network stayed unreachable for the check's whole lifetime, and they do
   not enumerate every address a check might try. A control that failed open after the probe
   ran would not be caught.
2. **There is no read-only root filesystem.** A Cloud Run container has a writable overlay. The
   check can write anywhere its user can write, including over the interpreters on `PATH`,
   inside its own task. This is one of the two reasons the level is not `independent_sandbox`,
   and `runner.read_only_root` is reported as `false` rather than omitted.
3. **There is no gVisor runtime class.** The isolation boundary is the ordinary container
   boundary Cloud Run provides, not a user-space kernel. A container escape is a container
   escape.
4. **The unprivileged user namespace may not be available, and it is the only thing denying the
   metadata server.** The entrypoint tests the check user's exact demotion and namespace step
   in a throwaway child and reports `network_namespace: "applied"` or `"unavailable"`.
   An unavailable namespace stops the task before it runs any repository command. Every
   required probe must then complete and explicitly report `false` before the command can
   start. The command repeats the demotion and namespace step in its own pre-exec hook; a
   failure there also prevents execution. The driver rejects completed evidence without the
   namespace control even if its probes say `false`. See
   [The one thing step 4 might tell you](#the-one-thing-step-4-might-tell-you).
5. **The entrypoint runs as root inside the job container.** It has to, in order to drop the
   check to a different user. It never executes repository content, and the check runs as
   `sandboxcheck`, which holds none of the task's credentials and cannot read the entrypoint's
   environment. But root in that container is real, and a defect in the entrypoint itself is not
   contained by any of the controls above. A configured check user with UID 0 or the
   entrypoint's own UID is refused before any repository command runs.
6. **There is no broker trust boundary.** The deployed shape is `SANDBOX_BROKER_MODE=inprocess`:
   the evidence is assembled in the repair service's own process, and there is no attestation
   between that process and the control plane. This level improves where the *check* runs. It
   does not add the separate, attested broker the production design calls for.
7. **The image digest check trusts the Cloud Run Admin API, not the running kernel.** Each task
   reads the job's configured image with its own credentials and reports it; the driver compares
   that against the pinned digest. That establishes the job was configured to run that image. It
   is not an attestation of the bytes that were actually executed. The release gate also checks
   the immutable execution template's pinned image; that is still an API assertion rather than
   a kernel attestation.
8. **The HMAC nonce proves origin, not correctness.** A result that verifies against the nonce
   came from a task this driver started with this nonce. It does not make the task's own
   measurements true, which is why the driver independently checks the check id, the variant,
   the image digest, and every probe before it accepts anything.
9. **None of this satisfies the production isolation gate.** `SANDBOX_NETWORK_POLICY_ATTESTED`
   and `SANDBOX_NODE_LIMITS_ATTESTED` are about the Kubernetes/gVisor broker and stay `false`.
   Nothing in this runbook is evidence for setting either of them.

## Failure modes and what they mean

| What you see | What it means | What to do |
| --- | --- | --- |
| `sandbox_network_namespace_unavailable` on a variant | The check user's namespace preflight failed. No repository command was executed | Stop rollout and investigate platform support for unprivileged user/network namespaces. Local tests cannot clear this deployment gate |
| `inconclusive` / `sandbox_network_not_denied` | A required probe reached its target or could not complete, so the task skipped the repository command; the driver also rejects completed evidence without the namespace control | Stop rollout and re-run step 4. Inspect the task's namespace result and probe details |
| `inconclusive` / `sandbox_image_digest_mismatch` | A task reported an image other than `SANDBOX_IMAGE_DIGEST`, or could not read one | A deploy updated the job without updating the service's env var, or the job identity lost `run.viewer` on the job. Re-run step 3 |
| `sandbox_result_unavailable` on every variant | No signed result object was readable | Check the job identity still holds `objectCreator` on the results bucket and the remediation identity still holds `objectViewer`. Read the execution's logs |
| `check_user_unavailable:KeyError` | The image has no `sandboxcheck` user | The job image was built from an older Dockerfile. Re-run steps 2 and 3 |
| `check_user_unavailable:ValueError` | The configured check user is root or shares the entrypoint's UID. No repository command was executed | Restore the separate non-root `sandboxcheck` user |
| `check_deadline_exceeded` | The execution did not finish inside the check's budget plus the 180 s start margin | Usually a cold start behind an image pull. If it repeats, the check's own `timeout_seconds` is too small for a container-start-bound sandbox |
| `sandbox_execution_failed` | The driver itself raised | Configuration: a missing `SANDBOX_JOB_*` variable, or the remediation identity lacking the custom operator role. The service logs name which |

## Related

* [Remediation operations runbook](remediation.md) for the rest of the deployment.
* `services/remediation-service/contracts/sandbox-broker-v1.md` for the driver's evidence shape.
* `services/remediation-service/contracts/repair-v1.md` for what each verification level means
  to a consumer of the repair API.
