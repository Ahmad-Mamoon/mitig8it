"""Live release gate for the Cloud Run Jobs sandbox.

The smoke uses the deployed remediation identity and the real driver/object transport. A
receipt is an observation made by this trusted release process, not an independent platform
attestation. It is valid only for this commit, image, job generation, identities and buckets,
and is checked against live Cloud Run state immediately before deploying the service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.digests import digest_json  # noqa: E402
from src.sandbox import job_entrypoint as entry  # noqa: E402
from src.sandbox.cloud_run_job_driver import CloudRunJobDriver, CloudRunJobDriverConfig  # noqa: E402

RECEIPT_SCHEMA = "cloud-run-sandbox-release-v1"
MAX_RECEIPT_AGE_SECONDS = 900
COMMAND = ["python3", "-m", "src.sandbox.job_entrypoint"]
CHECK = {"check_id": "release-smoke", "kind": "behavior", "argv": ["python3", "smoke.py"], "timeout_seconds": 30}
OVERRIDE_NAMES = {
    entry.ENV_SNAPSHOT_BUCKET, entry.ENV_SNAPSHOT_MANIFEST, entry.ENV_RESULT_BUCKET,
    entry.ENV_RESULT_PREFIX, entry.ENV_CHECK, entry.ENV_NONCE, entry.ENV_CHECK_USER,
    entry.ENV_PROJECT, entry.ENV_REGION, entry.ENV_JOB,
}


class SandboxReleaseError(RuntimeError):
    pass


def require(condition: Any, message: str) -> None:
    if not condition:
        raise SandboxReleaseError(message)


def validate_image(image: str, *, allow_placeholder: bool = False) -> str:
    require(isinstance(image, str) and re.fullmatch(
        r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}", image
    ), "sandbox image must be a complete digest-pinned registry reference")
    require(allow_placeholder or not image.endswith("0" * 64), "the placeholder sandbox image cannot pass a release gate")
    return image


def validate_account(account: str) -> None:
    require(re.fullmatch(r"[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com", account),
            "an explicit Google service-account email is required")


def resolve_driver(requested: str, service: Any | None = None) -> str:
    require(requested in {"preserve", "local", "cloud_run_job"}, "unknown sandbox driver selection")
    if requested != "preserve":
        return requested
    require(service is not None and len(service.template.containers) == 1,
            "preserve requires an existing remediation service; select a driver explicitly for first deployment")
    configured = [item.value for item in service.template.containers[0].env if item.name == "SANDBOX_DRIVER"]
    require(len(configured) == 1 and configured[0] in {"local", "cloud_run_job"},
            "the existing service has no supported sandbox driver; select one explicitly")
    return configured[0]


def validate_template(template: Any, settings: CloudRunJobDriverConfig, job_account: str, *, execution: bool) -> None:
    from google.cloud import run_v2

    require(template.service_account == job_account, "sandbox job identity does not match the expected dedicated identity")
    require(template.max_retries == 0, "sandbox tasks must not retry")
    require(0 < template.timeout.total_seconds() <= 600, "sandbox task timeout must be bounded to 600 seconds")
    require(template.execution_environment == run_v2.ExecutionEnvironment.EXECUTION_ENVIRONMENT_GEN2,
            "sandbox tasks must explicitly use the second generation environment")
    require(not template.volumes and len(template.containers) == 1, "sandbox tasks must have one container and no mounted volumes")
    container = template.containers[0]
    require(container.image == settings.image_digest, "Cloud Run image differs from the pinned release image")
    require(list(container.command) == COMMAND and not container.args, "sandbox task entrypoint was changed")
    require(not container.volume_mounts, "sandbox task must not mount credentials or shared storage")
    require(container.resources.limits.get("cpu") in {"1", "1000m"}
            and container.resources.limits.get("memory") in {"1Gi", "1024Mi", "1073741824"},
            "sandbox resource limits must be 1 vCPU and 1 GiB")
    names = [item.name for item in container.env]
    require(len(names) == len(set(names)), "sandbox task environment contains duplicate names")
    require(set(names) == (OVERRIDE_NAMES if execution else set()), "sandbox task environment differs from the trusted overrides")
    require(not any(item.value_source.secret_key_ref.secret for item in container.env), "sandbox tasks must not mount secrets")
    vpc = template.vpc_access
    require(vpc.egress == run_v2.VpcAccess.VpcEgress.ALL_TRAFFIC and not vpc.connector
            and len(vpc.network_interfaces) == 1 and vpc.network_interfaces[0].network
            and vpc.network_interfaces[0].subnetwork,
            "sandbox job must use direct VPC egress for all traffic")


def job_stamp(job: Any, settings: CloudRunJobDriverConfig, job_account: str) -> dict[str, Any]:
    from google.cloud import run_v2

    require(job.name == settings.job_path and job.uid and job.generation > 0, "Cloud Run did not identify the expected sandbox job")
    require(not job.reconciling and job.observed_generation == job.generation
            and job.terminal_condition.state == run_v2.Condition.State.CONDITION_SUCCEEDED,
            "sandbox job configuration is not ready")
    require(job.template.task_count == 2 and job.template.parallelism == 2,
            "sandbox job must declare exactly two parallel variant tasks")
    validate_template(job.template.template, settings, job_account, execution=False)
    return {"uid": job.uid, "generation": job.generation,
            "template_digest": digest_json(run_v2.ExecutionTemplate.to_dict(job.template))}


def validate_execution(execution: Any, name: str, settings: CloudRunJobDriverConfig, job_account: str) -> None:
    require(name.startswith(f"{settings.job_path}/executions/") and execution.name == name,
            "smoke execution does not belong to the selected job")
    require(execution.task_count == 2 and execution.succeeded_count == 2
            and execution.failed_count == execution.cancelled_count == execution.retried_count == execution.running_count == 0
            and not execution.reconciling and execution.completion_time,
            "the two smoke tasks did not complete successfully without retries")
    # Unlike the job's mutable configured image, this is the immutable template that the
    # particular execution actually used. It also verifies the actual identity and limits.
    validate_template(execution.template, settings, job_account, execution=True)


def smoke_payload(challenge: str, image: str) -> tuple[dict[str, Any], str]:
    require(re.fullmatch(r"[0-9a-f]{64}", challenge), "invalid smoke challenge")
    output = f"sandbox-release-smoke:{challenge}\n"
    source = (
        "import os\n"
        "assert os.geteuid() == 65533 and os.getegid() == 65533\n"
        "assert not any(k.startswith(('SANDBOX_JOB_', 'GOOGLE_')) for k in os.environ)\n"
        f"print({output.rstrip()!r})\n"
    )
    core = {"schema_version": "v1", "snapshot": [{"path": "smoke.py", "content": source}], "patches": [],
            "request_nonce": challenge, "execution_policy": {"commands": [dict(CHECK)], "deadline_seconds": 300,
                                                            "image_digest": image}}
    return {**core, "request_digest": digest_json(core)}, f"sha256:{hashlib.sha256(output.encode()).hexdigest()}"


class ObservedDriver(CloudRunJobDriver):
    """Retains only the smoke's task documents after the real driver verifies their MACs."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.documents: dict[str, dict[str, Any]] = {}
        self.started_executions: list[str] = []

    def _start(self, *args: Any, **kwargs: Any) -> str:
        name = super()._start(*args, **kwargs)
        self.started_executions.append(name)
        return name

    def _collect(self, prefix: str, index: int, variant: str, nonce: str) -> dict[str, Any] | None:
        document = super()._collect(prefix, index, variant, nonce)
        if document is not None:
            self.documents[variant] = document
        return document


def validate_documents(documents: Any, execution: str, image: str, output_digest: str) -> None:
    require(isinstance(documents, dict) and set(documents) == set(entry.VARIANTS), "signed results from both smoke tasks are required")
    for index, variant in enumerate(entry.VARIANTS):
        document = documents[variant]
        require(isinstance(document, dict), "smoke task result is malformed")
        require(document.get("schema_version") == "v1" and document.get("variant") == variant
                and all(document.get(key) == CHECK[key] for key in ("check_id", "kind", "argv")),
                "smoke result does not bind the requested check and variant")
        require(document.get("completed") is True and type(document.get("exit_code")) is int and document["exit_code"] == 0
                and document.get("timed_out") is False and document.get("output_truncated") is False,
                "smoke command did not complete successfully")
        output = document.get("output")
        require(isinstance(output, str) and f"sha256:{hashlib.sha256(output.encode()).hexdigest()}" == output_digest,
                "smoke command did not return the current challenge")
        runner = document.get("runner", {})
        require(isinstance(runner, dict) and runner.get("job_execution") == execution
                and type(runner.get("task_index")) is int and runner["task_index"] == index
                and runner.get("image_digest") == image and runner.get("environment_kind") == entry.ENVIRONMENT_KIND
                and runner.get("network_namespace") == "applied", "smoke runner identity or namespace does not match")
        probes = document.get("probes")
        require(entry.probes_denied(probes), "smoke task did not explicitly deny all network probes")
        require(all(probes[probe["target"]].get("endpoint") == probe["endpoint"] for probe in entry.PROBES),
                "smoke probes measured unexpected targets")


def live_smoke(settings: CloudRunJobDriverConfig, release_sha: str, runtime_account: str, job_account: str,
               jobs: Any, executions: Any, storage: Any, *, now: datetime | None = None) -> dict[str, Any]:
    validate_image(settings.image_digest)
    validate_account(runtime_account)
    validate_account(job_account)
    require(runtime_account != job_account, "the sandbox job must not use the remediation identity")
    require(settings.snapshot_bucket != settings.result_bucket, "snapshot and result buckets must be separate")
    require(re.fullmatch(r"[0-9a-f]{40}", release_sha), "the release must name an exact Git commit")
    before = job_stamp(jobs.get_job(name=settings.job_path), settings, job_account)
    challenge = secrets.token_hex(32)
    payload, output_digest = smoke_payload(challenge, settings.image_digest)
    driver = ObservedDriver(settings, jobs_client=jobs, executions_client=executions, storage_client=storage)
    try:
        result = driver.execute(payload, 300)
        require(result.get("outcome") == "passed", "live sandbox smoke refused or failed; the driver cannot be selected")
        identity = driver.runner_identity(payload)
        names = identity.get("job_executions", [])
        require(len(names) == 1 and identity.get("network") == "deny", "smoke has no unique network-denied execution")
        name = names[0]
        validate_documents(driver.documents, name, settings.image_digest, output_digest)
        validate_execution(executions.get_execution(name=name), name, settings, job_account)
        require(job_stamp(jobs.get_job(name=settings.job_path), settings, job_account) == before,
                "sandbox job changed while the smoke ran")
        return {"schema_version": RECEIPT_SCHEMA, "status": "passed", "release_sha": release_sha,
                "verified_at": (now or datetime.now(timezone.utc)).isoformat(), "image_digest": settings.image_digest,
                "job_path": settings.job_path, "job_stamp": before, "runtime_service_account": runtime_account,
                "job_service_account": job_account, "snapshot_bucket": settings.snapshot_bucket,
                "result_bucket": settings.result_bucket, "execution": name, "challenge": challenge,
                "documents": driver.documents}
    finally:
        # The ordinary driver's in-flight map is cleared when execute returns. Retain names
        # here so a timed-out smoke cannot leave a task running after its release was refused.
        for name in driver.started_executions:
            try:
                current = executions.get_execution(name=name)
                if not current.completion_time:
                    executions.cancel_execution(name=name)
            except Exception:
                # The cancellation API may race a task completing, but cancellation must
                # still be attempted if the status lookup itself was unavailable.
                try:
                    executions.cancel_execution(name=name)
                except Exception:
                    pass
        # Signed result objects contain only this generated fixture and expire via lifecycle.
        driver.cancel(payload["request_digest"])


def verify_receipt(receipt: Any, settings: CloudRunJobDriverConfig, release_sha: str, runtime_account: str,
                   job_account: str, jobs: Any, executions: Any, *, now: datetime | None = None) -> None:
    validate_image(settings.image_digest)
    require(isinstance(receipt, dict), "sandbox smoke receipt must be an object")
    expected = {"schema_version": RECEIPT_SCHEMA, "status": "passed", "release_sha": release_sha,
                "image_digest": settings.image_digest, "job_path": settings.job_path,
                "runtime_service_account": runtime_account, "job_service_account": job_account,
                "snapshot_bucket": settings.snapshot_bucket, "result_bucket": settings.result_bucket}
    require(all(receipt.get(key) == value for key, value in expected.items()), "sandbox smoke receipt does not bind this release configuration")
    try:
        verified = datetime.fromisoformat(receipt["verified_at"])
        age = ((now or datetime.now(timezone.utc)) - verified).total_seconds()
    except (KeyError, TypeError, ValueError) as error:
        raise SandboxReleaseError("sandbox smoke receipt has no valid timestamp") from error
    require(0 <= age <= MAX_RECEIPT_AGE_SECONDS, "sandbox smoke receipt is stale or future-dated; run a fresh live smoke")
    _, output_digest = smoke_payload(receipt.get("challenge", ""), settings.image_digest)
    validate_documents(receipt.get("documents"), receipt.get("execution", ""), settings.image_digest, output_digest)
    validate_execution(executions.get_execution(name=receipt["execution"]), receipt["execution"], settings, job_account)
    require(job_stamp(jobs.get_job(name=settings.job_path), settings, job_account) == receipt.get("job_stamp"),
            "sandbox job changed after its release smoke")


def google_clients(region: str, project: str, runtime_account: str | None = None) -> tuple[Any, Any, Any]:
    import google.auth
    from google.auth import impersonated_credentials
    from google.api_core.client_options import ClientOptions
    from google.cloud import run_v2, storage

    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    if runtime_account:
        validate_account(runtime_account)
        credentials = impersonated_credentials.Credentials(
            source_credentials=credentials, target_principal=runtime_account,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"], lifetime=600,
        )
    options = ClientOptions(api_endpoint=f"{region}-run.googleapis.com")
    return (run_v2.JobsClient(credentials=credentials, client_options=options),
            run_v2.ExecutionsClient(credentials=credentials, client_options=options),
            storage.Client(project=project, credentials=credentials))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    image_parser = sub.add_parser("check-image")
    image_parser.add_argument("image")
    for command in ("smoke", "verify", "job-image", "resolve-driver"):
        child = sub.add_parser(command)
        child.add_argument("--project", required=True)
        child.add_argument("--region", required=True)
        if command == "resolve-driver":
            child.add_argument("--service", required=True)
            child.add_argument("--requested", choices=["preserve", "local", "cloud_run_job"], required=True)
            continue
        child.add_argument("--job", required=True)
        if command == "job-image":
            continue
        for name in ("image", "snapshot-bucket", "result-bucket", "runtime-service-account", "job-service-account", "release-sha", "receipt"):
            child.add_argument(f"--{name}", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "check-image":
            print(validate_image(args.image))
            return 0
        if args.command == "resolve-driver":
            service = None
            if args.requested == "preserve":
                from google.cloud import run_v2
                service = run_v2.ServicesClient().get_service(
                    name=f"projects/{args.project}/locations/{args.region}/services/{args.service}")
            print(resolve_driver(args.requested, service))
            return 0
        runtime = getattr(args, "runtime_service_account", None)
        jobs, executions, storage = google_clients(args.region, args.project, runtime)
        if args.command == "job-image":
            job = jobs.get_job(name=f"projects/{args.project}/locations/{args.region}/jobs/{args.job}")
            require(len(job.template.template.containers) == 1, "expected exactly one sandbox job container")
            print(validate_image(job.template.template.containers[0].image, allow_placeholder=True))
            return 0
        settings = CloudRunJobDriverConfig(job_name=args.job, project=args.project, region=args.region,
                                          snapshot_bucket=args.snapshot_bucket, result_bucket=args.result_bucket,
                                          image_digest=args.image)
        path = Path(args.receipt)
        if args.command == "smoke":
            require(not path.exists(), "a smoke receipt already exists; use a fresh output path")
            receipt = live_smoke(settings, args.release_sha, runtime, args.job_service_account, jobs, executions, storage)
            with path.open("x", encoding="utf-8") as handle:
                json.dump(receipt, handle, sort_keys=True, indent=2)
                handle.write("\n")
            print("Cloud Run sandbox release smoke passed")
        else:
            verify_receipt(json.loads(path.read_text(encoding="utf-8")), settings, args.release_sha, runtime,
                           args.job_service_account, jobs, executions)
            print("Fresh sandbox smoke receipt matches live job and release")
        return 0
    except SandboxReleaseError as error:
        print(f"Sandbox release gate refused: {error}", file=sys.stderr)
    except Exception as error:
        # Never print SDK credential material or raw result documents in a release log.
        print(f"Sandbox release gate could not verify live evidence ({type(error).__name__})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
