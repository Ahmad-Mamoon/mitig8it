"""The release gate exercises real override protos, object MACs and driver behavior with fake cloud clients."""
from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from google.cloud import run_v2

from scripts import cloud_run_sandbox_release as release
from src.sandbox import job_entrypoint as entry
from tests.test_cloud_run_job_driver import FakeJobs, FakeStorage, IMAGE_DIGEST, responder, settings, task_result

NOW = datetime.now(timezone.utc)
SHA = "d" * 40
RUNTIME = "remediation@proj.iam.gserviceaccount.com"
JOB_ACCOUNT = "sandbox@proj.iam.gserviceaccount.com"
REPO = Path(__file__).resolve().parents[3]


def template() -> run_v2.TaskTemplate:
    return run_v2.TaskTemplate(
        service_account=JOB_ACCOUNT, max_retries=0, timeout=timedelta(seconds=600),
        execution_environment=run_v2.ExecutionEnvironment.EXECUTION_ENVIRONMENT_GEN2,
        containers=[run_v2.Container(image=IMAGE_DIGEST, command=release.COMMAND,
                                     resources=run_v2.ResourceRequirements(limits={"cpu": "1000m", "memory": "1Gi"}))],
        vpc_access=run_v2.VpcAccess(egress=run_v2.VpcAccess.VpcEgress.ALL_TRAFFIC,
                                    network_interfaces=[run_v2.VpcAccess.NetworkInterface(network="isolated", subnetwork="isolated")]),
    )


class Cloud:
    def __init__(self, *, mutate_document=None, wrong_nonce=False):
        self.storage = FakeStorage()
        self.job = run_v2.Job(
            name=settings().job_path, uid="job-uid", generation=1, observed_generation=1,
            terminal_condition=run_v2.Condition(state=run_v2.Condition.State.CONDITION_SUCCEEDED),
            template=run_v2.ExecutionTemplate(task_count=2, parallelism=2, template=template()),
        )
        self.reads = 0
        self.change_after_smoke = False
        self.cancelled = []
        self.execution_mutator = None

        def document(env, variant, execution):
            manifest = json.loads(env[entry.ENV_SNAPSHOT_MANIFEST])
            body = self.storage.objects[("snap", manifest[variant]["object"])]
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                source = archive.extractfile("smoke.py").read().decode()
            challenge = re.search(r"sandbox-release-smoke:([a-f0-9]{64})", source)[1]
            result = task_result(env, variant, execution, exit_code=0, output=f"sandbox-release-smoke:{challenge}\n")
            if mutate_document:
                mutate_document(result)
            return result

        self.jobs = FakeJobs(responder(self.storage, documents=document, nonce="f" * 64 if wrong_nonce else None))
        self.jobs.get_job = self.get_job

    def get_job(self, name):
        assert name == self.job.name
        self.reads += 1
        if self.change_after_smoke and self.reads > 1:
            self.job.generation += 1
            self.job.observed_generation = self.job.generation
        return self.job

    def get_execution(self, name):
        started = next(item for item in self.jobs.started if item["name"] == name)
        task = template()
        task.containers[0].env = [run_v2.EnvVar(name=key, value=value) for key, value in started["env"].items()]
        result = run_v2.Execution(name=name, task_count=2, succeeded_count=2, completion_time=NOW, template=task)
        if self.execution_mutator:
            self.execution_mutator(result)
        return result

    def cancel_execution(self, name):
        self.cancelled.append(name)

    def smoke(self):
        return release.live_smoke(settings(), SHA, RUNTIME, JOB_ACCOUNT,
                                  self.jobs, self, self.storage, now=NOW)

    def verify(self, receipt, **overrides):
        args = {"release_sha": SHA, "runtime_account": RUNTIME, "job_account": JOB_ACCOUNT, "now": NOW}
        args.update(overrides)
        return release.verify_receipt(receipt, settings(), jobs=self.jobs, executions=self, **args)


def test_live_smoke_uses_real_driver_transport_and_receipt_verifies_against_live_state():
    cloud = Cloud()
    receipt = cloud.smoke()
    cloud.verify(receipt)
    assert receipt["status"] == "passed" and receipt["image_digest"] == IMAGE_DIGEST
    assert receipt["runtime_service_account"] == RUNTIME and receipt["job_service_account"] == JOB_ACCOUNT
    assert len(cloud.jobs.started) == 1 and cloud.jobs.started[0]["task_count"] == 2
    assert receipt["execution"] == cloud.jobs.started[0]["name"]
    assert not any(bucket == "snap" for bucket, _ in cloud.storage.objects), "input snapshots must be cleaned up"
    assert entry.ENV_NONCE not in json.dumps(receipt), "do not retain the task result signing secret"


@pytest.mark.parametrize("image", ["registry/image:latest", "sha256:" + "a" * 64, "reg/img@sha256:" + "0" * 64, "reg/img@sha256:no"])
def test_mutable_partial_or_placeholder_images_cannot_pass_a_release_gate(image):
    with pytest.raises(release.SandboxReleaseError):
        release.validate_image(image)


@pytest.mark.parametrize("mutation", [
    lambda job: setattr(job.template, "task_count", 1),
    lambda job: setattr(job.template, "parallelism", 0),
    lambda job: setattr(job, "reconciling", True),
    lambda job: setattr(job, "observed_generation", 0),
    lambda job: setattr(job.template.template, "service_account", RUNTIME),
    lambda job: setattr(job.template.template, "max_retries", 1),
    lambda job: setattr(job.template.template, "timeout", timedelta(seconds=601)),
    lambda job: setattr(job.template.template, "execution_environment", 0),
    lambda job: setattr(job.template.template.containers[0], "image", "reg/img:latest"),
    lambda job: setattr(job.template.template.containers[0], "command", ["sh", "-c"]),
    lambda job: setattr(job.template.template.containers[0], "args", ["untrusted.py"]),
    lambda job: job.template.template.containers[0].resources.limits.update({"memory": "8Gi"}),
    lambda job: setattr(job.template.template.containers[0], "env", [run_v2.EnvVar(name="GOOGLE_APPLICATION_CREDENTIALS", value="secret")]),
    lambda job: setattr(job.template.template.vpc_access, "egress", run_v2.VpcAccess.VpcEgress.PRIVATE_RANGES_ONLY),
])
def test_unsafe_job_configuration_is_refused_before_a_smoke_execution_starts(mutation):
    cloud = Cloud()
    mutation(cloud.job)
    with pytest.raises(release.SandboxReleaseError):
        cloud.smoke()
    assert cloud.jobs.started == []


@pytest.mark.parametrize("mutation", [
    lambda result: result["runner"].update(network_namespace="unavailable"),
    lambda result: result["runner"].update(environment_kind="unknown"),
    lambda result: result["runner"].update(job_execution="another-execution"),
    lambda result: result["runner"].update(task_index=99),
    lambda result: result["probes"]["metadata"].update(reached=True),
    lambda result: result["probes"]["dns"].update(reached=None),
    lambda result: result["probes"]["internet"].update(endpoint="127.0.0.1:443"),
    lambda result: result.update(argv=["python3", "some-other-check.py"]),
    lambda result: result.update(output="stale fixture output\n"),
    lambda result: result.update(completed=False, reason_code="sandbox_network_namespace_unavailable"),
    lambda result: result.update(output_truncated=True),
])
def test_signed_but_wrong_or_unsafe_task_evidence_cannot_select_the_driver(mutation):
    with pytest.raises(release.SandboxReleaseError):
        Cloud(mutate_document=mutation).smoke()


def test_results_signed_with_another_executions_nonce_cannot_select_the_driver():
    with pytest.raises(release.SandboxReleaseError):
        Cloud(wrong_nonce=True).smoke()


def test_a_refused_timed_out_smoke_cancels_its_execution_and_removes_inputs(monkeypatch):
    cloud = Cloud()
    cloud.execution_mutator = lambda execution: setattr(execution, "completion_time", None)
    monkeypatch.setattr(release.ObservedDriver, "_await", lambda *args: False)
    with pytest.raises(release.SandboxReleaseError):
        cloud.smoke()
    assert cloud.cancelled == [cloud.jobs.started[0]["name"]]
    assert not any(bucket == "snap" for bucket, _ in cloud.storage.objects)


@pytest.mark.parametrize("mutation", [
    lambda execution: setattr(execution, "task_count", 1),
    lambda execution: setattr(execution, "succeeded_count", 1),
    lambda execution: setattr(execution, "retried_count", 1),
    lambda execution: setattr(execution.template.containers[0], "image", IMAGE_DIGEST.replace("a" * 64, "b" * 64)),
    lambda execution: setattr(execution.template, "service_account", RUNTIME),
])
def test_the_actual_immutable_execution_must_match_the_pinned_job_policy(mutation):
    cloud = Cloud()
    cloud.execution_mutator = mutation
    with pytest.raises(release.SandboxReleaseError):
        cloud.smoke()


def test_a_job_change_during_the_smoke_invalidates_its_result():
    cloud = Cloud()
    cloud.change_after_smoke = True
    with pytest.raises(release.SandboxReleaseError, match="changed while"):
        cloud.smoke()


def test_a_job_change_after_the_smoke_invalidates_the_deployment_receipt():
    cloud = Cloud()
    receipt = cloud.smoke()
    cloud.job.generation += 1
    cloud.job.observed_generation += 1
    with pytest.raises(release.SandboxReleaseError, match="changed after"):
        cloud.verify(receipt)


@pytest.mark.parametrize("age", [-1, 901])
def test_future_or_stale_receipts_cannot_authorize_a_deployment(age):
    cloud = Cloud()
    receipt = cloud.smoke()
    receipt["verified_at"] = (NOW - timedelta(seconds=age)).isoformat()
    with pytest.raises(release.SandboxReleaseError, match="stale or future"):
        cloud.verify(receipt)


@pytest.mark.parametrize("key,value", [
    ("release_sha", "e" * 40), ("image_digest", "reg/img@sha256:" + "e" * 64),
    ("snapshot_bucket", "another-snapshot-bucket"), ("result_bucket", "another-result-bucket"),
    ("runtime_service_account", JOB_ACCOUNT), ("job_service_account", RUNTIME),
    ("job_path", "another-job"), ("status", "inconclusive"),
])
def test_receipts_are_bound_to_the_exact_release_configuration(key, value):
    cloud = Cloud()
    receipt = cloud.smoke()
    receipt[key] = value
    with pytest.raises(release.SandboxReleaseError, match="does not bind"):
        cloud.verify(receipt)


def test_a_receipt_with_forged_namespace_evidence_is_refused_again_before_deployment():
    cloud = Cloud()
    receipt = cloud.smoke()
    receipt["documents"]["baseline"]["runner"]["network_namespace"] = "unavailable"
    with pytest.raises(release.SandboxReleaseError):
        cloud.verify(receipt)


@pytest.mark.parametrize("selected", ["local", "cloud_run_job"])
def test_routine_releases_preserve_the_explicitly_configured_live_driver(selected):
    service = run_v2.Service(template=run_v2.RevisionTemplate(
        containers=[run_v2.Container(env=[run_v2.EnvVar(name="SANDBOX_DRIVER", value=selected)])]))
    assert release.resolve_driver("preserve", service) == selected
    assert release.resolve_driver(selected) == selected


def test_first_deployment_or_missing_driver_requires_an_explicit_selection():
    for service in (None, run_v2.Service()):
        with pytest.raises(release.SandboxReleaseError):
            release.resolve_driver("preserve", service)


def test_cli_refuses_an_unpinned_image_without_using_cloud_credentials(capsys):
    assert release.main(["check-image", "registry/image:latest"]) == 1
    assert "digest-pinned" in capsys.readouterr().err


def test_deployment_workflow_cannot_bypass_live_smoke_or_receipt_verification():
    import yaml

    workflow = yaml.safe_load((REPO / ".github/workflows/deploy-remediation-cloudrun.yml").read_text())
    job = workflow["jobs"]["deploy"]
    steps = job["steps"]
    smoke = next(step for step in steps if step.get("id") == "sandbox-smoke")
    deploy = next(step for step in steps if step.get("id") == "deploy-service")
    assert steps.index(smoke) < steps.index(deploy)
    assert smoke["if"] == "env.SANDBOX_DRIVER == 'cloud_run_job'"
    assert "continue-on-error" not in smoke and "continue-on-error" not in deploy
    assert "cloud_run_sandbox_release.py smoke" in smoke["run"]
    assert deploy["run"].index("cloud_run_sandbox_release.py verify") < deploy["run"].index("gcloud run deploy")
    assert "--service-account" in deploy["run"] and "--runtime-service-account" in deploy["run"]
    assert "preserve" in job["env"]["SANDBOX_DRIVER_REQUEST"]
    assert job["environment"] and workflow["concurrency"]["cancel-in-progress"] is False
    for step in steps:
        if "run" in step:
            subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True, capture_output=True)


def test_terraform_supplies_override_permission_identity_delegation_and_two_bounded_tasks():
    source = (REPO / "infrastructure/remediation/terraform/cloud_run_job.tf").read_text()
    operator = source.split('resource "google_project_iam_custom_role" "sandbox_job_operator"', 1)[1].split('\n}', 1)[0]
    assert '"run.jobs.runWithOverrides"' in operator
    assert '"run.jobs.update"' not in operator and '"run.jobs.delete"' not in operator
    assert 'permissions = ["iam.serviceAccounts.getAccessToken"]' in source
    assert 'execution_environment = "EXECUTION_ENVIRONMENT_GEN2"' in source
    assert re.search(r"task_count\s*=\s*2", source) and re.search(r"parallelism\s*=\s*2", source)
    assert 'dns_name   = "googleapis.com."' in source
    assert 'name         = "*.googleapis.com."' in source
    assert 'destination_ranges = ["199.36.153.8/30"]' in source
