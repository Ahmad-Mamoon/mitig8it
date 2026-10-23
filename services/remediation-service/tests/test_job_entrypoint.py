"""The program one Cloud Run job sandbox task runs, exercised with fakes for everything the
container supplies: the object downloader, the metadata and Admin API fetches, the probe
subprocess, and the check subprocess.

The two controls that need real kernel support are not asserted here; they are the parts the
runbook says are measured at deploy time by the smoke test. Task tests inject the namespace
verdict and a separate check identity, and replace ownership changes so they never change the
host's configuration. `execute_task` is given a recording check runner
while `run_check` is exercised directly with no pre-exec step.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import types

import pytest

from src.sandbox import job_entrypoint as entry

CHECK = {"check_id": "exploit", "kind": "exploit", "argv": [sys.executable, "-c", "print('ok')"], "timeout_seconds": 30}
NONCE = "n" * 64


def archive(files: dict[str, str]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as bundle:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(body.encode("utf-8"))
            info.mtime, info.mode, info.uid, info.gid = 0, 0o644, 0, 0
            bundle.addfile(info, io.BytesIO(body.encode("utf-8")))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as handle:
        handle.write(raw.getvalue())
    return out.getvalue()


def config(body: bytes, *, check=None, digest=None, user=None) -> dict:
    return {
        "variant": "candidate",
        "task_index": 1,
        "snapshot_bucket": "snap",
        "entry": {"object": "snapshots/x/candidate.tar.gz",
                  "sha256": digest or f"sha256:{hashlib.sha256(body).hexdigest()}"},
        "result_bucket": "res",
        "result_prefix": "snapshots/x/0",
        "check": check or CHECK,
        "nonce": NONCE,
        "check_user": user or "sandboxcheck",
        "project": "proj",
        "region": "us-central1",
        "job": "sandbox",
        "execution": "projects/proj/locations/us-central1/jobs/sandbox/executions/exec-1",
    }


def denied(argv):  # noqa: ARG001 - the probe subprocess is replaced wholesale.
    measured = {
        probe["target"]: {"reached": False, "detail": "TimeoutError", "endpoint": probe["endpoint"]}
        for probe in entry.PROBES
    }
    return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(measured), stderr="")


def digest_reader(digest="sha256:" + "a" * 64, error=None):
    return lambda project, region, job: (digest, error)


@pytest.fixture(autouse=True)
def use_an_isolated_fake_check_identity(monkeypatch):
    separate_user = types.SimpleNamespace(pw_uid=os.geteuid() + 1, pw_gid=os.getegid() + 1)

    def getpwnam(user):
        if user != "sandboxcheck":
            raise KeyError(user)
        return separate_user

    monkeypatch.setattr(entry.pwd, "getpwnam", getpwnam)
    monkeypatch.setattr(entry, "_chown_tree", lambda *args: None)


class RecordingCheckRunner:
    """Stands in for `run_check`, which needs privileges this test process does not have."""

    def __init__(self, result: dict | None = None):
        self.calls: list[tuple] = []
        self.result = result if result is not None else {
            "completed": True, "timed_out": False, "exit_code": 0, "output": "ok\n",
            "output_truncated": False, "duration_ms": 5,
        }

    def __call__(self, argv, workspace, timeout_seconds, preexec):
        self.calls.append((list(argv), workspace, timeout_seconds, preexec))
        return dict(self.result)


def run_task(tmp_path, body: bytes, **kwargs) -> dict:
    settings = kwargs.pop("config", None) or config(body)
    return entry.execute_task(
        settings,
        download=kwargs.pop("download", lambda bucket, name: body),
        workspace_root=str(tmp_path),
        isolate_network=kwargs.pop("isolate_network", True),
        image_digest_reader=kwargs.pop("image_digest_reader", digest_reader()),
        probe_runner=kwargs.pop("probe_runner", denied),
        check_runner=kwargs.pop("check_runner", RecordingCheckRunner()),
        **kwargs,
    )


def run_the_real_check(tmp_path, files: dict[str, str], argv: list[str], timeout_seconds: float = 30) -> dict:
    """`run_check` with no pre-exec step: the demotion it normally does needs root."""
    entry.extract_archive(archive(files), tmp_path / "repo")
    (tmp_path / "no-home").mkdir(exist_ok=True)
    return entry.run_check(argv, tmp_path, timeout_seconds, None)


# -- overrides -----------------------------------------------------------------------------


def test_every_missing_override_is_named():
    with pytest.raises(entry.JobConfigurationError) as failure:
        entry._config({entry.ENV_SNAPSHOT_BUCKET: "snap"})
    assert entry.ENV_NONCE in str(failure.value) and entry.ENV_CHECK in str(failure.value)


def environ(**overrides) -> dict[str, str]:
    base = {
        entry.ENV_SNAPSHOT_BUCKET: "snap",
        entry.ENV_SNAPSHOT_MANIFEST: json.dumps({"baseline": {"object": "b", "sha256": "sha256:0"},
                                                 "candidate": {"object": "c", "sha256": "sha256:1"}}),
        entry.ENV_RESULT_BUCKET: "res",
        entry.ENV_RESULT_PREFIX: "snapshots/x/0/",
        entry.ENV_CHECK: json.dumps(CHECK),
        entry.ENV_NONCE: NONCE,
        entry.ENV_TASK_INDEX: "1",
        entry.ENV_EXECUTION: "projects/p/locations/r/jobs/j/executions/exec-1",
    }
    base.update(overrides)
    return base


def test_the_task_index_chooses_the_variant():
    assert entry._config(environ(**{entry.ENV_TASK_INDEX: "0"}))["variant"] == "baseline"
    assert entry._config(environ())["variant"] == "candidate"


def test_a_task_index_that_names_no_variant_is_refused():
    with pytest.raises(entry.JobConfigurationError):
        entry._config(environ(**{entry.ENV_TASK_INDEX: "2"}))


def test_a_check_without_an_argv_is_refused():
    with pytest.raises(entry.JobConfigurationError):
        entry._config(environ(**{entry.ENV_CHECK: json.dumps({"check_id": "x", "argv": []})}))


def test_the_result_prefix_never_doubles_its_separator():
    assert entry._config(environ())["result_prefix"] == "snapshots/x/0"


def test_environment_kind_is_unknown_outside_a_cloud_run_job():
    assert entry.environment_kind({entry.ENV_EXECUTION: "exec-1"}) == "cloud-run-job"
    assert entry.environment_kind({}) == "unknown"


def test_main_refuses_to_run_without_overrides(capsys):
    assert entry.main({}) == 78
    assert "missing container overrides" in capsys.readouterr().err


# -- archive handling ----------------------------------------------------------------------


def test_the_archive_is_extracted_under_the_workspace(tmp_path):
    entry.extract_archive(archive({"src/db.ts": "x\n", "package.json": "{}\n"}), tmp_path / "repo")
    assert (tmp_path / "repo" / "src" / "db.ts").read_text() == "x\n"


@pytest.mark.parametrize("name", ["/etc/passwd", "../outside.ts", "a/../../outside.ts", "src\\db.ts"])
def test_an_archive_path_that_escapes_the_workspace_is_refused(tmp_path, name):
    with pytest.raises(ValueError):
        entry.extract_archive(archive({name: "x\n"}), tmp_path / "repo")


def test_an_archive_member_that_is_not_a_regular_file_is_refused(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as bundle:
        link = tarfile.TarInfo("evil")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        bundle.addfile(link)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as handle:
        handle.write(raw.getvalue())
    with pytest.raises(ValueError):
        entry.extract_archive(out.getvalue(), tmp_path / "repo")


def test_a_substituted_object_is_never_executed(tmp_path):
    body = archive({"src/db.ts": "x\n"})
    runner = RecordingCheckRunner()
    result = run_task(tmp_path, body, config=config(body, digest="sha256:" + "0" * 64), check_runner=runner)
    assert result["reason_code"] == "snapshot_digest_mismatch"
    assert result["completed"] is False and runner.calls == []


def test_an_undownloadable_object_becomes_evidence_rather_than_a_crash(tmp_path):
    def download(bucket, name):
        raise OSError("no such object")

    result = run_task(tmp_path, archive({"src/db.ts": "x\n"}), download=download)
    assert result["reason_code"] == "materializer_failed:OSError"
    assert result["completed"] is False


# -- the container's identity ----------------------------------------------------------------


def test_the_image_digest_is_read_from_the_admin_api():
    calls: list[str] = []

    def fetch(url, headers):
        calls.append(url)
        if url == entry.METADATA_TOKEN_URL:
            assert headers == {"Metadata-Flavor": "Google"}
            return json.dumps({"access_token": "tok"}).encode()
        assert headers == {"Authorization": "Bearer tok"}
        return json.dumps({"template": {"template": {"containers": [{"image": "reg/img@sha256:" + "a" * 64}]}}}).encode()

    digest, error = entry.read_image_digest("proj", "us-central1", "sandbox", fetch=fetch)
    assert digest == "reg/img@sha256:" + "a" * 64 and error is None
    assert calls[1] == "https://us-central1-run.googleapis.com/v2/projects/proj/locations/us-central1/jobs/sandbox"


def test_an_unreadable_image_digest_is_reported_and_never_invented():
    def fetch(url, headers):
        raise OSError("denied")

    assert entry.read_image_digest("p", "r", "j", fetch=fetch) == (None, "OSError")


def test_the_result_carries_the_execution_name_and_the_image_digest(tmp_path):
    result = run_task(tmp_path, archive({"src/db.ts": "x\n"}))
    assert result["runner"]["job_execution"].endswith("/executions/exec-1")
    assert result["runner"]["image_digest"] == "sha256:" + "a" * 64
    assert result["runner"]["task_index"] == 1


def test_a_digest_the_task_could_not_read_is_reported_as_absent(tmp_path):
    result = run_task(tmp_path, archive({"src/db.ts": "x\n"}), image_digest_reader=digest_reader(None, "OSError"))
    assert result["runner"]["image_digest"] is None
    assert result["runner"]["image_digest_error"] == "OSError"


def test_a_missing_check_user_stops_the_task_instead_of_running_as_the_credentialed_identity(tmp_path):
    body = archive({"src/db.ts": "x\n"})
    runner = RecordingCheckRunner()
    result = run_task(tmp_path, body, config=config(body, user="no-such-sandbox-user"), check_runner=runner)
    assert result["reason_code"].startswith("check_user_unavailable:")
    assert runner.calls == [], "the check must never run as the identity holding the nonce"
    assert all(probe["reached"] is None for probe in result["probes"].values())


@pytest.mark.parametrize("uid", [0, os.geteuid()])
def test_root_or_the_credentialed_identity_never_runs_repository_code(tmp_path, monkeypatch, uid):
    monkeypatch.setattr(entry.pwd, "getpwnam", lambda user: types.SimpleNamespace(pw_uid=uid, pw_gid=uid))
    runner = RecordingCheckRunner()
    result = run_task(tmp_path, archive({"x.txt": "x"}), check_runner=runner)
    assert result["reason_code"] == "check_user_unavailable:ValueError"
    assert result["completed"] is False and runner.calls == []


# -- probes --------------------------------------------------------------------------------


def test_probes_report_what_the_check_user_measured(tmp_path):
    result = run_task(tmp_path, archive({"src/db.ts": "x\n"}))
    assert sorted(result["probes"]) == ["dns", "internet", "metadata"]
    assert all(probe["reached"] is False for probe in result["probes"].values())


@pytest.mark.parametrize("target", ["metadata", "internet", "dns"])
def test_a_reached_probe_stops_repository_code_before_execution(tmp_path, target):
    def reached(argv):
        measured = {probe["target"]: {"reached": False, "detail": "x", "endpoint": ""} for probe in entry.PROBES}
        measured[target] = {"reached": True, "detail": "connected", "endpoint": "x"}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(measured), stderr="")

    runner = RecordingCheckRunner()
    result = run_task(tmp_path, archive({"src/db.ts": "x\n"}), probe_runner=reached, check_runner=runner)
    assert result["probes"][target]["reached"] is True
    assert result["reason_code"] == "sandbox_network_not_denied"
    assert result["completed"] is False and runner.calls == []


@pytest.mark.parametrize("measurement", [None, {}, {"reached": None}, {"reached": 0}, "false"])
def test_an_inconclusive_or_malformed_probe_never_runs_repository_code(tmp_path, measurement):
    def measured(argv):
        probes = json.loads(denied(argv).stdout)
        probes["dns"] = measurement
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(probes), stderr="")

    runner = RecordingCheckRunner()
    result = run_task(tmp_path, archive({"x.txt": "x"}), probe_runner=measured, check_runner=runner)
    assert result["reason_code"] == "sandbox_network_not_denied"
    assert result["completed"] is False and runner.calls == []


def test_an_unavailable_namespace_never_runs_probes_or_repository_code(tmp_path):
    runner = RecordingCheckRunner()

    def probe(argv):
        pytest.fail("no probe should run without the isolation control")

    result = run_task(tmp_path, archive({"x.txt": "x"}), isolate_network=False,
                      probe_runner=probe, check_runner=runner)
    assert result["runner"]["network_namespace"] == "unavailable"
    assert result["reason_code"] == "sandbox_network_namespace_unavailable"
    assert result["completed"] is False and runner.calls == []
    assert all(probe["reached"] is None for probe in result["probes"].values())


def test_the_namespace_preflight_uses_the_same_demotion_as_the_check(tmp_path, monkeypatch):
    tested = []
    monkeypatch.setattr(entry, "network_isolation_available", lambda preexec: tested.append(preexec) or True)
    runner = RecordingCheckRunner()
    run_task(tmp_path, archive({"x.txt": "x"}), isolate_network=None, check_runner=runner)
    assert len(tested) == 1 and tested[0] is runner.calls[0][3]


def test_a_probe_that_could_not_run_is_null_and_never_false():
    def explode(argv):
        raise OSError("no fork")

    measured = entry.run_probes(explode)
    assert all(probe["reached"] is None for probe in measured.values())
    assert all(probe["detail"] == "probe_failed:OSError" for probe in measured.values())


def test_unreadable_probe_output_is_null_for_every_target():
    measured = entry.run_probes(lambda argv: subprocess.CompletedProcess(argv, 0, stdout="not json", stderr=""))
    assert set(measured) == {"metadata", "internet", "dns"}
    assert all(probe["reached"] is None for probe in measured.values())


def test_a_failed_probe_process_cannot_report_denial_with_partial_output():
    def failed(argv):
        return subprocess.CompletedProcess(argv, 1, stdout=denied(argv).stdout, stderr="failed")

    assert all(probe["reached"] is None for probe in entry.run_probes(failed).values())


def test_a_target_the_probe_left_out_is_null_rather_than_absent():
    partial = {"metadata": {"reached": False, "detail": "TimeoutError", "endpoint": "x"}}
    measured = entry.run_probes(lambda argv: subprocess.CompletedProcess(argv, 0, stdout=json.dumps(partial), stderr=""))
    assert measured["metadata"]["reached"] is False
    assert measured["dns"] == {"reached": None, "detail": "probe_missing", "endpoint": None}


def test_the_probe_program_measures_the_three_documented_targets():
    assert [probe["endpoint"] for probe in entry.PROBES] == ["169.254.169.254:80", "1.1.1.1:443", "example.com"]
    assert entry.PROBE_TIMEOUT_SECONDS == 2


# -- running the check -----------------------------------------------------------------------


def test_the_task_hands_the_check_its_argv_timeout_and_a_demotion_step(tmp_path):
    body = archive({"src/db.ts": "x\n"})
    runner = RecordingCheckRunner()
    check = {**CHECK, "argv": ["node", "t.js"], "timeout_seconds": 45}
    result = run_task(tmp_path, body, config=config(body, check=check), check_runner=runner)
    argv, workspace, timeout_seconds, preexec = runner.calls[0]
    assert argv == ["node", "t.js"] and timeout_seconds == 45.0
    assert (workspace / "repo" / "src" / "db.ts").read_text() == "x\n"
    assert callable(preexec), "the check is always demoted to the separate user"
    assert result["completed"] is True and result["probes"]["dns"]["reached"] is False


def test_task_network_denial_does_not_break_the_trusted_result_transport_resolver(tmp_path, monkeypatch):
    real_path = entry.Path

    def path_without_global_resolver_access(path):
        assert str(path) != "/etc/resolv.conf", "the trusted task still needs DNS to upload its signed result"
        return real_path(path)

    monkeypatch.setattr(entry, "Path", path_without_global_resolver_access)
    result = run_task(tmp_path, archive({"x.txt": "x"}))
    assert result["completed"] is True
    assert result["runner"]["dns_resolution"] == "isolated_by_network_namespace"


def test_the_check_runs_in_the_extracted_tree_and_its_exit_code_is_data(tmp_path):
    result = run_the_real_check(
        tmp_path,
        {"probe.py": "import pathlib,sys; sys.exit(0 if pathlib.Path('probe.py').exists() else 3)\n"},
        [sys.executable, "probe.py"],
    )
    assert result["completed"] is True and result["exit_code"] == 0
    assert result["timed_out"] is False


def test_a_failing_check_is_evidence_and_not_an_infrastructure_failure(tmp_path):
    result = run_the_real_check(tmp_path, {"x.txt": "x"}, [sys.executable, "-c", "raise SystemExit(7)"])
    assert result["completed"] is True and result["exit_code"] == 7


def test_a_check_that_overruns_its_timeout_is_check_timed_out(tmp_path):
    result = run_the_real_check(tmp_path, {"x.txt": "x"}, [sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
    assert result["completed"] is False and result["timed_out"] is True
    assert result["reason_code"] == "check_timed_out" and result["exit_code"] is None


def test_a_check_that_cannot_be_executed_says_so(tmp_path):
    result = run_the_real_check(tmp_path, {"x.txt": "x"}, ["/nonexistent/binary"])
    assert result["reason_code"].startswith("check_not_executable:")
    assert result["completed"] is False


def test_a_namespace_failure_during_preexec_is_incomplete_evidence(tmp_path, monkeypatch):
    def fail_preexec(*args, **kwargs):
        raise subprocess.SubprocessError("Exception occurred in preexec_fn")

    monkeypatch.setattr(entry.subprocess, "run", fail_preexec)
    result = run_the_real_check(tmp_path, {"x.txt": "x"}, [sys.executable, "-c", "print('unsafe')"])
    assert result["reason_code"] == "check_not_executable:SubprocessError"
    assert result["completed"] is False and result["exit_code"] is None


def test_the_check_environment_is_built_and_never_inherited(tmp_path):
    env = entry.check_environment(tmp_path / "no-home")
    assert env["GCE_METADATA_HOST"] == entry.UNROUTABLE_METADATA_HOST
    assert env["GCE_METADATA_IP"] == entry.UNROUTABLE_METADATA_HOST
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env
    assert not any(name.startswith("SANDBOX_JOB_") for name in env)


def test_the_check_cannot_read_the_nonce_or_the_bucket_names(tmp_path, monkeypatch):
    monkeypatch.setenv(entry.ENV_NONCE, NONCE)
    monkeypatch.setenv(entry.ENV_SNAPSHOT_BUCKET, "snap")
    result = run_the_real_check(
        tmp_path, {"leak.py": "import json,os; print(json.dumps(dict(os.environ)))\n"}, [sys.executable, "leak.py"]
    )
    leaked = json.loads(result["output"])
    assert NONCE not in result["output"]
    assert not any(name.startswith("SANDBOX_JOB_") for name in leaked)
    assert leaked["GCE_METADATA_HOST"] == entry.UNROUTABLE_METADATA_HOST


def test_long_output_is_truncated_and_says_it_was(tmp_path):
    result = run_the_real_check(
        tmp_path, {"noisy.py": f"print('x' * {entry.MAX_CAPTURED_CHARS + 500})\n"}, [sys.executable, "noisy.py"]
    )
    assert result["output_truncated"] is True
    assert len(result["output"]) == entry.MAX_CAPTURED_CHARS


# -- the signed result ------------------------------------------------------------------------


def test_the_result_is_signed_with_the_execution_nonce():
    import hmac

    envelope = json.loads(entry.sign_result({"check_id": "exploit"}, NONCE))
    expected = hmac.new(NONCE.encode(), envelope["payload"].encode(), hashlib.sha256).hexdigest()
    assert envelope["signature"] == expected
    assert envelope["schema_version"] == entry.RESULT_SCHEMA_VERSION
    assert json.loads(envelope["payload"]) == {"check_id": "exploit"}


def test_signing_is_deterministic_regardless_of_key_order():
    assert entry.sign_result({"a": 1, "b": 2}, NONCE) == entry.sign_result({"b": 2, "a": 1}, NONCE)


def test_main_writes_one_signed_result_and_exits_zero_even_when_the_task_failed(tmp_path, monkeypatch):
    written: dict[tuple[str, str], bytes] = {}
    monkeypatch.setattr(entry, "download_object", lambda bucket, name: archive({"x.txt": "x"}))
    monkeypatch.setattr(entry, "upload_object", lambda bucket, name, body: written.__setitem__((bucket, name), body))
    monkeypatch.setattr(entry, "execute_task", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    assert entry.main(environ()) == 0

    (bucket, name), body = next(iter(written.items()))
    assert (bucket, name) == ("res", "snapshots/x/0/candidate.json")
    document = json.loads(json.loads(body)["payload"])
    assert document["reason_code"] == "job_entrypoint_failed:RuntimeError"
    assert document["completed"] is False and document["probes"] == {}


def test_main_uploads_the_result_the_driver_will_verify(tmp_path, monkeypatch):
    written: dict[tuple[str, str], bytes] = {}
    monkeypatch.setattr(entry, "download_object", lambda bucket, name: archive({"x.txt": "x"}))
    monkeypatch.setattr(entry, "upload_object", lambda bucket, name, body: written.__setitem__((bucket, name), body))
    monkeypatch.setattr(
        entry,
        "execute_task",
        lambda config, **kwargs: {"check_id": config["check"]["check_id"], "variant": config["variant"], "completed": True},
    )

    entry.main(environ())

    envelope = json.loads(written[("res", "snapshots/x/0/candidate.json")])
    document = json.loads(envelope["payload"])
    assert document["variant"] == "candidate" and document["check_id"] == "exploit"


# -- the controls this file cannot enforce ------------------------------------------------------


def test_the_namespace_probe_runs_in_a_throwaway_child_and_never_raises():
    """On a kernel that forbids unprivileged user namespaces this must be False, not an exception."""
    assert entry.network_isolation_available() in {True, False}
