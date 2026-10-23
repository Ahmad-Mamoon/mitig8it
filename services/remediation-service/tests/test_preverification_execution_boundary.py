"""Proposal construction may parse untrusted code, but only the broker may execute it."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from src import patches
from src.agent import ProviderAction, RepairAgent
from src.engine import RepairEngine
from src.models import RepairRequest
from src.retrieval import Snapshot
from src.verification import VerificationResult, Verifier
from src.sandbox import InProcessSandboxBroker, LocalSubprocessDriver, validate_sandbox_configuration
from src.sandbox.drivers import DriverSelectionError, build_driver
from tests.conftest import MODEL_ONLY_REPAIRED, regression_test_spec, whole_file_change
from tests.test_agent_budget import SettlingCheckpointStore
from tests.test_engine import PassingBroker, ScriptedProvider, _ready_engine
from tests.test_per_finding_candidates import (
    EXEC_HUNK, FINDINGS, IMPORT_HUNK, SQL_HUNK, TAR_HUNK, _propose, _repair, _request,
)


@pytest.fixture(autouse=True)
def forbid_host_module_execution(monkeypatch):
    """Fail at either the loader or subprocess boundary, while exercising real syntax checks."""
    real_run = patches.subprocess.run

    def refuse_load(*args, **kwargs):
        pytest.fail("untrusted module loading escaped the configured verifier sandbox")

    def parse_only(argv, *args, **kwargs):
        command = list(argv)
        node = Path(command[0]).name == "node"
        allowed = (
            node and len(command) > 1 and command[1] == "--check"
            or node and "-e" in command and command[command.index("-e") + 1] == patches.TYPESCRIPT_SYNTAX_PROGRAM
            or not node and command[1:3] == ["-m", "py_compile"]
        )
        assert allowed, f"host subprocess attempted to execute untrusted code: {command[:3]}"
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(patches, "_load_checks", refuse_load)
    monkeypatch.setattr(patches, "_load_module", refuse_load)
    monkeypatch.setattr(patches.subprocess, "run", parse_only)


class RecordingBroker(PassingBroker):
    def __init__(self):
        self.calls = []

    async def verify(self, payload, timeout_seconds):
        self.calls.append(payload)
        return await super().verify(payload, timeout_seconds)


class Checkpoints(SettlingCheckpointStore):
    def __init__(self, checkpoint):
        super().__init__()
        self.checkpoint = checkpoint

    async def load(self):
        return self.checkpoint


def proposal(source):
    return {
        "hypothesis": "Untrusted input reaches SQL.",
        "intended_behavior": "Preserve legitimate user lookup.",
        "assumptions": ["pg positional parameters are supported"],
        "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": len(source.splitlines())}],
        "changes": [whole_file_change("src/db.ts", source, MODEL_ONLY_REPAIRED)],
        "regression_tests": [regression_test_spec()],
    }


@pytest.mark.asyncio
async def test_template_path_reaches_sandbox_without_host_module_execution(request_payload, source):
    response = await _ready_engine(request_payload, source)
    assert response.state == "ready"
    assert response.candidates[0].preview["evidence"]["candidate_source"] == "template"


@pytest.mark.asyncio
async def test_agent_proposal_reaches_sandbox_with_exact_patch_and_generated_test(model_only_payload, model_only_source):
    request = RepairRequest.model_validate(model_only_payload)
    broker = RecordingBroker()
    provider = ScriptedProvider([ProviderAction("propose_patch", proposal(model_only_source)), ProviderAction("request_verification", {})])
    agent = RepairAgent(provider, Verifier(broker))
    response = await RepairEngine(lambda prepared: agent).repair(request)
    assert response.state == "ready", response.reason
    assert broker.calls, "a ready repair still requires the configured verifier sandbox"
    payload = broker.calls[0]
    assert payload["patches"][0]["replacement_content"] == MODEL_ONLY_REPAIRED
    assert any(item["path"].startswith(".mitig8it/regression/") for item in payload["snapshot"])
    assert response.candidates[0].preview["evidence"]["candidate_source"] == "model"


@pytest.mark.asyncio
@pytest.mark.parametrize("restore_best", [False, True])
async def test_resumed_current_and_best_proposals_never_load_on_host(model_only_payload, model_only_source, restore_best):
    request = RepairRequest.model_validate(model_only_payload)
    snapshot = Snapshot(request)
    arguments = proposal(model_only_source)
    checkpoint = {"context_manifest_digest": snapshot.manifest_digest, "proposal_arguments": arguments}
    if restore_best:
        checkpoint["coverage"] = {"best": {
            "proposal_arguments": arguments,
            "verification": asdict(VerificationResult("passed", {}, "sha256:" + "1" * 64,
                                                       verification_level="independent_sandbox", proven_finding_ids=["finding-1"])),
        }}
    broker = RecordingBroker()
    agent = RepairAgent(ScriptedProvider([ProviderAction("request_verification", {})]), Verifier(broker),
                        Checkpoints(checkpoint))
    result = await agent.run(request, snapshot)
    assert result.state == "ready", result.explanation
    assert broker.calls


@pytest.mark.asyncio
async def test_per_finding_split_and_combined_tree_reach_sandbox_without_host_loads(request_payload):
    request = _request(request_payload)
    broker = RecordingBroker()
    response = await _repair(request, [
        _propose([IMPORT_HUNK, SQL_HUNK, EXEC_HUNK, TAR_HUNK], [finding["snapshot_id"] for finding in FINDINGS]),
        ProviderAction("request_verification", {}),
    ], broker)
    assert response.state == "ready", response.reason
    assert len(response.candidates) == 3
    assert len(broker.calls) >= 4, "split candidates must retain their sandbox verification"


@pytest.mark.parametrize("replacement,reason", [
    ("export function loadUser( {", "candidate_syntax_invalid:"),
    ("export function loadUser(db, id) { return missingQueryHelper(id); }\n", "undefined_name:missingQueryHelper"),
])
def test_static_syntax_and_name_rejections_survive_host_execution_refusal(request_payload, source, replacement, reason):
    request = RepairRequest.model_validate(request_payload)
    with pytest.raises(patches.PatchPolicyError) as failure:
        patches.build_patch_bundle(request, Snapshot(request),
                                   [whole_file_change("src/db.ts", source, replacement)], load_checks=False)
    assert failure.value.code.startswith(reason)


@pytest.mark.asyncio
async def test_disallowed_development_verification_calls_neither_broker_nor_driver(request_payload, source):
    request = RepairRequest.model_validate(request_payload)
    assert request.policy.allow_development_verification is False
    snapshot = Snapshot(request)
    replacement = source.replace("${id}", "$1")
    bundle = patches.build_patch_bundle(request, snapshot, [whole_file_change("src/db.ts", source, replacement)],
                                        [regression_test_spec()])

    class Driver:
        verification_level = "development_unverified"
        calls = 0

        def execute(self, *args):
            self.calls += 1
            pytest.fail("the policy-prohibited driver must never execute")

    class Broker(InProcessSandboxBroker):
        calls = 0

        async def verify(self, *args):
            self.calls += 1
            pytest.fail("the policy-prohibited broker must never be invoked")

    driver = Driver()
    broker = Broker(driver)
    result = await Verifier(broker).verify(request, snapshot, bundle)
    assert result.status == "unsupported" and result.reason_code == "development_verification_not_permitted"
    assert broker.calls == driver.calls == 0


@pytest.mark.parametrize("marker", ["DEPLOY_ENVIRONMENT", "ENVIRONMENT", "NODE_ENV"])
def test_production_refuses_local_driver_before_creating_a_workspace(monkeypatch, tmp_path, marker):
    monkeypatch.setenv(marker, "production")
    workspace = tmp_path / "must-not-be-created"
    with pytest.raises(DriverSelectionError, match="prohibited in production"):
        LocalSubprocessDriver(str(workspace))
    with pytest.raises(DriverSelectionError, match="prohibited in production"):
        build_driver("local")
    assert not workspace.exists()


def test_production_api_startup_refuses_local_driver_before_backend_or_worker(monkeypatch):
    from fastapi.testclient import TestClient
    from src import main

    monkeypatch.setenv("DEPLOY_ENVIRONMENT", "production")
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "local")
    monkeypatch.setattr(main, "get_execution_backend", lambda: pytest.fail("startup must stop before opening the backend"))
    with pytest.raises(DriverSelectionError, match="prohibited in production"):
        with TestClient(main.app):
            pytest.fail("an unsafe production configuration must not start serving")


@pytest.mark.asyncio
async def test_production_worker_startup_refuses_local_driver_before_claiming_jobs(monkeypatch):
    from src import worker

    monkeypatch.setenv("DEPLOY_ENVIRONMENT", "production")
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "local")
    monkeypatch.setattr(worker, "create_execution_backend", lambda: pytest.fail("startup must stop before reading jobs"))
    with pytest.raises(DriverSelectionError, match="prohibited in production"):
        await worker.main()


def test_production_startup_accepts_cloud_job_configuration_without_constructing_clients(monkeypatch):
    monkeypatch.setenv("DEPLOY_ENVIRONMENT", "production")
    monkeypatch.setenv("SANDBOX_BROKER_MODE", "inprocess")
    monkeypatch.setenv("SANDBOX_DRIVER", "cloud_run_job")
    validate_sandbox_configuration()
