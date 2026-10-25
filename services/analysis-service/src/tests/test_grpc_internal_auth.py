from unittest.mock import Mock

import grpc
import pytest
from grpc_health.v1 import health_pb2, health_pb2_grpc

import analysis_grpc_server as server_module
from analysis_grpc_server import analysis_pb2, analysis_pb2_grpc, common_pb2
import request_context


SECRET = "grpc-internal-test-secret"
RPCS = ["AnalyzePullRequest", "AnalyzeTier1", "AnalyzeTier2", "TriageFindings", "HealthCheck"]


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("ANALYSIS_SERVICE_INTERNAL_SECRET", SECRET)
    monkeypatch.delenv("GITHUB_SERVICE_INTERNAL_SECRET", raising=False)
    operation = Mock(return_value={"findings": []})
    for name in ["analyze_pull_request_payload", "analyze_tier1_payload",
                 "analyze_tier2_payload", "triage_findings_payload"]:
        monkeypatch.setattr(server_module, name, operation)
    instance = server_module.create_server()
    port = instance.add_insecure_port("127.0.0.1:0")
    instance.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    grpc.channel_ready_future(channel).result(timeout=3)
    yield analysis_pb2_grpc.AnalysisServiceStub(channel), channel, operation
    channel.close()
    instance.stop(0).wait(timeout=3)


def call(stub, method="AnalyzeTier1", metadata=()):
    if method == "HealthCheck":
        request = common_pb2.HealthCheckRequest()
    elif method == "TriageFindings":
        request = analysis_pb2.TriageFindingsRequest(
            repository_full_name="owner/repo", commit_sha="a" * 40
        )
    else:
        request = analysis_pb2.AnalyzePullRequestRequest(
            repository_full_name="owner/repo", commit_sha="a" * 40
        )
    return getattr(stub, method)(request, metadata=metadata, timeout=3)


@pytest.mark.parametrize("method", RPCS)
def test_every_application_rpc_requires_internal_auth(server, method):
    stub, _, operation = server
    with pytest.raises(grpc.RpcError) as error:
        call(stub, method)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
    operation.assert_not_called()


@pytest.mark.parametrize("metadata", [
    (("x-internal-secret", "wrong-secret"),),
    (("x-internal-secret", SECRET[:-1]),),
    (("x-internal-secret", SECRET + "x"),),
    (("x-internal-secret", SECRET), ("x-internal-secret", SECRET)),
    (("x-serverless-authorization", "Bearer ingress-token"),),
])
def test_invalid_or_ambiguous_credentials_do_not_run_analysis(server, metadata):
    stub, _, operation = server
    with pytest.raises(grpc.RpcError) as error:
        call(stub, metadata=metadata)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
    operation.assert_not_called()


@pytest.mark.parametrize("method", RPCS)
def test_matching_secret_reaches_each_application_rpc(server, method):
    stub, _, operation = server
    response = call(stub, method, (("x-internal-secret", SECRET),))
    assert response is not None
    if method != "HealthCheck":
        operation.assert_called_once()


def test_auth_preserves_correlation_without_exposing_credentials(server):
    stub, _, operation = server

    def analyze(_request):
        assert request_context.current() == {"delivery_id": "auth-delivery"}
        return {"findings": []}

    operation.side_effect = analyze
    call(stub, metadata=(("x-internal-secret", SECRET), ("x-github-delivery", "auth-delivery")))
    operation.assert_called_once()


def test_missing_server_secret_fails_closed(server, monkeypatch):
    stub, _, operation = server
    monkeypatch.delenv("ANALYSIS_SERVICE_INTERNAL_SECRET")
    with pytest.raises(grpc.RpcError) as error:
        call(stub, metadata=(("x-internal-secret", SECRET),))
    assert error.value.code() == grpc.StatusCode.UNAVAILABLE
    operation.assert_not_called()


def test_shared_github_secret_is_a_compatible_analysis_fallback(server, monkeypatch):
    stub, _, operation = server
    monkeypatch.delenv("ANALYSIS_SERVICE_INTERNAL_SECRET")
    monkeypatch.setenv("GITHUB_SERVICE_INTERNAL_SECRET", SECRET)
    call(stub, metadata=(("x-internal-secret", SECRET),))
    operation.assert_called_once()


def test_analysis_specific_secret_takes_precedence(server, monkeypatch):
    stub, _, operation = server
    monkeypatch.setenv("GITHUB_SERVICE_INTERNAL_SECRET", "different-shared-secret")
    with pytest.raises(grpc.RpcError) as error:
        call(stub, metadata=(("x-internal-secret", "different-shared-secret"),))
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED
    operation.assert_not_called()


def test_standard_health_probe_remains_available_without_configured_auth(server, monkeypatch):
    _, channel, operation = server
    monkeypatch.delenv("ANALYSIS_SERVICE_INTERNAL_SECRET")
    response = health_pb2_grpc.HealthStub(channel).Check(health_pb2.HealthCheckRequest(), timeout=3)
    assert response.status == health_pb2.HealthCheckResponse.SERVING
    operation.assert_not_called()
