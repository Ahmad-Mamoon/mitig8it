"""Combined HTTP and gRPC analysis must publish findings, never Tier 3 code.

These tests exercise the shared payload pipeline and the real Tier 3 parser /
applicator with a mocked provider, without a scanner binary or network access.
"""
from copy import deepcopy
import json
from unittest.mock import Mock

from fastapi.testclient import TestClient
from google.protobuf.json_format import ParseDict
import pytest

import analysis_grpc_server as grpc_server
import llm_triage
import main


RULE = "sql.injection.raw_query"
SNIPPET = 'db.query("SELECT * FROM users WHERE id = " + userId);'
CANDIDATE = 'db.query("SELECT * FROM users WHERE id = ?", [userId]);'
PAYLOAD = {
    "repository_full_name": "owner/repo", "pull_request_number": 1,
    "commit_sha": "a" * 40,
    "files": [{"path": "app.js", "patch": "@@ -0,0 +1 @@\n+" + SNIPPET}],
}


def detector_finding():
    return {
        "rule_id": RULE, "fingerprint": "sql-1", "internal_type": "sql_injection",
        "title": "SQL injection", "description": "User input is interpolated into SQL.",
        "category": "SQL injection", "cwe_id": "CWE-89", "severity": "high",
        "confidence": 0.9, "file_path": "app.js", "line_start": 1, "line_end": 1,
        "code_snippet": SNIPPET, "remediation": "Use bound SQL parameters.",
        "remediation_patch": "detector_candidate()", "fixed_code": "raw_detector_candidate()",
        "evidence_details": {
            "auto_fix_eligible": True, "fix_scope": "line",
            "trace_steps": [
                {"kind": "source", "expr": "request.args['id']", "line": 1},
                {"kind": "sink", "expr": SNIPPET, "line": 1},
            ],
        },
    }


@pytest.fixture(params=["http", "grpc"])
def submit(request, monkeypatch):
    monkeypatch.setattr(main, "PUBLICATION_RULE_IDS", frozenset({RULE}))
    monkeypatch.setattr(main, "QUARANTINED_RULE_IDS", frozenset())
    monkeypatch.setattr(main, "pattern_findings", lambda *_args: [detector_finding()])
    monkeypatch.setattr(main, "run_opengrep_with_limitations", lambda _files: ([], []))
    if request.param == "http":
        monkeypatch.setenv("ANALYSIS_SERVICE_INTERNAL_SECRET", "synthetic-test-secret")
        with TestClient(main.app) as client:
            def post():
                response = client.post("/analyze/pr", json=deepcopy(PAYLOAD),
                                       headers={"x-internal-secret": "synthetic-test-secret"})
                assert response.status_code == 200, response.text
                return response.json()
            yield post
    else:
        def invoke():
            encoded = ParseDict(deepcopy(PAYLOAD), grpc_server.analysis_pb2.AnalyzePullRequestRequest())
            decoded = grpc_server.analysis_pb2.AnalyzePullRequestRequest.FromString(encoded.SerializeToString())
            context = Mock()
            context.abort.side_effect = lambda *_args: pytest.fail("Combined gRPC analysis unexpectedly aborted")
            response = grpc_server.AnalysisGrpcService().AnalyzePullRequest(decoded, context)
            context.abort.assert_not_called()
            decoded_response = grpc_server.analysis_pb2.AnalyzePullRequestResponse.FromString(response.SerializeToString())
            return grpc_server._message_to_dict(decoded_response)
        yield invoke


@pytest.mark.parametrize("propose_code", [True, False], ids=["model_code", "fallback_code"])
def test_combined_transport_strips_real_triage_generated_code_but_retains_advice(
    submit, monkeypatch, propose_code,
):
    recommendation = {
        "fix": "Bind userId separately from the SQL statement.",
        "regression_test": "Assert injection input is treated as a literal value.",
        "uncertainty": "The database driver configuration is not shown.",
        "evidence": [{"file_path": "app.js", "line": 1, "quote": SNIPPET}],
    }
    model_verdict = {
        "fingerprint": "sql-1", "verdict": "true_positive", "reasoning": "Input reaches SQL.",
        "recommendation": recommendation,
    }
    if propose_code:
        model_verdict["fixed_code"] = CANDIDATE
    provider = Mock(return_value=(json.dumps([model_verdict]), 100, 100))
    monkeypatch.setattr(llm_triage, "is_llm_triage_enabled", lambda: True)
    monkeypatch.setattr(llm_triage, "_call_triage_llm", provider)
    proposals = []
    real_triage = llm_triage.triage_findings

    def triage(*args):
        assert args[0][0]["remediation_patch"] == ""
        assert "fixed_code" not in args[0][0]
        findings = real_triage(*args)
        # Prove the model/fallback actually recreated executable text before the
        # final boundary, so this cannot pass just because auto-fix was ineligible.
        assert findings[0]["remediation_patch"]
        proposals.append(findings[0]["remediation_patch"])
        return findings

    monkeypatch.setattr(main, "triage_findings", triage)
    result = submit()
    provider.assert_called_once()
    assert len(proposals) == 1
    if propose_code:
        assert proposals == [CANDIDATE]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["rule_id"] == RULE
    assert not finding.get("remediation_patch")
    assert "fixed_code" not in finding
    assert finding["remediation"] == recommendation["fix"]
    advice = finding["evidence_details"]["extra"]["llm_recommendation"]
    assert advice["status"] == "advisory" and advice["verification"] == "not_verified"


@pytest.mark.parametrize("raise_after_mutation", [False, True], ids=["return", "error_fallback"])
def test_combined_transport_sanitizes_mutated_input_even_if_triage_raises(
    submit, monkeypatch, raise_after_mutation,
):
    calls = []

    def triage(findings, *_args):
        calls.append(True)
        assert findings[0]["remediation_patch"] == "" and "fixed_code" not in findings[0]
        findings[0].update(remediation_patch=CANDIDATE, fixed_code=CANDIDATE)
        if raise_after_mutation:
            raise RuntimeError("synthetic provider failure after mutation")
        # A model cannot invent an allowed rule ID by inventing high confidence.
        return findings + [{**findings[0], "rule_id": "unapproved.model.rule", "confidence": 1.0}]

    monkeypatch.setattr(main, "triage_findings", triage)
    result = submit()
    assert calls == [True]
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == RULE
    assert not result["findings"][0].get("remediation_patch")
    assert "fixed_code" not in result["findings"][0]
