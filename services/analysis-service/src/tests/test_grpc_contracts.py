from analysis_grpc_server import (
    _analysis_request_from_proto,
    _triage_request_from_proto,
    analysis_pb2,
)


def test_synthetic_zero_pr_number_survives_analysis_wire_roundtrip():
    request = analysis_pb2.AnalyzePullRequestRequest(
        repository_full_name="playground/code", pull_request_number=0, commit_sha="a" * 40
    )
    decoded = analysis_pb2.AnalyzePullRequestRequest.FromString(request.SerializeToString())
    assert _analysis_request_from_proto(decoded).pull_request_number == 0


def test_synthetic_zero_pr_number_survives_triage_wire_roundtrip():
    request = analysis_pb2.TriageFindingsRequest(
        repository_full_name="playground/code", pull_request_number=0, commit_sha="a" * 40
    )
    decoded = analysis_pb2.TriageFindingsRequest.FromString(request.SerializeToString())
    assert _triage_request_from_proto(decoded).pull_request_number == 0


def test_analysis_limitations_survive_the_response_wire_roundtrip():
    """A limitation is useless if it stops at the service boundary."""
    from analysis_grpc_server import _parse_analysis_response

    payload = {
        "repository_full_name": "owner/repo",
        "pull_request_number": 135,
        "commit_sha": "a" * 40,
        "files_analyzed": 12,
        "tier": 2,
        "findings": [],
        "analysis_limitations": [
            {
                "path": "svc/cwe-vul.py",
                "kind": "partial_parse",
                "type": "Lexical error",
                "message": "unrecognized symbol in string",
                "line": 127,
            },
            {
                "path": "svc/huge.ts",
                "kind": "not_analyzed",
                "type": "Timeout",
                "message": "timed out",
                "line": None,
            },
        ],
    }

    decoded = analysis_pb2.AnalyzePullRequestResponse.FromString(
        _parse_analysis_response(payload).SerializeToString()
    )

    assert [limitation.path for limitation in decoded.analysis_limitations] == [
        "svc/cwe-vul.py",
        "svc/huge.ts",
    ]
    assert decoded.analysis_limitations[0].kind == "partial_parse"
    assert decoded.analysis_limitations[0].type == "Lexical error"
    assert decoded.analysis_limitations[0].line == 127
    assert decoded.analysis_limitations[1].type == "Timeout"
    assert decoded.analysis_limitations[1].line == 0


def test_a_response_without_limitations_stays_empty():
    from analysis_grpc_server import _parse_analysis_response

    response = _parse_analysis_response({
        "repository_full_name": "owner/repo",
        "pull_request_number": 1,
        "commit_sha": "a" * 40,
        "findings": [],
    })
    assert list(response.analysis_limitations) == []


def test_advisory_llm_recommendation_survives_response_wire_roundtrip(monkeypatch):
    import json
    from unittest.mock import Mock

    import llm_triage
    from analysis_grpc_server import _message_to_dict, _parse_analysis_response

    recommendation = {
        "fix": "Bind user_id as a SQL parameter.",
        "regression_test": "Assert injection input is treated as a literal value.",
        "uncertainty": "The database driver is not shown in this diff.",
        "evidence": [{"file_path": "app.py", "line": 800, "quote": "db.execute(query)"}],
        "source": "llm",
        "status": "advisory",
        "verification": "not_verified",
    }
    model_call = Mock(return_value=(json.dumps([{
        "fingerprint": "sql-800",
        "verdict": "uncertain",
        "reasoning": "The query construction is outside the supplied context.",
        "recommendation": recommendation,
    }]), 100, 100))
    monkeypatch.setattr(llm_triage, "is_llm_triage_enabled", lambda: True)
    monkeypatch.setattr(llm_triage, "_call_triage_llm", model_call)
    findings = llm_triage.triage_findings([{
            "fingerprint": "sql-800",
            "file_path": "app.py",
            "line_start": 800,
            "code_snippet": "db.execute(query)",
            "severity": "high",
            "confidence": 0.7,
            "evidence_details": {"extra": {
                "in_test_code": False,
            }},
        }], {"app.py": "@@ -800 +800 @@\n-db.execute(old_query)\n+db.execute(query)"})
    model_call.assert_called_once()
    response = _parse_analysis_response({"findings": findings})
    decoded = analysis_pb2.AnalyzePullRequestResponse.FromString(response.SerializeToString())
    finding = _message_to_dict(decoded)["findings"][0]
    assert finding["evidence_details"]["extra"]["llm_recommendation"] == recommendation
    assert finding["evidence_details"]["extra"]["in_test_code"] is False
    assert finding["remediation"] == recommendation["fix"]
