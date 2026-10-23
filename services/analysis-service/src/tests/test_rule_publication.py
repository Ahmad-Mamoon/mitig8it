import json

import pytest

import main
import rule_publication as publication


DIGEST = "a" * 64


@pytest.fixture
def artifact(monkeypatch, tmp_path):
    path = tmp_path / "publication-policy.json"
    monkeypatch.setattr(publication, "POLICY_FILE", path)
    monkeypatch.setattr(publication, "current_rules", lambda: {
        "approved": {"posting": "post", "rule_digest": DIGEST},
        "new": {"posting": "post", "rule_digest": "b" * 64},
        "disabled": {"posting": "quarantine", "rule_digest": DIGEST},
    })
    publication.postable_rule_ids.cache_clear()
    yield path
    publication.postable_rule_ids.cache_clear()


def test_missing_or_malformed_artifact_cannot_approve_any_rule(artifact):
    assert publication.postable_rule_ids() == frozenset()
    assert not publication.remediation_publication_ready()
    publication.postable_rule_ids.cache_clear()
    artifact.write_text("null")
    assert publication.postable_rule_ids() == frozenset()


def test_runtime_matches_exact_definition_and_declared_posting_policy(artifact):
    artifact.write_text(json.dumps({"schema_version": "v1", "rules": {
        "approved": {"status": "legacy_unvalidated", "rule_digest": DIGEST},
        "new": {"status": "validated", "rule_digest": DIGEST},
        "disabled": {"status": "validated", "rule_digest": DIGEST},
    }}))
    assert publication.postable_rule_ids() == frozenset({"approved"})


def test_unknown_status_is_not_publication_permission(artifact):
    artifact.write_text(json.dumps({"schema_version": "v1", "rules": {
        "approved": {"status": "measured", "rule_digest": DIGEST},
    }}))
    assert publication.postable_rule_ids() == frozenset()


def test_new_or_unknown_findings_are_withheld_even_with_high_model_confidence():
    approved, withheld = main.partition_by_posting_policy([
        {"rule_id": "unreviewed.new.rule", "confidence": 1.0}, {"confidence": 1.0},
    ])
    assert approved == []
    assert len(withheld) == 2


def test_legacy_detection_can_report_but_cannot_publish_unreviewed_repair():
    finding = {"rule_id": "sql.injection.raw_query", "remediation_patch": "candidate();"}
    approved, withheld = main.partition_by_posting_policy([finding])
    assert not withheld
    assert approved[0]["remediation_patch"] == ""
    assert finding["remediation_patch"] == "candidate();", "The proposal remains available for evaluation"


def test_analysis_patch_always_stays_advisory(monkeypatch):
    monkeypatch.setattr(main, "PUBLICATION_RULE_IDS", frozenset({"sql.injection.raw_query"}))
    finding = {"rule_id": "sql.injection.raw_query", "remediation_patch": "candidate();"}
    approved, withheld = main.partition_by_posting_policy([finding])
    assert withheld == []
    assert approved == [{"rule_id": "sql.injection.raw_query", "remediation_patch": ""}]


def test_raw_model_replacement_cannot_leave_the_publication_boundary():
    finding = {"rule_id": "sql.injection.raw_query", "fixed_code": "raw_candidate();",
               "remediation_patch": "normalized_candidate();", "remediation": "Use bound values."}
    approved, withheld = main.partition_by_posting_policy([finding])
    assert withheld == []
    assert approved == [{"rule_id": "sql.injection.raw_query", "remediation_patch": "",
                         "remediation": "Use bound values."}]
    assert finding["fixed_code"] == "raw_candidate();"
    assert finding["remediation_patch"] == "normalized_candidate();"


def test_tier3_filters_unapproved_input_and_model_output(monkeypatch):
    calls = []
    def triage(findings, *_):
        calls.append(findings)
        return findings + [{"rule_id": "model.invented.rule", "confidence": 1.0}]
    monkeypatch.setattr(main, "triage_findings", triage)
    payload = main.TriageRequest(repository_full_name="owner/repo", pull_request_number=1,
                                 commit_sha="a" * 40, findings=[
                                     {"rule_id": "unreviewed.new.rule"},
                                     {"rule_id": "sql.injection.raw_query", "file_path": "app.py",
                                      "severity": "high", "category": "SQL injection", "line_start": 1},
                                 ])
    result = main.triage_findings_payload(payload)
    assert len(calls) == 1 and len(calls[0]) == 1
    assert [finding["rule_id"] for finding in result["findings"]] == ["sql.injection.raw_query"]
    assert result["filtered_count"] == 1


def test_tier3_never_calls_model_for_only_unapproved_findings(monkeypatch):
    def unexpected(*_):
        pytest.fail("Unreviewed findings must not reach model triage")
    monkeypatch.setattr(main, "triage_findings", unexpected)
    result = main.triage_findings_payload(main.TriageRequest(
        repository_full_name="owner/repo", pull_request_number=1, commit_sha="a" * 40,
        findings=[{"rule_id": "unreviewed.new.rule"}],
    ))
    assert result["findings"] == [] and result["filtered_count"] == 1
