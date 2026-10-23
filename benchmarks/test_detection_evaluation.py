"""Synthetic contract tests; none of these invented observations are release evidence."""
from copy import deepcopy
import json

import pytest

from benchmarks import detection_evaluation as evaluation


REF = "a" * 40
SYSTEM = {"source_revision": "b" * 40, "artifact_sha256": "c" * 64,
          "configuration_sha256": "d" * 64, "publication_policy_sha256": "e" * 64,
          "triage_enabled": False}


def corpus():
    return {"version": 1, "labels": [
        {"id": "sql", "repo": "owner/repo", "ref": REF, "path": "app.py",
         "line_range": [10, 10], "cwe": "CWE-89", "rule_classes_expected": ["sql_injection"],
         "source": "Synthetic contract-test label", "evidence": "db.execute(query)"},
        {"id": "command", "repo": "owner/repo", "ref": REF, "path": "other.js",
         "line_range": [20, 20], "cwe": "CWE-78", "rule_classes_expected": ["command_injection"],
         "source": "Synthetic contract-test label", "evidence": "exec(command)"},
    ]}


def finding(fingerprint="f", *, path="app.py", line=10, kind="sql_injection"):
    return {"fingerprint": fingerprint, "rule_id": "synthetic.rule", "file_path": path,
            "line_start": line, "line_end": line, "internal_type": kind,
            "code_snippet": "synthetic_source()"}


def file(path="app.py", findings=None, stages=None):
    return {"path": path, "source_sha256": "f" * 64,
            "stages": stages or {"tier1": "complete", "tier2": "complete"},
            "findings": findings if findings is not None else [finding()]}


def run(files=None, *, manifest=None):
    return {"schema_version": evaluation.RUN_SCHEMA, "corpus_sha256": evaluation.digest(manifest or corpus()),
            "scope": "published_detection", "system": deepcopy(SYSTEM), "repo": "owner/repo", "ref": REF,
            "files": files if files is not None else [file(), file("other.js", [])]}


def review_for(document, prediction, verdict="false", *, manifest=None):
    return {"schema_version": evaluation.REVIEW_SCHEMA, "corpus_sha256": evaluation.digest(manifest or corpus()),
            "observations": [{
                "observation_id": evaluation.observation_id(document["system"], document["repo"],
                    document["ref"], document["files"][0]["source_sha256"], prediction),
                "verdict": verdict, "reviewer": "synthetic-reviewer", "source": "synthetic review record",
                "sampling_unit": "synthetic-repository-unit",
            }]}


def test_reports_distinct_precision_recall_coverage_and_small_sample_uncertainty():
    false = finding("false", line=40)
    document = run([file(findings=[finding(), false]), file("other.js", [])])
    result = evaluation.evaluate(corpus(), [document], review_for(document, false))
    assert result["data_contract_valid"] and result["observations_complete"]
    assert result["metrics"]["precision_reviewed_alerts"]["estimate"] == 0.5
    assert result["metrics"]["recall_observed_labels"]["estimate"] == 0.5
    assert result["metrics"]["precision_reviewed_alerts"]["wilson_95_iid_reference"][0] < 0.1
    assert result["metrics"]["recall_all_labels_identification_bounds"] == [0.5, 0.5]
    assert result["metrics"]["accuracy"] is None and result["metrics"]["true_negatives"] is None
    assert result["by_language"]["JavaScript"]["missed_labels_on_complete_scans"] == 1
    assert not result["production_ready"] and not result["release_admissible"]


def test_missing_observations_are_unknown_not_successes_or_false_negatives():
    result = evaluation.evaluate(corpus(), [])
    assert result["metrics"]["recall_observed_labels"]["estimate"] is None
    assert result["metrics"]["unobserved_labels"] == 2
    assert result["metrics"]["missed_labels_on_complete_scans"] == 0
    assert result["metrics"]["recall_all_labels_identification_bounds"] == [0, 1]
    assert result["coverage"]["missing_repository_trees"] == 1
    assert not result["observations_complete"]


def test_partial_failed_or_unattempted_stages_do_not_manufacture_negative_observations():
    for status in ("partial", "error", "not_attempted"):
        result = evaluation.evaluate(corpus(), [run([file(findings=[], stages={"tier1": "complete", "tier2": status})])])
        assert result["metrics"]["unobserved_labels"] == 2
        assert result["metrics"]["missed_labels_on_complete_scans"] == 0
        assert result["coverage"]["file_observations_with_incomplete_stages"] == 1
        assert not result["observations_complete"]


def test_valid_positive_survives_partial_scan_but_remaining_labels_stay_unknown():
    result = evaluation.evaluate(corpus(), [run([file(stages={"tier1": "complete", "tier2": "error"})])])
    assert result["metrics"]["detected_labels"] == 1
    assert result["metrics"]["unobserved_labels"] == 1
    assert result["metrics"]["recall_all_labels_identification_bounds"] == [0.5, 1]
    assert result["coverage"]["complete_labeled_files"] == 0


def test_unreviewed_alerts_remain_in_precision_bounds_and_block_complete_evidence():
    result = evaluation.evaluate(corpus(), [run([file(findings=[finding(), finding("unread", line=40)])])])
    assert result["metrics"]["precision_reviewed_alerts"]["estimate"] == 1
    assert result["metrics"]["precision_reviewed_alerts"]["denominator"] == 1
    assert result["metrics"]["precision_accepted_alerts_identification_bounds"] == [0.5, 1]
    assert result["metrics"]["unresolved_alerts"] == 1
    assert not result["observations_complete"]


@pytest.mark.parametrize("change", ["legacy_schema", "wrong_corpus", "missing_system", "raw_scope", "wrong_ref"])
def test_unidentified_legacy_stale_or_nonproduction_scope_cannot_support_metrics(change):
    document = run()
    if change == "legacy_schema":
        document = {"mode": "snapshot", "repo": "owner/repo", "ref": REF, "records": [{"findings": [finding()]}]}
    elif change == "wrong_corpus":
        document["corpus_sha256"] = "0" * 64
    elif change == "missing_system":
        document["system"].pop("artifact_sha256")
    elif change == "raw_scope":
        document["scope"] = "raw_detection"
    else:
        document["ref"] = "0" * 40
    result = evaluation.evaluate(corpus(), [document])
    assert not result["data_contract_valid"]
    assert result["metrics"]["detected_labels"] == 0
    assert result["metrics"]["unobserved_labels"] == 2


def test_duplicate_runs_and_mixed_system_revisions_are_rejected_not_pooled():
    document = run()
    duplicate = evaluation.evaluate(corpus(), [document, deepcopy(document)])
    assert not duplicate["data_contract_valid"] and duplicate["metrics"]["detected_labels"] == 0
    other = deepcopy(document)
    other["system"]["configuration_sha256"] = "0" * 64
    mixed = evaluation.evaluate(corpus(), [document, other])
    assert any(error["code"] == "mixed_system_identities" for error in mixed["errors"])
    assert not mixed["production_ready"]


def test_duplicate_files_and_fingerprints_are_invalid_not_additional_true_positives():
    for document in [run([file(), file()]), run([file(findings=[finding(), finding()])])]:
        result = evaluation.evaluate(corpus(), [document])
        assert not result["data_contract_valid"]
        assert result["metrics"]["detected_labels"] == 0
        assert result["coverage"]["complete_labeled_files"] == 0


def test_duplicate_alert_variants_cannot_automatically_inflate_label_confirmed_precision():
    result = evaluation.evaluate(corpus(), [run([file(findings=[finding("a"), finding("b")])])])
    assert result["metrics"]["reviewed_true_alerts"] == result["metrics"]["detected_labels"] == 1
    assert result["metrics"]["unresolved_alerts"] == 1


def test_maximum_matching_is_one_to_one_and_does_not_lose_an_augmenting_path():
    assert evaluation._maximum_matching([["one", "two"], ["one"]]) == {0: "two", 1: "one"}
    assert len(evaluation._maximum_matching([["one", "two"]])) == 1


def test_location_without_class_or_exact_overlap_is_not_a_hit():
    for observation in [finding(kind="command_injection"), finding(line=11)]:
        result = evaluation.evaluate(corpus(), [run([file(findings=[observation])])])
        assert result["metrics"]["detected_labels"] == 0
        assert result["metrics"]["unresolved_alerts"] == 1
        assert result["metrics"]["missed_labels_on_complete_scans"] == 1


def test_human_review_is_bound_to_tree_source_and_whole_observation():
    alert = finding(line=40)
    document = run([file(findings=[alert])])
    reviews = review_for(document, alert)
    changed = deepcopy(document)
    changed["files"][0]["source_sha256"] = "0" * 64
    result = evaluation.evaluate(corpus(), [changed], reviews)
    assert not result["data_contract_valid"]
    assert result["metrics"]["unresolved_alerts"] == 1
    legacy = evaluation.evaluate(corpus(), [document], {"adjudications": [{"fingerprint": "f", "verdict": "false"}]})
    assert not legacy["data_contract_valid"] and legacy["metrics"]["reviewed_false_alerts"] == 0


def test_contradictory_label_and_review_remain_uncertain_not_automatic_true_or_false():
    document = run()
    result = evaluation.evaluate(corpus(), [document], review_for(document, finding()))
    assert not result["data_contract_valid"]
    assert result["metrics"]["reviewed_true_alerts"] == result["metrics"]["reviewed_false_alerts"] == 0
    assert result["metrics"]["unresolved_alerts"] == result["metrics"]["unobserved_labels"] == 1


@pytest.mark.parametrize("bad", [None, True, {}, [], "unknown"])
def test_malformed_stage_shapes_fail_closed(bad):
    document = run()
    document["files"][0]["stages"] = {"tier1": bad, "tier2": "complete"}
    result = evaluation.evaluate(corpus(), [document])
    assert not result["data_contract_valid"]
    assert result["metrics"]["detected_labels"] == 0


def test_model_enabled_requires_a_completed_tier3_observation():
    document = run()
    document["system"]["triage_enabled"] = True
    result = evaluation.evaluate(corpus(), [document])
    assert not result["data_contract_valid"] and result["metrics"]["detected_labels"] == 0
    for record in document["files"]:
        record["stages"]["tier3"] = "complete"
    assert evaluation.evaluate(corpus(), [document])["observations_complete"]


def test_perfect_fixture_metrics_never_open_release_readiness_or_mutate_inputs():
    document = run([file(), file("other.js", [finding("command", path="other.js", line=20, kind="command_injection")])])
    before = deepcopy(document)
    result = evaluation.evaluate(corpus(), [document])
    assert result["metrics"]["precision_reviewed_alerts"]["estimate"] == 1
    assert result["metrics"]["recall_observed_labels"]["estimate"] == 1
    assert result["data_contract_valid"] and result["observations_complete"]
    assert not result["release_admissible"] and not result["production_ready"]
    assert document == before


def test_cli_blocks_missing_or_malformed_observations_and_report_only_is_explicit(tmp_path, capsys):
    manifest = tmp_path / "labels.json"
    manifest.write_text(json.dumps(corpus()))
    assert evaluation.main(["--labels", str(manifest)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["metrics"]["unobserved_labels"] == 2
    assert evaluation.main(["--labels", str(manifest), "--report-only"]) == 0
    assert json.loads(capsys.readouterr().out)["production_ready"] is False
    broken = tmp_path / "broken.json"
    broken.write_text("not JSON")
    assert evaluation.main(["--labels", str(manifest), "--observations", str(broken)]) == 2
    assert json.loads(capsys.readouterr().out)["data_contract_valid"] is False


def test_invalid_or_duplicate_labels_invalidate_the_manifest_instead_of_overwriting_truth():
    for change in ("duplicate", "boolean_line", "missing_source"):
        manifest = corpus()
        if change == "duplicate":
            manifest["labels"].append(deepcopy(manifest["labels"][0]))
        elif change == "boolean_line":
            manifest["labels"][0]["line_range"] = [True, 10]
        else:
            manifest["labels"][0].pop("source")
        result = evaluation.evaluate(manifest, [])
        assert not result["data_contract_valid"]
        assert result["metrics"]["recall_observed_labels"]["estimate"] is None


def test_checked_in_corpus_can_be_reported_without_inventing_observations():
    manifest = json.loads((evaluation.ROOT / "benchmarks/vulnerable-corpus/labels.json").read_text())
    result = evaluation.evaluate(manifest, [])
    assert result["data_contract_valid"]
    assert result["metrics"]["unobserved_labels"] == len(manifest["labels"])
    assert result["metrics"]["recall_observed_labels"]["estimate"] is None
    assert not result["observations_complete"] and not result["production_ready"]
