import copy
import pytest

from benchmarks.security_curation.validate import ValidationError, validate_dataset


def case(case_id="sql-1", lineage="family-1", split="dev"):
    source = "name = input()\nprint(name)\n"
    return {
        "id": case_id,
        "split": split,
        "lineage": lineage,
        "language": "python",
        "expected_verdict": "true_positive",
        "finding": {"fingerprint": case_id + "-fp", "file_path": "app.py", "line_start": 1,
                     "line_end": 1, "code_snippet": "name = input()"},
        "file_patch": "@@ -0,0 +1,2 @@\n+name = input()\n+print(name)\n",
        "source_refs": [{"url": "https://cwe.mitre.org/top25/", "title": "CWE"}],
        "human_review_rubric": ["check it"],
    }


def test_validates_counts_and_dev_split():
    summary = validate_dataset({"schema_version": 1, "cases": [case()]})
    assert summary["cases"] == 1
    assert summary["split_counts"]["dev"] == 1
    assert summary["languages"]["python"] == 1


def test_rejects_duplicate_ids_and_fingerprints():
    first = case()
    second = copy.deepcopy(first)
    second["lineage"] = "family-2"
    with pytest.raises(ValidationError, match="duplicate id"):
        validate_dataset({"schema_version": 1, "cases": [first, second]})


def test_rejects_finding_that_does_not_match_diff_lines():
    bad = case()
    bad["finding"]["code_snippet"] = "print(name)"
    with pytest.raises(ValidationError, match="does not exactly match"):
        validate_dataset({"schema_version": 1, "cases": [bad]})


def test_rejects_lineage_split_leakage():
    first = case(split="dev")
    second = case(case_id="sql-2", split="validation")
    with pytest.raises(ValidationError, match="crosses splits"):
        validate_dataset({"schema_version": 1, "cases": [first, second]})


def test_rejects_non_https_or_missing_primary_source():
    bad = case()
    bad["source_refs"] = [{"url": "http://example.com/source", "title": "Example"}]
    with pytest.raises(ValidationError, match="HTTPS"):
        validate_dataset({"schema_version": 1, "cases": [bad]})


def test_javascript_is_checked_without_execution():
    good = case()
    good["language"] = "javascript"
    good["file_patch"] = "@@ -0,0 +1,2 @@\n+const x = { value: 1 };\n+console.log(x);\n"
    good["finding"]["code_snippet"] = "const x = { value: 1 };"
    # The lightweight JS check catches malformed delimiters without running the fixture.
    good["finding"]["code_snippet"] = "const x = { value: 1;"
    good["file_patch"] = "@@ -0,0 +1,1 @@\n+const x = { value: 1;\n"
    with pytest.raises(ValidationError, match="delimiters"):
        validate_dataset({"schema_version": 1, "cases": [good]})


def test_v2_requires_metadata_for_new_cases_but_preserves_inherited_seed():
    seed = case(case_id="seed", lineage="seed-lineage")
    fresh = case(case_id="fresh", lineage="fresh-lineage")
    seed["scenario_id"] = "scenario-seed"
    seed["isolation_group"] = "isolation-seed"
    fresh["scenario_id"] = "scenario-fresh"
    fresh["isolation_group"] = "isolation-fresh"
    summary = validate_dataset({"schema_version": 1, "dataset_version": 2,
                                "inherited_seed_ids": ["seed"], "cases": [seed, fresh]})
    assert summary["inherited_case_count"] == 1
    assert summary["new_case_count"] == 1


def test_v2_requires_scenario_and_isolation_for_new_cases():
    bad = case()
    bad["isolation_group"] = "isolation-1"
    with pytest.raises(ValidationError, match="scenario_id"):
        validate_dataset({"schema_version": 1, "dataset_version": 2, "cases": [bad]})


def test_v2_rejects_title_confidence_leakage_in_new_lineage():
    left = case(case_id="left", lineage="paired")
    right = case(case_id="right", lineage="paired")
    for item in (left, right):
        item["scenario_id"] = item["id"]
        item["isolation_group"] = "paired"
    left["finding"]["title"] = "Neutral scanner finding"
    right["finding"]["title"] = "Definitely vulnerable"
    with pytest.raises(ValidationError, match="title/confidence"):
        validate_dataset({"schema_version": 1, "dataset_version": 2, "cases": [left, right]})


def test_v2_rejects_application_annotation_leakage_but_allows_code_expressions():
    left = case(case_id="left", lineage="app-pair")
    right = case(case_id="right", lineage="app-pair")
    for item in (left, right):
        item["suite"] = "application"
        item["scenario_id"] = item["id"]
        item["isolation_group"] = "app-pair"
        item["finding"]["evidence"] = "Same neutral evidence"
        item["finding"]["remediation"] = "Same neutral remediation"
        item["finding"]["evidence_details"] = {"analysis_scope": "synthetic", "source_expr": item["id"]}
    right["finding"]["evidence_details"]["reviewability"] = "label leak"
    with pytest.raises(ValidationError, match="evidence_details.reviewability"):
        validate_dataset({"schema_version": 1, "dataset_version": 2, "cases": [left, right]})
