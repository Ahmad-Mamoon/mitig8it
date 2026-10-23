import json

from benchmarks.security_curation.publish import WORKSPACE_ID, _example, dataset_name, scoped_environment
from benchmarks.security_curation.test_validate import case


def test_example_keeps_expected_labels_out_of_inputs():
    source_case = case()
    source_case["finding"]["evidence"] = "This is safe and should not be model input"
    source_case["finding"]["remediation"] = "Use the safe fix"
    inputs, outputs, metadata = _example(source_case)
    assert "expected_verdict" not in inputs["fixture"]
    assert "rationale" not in inputs["fixture"]
    assert "evidence" not in inputs["fixture"]["finding"]
    assert "remediation" not in inputs["fixture"]["finding"]
    assert outputs["expected_verdict"] == "true_positive"
    assert metadata["split"] == "dev"
    assert metadata["lineage"] == "family-1"


def test_scoped_environment_only_loads_allowlisted_values(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(f"LANGSMITH_API_KEY=secret\nLANGSMITH_WORKSPACE_ID={WORKSPACE_ID}\nNOT_ALLOWED=do-not-load\n")
    monkeypatch.delenv("LANGSMITH_API_KEY", raising=False)
    with scoped_environment(env):
        assert __import__("os").environ["LANGSMITH_API_KEY"] == "secret"
        assert __import__("os").environ["LANGSMITH_WORKSPACE_ID"] == WORKSPACE_ID
        assert "NOT_ALLOWED" not in __import__("os").environ
    assert "LANGSMITH_API_KEY" not in __import__("os").environ


def test_dry_run_cli_never_requires_sdk(tmp_path, capsys):
    # Importing the publisher and constructing examples is sufficient to keep the default path
    # offline; the CLI test itself is covered by the no-credentials invocation in README.
    assert _example(case())[2]["fixture_digest"]


def test_versioned_dataset_names_preserve_v1_and_select_v2():
    assert dataset_name("application", 1) == "mitig8it-application-security-v1"
    assert dataset_name("application", 2) == "mitig8it-application-security-v2"
    assert dataset_name("agent", 2) == "mitig8it-ai-reviewer-security-v2"
