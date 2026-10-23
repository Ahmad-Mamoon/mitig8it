import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import benchmarks.production_readiness as readiness
import benchmarks.rule_quality_gate as gate


ROOT = Path(__file__).resolve().parents[1]


def test_legacy_compatibility_is_never_reported_as_production_readiness():
    report = readiness.build_report()
    assert report["compatibility_admission_passed"]
    assert not report["production_ready"]
    assert report["analysis"]["counts"]["legacy_unvalidated"] == 201
    assert report["analysis"]["counts"]["validated"] == 0
    assert "no_statistically_validated_posting_rules" in report["analysis"]["reasons"]
    assert not report["remediation"]["production_ready"]


@pytest.mark.parametrize("counts", [{"quarantined": 10}, {"legacy_unvalidated": 10},
                                    {"quarantined": 10, "legacy_unvalidated": 10},
                                    {"validated": 1, "legacy_unvalidated": 1}])
def test_missing_or_partial_rule_evidence_cannot_establish_readiness(counts):
    report = readiness.assess_readiness({"passed": True, "counts": counts}, component="analysis")
    assert not report["production_ready"]


def test_validated_analysis_does_not_imply_remediation_is_ready():
    rules = {"passed": True, "counts": {"validated": 5, "legacy_unvalidated": 0, "quarantined": 10}}
    assert readiness.assess_readiness(rules, component="analysis")["production_ready"]
    assert not readiness.assess_readiness(rules)["production_ready"]
    assert not readiness.assess_readiness(rules, component="remediation")["production_ready"]


@pytest.mark.parametrize("args,exit_code", [([], 2), (["--component", "analysis"], 2),
                                         (["--component", "remediation"], 2),
                                         (["--compatibility"], 0), (["--report-only"], 0)])
def test_readiness_cli_enforces_production_unless_reporting_or_staging_is_explicit(args, exit_code):
    result = subprocess.run([sys.executable, "-m", "benchmarks.production_readiness", *args],
                            cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == exit_code, result.stderr
    assert json.loads(result.stdout)["production_ready"] is False


def test_manual_release_artifact_edits_cannot_open_either_gate(monkeypatch, tmp_path):
    path = tmp_path / "quality-release.json"
    path.write_text(json.dumps({**readiness.RELEASE_ARTIFACT, "remediation_release_verified": True}))
    monkeypatch.setattr(readiness, "RELEASE_ARTIFACT_PATHS", [path])
    report = readiness.build_report()
    assert not report["production_ready"]
    assert not report["compatibility_admission_passed"]
    assert "packaged_release_evidence_artifact_missing_or_tampered" in report["remediation"]["reasons"]


def test_compiled_allowlist_must_match_the_canonical_evidence(monkeypatch, tmp_path):
    path = tmp_path / "publication-policy.json"
    path.write_text(json.dumps({"schema_version": "v1", "rules": {}}))
    monkeypatch.setattr(gate, "RUNTIME_POLICY", path)
    report = gate.run_gate()
    assert not report["passed"]
    assert "packaged_runtime_publication_policy_missing_or_stale" in report["reasons"]


def test_packaged_release_admission_is_identical_in_all_node_services():
    for path in readiness.RELEASE_ARTIFACT_PATHS:
        assert json.loads(path.read_text()) == readiness.RELEASE_ARTIFACT


def test_every_external_shipping_job_checks_local_readiness_first():
    shipping_pattern = re.compile(r"docker push|gcloud run deploy|firebase-tools@\S+ deploy|gh release create|kubectl apply|helm (?:upgrade|install)")
    found = []
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        for job_name, job in workflow.get("jobs", {}).items():
            steps = job.get("steps", [])
            writes = [index for index, step in enumerate(steps) if shipping_pattern.search(step.get("run", ""))]
            if not writes:
                continue
            found.append((path.name, job_name))
            gates = [index for index, step in enumerate(steps)
                     if step.get("uses") == "./.github/actions/quality-readiness"
                     or ("-m benchmarks.production_readiness" in step.get("run", "")
                         and "--report-only" not in step["run"] and "--compatibility" not in step["run"])]
            assert gates and min(gates) < min(writes), f"{path.name}/{job_name} can ship without evidence"
    assert len(found) >= 6


def test_composite_has_no_production_compatibility_fallback():
    path = ROOT / ".github/actions/quality-readiness/action.yml"
    action = yaml.safe_load(path.read_text())
    commands = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert 'production) python -m benchmarks.production_readiness --component "$QUALITY_COMPONENT" ;;' in commands
    assert 'staging) python -m benchmarks.production_readiness --component "$QUALITY_COMPONENT" --compatibility ;;' in commands
    assert "--report-only" not in commands
    assert "|| true" not in commands


@pytest.mark.parametrize("filename", ["deploy-production.yml", "deploy-staging.yml"])
def test_ordered_deployment_callers_allow_the_permissions_requested_by_reusable_jobs(filename):
    caller = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    checked = 0
    for name, job in caller["jobs"].items():
        reusable = job.get("uses", "")
        if not reusable.startswith("./.github/workflows/"):
            continue
        called = yaml.safe_load((ROOT / reusable).read_text())
        allowed = job.get("permissions", caller.get("permissions", {}))
        for called_job in called["jobs"].values():
            requested = called_job.get("permissions", called.get("permissions", {}))
            if requested.get("id-token") == "write":
                checked += 1
                assert allowed.get("id-token") == "write", (
                    f"{filename}/{name} cannot delegate the id-token: write permission requested by {reusable}"
                )
    assert checked >= 5, "API, analysis, GitHub, remediation, and dependency smoke must be checked"
    assert {scope for scope, access in caller["permissions"].items() if access == "write"} == {"id-token"}


@pytest.mark.parametrize("filename,job", [
    ("deploy-production.yml", "verify-ci"),
    ("deploy-staging.yml", "authorize"),
])
def test_deployment_preflight_jobs_do_not_receive_oidc_or_write_permissions(filename, job):
    caller = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    permissions = caller["jobs"][job].get("permissions", caller["permissions"])
    assert permissions.get("id-token", "none") == "none"
    assert all(access in {"read", "none"} for access in permissions.values())
