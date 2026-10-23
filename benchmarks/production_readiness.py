"""Offline production readiness. Reporting compatibility never establishes readiness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from benchmarks.rule_quality_gate import ROOT, run_gate


RELEASE_ARTIFACT = {
    "schema_version": "v1",
    "remediation_release_verified": False,
    "reason": "external_review_signature_cryptographic_verifier_not_configured",
}
RELEASE_ARTIFACT_PATHS = (
    ROOT / "services/github-service/src/quality-release.json",
    ROOT / "services/api-service/src/quality-release.json",
)


def assess_readiness(rule_report: dict, *, component: str = "all", artifacts_match: bool = True) -> dict:
    counts = rule_report.get("counts", {})
    analysis_reasons = list(rule_report.get("reasons", []))
    if not rule_report.get("passed"):
        analysis_reasons.append("rule_promotion_gate_failed")
    if counts.get("legacy_unvalidated", 0):
        analysis_reasons.append(f"legacy_rule_evidence_missing:{counts['legacy_unvalidated']}")
    if not counts.get("validated", 0):
        analysis_reasons.append("no_statistically_validated_posting_rules")
    # The remediation gate has no configured signature trust root/verifier. A
    # hand-edited 'passed' flag, model assertion, or fixture percentage cannot
    # authenticate release evidence and must never open publication.
    remediation_reasons = [RELEASE_ARTIFACT["reason"], "independent_production_release_evidence_missing"]
    if not artifacts_match:
        remediation_reasons.append("packaged_release_evidence_artifact_missing_or_tampered")
    analysis = {"production_ready": not analysis_reasons, "reasons": analysis_reasons, "counts": counts}
    remediation = {"production_ready": False, "reasons": remediation_reasons}
    required = [analysis, remediation] if component == "all" else [analysis if component == "analysis" else remediation]
    return {
        "schema_version": "v1", "component": component,
        "scope": "analysis_rule_and_remediation_quality",
        "production_ready": all(item["production_ready"] for item in required),
        "compatibility_admission_passed": bool(rule_report.get("passed")) and artifacts_match,
        "analysis": analysis, "remediation": remediation,
    }


def build_report(component: str = "all") -> dict:
    try:
        rule_report = run_gate()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as error:
        rule_report = {"passed": False, "reasons": [f"invalid_rule_evidence:{error}"]}
    artifacts_match = True
    for path in RELEASE_ARTIFACT_PATHS:
        try:
            artifacts_match = artifacts_match and json.loads(path.read_text()) == RELEASE_ARTIFACT
        except (OSError, ValueError):
            artifacts_match = False
    return assess_readiness(rule_report, component=component, artifacts_match=artifacts_match)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=["all", "analysis", "remediation"], default="all")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report-only", action="store_true", help="Emit readiness without enforcing it; never use for shipping")
    parser.add_argument("--compatibility", action="store_true", help="Staging admission; explicitly allows documented legacy exceptions")
    args = parser.parse_args()
    report = build_report(args.component)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.report_only:
        return 0
    passed = report["compatibility_admission_passed"] if args.compatibility else report["production_ready"]
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
