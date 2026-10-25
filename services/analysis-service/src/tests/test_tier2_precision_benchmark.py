"""The tier 2 precision benchmark: every posting rule fires on its own fixture, and the
lines a rule was narrowed away from stay silent.

A rule that posts is a claim about real code, and the claim decays. A pattern edited to
remove a false positive can remove the true positive with it, and nothing else in the suite
would notice: the replay is not run in CI and a rule that has stopped matching produces no
failure, only silence. `benchmarks/tier2-precision/cases.json` turns that silence into a
failing test.

Every fixture is scanned in one scanner pass, because a pass costs a second and there are
ninety of them.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from finding_quality import cluster_findings
from main import partition_by_posting_policy
from opengrep_runner import RULES_DIR, load_rule_metadata, quarantined_rule_ids, run_opengrep
from test_code_scope import classify_findings

CASES_PATH = Path(__file__).resolve().parents[4] / "benchmarks" / "tier2-precision" / "cases.json"

# The coverage files. They are the rule set the benchmark is responsible for.
COVERAGE_FILES = (
    "javascript_coverage.yml",
    "python_coverage.yml",
    "template_coverage.yml",
    "workflow_coverage.yml",
)


def _coverage_rule_ids() -> list[str]:
    ids: list[str] = []
    for name in COVERAGE_FILES:
        document = yaml.safe_load((RULES_DIR / name).read_text(encoding="utf-8"))
        ids.extend(str(rule["id"]) for rule in document["rules"])
    return ids


COVERAGE_RULE_IDS = _coverage_rule_ids()

# The fixture records the raw reconciliation contract from before the stricter
# evidence gate. Keep that detector truth intact; publication is a separate claim.
# The newer pwn-request shape remains measurable but cannot supersede an admitted
# older rule in a response while its independent holdout evidence is missing.
CURRENT_POSTED_EXPECTATIONS = {
    "subsumption.persist-credentials-folded-into-untrusted-checkout": [{
        "rule": "cwe-829.gha-untrusted-checkout-privileged-trigger",
        "merged_rule_ids": [
            "opengrep.cwe-829.gha-untrusted-checkout-privileged-trigger",
            "opengrep.cwe-522.gha-persist-credentials-on-untrusted-checkout",
        ],
    }],
}


def _cases() -> list[dict]:
    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    return list(document["cases"])


@pytest.fixture(scope="module")
def scan_findings() -> dict[str, list[dict]]:
    """Whole findings, keyed by fixture path, from the one scanner pass.

    `scan` below reduces these to rule ids, which is all most of the file asks. The findings
    themselves are kept because a `posted` case is a claim about what survives the
    reconciliation, and that needs the line numbers and internal types, not just the ids.
    """
    files = [
        {"path": case["path"], "content": case["code"], "patch": "", "reviewable_line_spans": []}
        for case in _cases()
    ]
    hits: dict[str, list[dict]] = {case["path"]: [] for case in _cases()}
    for finding in run_opengrep(files):
        hits.setdefault(finding["file_path"], []).append(finding)
    return hits


@pytest.fixture(scope="module")
def scan(scan_findings) -> dict[str, set[str]]:
    """Rule ids that fired, keyed by fixture path."""
    return {path: {finding["rule_id"] for finding in findings} for path, findings in scan_findings.items()}


class TestCaseFile:
    def test_every_case_names_a_rule_that_exists(self):
        known = load_rule_metadata()
        for case in _cases():
            for rule in case.get("rules") or [case["rule"]]:
                assert f"opengrep.{rule}" in known, f"{case['id']} names an unknown rule"

    def test_every_posting_coverage_rule_has_a_true_positive_fixture(self):
        """A coverage rule that posts and that no fixture proves is a gap in the benchmark.

        The pre-existing rules in javascript.yml and python.yml are out of scope: they were
        in the tree before the coverage set, and their measurement is the replay.
        """
        covered = {case["rule"] for case in _cases() if case["expect"] == "finding"}
        quarantined = quarantined_rule_ids()
        missing = sorted(
            rule
            for rule in COVERAGE_RULE_IDS
            if f"opengrep.{rule}" not in quarantined and rule not in covered
        )
        assert not missing, f"posting rules with no true-positive fixture: {missing}"


class TestTruePositives:
    @pytest.mark.parametrize("case", [c for c in _cases() if c["expect"] == "finding"], ids=lambda c: c["id"])
    def test_rule_fires_on_its_fixture(self, case, scan):
        fired = scan[case["path"]]
        assert f"opengrep.{case['rule']}" in fired, (
            f"{case['rule']} did not fire on its own fixture; it fired: {sorted(fired) or 'nothing'}"
        )


class TestAQuarantinedRuleNeverPosts:
    """A quarantined rule may fire. What it may not do is arrive.

    The fixtures above are deliberately kept for quarantined rules, because a quarantined rule
    is expected to earn its way back and the fixture is what the re-enabling is measured
    against. That means the benchmark holds live code that several quarantined rules match, and
    it is the right place to assert the rest of the contract: those matches are removed by
    `main.partition_by_posting_policy` before a response is built, so nothing is posted to
    GitHub, nothing reaches the check summary and nothing is handed to remediation.

    Without this the gate would pass on the day someone flipped a `posting` key by accident.
    """

    def test_the_fixtures_do_produce_quarantined_findings(self):
        """Otherwise the assertion below is vacuous."""
        quarantined = quarantined_rule_ids()
        assert quarantined, "no rule is quarantined, so this class asserts nothing"
        matched = {
            case["rule"]
            for case in _cases()
            if case["expect"] == "finding" and f"opengrep.{case['rule']}" in quarantined
        }
        assert matched, "no fixture covers a quarantined rule, so this class asserts nothing"

    def test_nothing_quarantined_survives_the_posting_policy(self, scan):
        quarantined = quarantined_rule_ids()
        findings = [
            {"rule_id": rule_id, "file_path": path}
            for path, rule_ids in scan.items()
            for rule_id in rule_ids
        ]
        postable, withheld = partition_by_posting_policy(findings)
        leaked = sorted({f["rule_id"] for f in postable} & quarantined)
        assert not leaked, (
            f"{leaked} fired on a benchmark fixture and survived the posting policy; a "
            "quarantined rule must never reach a reviewer"
        )
        # And the removal is real rather than a relabelling: what was dropped is exactly the
        # quarantined matches, so no posting rule was lost with them.
        assert {f["rule_id"] for f in withheld} <= quarantined


class TestWhatIsPosted:
    """A `posted` case checks the comments a reviewer receives, not the rules that matched.

    Every other class here stops at the scanner. That is the wrong altitude for a rule whose
    findings are reconciled against another rule's afterwards: two rules can both be right about
    one `actions/checkout` step, and what the benchmark has to pin down is that the step draws one
    comment rather than two. So these cases replay the production order from
    `main.analyze_*`: the posting policy first, then the test-code classification, then
    `cluster_findings`, whose last act is the directional fold in
    `finding_quality._apply_subsumption`.
    """

    @staticmethod
    def _posted(findings: list[dict]) -> list[dict]:
        postable, _ = partition_by_posting_policy(findings)
        return cluster_findings(classify_findings(postable))

    @pytest.mark.parametrize("case", [c for c in _cases() if c.get("posted")], ids=lambda c: c["id"])
    def test_the_expected_findings_reach_the_reviewer(self, case, scan_findings):
        posted = self._posted(scan_findings[case["path"]])
        expected = CURRENT_POSTED_EXPECTATIONS.get(case["id"], case["posted"])

        assert [finding["rule_id"] for finding in posted] == [
            f"opengrep.{entry['rule']}" for entry in expected
        ], f"{case['id']}: the fixture posted {[f['rule_id'] for f in posted]}"

        for finding, entry in zip(posted, expected):
            if entry["merged_rule_ids"] is None:
                assert "merged_rule_ids" not in finding, (
                    f"{case['id']}: {finding['rule_id']} was reconciled with something, and this "
                    "case says it fires on its own"
                )
                continue
            assert finding["merged_rule_ids"] == entry["merged_rule_ids"]
            # The union has to survive the gRPC contract, and `evidence_details.extra` is the one
            # map on a finding that does. Remediation reads the rule ids from there.
            assert finding["evidence_details"]["extra"]["merged_rule_ids"] == entry["merged_rule_ids"]

    @pytest.mark.parametrize("case", [c for c in _cases() if c.get("posted")], ids=lambda c: c["id"])
    def test_every_admitted_rule_that_matched_is_named_by_something_posted(self, case, scan_findings):
        """Nothing admitted is folded away silently; withheld evidence is not published.

        A rule dropped by the reconciliation still has to appear in a survivor's
        `merged_rule_ids`, because the evidence is the only record that it matched.
        """
        admitted, withheld = partition_by_posting_policy(scan_findings[case["path"]])
        matched = {finding["rule_id"] for finding in admitted}
        posted = self._posted(scan_findings[case["path"]])
        accounted = {
            rule_id
            for finding in posted
            for rule_id in (finding.get("merged_rule_ids") or [finding["rule_id"]])
        }
        assert matched <= accounted, f"{case['id']}: {sorted(matched - accounted)} vanished"
        assert not {finding["rule_id"] for finding in withheld} & accounted

    @pytest.mark.parametrize("case", [c for c in _cases() if c.get("posted")], ids=lambda c: c["id"])
    def test_raw_reconciliation_fixture_still_holds_without_claiming_publication(self, case, scan_findings):
        reconciled = cluster_findings(classify_findings(scan_findings[case["path"]]))
        assert [finding["rule_id"] for finding in reconciled] == [
            f"opengrep.{entry['rule']}" for entry in case["posted"]
        ]
        for finding, entry in zip(reconciled, case["posted"]):
            assert finding.get("merged_rule_ids") == entry["merged_rule_ids"]


class TestNoFindingLines:
    @pytest.mark.parametrize("case", [c for c in _cases() if c["expect"] == "no-finding"], ids=lambda c: c["id"])
    def test_narrowed_rule_stays_silent(self, case, scan):
        """A line the September 2026 replay raised a false positive on.

        The rule named here was narrowed because of this exact line. If it fires again the
        narrowing has been undone, and the rule's measured precision no longer describes it.
        """
        fired = scan[case["path"]]
        unwanted = sorted(f"opengrep.{rule}" for rule in case["rules"] if f"opengrep.{rule}" in fired)
        assert not unwanted, f"{case['id']}: {unwanted} fired on a line they were narrowed away from"
