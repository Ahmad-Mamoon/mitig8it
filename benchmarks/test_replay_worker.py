from types import SimpleNamespace

from scripts.replay.worker import _admit_quarantined_rules_for_measurement


def test_measurement_admits_only_declared_posting_and_quarantined_rules() -> None:
    analysis_main = SimpleNamespace(
        PUBLICATION_RULE_IDS=frozenset({"rule.post"}),
        QUARANTINED_RULE_IDS=frozenset({"rule.quarantine"}),
    )

    _admit_quarantined_rules_for_measurement(analysis_main)

    assert analysis_main.PUBLICATION_RULE_IDS == frozenset(
        {"rule.post", "rule.quarantine"}
    )
    assert analysis_main.QUARANTINED_RULE_IDS == frozenset()
