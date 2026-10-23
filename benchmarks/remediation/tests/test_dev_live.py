"""Live-evaluation helpers: budget, pricing, capture and grading. No network, no keys."""
import unittest
from unittest.mock import patch

from benchmarks.remediation import dev_live

harness = dev_live.harness

ENV = {"REPAIR_LLM_BASE_URL": "https://provider.invalid/v1", "REPAIR_LLM_API_KEY": "fake-key-value",
       "REPAIR_LLM_MODEL": "fake-model", "REPAIR_LLM_INPUT_USD_PER_MTOK": "0.25",
       "REPAIR_LLM_OUTPUT_USD_PER_MTOK": "2"}
FIXTURES = {path.name: (path, fixture) for path, fixture in harness.load_fixtures()}


def env(**changes):
    value = dict(ENV)
    value.update(changes)
    return {key: item for key, item in value.items() if item is not None}


def budget(max_cost_usd=1.0, max_case_cost_usd=0.25):
    return dev_live.SuiteBudget(max_cost_usd, max_case_cost_usd, 0.25, 2.0)


def row(**changes):
    value = dict(fixture_id="python-sql-sqlite-001", kind="supported", expected_state="ready",
                 observed_state="ready", outcome="failed", reason=dev_live.REFERENCE_MISMATCH,
                 usage={"input_tokens": 10, "output_tokens": 5})
    value.update(changes)
    return value


def candidates_from(name, repaired):
    """The reference repair, or the unrepaired source, shaped like the adapter's candidates."""
    fixture_dir, fixture = FIXTURES[name]
    items = []
    for unit in harness.fixture_units(fixture):
        relative = unit["reference_repair"] if repaired else unit["source"]
        content = harness.resolve_fixture_path(fixture_dir, relative).read_text(encoding="utf-8")
        items.append({"path": unit["source"], "replacement_content": content})
    return fixture_dir, fixture, items


class LiveSettingsTests(unittest.TestCase):
    def test_returns_model_and_prices_but_never_key_or_url(self):
        settings = dev_live.live_settings(env())
        self.assertEqual(settings, {"model": "fake-model", "input_usd_per_mtok": 0.25, "output_usd_per_mtok": 2.0})
        self.assertNotIn("fake-key-value", repr(settings))
        self.assertNotIn("provider.invalid", repr(settings))

    def test_missing_variables_are_named_and_prices_are_not_defaulted(self):
        with self.assertRaises(dev_live.LiveConfigError) as raised:
            dev_live.live_settings(env(REPAIR_LLM_INPUT_USD_PER_MTOK=None, REPAIR_LLM_API_KEY=""))
        self.assertIn("REPAIR_LLM_INPUT_USD_PER_MTOK", str(raised.exception))
        self.assertIn("REPAIR_LLM_API_KEY", str(raised.exception))
        self.assertNotIn("REPAIR_LLM_MODEL", str(raised.exception))
        self.assertIsInstance(raised.exception, ValueError)

    def test_invalid_values_are_named_without_echoing_any_value(self):
        for name, bad in (("REPAIR_LLM_BASE_URL", "http://insecure.invalid/secret-path"),
                          ("REPAIR_LLM_INPUT_USD_PER_MTOK", "free"),
                          ("REPAIR_LLM_OUTPUT_USD_PER_MTOK", "0"),
                          ("REPAIR_LLM_OUTPUT_USD_PER_MTOK", "-1"),
                          ("REPAIR_LLM_INPUT_USD_PER_MTOK", "nan"),
                          ("REPAIR_LLM_INPUT_USD_PER_MTOK", "inf")):
            with self.subTest(name=name, bad=bad), self.assertRaises(dev_live.LiveConfigError) as raised:
                dev_live.live_settings(env(**{name: bad}))
            message = str(raised.exception)
            self.assertIn(name, message)
            self.assertNotIn("insecure.invalid", message)
            self.assertNotIn("fake-key-value", message)


class SuiteBudgetTests(unittest.TestCase):
    def test_settle_charges_real_prices_and_reduces_the_cap(self):
        suite = budget(max_cost_usd=0.30, max_case_cost_usd=0.25)
        self.assertEqual(suite.case_cap(), 0.25)
        cost = suite.settle(400_000, 50_000)
        self.assertAlmostEqual(cost, 0.2)
        self.assertAlmostEqual(suite.spent_usd, 0.2)
        self.assertAlmostEqual(suite.remaining_usd, 0.1)
        self.assertAlmostEqual(suite.case_cap(), 0.1)

    def test_cap_is_none_below_the_engine_floor(self):
        suite = budget(max_cost_usd=0.21, max_case_cost_usd=0.25)
        suite.settle(400_000, 50_000)
        self.assertLess(suite.remaining_usd, dev_live.MIN_CASE_USD)
        self.assertIsNone(suite.case_cap())
        suite.settle(4_000_000, 0)
        self.assertEqual(suite.remaining_usd, 0.0)

    def test_unknown_usage_stays_unknown(self):
        suite = budget()
        for pair in ((None, 5), (5, None), ("12", 5), (True, 5), (float("nan"), 5), (-1, 5)):
            with self.subTest(pair=pair):
                self.assertIsNone(suite.settle(*pair))
        self.assertEqual(suite.spent_usd, 0.0)
        self.assertEqual(suite.settle(0, 0), 0.0)

    def test_floor_matches_the_engine(self):
        harness.load_service_modules()
        from src.engine import GROUP_SPEND_FLOOR_USD  # noqa: PLC0415 - service path set above.
        self.assertEqual(dev_live.MIN_CASE_USD, GROUP_SPEND_FLOOR_USD)


class PricedRequestBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = harness.load_service_modules()
        cls.fixture_dir, cls.fixture = FIXTURES["js-sql-pg-template"]

    def build(self, suite):
        builder = dev_live.priced_request_builder(self.modules["build_repair_request"], suite)
        return builder(self.fixture_dir, self.fixture, versions={"benchmark": "fixture-development-v1"})

    def test_real_request_carries_real_prices_and_the_case_cap(self):
        original = self.modules["build_repair_request"](self.fixture_dir, self.fixture)
        request = self.build(budget())
        self.assertEqual(request.policy.input_usd_per_million_tokens, 0.25)
        self.assertEqual(request.policy.output_usd_per_million_tokens, 2.0)
        self.assertEqual(request.policy.max_spend_usd, 0.25)
        self.assertEqual(request.versions, {"benchmark": "fixture-development-v1"})
        # Everything outside the three priced fields is the fixture's own request.
        priced = {"input_usd_per_million_tokens", "output_usd_per_million_tokens", "max_spend_usd"}
        self.assertEqual(request.policy.model_dump(exclude=priced), original.policy.model_dump(exclude=priced))
        self.assertEqual(request.model_dump(exclude={"policy", "versions"}), original.model_dump(exclude={"policy", "versions"}))
        # The original is untouched, and the copy survives the model's own validators.
        self.assertEqual(original.policy.max_spend_usd, 2.0)
        revalidated = type(request).model_validate(request.model_dump())
        self.assertEqual(revalidated.policy.max_spend_usd, 0.25)

    def test_cap_never_raises_the_fixture_ceiling_and_follows_the_remainder(self):
        self.assertEqual(self.build(budget(max_cost_usd=50, max_case_cost_usd=10)).policy.max_spend_usd, 2.0)
        suite = budget(max_cost_usd=0.30, max_case_cost_usd=0.25)
        suite.settle(400_000, 50_000)
        self.assertAlmostEqual(self.build(suite).policy.max_spend_usd, 0.1)

    def test_exhausted_budget_refuses_before_building(self):
        suite = budget(max_cost_usd=0.21)
        suite.settle(400_000, 50_000)
        calls = []
        builder = dev_live.priced_request_builder(lambda *a, **k: calls.append(a), suite)
        with self.assertRaises(dev_live.SuiteBudgetExhausted):
            builder(self.fixture_dir, self.fixture)
        self.assertEqual(calls, [])


class CaptureCandidatesTests(unittest.TestCase):
    def test_records_latest_result_and_restores_the_adapter(self):
        results = iter([{"state": "ready", "candidates": [{"path": "a"}]}, {"state": "unsupported"}])
        with patch.object(harness, "engine_local_adapter", lambda *a, **k: next(results)) as fake:
            with dev_live.capture_candidates() as capture:
                self.assertIsNone(capture.last)
                self.assertIsNot(harness.engine_local_adapter, fake)
                harness.engine_local_adapter("dir", {}, {}, "state", "kind")
                self.assertEqual(capture.last["candidates"], [{"path": "a"}])
                harness.engine_local_adapter("dir", {}, {}, "state", "kind")
                self.assertEqual(capture.last, {"state": "unsupported"})
                capture.reset()
                self.assertIsNone(capture.last)
            self.assertIs(harness.engine_local_adapter, fake)

    def test_restores_on_error_and_never_keeps_a_stale_result(self):
        original = harness.engine_local_adapter
        outcomes = iter([{"state": "ready"}, RuntimeError("boom")])

        def fake(*args, **kwargs):
            item = next(outcomes)
            if isinstance(item, Exception):
                raise item
            return item

        with patch.object(harness, "engine_local_adapter", fake):
            with self.assertRaises(RuntimeError):
                with dev_live.capture_candidates() as capture:
                    harness.engine_local_adapter()
                    harness.engine_local_adapter()
            self.assertIsNone(capture.last)
            self.assertIs(harness.engine_local_adapter, fake)
        self.assertIs(harness.engine_local_adapter, original)

    def test_evaluate_fixture_goes_through_the_capture(self):
        fixture_dir, fixture, items = candidates_from("python-sql-sqlite", repaired=True)
        result = {"state": "ready", "candidates": items, "usage": {}, "verification_level": "development_unverified"}
        with patch.object(harness, "engine_local_adapter", lambda *a, **k: result):
            with dev_live.capture_candidates() as capture:
                case = harness.evaluate_fixture(fixture_dir, fixture, "engine-live", None,
                                                {"modules": {}, "state_dir": None, "provider_kind": "live-provider"})
        self.assertEqual(case.outcome, "passed")
        self.assertEqual(capture.last["candidates"], items)


class CandidateTrustedCheckTests(unittest.TestCase):
    def test_reference_repair_passes_and_unrepaired_source_fails(self):
        for name in ("python-sql-sqlite", "js-sql-pg-template", "multi-file-batch"):
            with self.subTest(fixture=name):
                fixture_dir, fixture, repaired = candidates_from(name, repaired=True)
                self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, repaired),
                                 {"status": "passed", "reason": None})
                _, _, unrepaired = candidates_from(name, repaired=False)
                check = dev_live.candidate_trusted_check(fixture_dir, fixture, unrepaired)
                self.assertEqual(check["status"], "failed")
                self.assertIn(check["reason"], {"trusted_check_nonzero_exit", "vulnerability_not_observed",
                                                "behavior_not_preserved"})
                self.assertEqual(set(check), {"status", "reason"})

    def test_two_unit_fixture_needs_both_files_in_any_order(self):
        fixture_dir, fixture, repaired = candidates_from("multi-file-batch", repaired=True)
        self.assertEqual(len(repaired), 2)
        self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, repaired[::-1])["status"], "passed")
        self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, repaired[:1]),
                         {"status": "failed", "reason": "candidate_missing_file"})

    def test_candidate_shape_is_checked_before_anything_runs(self):
        fixture_dir, fixture, repaired = candidates_from("python-sql-sqlite", repaired=True)
        item = repaired[0]
        cases = {
            "candidate_extra_file": [item, {"path": "tests/verify.py", "replacement_content": "x"}],
            "candidate_duplicate_path": [item, dict(item)],
            "candidate_content_not_text": [{"path": item["path"], "replacement_content": None}],
            "candidate_missing_file": [{"path": "other.py", "replacement_content": "x"}],
            "candidate_malformed": [{"replacement_content": "x"}],
        }
        with patch.object(dev_live.subprocess, "run", side_effect=AssertionError("must not run")):
            for reason, candidates in cases.items():
                with self.subTest(reason=reason):
                    self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, candidates),
                                     {"status": "failed", "reason": reason})
            self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, "app.py")["reason"], "candidate_malformed")

    def test_not_run_without_candidates_or_for_unsupported_kinds(self):
        fixture_dir, fixture, repaired = candidates_from("python-sql-sqlite", repaired=True)
        for empty in ([], None):
            self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, empty),
                             {"status": "not_run", "reason": "no_candidates"})
        adversarial_dir, adversarial = FIXTURES["adversarial-readme"]
        self.assertEqual(dev_live.candidate_trusted_check(adversarial_dir, adversarial, repaired),
                         {"status": "not_run", "reason": "fixture_not_supported"})

    def test_candidate_is_written_outside_the_fixture_and_removed(self):
        fixture_dir, fixture, repaired = candidates_from("python-sql-sqlite", repaired=True)
        before = sorted(str(path) for path in fixture_dir.rglob("*") if "__pycache__" not in path.parts)
        seen = {}
        real_run = dev_live.subprocess.run

        def spy(argv, **kwargs):
            seen.update(argv=argv, kwargs=kwargs)
            return real_run(argv, **kwargs)

        with patch.object(dev_live.subprocess, "run", spy):
            self.assertEqual(dev_live.candidate_trusted_check(fixture_dir, fixture, repaired)["status"], "passed")
        original, candidate = map(dev_live.Path, seen["argv"][-2:])
        self.assertEqual(original, fixture_dir.resolve() / "app.py")
        self.assertEqual(candidate.name, "app.py")
        self.assertNotIn(fixture_dir.resolve(), candidate.parents)
        self.assertFalse(candidate.exists())
        self.assertEqual(seen["kwargs"]["cwd"], fixture_dir)
        self.assertEqual(seen["kwargs"]["timeout"], 10)
        self.assertEqual(set(seen["kwargs"]["env"]), {"PATH", "NODE_OPTIONS", "PYTHONDONTWRITEBYTECODE"})
        self.assertEqual(before, sorted(str(path) for path in fixture_dir.rglob("*") if "__pycache__" not in path.parts))

    def test_process_failures_become_codes_and_output_is_never_returned(self):
        fixture_dir, fixture, repaired = candidates_from("python-sql-sqlite", repaired=True)
        completed = lambda code, out: dev_live.subprocess.CompletedProcess([], code, out, "SECRET-STDERR")  # noqa: E731
        good = '{"vulnerability_observed": true, "behavior_preserved": true, "note": "SECRET-STDOUT"}'
        outcomes = [
            (completed(0, good), "passed", None),
            (completed(1, good), "failed", "trusted_check_nonzero_exit"),
            (completed(0, "SECRET-STDOUT not json"), "failed", "trusted_check_invalid_json"),
            (completed(0, "[]"), "failed", "trusted_check_invalid_json"),
            (completed(0, '{"vulnerability_observed": false, "behavior_preserved": true}'), "failed", "vulnerability_not_observed"),
            (completed(0, '{"vulnerability_observed": true, "behavior_preserved": "yes"}'), "failed", "behavior_not_preserved"),
            (dev_live.subprocess.TimeoutExpired("cmd", 1, output="SECRET-STDOUT"), "failed", "trusted_check_timeout"),
            (FileNotFoundError("SECRET-STDERR"), "not_run", "trusted_check_unavailable"),
        ]
        for outcome, status, reason in outcomes:
            with self.subTest(reason=reason):
                effect = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
                with patch.object(dev_live.subprocess, "run", **effect):
                    check = dev_live.candidate_trusted_check(fixture_dir, fixture, repaired)
                self.assertEqual(check, {"status": status, "reason": reason})
                self.assertNotIn("SECRET", repr(check))


class GradeLiveTests(unittest.TestCase):
    PASSED = {"status": "passed", "reason": None}
    FAILED = {"status": "failed", "reason": "trusted_check_nonzero_exit"}
    NOT_RUN = {"status": "not_run", "reason": "no_candidates"}

    def test_reference_match_is_kept(self):
        original = row(outcome="passed", reason=None)
        graded = dev_live.grade_live(original, self.PASSED)
        self.assertEqual((graded["outcome"], graded["graded_by"]), ("passed", "reference_match"))
        self.assertEqual(graded["candidate_check"], self.PASSED)
        self.assertNotIn("graded_by", original)
        self.assertEqual(dev_live.live_scores(graded), {"reference_match": 1, "trusted_check_passed": 1})

    def test_reference_mismatch_is_upgraded_only_by_a_passing_check(self):
        original = row()
        graded = dev_live.grade_live(original, self.PASSED)
        self.assertEqual((graded["outcome"], graded["reason"], graded["graded_by"]),
                         ("passed", None, "trusted_fixture_check"))
        self.assertEqual((original["outcome"], original["reason"]), ("failed", dev_live.REFERENCE_MISMATCH))
        self.assertEqual(dev_live.live_scores(graded), {"reference_match": 0, "trusted_check_passed": 1})
        for check in (self.FAILED, self.NOT_RUN):
            with self.subTest(check=check):
                kept = dev_live.grade_live(row(), check)
                self.assertEqual((kept["outcome"], kept["reason"], kept["graded_by"]),
                                 ("failed", dev_live.REFERENCE_MISMATCH, "harness"))

    def test_other_failures_are_never_upgraded(self):
        for reason in ("fixed_budget_exceeded", "no_verified_candidate", "unexpected_verification_level:none",
                       "trusted_fixture_reference_check_failed", None):
            with self.subTest(reason=reason):
                graded = dev_live.grade_live(row(reason=reason), self.PASSED)
                self.assertEqual((graded["outcome"], graded["reason"], graded["graded_by"]), ("failed", reason, "harness"))

    def test_negative_and_adversarial_cases_are_never_upgraded(self):
        for kind in sorted(harness.NEGATIVE_KINDS):
            with self.subTest(kind=kind):
                graded = dev_live.grade_live(row(kind=kind), self.PASSED)
                self.assertEqual((graded["outcome"], graded["graded_by"]), ("failed", "harness"))
                self.assertEqual(dev_live.live_scores(graded), {})

    def test_scores_omit_a_check_that_did_not_run(self):
        self.assertEqual(dev_live.live_scores(dev_live.grade_live(row(), self.NOT_RUN)), {"reference_match": 0})
        self.assertEqual(dev_live.live_scores(dev_live.grade_live(row(), self.FAILED)),
                         {"reference_match": 0, "trusted_check_passed": 0})

    def test_the_check_is_copied_into_the_row(self):
        check = dict(self.PASSED)
        graded = dev_live.grade_live(row(), check)
        check["status"] = "failed"
        self.assertEqual(graded["candidate_check"]["status"], "passed")


class TraceSummaryTests(unittest.TestCase):
    def test_summary_keeps_codes_and_drops_arguments_and_model_chosen_paths(self):
        evidence = {"agent_trace": [
            {"tool": "read_file", "outcome": "ok", "reason": None, "arguments_digest_only": {"paths": ["secret.py"]}},
            {"tool": "propose_patch", "outcome": "rejected", "reason": "regression_test_outside_generated_directory:evil/path.js"},
            "not-a-step"]}
        steps = dev_live.step_summary(evidence)
        self.assertEqual(steps, ["read_file:ok", "propose_patch:rejected:regression_test_outside_generated_directory"])
        self.assertEqual(dev_live.step_summary(None), [])

    def test_traced_backend_records_each_result_and_returns_it_unchanged(self):
        class Base:
            def read_result(self, record):
                return type("Result", (), {"evidence": {"agent_trace": [{"tool": "abstain", "outcome": "abstained", "reason": "x:y"}]}})()
        sink = []
        result = dev_live.traced_backend(Base, sink)().read_result(None)
        self.assertEqual(sink, [["abstain:abstained:x"]])
        self.assertTrue(hasattr(result, "evidence"))


if __name__ == "__main__":
    unittest.main()
