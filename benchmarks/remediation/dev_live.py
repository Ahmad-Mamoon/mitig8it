#!/usr/bin/env python3
"""Helpers for evaluating a real model locally under a hard suite budget.

The `engine-live` adapter calls a paid provider. These helpers price the run with the
operator's real prices, cap what one case and the whole suite may spend, and grade a
candidate by the fixture's own trusted check instead of only by byte equality with the
reference patch. Nothing here reads a `.env` file, and no key or URL is ever returned.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Callable, Iterator, Mapping

try:
    from . import evaluate as harness
except ImportError:
    import evaluate as harness

# Mirrors the engine's GROUP_SPEND_FLOOR_USD: below this the engine cannot fund one group,
# so starting the case would only spend money on a run that must abstain.
MIN_CASE_USD = 0.02
# The policy model rejects a price above this, so it is refused here, before any call.
MAX_USD_PER_MTOK = 1000.0
REFERENCE_MISMATCH = "candidate_does_not_match_reference_patch"
REQUIRED_ENV = ("REPAIR_LLM_BASE_URL", "REPAIR_LLM_API_KEY", "REPAIR_LLM_MODEL",
                "REPAIR_LLM_INPUT_USD_PER_MTOK", "REPAIR_LLM_OUTPUT_USD_PER_MTOK")


class LiveConfigError(ValueError):
    """The live provider configuration is unusable. Carries variable names, never values."""


class SuiteBudgetExhausted(RuntimeError):
    """The suite budget cannot fund another case."""


def live_settings(environ: Mapping[str, str] = os.environ) -> dict[str, Any]:
    """The model and its real prices. Prices are mandatory: without them no budget holds."""
    missing = sorted(name for name in REQUIRED_ENV if not str(environ.get(name) or "").strip())
    if missing:
        raise LiveConfigError("missing: " + ", ".join(missing))
    invalid = []
    if not environ["REPAIR_LLM_BASE_URL"].strip().startswith("https://"):
        invalid.append("REPAIR_LLM_BASE_URL")
    prices = {}
    for name in REQUIRED_ENV[3:]:
        try:
            prices[name] = float(environ[name])
        except ValueError:
            prices[name] = math.nan
        # The comparison is written so NaN and infinity are refused too.
        if not 0 < prices[name] <= MAX_USD_PER_MTOK:
            invalid.append(name)
    if invalid:
        raise LiveConfigError("invalid: " + ", ".join(sorted(invalid)))
    return {"model": environ["REPAIR_LLM_MODEL"].strip(),
            "input_usd_per_mtok": prices["REPAIR_LLM_INPUT_USD_PER_MTOK"],
            "output_usd_per_mtok": prices["REPAIR_LLM_OUTPUT_USD_PER_MTOK"]}


def _token_count(value: Any) -> bool:
    # bool is an int in Python, and True must not be billed as one token.
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


class SuiteBudget:
    """Tracks real spend across a suite and hands each case the most it may spend."""

    def __init__(self, max_cost_usd: float, max_case_cost_usd: float,
                 input_usd_per_mtok: float, output_usd_per_mtok: float) -> None:
        for value in (max_cost_usd, max_case_cost_usd, input_usd_per_mtok, output_usd_per_mtok):
            if not _token_count(value) or value <= 0:
                raise ValueError("budget limits and prices must be positive numbers")
        self.max_cost_usd = float(max_cost_usd)
        self.max_case_cost_usd = float(max_case_cost_usd)
        self.input_usd_per_mtok = float(input_usd_per_mtok)
        self.output_usd_per_mtok = float(output_usd_per_mtok)
        self._spent_usd = 0.0

    @property
    def spent_usd(self) -> float:
        return self._spent_usd

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.max_cost_usd - self._spent_usd)

    def case_cap(self) -> float | None:
        cap = min(self.max_case_cost_usd, self.remaining_usd)
        return cap if cap >= MIN_CASE_USD else None

    def settle(self, input_tokens: Any, output_tokens: Any) -> float | None:
        """Add one case's cost at the real prices. Unknown usage stays unknown, never 0."""
        if not _token_count(input_tokens) or not _token_count(output_tokens):
            return None
        cost = (input_tokens * self.input_usd_per_mtok + output_tokens * self.output_usd_per_mtok) / 1_000_000
        self._spent_usd += cost
        return cost

    def reserve_unknown(self) -> float:
        """Charge a started case whose usage was lost its whole cap, so the suite cap still holds."""
        reserved = min(self.max_case_cost_usd, self.remaining_usd)
        self._spent_usd += reserved
        return reserved


def priced_request_builder(original_builder: Callable[..., Any], budget: SuiteBudget) -> Callable[..., Any]:
    """Wrap `build_repair_request` so the engine reserves spend at the real prices.

    The fixture builder hardcodes 1.0 USD per million tokens and the fixture's own ceiling.
    The engine reserves against the policy before each provider call, so the policy is the
    only place a cap is enforced rather than merely reported afterwards.
    """
    def build(*args: Any, **kwargs: Any) -> Any:
        cap = budget.case_cap()
        if cap is None:
            raise SuiteBudgetExhausted("suite budget cannot fund another case")
        request = original_builder(*args, **kwargs)
        policy = request.policy.model_copy(update={
            "input_usd_per_million_tokens": budget.input_usd_per_mtok,
            "output_usd_per_million_tokens": budget.output_usd_per_mtok,
            "max_spend_usd": min(float(request.policy.max_spend_usd), cap),
        })
        return request.model_copy(update={"policy": policy})
    return build


class CandidateCapture:
    """The most recent raw adapter result, which `CaseResult` does not carry."""

    def __init__(self) -> None:
        self.last: dict[str, Any] | None = None

    def reset(self) -> None:
        self.last = None


@contextmanager
def capture_candidates() -> Iterator[CandidateCapture]:
    """Record what `engine_local_adapter` returns while `evaluate_fixture` runs."""
    capture = CandidateCapture()
    original = harness.engine_local_adapter

    def recording(*args: Any, **kwargs: Any) -> Any:
        # Cleared first, so a raised adapter never leaves the previous case's candidates.
        capture.last = None
        result = original(*args, **kwargs)
        capture.last = result if isinstance(result, dict) else None
        return result

    harness.engine_local_adapter = recording
    try:
        yield capture
    finally:
        harness.engine_local_adapter = original


def _check(status: str, reason: str | None = None) -> dict[str, Any]:
    return {"status": status, "reason": reason}


def candidate_trusted_check(fixture_dir: Path, fixture: dict[str, Any], candidates: Any) -> dict[str, Any]:
    """Run the fixture's trusted test against the model's files instead of the reference.

    Only a status and a short code come back. The test's stdout and stderr can echo
    model-written text, so they are neither returned nor written anywhere.
    """
    if fixture.get("kind") != "supported":
        return _check("not_run", "fixture_not_supported")
    if not candidates:
        return _check("not_run", "no_candidates")
    if not isinstance(candidates, list):
        return _check("failed", "candidate_malformed")
    produced: dict[str, str] = {}
    for item in candidates:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return _check("failed", "candidate_malformed")
        if item["path"] in produced:
            return _check("failed", "candidate_duplicate_path")
        if not isinstance(item.get("replacement_content"), str):
            return _check("failed", "candidate_content_not_text")
        produced[item["path"]] = item["replacement_content"]
    sources = [unit["source"] for unit in harness.fixture_units(fixture)]
    # Exactly the audited unit paths: a partial repair or an extra file is not this fixture's repair.
    if set(sources) - set(produced):
        return _check("failed", "candidate_missing_file")
    if set(produced) - set(sources):
        return _check("failed", "candidate_extra_file")
    test = fixture["trusted_fixture_test"]
    with tempfile.TemporaryDirectory(prefix="dev-live-candidate-") as temporary:
        root = Path(temporary).resolve()
        try:
            script = harness.resolve_fixture_path(fixture_dir, test["path"])
            pairs: list[str] = []
            for source in sources:
                target = harness.resolve_fixture_path(root, source)
                target.parent.mkdir(parents=True, exist_ok=True)
                # newline="" keeps the model's line endings byte for byte.
                with open(target, "w", encoding="utf-8", newline="") as handle:
                    handle.write(produced[source])
                pairs += [str(harness.resolve_fixture_path(fixture_dir, source)), str(target)]
        except (harness.FixtureError, OSError, UnicodeEncodeError):
            return _check("failed", "candidate_not_writable")
        try:
            # Same argv shape, env, cwd and timeout as harness.run_trusted_fixture_test.
            completed = subprocess.run(
                [*harness.FIXTURE_TEST_RUNTIMES[test["runtime"]], str(script), *pairs],
                cwd=fixture_dir,
                env={"PATH": os.environ.get("PATH", ""), "NODE_OPTIONS": "--disable-proto=throw", "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=int(test.get("timeout_seconds", 5)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _check("failed", "trusted_check_timeout")
        except OSError:
            # A missing runtime says nothing about the candidate.
            return _check("not_run", "trusted_check_unavailable")
    if completed.returncode != 0:
        return _check("failed", "trusted_check_nonzero_exit")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _check("failed", "trusted_check_invalid_json")
    if not isinstance(report, dict):
        return _check("failed", "trusted_check_invalid_json")
    if report.get("vulnerability_observed") is not True:
        return _check("failed", "vulnerability_not_observed")
    if report.get("behavior_preserved") is not True:
        return _check("failed", "behavior_not_preserved")
    return _check("passed")


def grade_live(row: dict[str, Any], check: dict[str, Any]) -> dict[str, Any]:
    """A new row that says which evidence decided the outcome.

    The harness fails any repair that is not byte-identical to the reference. A real model
    rarely writes the reference, so exactly that one failure is upgraded when the trusted
    check passes. Every other failure keeps the harness verdict, and a negative or
    adversarial case is never upgraded: there the correct result is abstention.
    """
    graded = {**row, "candidate_check": dict(check)}
    if row.get("outcome") == "passed":
        graded["graded_by"] = "reference_match"
    elif (row.get("kind") == "supported" and row.get("outcome") == "failed"
          and row.get("reason") == REFERENCE_MISMATCH and check.get("status") == "passed"):
        graded.update(outcome="passed", reason=None, graded_by="trusted_fixture_check")
    else:
        graded["graded_by"] = "harness"
    return graded


def live_scores(row: dict[str, Any]) -> dict[str, int]:
    """Numeric scores for a graded row. A check that did not run is omitted, never scored 0."""
    scores: dict[str, int] = {}
    if row.get("kind") != "supported":
        return scores
    scores["reference_match"] = int(row.get("graded_by") == "reference_match")
    status = (row.get("candidate_check") or {}).get("status")
    if status in {"passed", "failed"}:
        scores["trusted_check_passed"] = int(status == "passed")
    return scores


def step_summary(evidence: Any) -> list[str]:
    """The agent's tool sequence as `tool:outcome[:reason_code]`, with no arguments or paths."""
    steps = []
    trace = evidence.get("agent_trace") if isinstance(evidence, dict) else None
    for step in trace if isinstance(trace, list) else []:
        if not isinstance(step, dict):
            continue
        parts = [str(step.get("tool")), str(step.get("outcome"))]
        if isinstance(step.get("reason"), str):
            # A rejection reason is `code:detail`, and the detail can quote a model-chosen path.
            parts.append(step["reason"].split(":", 1)[0])
        steps.append(":".join(parts))
    return steps


def traced_backend(base: type, sink: list) -> type:
    """A backend subclass that records each persisted result's step summary into `sink`.

    The adapter returns only state, reason and usage, so why a live case failed is otherwise
    lost when the temporary execution store is removed.
    """
    class TracedBackend(base):  # type: ignore[misc, valid-type]
        def read_result(self, record: Any) -> Any:
            result = super().read_result(record)
            sink.append(step_summary(getattr(result, "evidence", None)))
            return result

    return TracedBackend
