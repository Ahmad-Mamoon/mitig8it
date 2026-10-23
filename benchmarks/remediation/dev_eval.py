#!/usr/bin/env python3
"""Observe, evaluate, compare locally; explicitly opt in to metadata-only LangSmith upload.

The default adapters call no model: scripted engine results measure pipeline integrity,
not repair quality. `--adapter engine-live` is the explicit, budgeted real-model mode.
This module is deliberately outside the production services.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
import shutil
from pathlib import Path
import sys
import subprocess
import tempfile
import uuid

try:
    from . import evaluate as harness
except ImportError:
    import evaluate as harness

SCHEMA_VERSION = "dev-eval-v1"
DEFAULT_OUTPUT = harness.ROOT.parent / "results" / "dev-eval.json"
DEFAULT_ENV_FILE = harness.ROOT / ".env"
ENV_FILE_PREFIXES = ("LANGSMITH_", "LANGCHAIN_", "REPAIR_LLM_")


def parse_env_file(path: Path) -> dict:
    """Read simple KEY=VALUE lines; a missing file yields nothing."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError):
        return {}
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


@contextmanager
def local_env_file(path: Path):
    """Apply allowlisted development keys from a gitignored file; yield applied key names only.

    The inherited environment is authoritative: a variable already set to a non-empty
    value is never replaced. Applied keys are removed or restored on exit.
    """
    updates = {key: value for key, value in parse_env_file(Path(path)).items()
               if key.startswith(ENV_FILE_PREFIXES) and value and not os.environ.get(key)}
    before = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield sorted(updates)
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def local_observation_only():
    """Prevent inherited tracing configuration from silently exporting local runs."""
    overrides = {key: "" for key in os.environ if key.startswith("OTEL_EXPORTER_")}
    overrides.update({"OTEL_EXPORTER_OTLP_ENDPOINT": "", "OTEL_SDK_DISABLED": "true",
                 "ANALYSIS_SERVICE_URL": "", "ANALYSIS_SERVICE_INTERNAL_SECRET": "",
                 "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
                 "LANGCHAIN_TRACING": "false"})
    before = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def local_scanner_runtime(state_dir: Path):
    """Use writable ephemeral scanner state and the checkout's installed scanner.

    A trusted certifi CA bundle supplies trust anchors on hosts where the native
    scanner cannot read the OS store. TLS verification is never disabled.
    Explicit scanner state/CA environment values remain authoritative.
    """
    updates = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    for key, filename in (("SEMGREP_LOG_FILE", "semgrep.log"),
                          ("SEMGREP_SETTINGS_FILE", "semgrep-settings.yml")):
        if not os.environ.get(key):
            updates[key] = str(state_dir / filename)
    if not os.environ.get("SSL_CERT_FILE"):
        try:
            import certifi
            if Path(certifi.where()).is_file():
                updates["SSL_CERT_FILE"] = certifi.where()
        except ImportError:
            pass
    scanner_bin = harness.REPOSITORY_ROOT / ".venv" / "analysis" / "bin"
    if (scanner_bin / "semgrep").is_file():
        updates["PATH"] = str(scanner_bin) + os.pathsep + os.environ.get("PATH", "")
    before = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def deterministic_scores(case: dict) -> dict:
    passed = case.get("outcome") == "passed"
    scores = {"outcome_match": int(passed)}
    if case.get("kind") in harness.NEGATIVE_KINDS:
        scores["safe_abstention"] = int(passed and case.get("observed_state") == "unsupported")
    elif case.get("kind") == "supported":
        scores["repair_correct"] = int(passed)
        levels = {level: index + 1 for index, level in enumerate(harness.VERIFICATION_LEVEL_ORDER)}
        scores["verification_strength"] = levels.get(case.get("verification_level"), 0)
    return scores


def compare_baseline(report: dict, baseline: dict) -> dict:
    """Refuse incompatible provenance; missing coverage and weaker evidence fail."""
    mismatches = [key for key in ("schema_version", "adapter", "provider_kind", "results_kind", "fixture_digest")
                  if not report.get(key) or report.get(key) != baseline.get(key)]
    if mismatches:
        return {"comparable": False, "incompatible_fields": mismatches, "regressions": [], "improvements": []}
    old = {row["fixture_id"]: row for row in baseline["results"]}
    new = {row["fixture_id"]: row for row in report["results"]}
    if not old or len(old) != len(baseline["results"]) or len(new) != len(report["results"]):
        return {"comparable": False, "incompatible_fields": ["invalid_case_identity"],
                "regressions": [], "improvements": []}
    regressions, improvements = [], []
    for fixture_id, previous in old.items():
        current = new.get(fixture_id)
        reasons = []
        if current is None:
            reasons.append("missing_case")
        else:
            if previous["outcome"] == "passed" and current["outcome"] != "passed":
                reasons.append("outcome_regressed")
            old_strength = deterministic_scores(previous).get("verification_strength", 0)
            new_strength = deterministic_scores(current).get("verification_strength", 0)
            if new_strength < old_strength:
                reasons.append("verification_weakened")
            if previous["outcome"] != "passed" and current["outcome"] == "passed":
                improvements.append(fixture_id)
        if reasons:
            regressions.append({"fixture_id": fixture_id, "reasons": reasons})
    return {"comparable": True, "incompatible_fields": [], "regressions": regressions,
            "improvements": improvements, "added_cases": sorted(new.keys() - old.keys())}


def fixture_digest(fixtures: list) -> str:
    # Include checked-in source/tests, not just metadata: changing an oracle changes the experiment.
    digest = hashlib.sha256()
    for directory, fixture in fixtures:
        digest.update(fixture["id"].encode())
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                digest.update(path.relative_to(directory).as_posix().encode())
                digest.update(path.read_bytes())
    return digest.hexdigest()


def scanner_preflight() -> dict:
    """Diagnose the exact local scanner executable without changing verification outcomes."""
    executable = shutil.which("semgrep")
    if executable is None:
        return {"status": "unavailable", "reason": "scanner_not_on_path", "executable": None}
    try:
        completed = subprocess.run([executable, "--version", "--metrics=off", "--disable-version-check"],
                                   capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "scanner_startup_timeout", "executable": executable}
    except OSError:
        return {"status": "failed", "reason": "scanner_startup_error", "executable": executable}
    if completed.returncode == 0:
        return {"status": "available", "executable": executable}
    # Classify known environment failures; never persist arbitrary scanner stderr.
    stderr = completed.stderr or ""
    reason = "scanner_startup_failed"
    if "empty trust anchors" in stderr:
        reason = "scanner_certificate_store_unavailable"
    elif "PermissionError" in stderr or "Permission denied" in stderr:
        reason = "scanner_local_file_permission_denied"
    return {"status": "failed", "reason": reason, "executable": executable,
            "exit_code": completed.returncode}


def git_provenance() -> dict:
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=harness.REPOSITORY_ROOT,
                                  capture_output=True, text=True, check=True, timeout=5).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=harness.REPOSITORY_ROOT,
                               capture_output=True, text=True, check=True, timeout=5).stdout
        return {"git_revision": revision, "git_dirty": bool(dirty), "evaluator_version": SCHEMA_VERSION}
    except (OSError, subprocess.SubprocessError):
        return {"git_revision": None, "git_dirty": None, "evaluator_version": SCHEMA_VERSION}


def is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def scalar(value):
    return value if isinstance(value, (str, int, float, bool)) else None


def upload_metadata(report: dict) -> dict:
    provenance = report.get("provenance") if isinstance(report.get("provenance"), dict) else {}
    metadata = {"environment": "development"}
    for key in ("results_kind", "usage_kind", "adapter", "provider_kind", "fixture_digest"):
        metadata[key] = scalar(report.get(key))
    for key in ("git_revision", "git_dirty"):
        metadata[key] = scalar(provenance.get(key))
    for key in ("model", "max_cost_usd"):
        if scalar(report.get(key)) is not None:
            metadata[key] = report[key]
    return metadata


def upload_outputs(case: dict) -> dict:
    outputs = {key: case.get(key) for key in ("observed_state", "outcome", "verification_level", "elapsed_ms")}
    usage = case.get("usage") if isinstance(case.get("usage"), dict) else {}
    # A missing measurement is omitted; zero would claim a measured value.
    for key in ("input_tokens", "output_tokens"):
        if is_number(usage.get(key)):
            outputs[key] = usage[key]
    if is_number(case.get("estimated_cost_usd")):
        outputs["estimated_cost_usd"] = case["estimated_cost_usd"]
    return outputs


def upload_scores(case: dict) -> dict:
    scores = case.get("scores")
    if (isinstance(scores, dict) and scores
            and all(isinstance(key, str) and is_number(value) for key, value in scores.items())):
        return scores
    return deterministic_scores(case)


def upload_report(report: dict, *, client=None) -> dict:
    """Upload only explicit scalar fields, never raw cases, reasons or test output.

    Uses public Client APIs: create_dataset/create_example, create_project with
    reference_dataset_id, create_run with reference_example_id, create_feedback.
    Dataset identity includes corpus content, adapter, and selection for repeatable comparisons.
    """
    if client is None:
        from langsmith import Client  # Optional development dependency; no import in offline runs.
        client = Client(auto_batch_tracing=False)
    selected = sorted(row["fixture_id"] for row in report["results"])
    identity = harness.canonical_digest({"fixture_digest": report["fixture_digest"],
                                         "adapter": report["adapter"], "selected": selected})[:20]
    dataset_name = f"mitig8it-dev-{identity}"
    if client.has_dataset(dataset_name=dataset_name):
        dataset = client.read_dataset(dataset_name=dataset_name)
    else:
        dataset = client.create_dataset(dataset_name=dataset_name,
                                       description="Development fixture metadata only; no source or model content.")
    existing = {example.inputs["fixture_id"]: example for example in client.list_examples(dataset_id=dataset.id)}
    experiment_name = f"mitig8it-dev-{report['adapter']}-{uuid.uuid4().hex[:12]}"
    project = client.create_project(project_name=experiment_name, reference_dataset_id=dataset.id,
                                    metadata=upload_metadata(report))
    for case in report["results"]:
        inputs = {key: case[key] for key in ("fixture_id", "family", "kind", "split")}
        reference = {"expected_state": case["expected_state"]}
        example = existing.get(case["fixture_id"])
        if example is None:
            example = client.create_example(inputs=inputs, outputs=reference, dataset_id=dataset.id)
        outputs = upload_outputs(case)
        run_id = uuid.uuid4()
        end = datetime.fromisoformat(case["ended_at"]) if case.get("ended_at") else datetime.now(timezone.utc)
        start = datetime.fromisoformat(case["started_at"]) if case.get("started_at") else end - timedelta(milliseconds=max(0, case.get("elapsed_ms", 0)))
        client.create_run(name="remediation-fixture", run_type="chain", id=run_id,
                          project_name=experiment_name, reference_example_id=example.id,
                          inputs=inputs, outputs=outputs,
                          start_time=start, end_time=end)
        for key, score in upload_scores(case).items():
            client.create_feedback(run_id=run_id, key=key, score=score, session_id=project.id,
                                   start_time=start, extend_trace_retention=False)
    client.update_project(project.id, end_time=datetime.now(timezone.utc))
    return {"status": "uploaded", "dataset_id": str(dataset.id), "experiment_id": str(project.id),
            "experiment_name": experiment_name, "cases": len(report["results"])}


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement leaves either the previous complete report or the next one.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False, encoding="utf-8") as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    temporary.replace(path)


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def upload_existing_report(parser, args, env_file_keys: list) -> int:
    """Retry an upload from a saved report; no fixture runs and no engine import."""
    if args.baseline or args.fixture or args.split or args.limit:
        parser.error("--upload-only cannot be combined with --baseline, --fixture, --split, or --limit")
    try:
        report = json.loads(args.upload_only.read_text())
        if (not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION
                or not isinstance(report.get("results"), list) or not report["results"]
                or not all(isinstance(row, dict) for row in report["results"])):
            raise ValueError("invalid report")
    except (OSError, ValueError):
        parser.error("--upload-only must be a readable dev-eval JSON report with results")
    if len(report["results"]) > args.max_upload_cases:
        parser.error("report exceeds --max-upload-cases; explicitly raise the cap")
    try:
        report["upload"] = upload_report(report)
    except Exception as error:
        # Do not expose API keys or response payloads embedded in SDK exception messages.
        report["upload"] = {"status": "failed", "error_type": type(error).__name__}
    write_report(args.upload_only, report)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    print(json.dumps({"output": str(args.upload_only), "cases": len(report["results"]),
                      "failures": summary.get("failures"), "upload": report["upload"],
                      "env_file_keys": env_file_keys}, indent=2))
    return 0 if report["upload"].get("status") == "uploaded" else 1


def repeat_agreement(rows: list) -> dict:
    """Per fixture, how many of its runs passed. One live run is not a stable label."""
    by_fixture = {}
    for row in rows:
        entry = by_fixture.setdefault(row["fixture_id"], {"runs": 0, "passed": 0, "reasons": []})
        entry["runs"] += 1
        entry["passed"] += int(row["outcome"] == "passed")
        if row.get("reason") not in entry["reasons"]:
            entry["reasons"].append(row.get("reason"))
    for entry in by_fixture.values():
        entry["stable"] = entry["passed"] in (0, entry["runs"])
    return by_fixture


def positive_float(value: str) -> float:
    number = float(value)
    if not 0 < number < float("inf"):
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", choices=("engine-local", "engine-live", "reference"), default="engine-local",
                        help="engine-live calls the configured REPAIR_LLM_* provider and spends real money")
    parser.add_argument("--split", choices=("train", "validation", "holdout"))
    parser.add_argument("--fixture", action="append", default=[], help="Select fixture ID; repeatable")
    parser.add_argument("--limit", type=positive_int)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--upload", action="store_true", help="Explicitly upload safe metadata to LangSmith")
    parser.add_argument("--max-upload-cases", type=positive_int, default=100)
    parser.add_argument("--allow-host-execution", action="store_true",
                        help="engine-live: accept that model-written patches and tests run on this host, unisolated")
    parser.add_argument("--max-cost-usd", type=positive_float, default=1.0,
                        help="engine-live: suite-wide model spend cap at the configured prices")
    parser.add_argument("--max-case-cost-usd", type=positive_float, default=0.25,
                        help="engine-live: spend cap the engine reserves against for one fixture")
    parser.add_argument("--max-live-cases", type=positive_int, default=10,
                        help="engine-live: cap on fixtures times repeats")
    parser.add_argument("--repeats", type=positive_int, default=1,
                        help="engine-live: run each fixture this many times and report agreement")
    parser.add_argument("--upload-only", type=Path, metavar="REPORT_PATH",
                        help="Upload an existing dev-eval report without running fixtures")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE,
                        help="Gitignored KEY=VALUE file; only LANGSMITH_, LANGCHAIN_ and REPAIR_LLM_ keys apply")
    args = parser.parse_args(argv)
    with local_env_file(args.env_file) as env_file_keys:
        if args.upload_only:
            return upload_existing_report(parser, args, env_file_keys)
        if args.baseline and args.baseline.resolve() == args.output.resolve():
            parser.error("baseline and output must be different files")
        baseline = None
        if args.baseline:
            try:
                baseline = json.loads(args.baseline.read_text())
                if not isinstance(baseline, dict) or not isinstance(baseline.get("results"), list):
                    raise ValueError("invalid report")
            except (OSError, ValueError):
                parser.error("baseline must be a readable dev-eval JSON report")
        all_fixtures = harness.load_fixtures()
        fixtures = [(directory, fixture) for directory, fixture in all_fixtures
                    if (not args.split or fixture["split"] == args.split)
                    and (not args.fixture or fixture["id"] in args.fixture)]
        unknown = set(args.fixture) - {fixture["id"] for _, fixture in all_fixtures}
        if unknown:
            parser.error("unknown fixture ID")
        if args.limit:
            fixtures = fixtures[:args.limit]
        if not fixtures:
            parser.error("selection contains no fixtures")
        if args.upload and len(fixtures) > args.max_upload_cases:
            parser.error("selection exceeds --max-upload-cases; reduce the selection or explicitly raise the cap")
        live = args.adapter == "engine-live"
        if args.repeats > 1 and not live:
            parser.error("--repeats applies only to --adapter engine-live; the other adapters are deterministic")
        budget = None
        if live and not args.allow_host_execution:
            # The local sandbox driver and the trusted fixture check both run code a model wrote
            # as ordinary subprocesses of this user: no network, kernel or filesystem isolation.
            parser.error("--adapter engine-live runs model-written code on this host without isolation; "
                         "pass --allow-host-execution on a machine where that is acceptable")
        if live:
            try:
                from . import dev_live
            except ImportError:
                import dev_live
            try:
                settings = dev_live.live_settings()
            except dev_live.LiveConfigError as error:
                parser.error(f"--adapter engine-live: {error}")
            if len(fixtures) * args.repeats > args.max_live_cases:
                parser.error("selection exceeds --max-live-cases; select fewer fixtures or explicitly raise the cap")
            budget = dev_live.SuiteBudget(args.max_cost_usd, args.max_case_cost_usd,
                                          settings["input_usd_per_mtok"], settings["output_usd_per_mtok"])
        results = []
        observations = []
        traces = []
        provenance = git_provenance()
        preflight = {"status": "not_required"}
        with local_observation_only(), tempfile.TemporaryDirectory(prefix="mitig8it-dev-eval-") as state_dir, local_scanner_runtime(Path(state_dir)):
            local = None
            if args.adapter == "engine-local":
                local = {"modules": harness.load_service_modules(), "state_dir": Path(state_dir),
                         "provider_kind": harness.SCRIPTED_PROVIDER_KIND}
            if live:
                # The engine reserves spend before every provider call, so real prices and the
                # remaining suite budget go into the request policy rather than a check afterwards.
                modules = dict(harness.load_service_modules())
                modules["build_repair_request"] = dev_live.priced_request_builder(modules["build_repair_request"], budget)
                if "LocalExecutionBackend" in modules:
                    modules["LocalExecutionBackend"] = dev_live.traced_backend(modules["LocalExecutionBackend"], traces)
                local = {"modules": modules, "state_dir": Path(state_dir), "provider_kind": harness.LIVE_PROVIDER_KIND}
            if args.adapter in harness.LOCAL_ADAPTERS and any(
                fixture.get("expected_verification_level") == harness.STATIC_ASSERTION_VERIFICATION_LEVEL
                for _, fixture in fixtures
            ):
                preflight = scanner_preflight()
            known = harness.load_known_failures()
            for repeat, directory, fixture in [(index + 1, directory, fixture) for directory, fixture in fixtures
                                               for index in range(args.repeats)]:
                started_at = datetime.now(timezone.utc).isoformat()
                candidates = []
                traces.clear()
                try:
                    if live and budget.case_cap() is None:
                        # Not started: no request is made once the suite budget cannot cover a case.
                        raise dev_live.SuiteBudgetExhausted()
                    if live:
                        # Each repeat gets its own execution store: the job id is derived from the
                        # fixture, so a second run in the same store is refused as a conflict.
                        run_local = dict(local, state_dir=Path(state_dir) / f"repeat-{repeat}")
                        with dev_live.capture_candidates() as captured:
                            result = harness.evaluate_fixture(directory, fixture, args.adapter, None, run_local, known)
                        candidates = (captured.last or {}).get("candidates") or []
                    else:
                        result = harness.evaluate_fixture(directory, fixture, args.adapter, None, local, known)
                except Exception as error:
                    # Keep one harness failure from discarding all observations; never persist exception text.
                    reason = ("suite_budget_exhausted" if live and isinstance(error, dev_live.SuiteBudgetExhausted)
                              else f"harness_error:{type(error).__name__}")
                    result = harness.CaseResult(fixture["id"], fixture["repository_id"], fixture["split"],
                        fixture["family"], fixture["kind"], fixture["expected_state"], "inconclusive", "failed",
                        reason, None, {}, 0)
                row = asdict(result)
                scores = deterministic_scores(row)
                if live:
                    # A real model rarely reproduces the reference byte for byte, so the fixture's own
                    # trusted check grades the candidate; reference equality stays a separate score.
                    row = dev_live.grade_live(row, dev_live.candidate_trusted_check(directory, fixture, candidates))
                    result = replace(result, outcome=row["outcome"], reason=row["reason"])
                    scores = deterministic_scores(row) | dev_live.live_scores(row)
                    usage = row.get("usage") or {}
                    # A template repair or an early refusal passes without any provider call, so a
                    # live pass alone is not evidence about the model.
                    row["repeat"] = repeat
                    row["model_invoked"] = bool(usage.get("input_tokens"))
                    if traces:
                        row["agent_steps"] = traces[-1]
                    # A static assertion is the engine's deterministic fallback after the agent gave
                    # up, so a pass at that level is not a repair the model produced.
                    row["model_repair"] = (row["kind"] == "supported" and row["outcome"] == "passed"
                                           and row["model_invoked"]
                                           and row.get("verification_level") != harness.STATIC_ASSERTION_VERIFICATION_LEVEL)
                    cost = budget.settle(usage.get("input_tokens"), usage.get("output_tokens"))
                    if cost is not None:
                        row["estimated_cost_usd"] = round(cost, 6)
                    elif not row["reason"] == "suite_budget_exhausted":
                        # Usage was lost after requests may have been paid for: the amount stays
                        # unknown in the row, and the suite cap assumes the case spent its full cap.
                        budget.reserve_unknown()
                        row["cost_unknown"] = True
                results.append(result)
                observations.append(dict(row, scores=scores,
                                         started_at=started_at, ended_at=datetime.now(timezone.utc).isoformat()))
        report = {"schema_version": SCHEMA_VERSION, "adapter": args.adapter,
                  "provider_kind": harness.SCRIPTED_PROVIDER_KIND if args.adapter == "engine-local" else "none",
                  "results_kind": "pipeline_integrity", "usage_kind": "synthetic", "provenance": provenance,
                  "note": "Scripted/reference fixtures measure pipeline integrity, not model repair quality. Usage is synthetic. No production isolation claim.",
                  "fixture_digest": fixture_digest(all_fixtures), "summary": harness.summarize(results),
                  "results": observations,
                  "comparison": None, "scanner_preflight": preflight, "upload": {"status": "disabled"},
                  "env_file_keys": env_file_keys}
        if live:
            report.update({"provider_kind": harness.LIVE_PROVIDER_KIND, "results_kind": "live_model_development",
                           "usage_kind": "provider_reported", "model": settings["model"],
                           "max_cost_usd": args.max_cost_usd,
                           "model_invoked_cases": sum(1 for row in observations if row.get("model_invoked")),
                           "model_repair_runs": sum(1 for row in observations if row.get("model_repair")),
                           "repeat_agreement": repeat_agreement(observations),
                           "spend": {"estimated_cost_usd": round(budget.spent_usd, 6),
                                     "max_case_cost_usd": args.max_case_cost_usd,
                                     "input_usd_per_mtok": settings["input_usd_per_mtok"],
                                     "output_usd_per_mtok": settings["output_usd_per_mtok"]},
                           "note": "Live-model results from the local development sandbox: verification is "
                                   "development_unverified. Cost is estimated from provider-reported tokens at the "
                                   "configured prices, not a bill. No production isolation claim."})
        if baseline is not None:
            try:
                report["comparison"] = compare_baseline(report, baseline)
            except (KeyError, TypeError, ValueError):
                report["comparison"] = {"comparable": False, "incompatible_fields": ["malformed_baseline"],
                                        "regressions": [], "improvements": []}
        write_report(args.output, report)
        if args.upload:
            try:
                report["upload"] = upload_report(report)
            except Exception as error:
                # Do not expose API keys or response payloads embedded in SDK exception messages.
                report["upload"] = {"status": "failed", "error_type": type(error).__name__}
            write_report(args.output, report)
        comparison = report["comparison"]
        failed = (any(result.outcome != "passed" for result in results)
                  or (comparison is not None and (not comparison["comparable"] or comparison["regressions"]))
                  or report["upload"]["status"] == "failed")
        print(json.dumps({"output": str(args.output), "cases": len(results), "failures": report["summary"]["failures"],
                          "comparison": comparison, "scanner_preflight": preflight, "upload": report["upload"],
                          "env_file_keys": env_file_keys, **({"spend": report["spend"], "model_invoked_cases": report["model_invoked_cases"]} if live else {})}, indent=2))
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
