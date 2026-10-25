"""Development eval safety and regression gates; all remote clients are fakes."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from benchmarks.remediation import dev_eval

ROOT = Path(__file__).resolve().parents[3]


def no_env_file(directory):
    # Hermetic even when a developer keeps a real benchmarks/remediation/.env.
    return ["--env-file", str(Path(directory) / "absent.env")]


def case(**changes):
    row = dict(fixture_id="sql-parameterized-001", repository_id="fixture-repo", split="train",
               family="sql_parameterization", kind="supported", expected_state="ready",
               observed_state="ready", outcome="passed", reason=None,
               fixture_tests={"passed": True}, usage={"input_tokens": 1}, elapsed_ms=12,
               verification_level="development_unverified", limitations=[], known_failure=None)
    row.update(changes)
    return row


def report(*rows, **changes):
    value = dict(schema_version=dev_eval.SCHEMA_VERSION, adapter="engine-local",
                 provider_kind=dev_eval.harness.SCRIPTED_PROVIDER_KIND,
                 results_kind="pipeline_integrity", fixture_digest="abc123", results=list(rows or [case()]))
    value.update(changes)
    return value


class ScoringAndComparisonTests(unittest.TestCase):
    def test_static_success_is_distinct_from_executed_development_success(self):
        static = dev_eval.deterministic_scores(case(verification_level="static_assertion"))
        executed = dev_eval.deterministic_scores(case())
        self.assertEqual(static["repair_correct"], 1)
        self.assertEqual(executed["repair_correct"], 1)
        self.assertLess(static["verification_strength"], executed["verification_strength"])
        self.assertNotIn("safe_abstention", executed)
        self.assertEqual(dev_eval.deterministic_scores(case(outcome="failed"))["repair_correct"], 0)

    def test_negative_and_adversarial_scores_require_actual_abstention(self):
        for kind in ("negative", "adversarial"):
            with self.subTest(kind=kind):
                scores = dev_eval.deterministic_scores(case(kind=kind, observed_state="unsupported"))
                self.assertEqual(scores["safe_abstention"], 1)
                self.assertNotIn("repair_correct", scores)
                self.assertNotIn("verification_strength", scores)
                self.assertEqual(dev_eval.deterministic_scores(case(kind=kind))["safe_abstention"], 0)

    def test_baseline_detects_lost_pass_weaker_evidence_and_missing_coverage(self):
        baseline = report(case(), case(fixture_id="missing"))
        current = report(case(outcome="failed", verification_level="static_assertion"))
        comparison = dev_eval.compare_baseline(current, baseline)
        self.assertTrue(comparison["comparable"])
        reasons = {row["fixture_id"]: row["reasons"] for row in comparison["regressions"]}
        self.assertIn("outcome_regressed", reasons["sql-parameterized-001"])
        self.assertIn("verification_weakened", reasons["sql-parameterized-001"])
        self.assertEqual(reasons["missing"], ["missing_case"])

    def test_pass_cannot_hide_verification_downgrade(self):
        comparison = dev_eval.compare_baseline(report(case(verification_level="static_assertion")), report())
        self.assertEqual(comparison["regressions"][0]["reasons"], ["verification_weakened"])

    def test_improvements_and_new_cases_are_explicit(self):
        comparison = dev_eval.compare_baseline(report(case(), case(fixture_id="new")), report(case(outcome="failed")))
        self.assertEqual(comparison["improvements"], ["sql-parameterized-001"])
        self.assertEqual(comparison["added_cases"], ["new"])
        self.assertEqual(comparison["regressions"], [])

    def test_incompatible_or_missing_provenance_is_not_comparable(self):
        for key in ("schema_version", "adapter", "provider_kind", "results_kind", "fixture_digest"):
            for value in (None, "different"):
                with self.subTest(key=key, value=value):
                    current = report(**{key: value})
                    comparison = dev_eval.compare_baseline(current, report())
                    self.assertFalse(comparison["comparable"])
                    self.assertIn(key, comparison["incompatible_fields"])


class RecordingClient:
    def __init__(self, existing=False):
        self.calls = []
        self.existing = existing

    def __getattr__(self, method):
        def record(*args, **kwargs):
            self.calls.append((method, args, kwargs))
            if method == "has_dataset":
                return self.existing
            if method == "list_examples":
                return [SimpleNamespace(id="example-id", inputs={"fixture_id": "sql-parameterized-001"})] if self.existing else []
            return SimpleNamespace(id=method + "-id")
        return record


class UploadTests(unittest.TestCase):
    def test_upload_allowlist_excludes_raw_content_errors_and_secret_fields(self):
        secret = "PRIVATE-CONTENT-DO-NOT-UPLOAD"
        row = case(reason=secret, fixture_tests={"stderr": secret}, usage={"api_key": secret},
                   source=secret, patch=secret, prompt=secret, completion=secret, limitations=[secret],
                   known_failure={"note": secret})
        value = report(row, api_key=secret, summary={"raw": secret})
        client = RecordingClient()
        uploaded = dev_eval.upload_report(value, client=client)
        self.assertEqual(uploaded["status"], "uploaded")
        self.assertNotIn(secret, json.dumps(client.calls, default=str))
        runs = [kwargs for method, _, kwargs in client.calls if method == "create_run"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(set(runs[0]["inputs"]), {"fixture_id", "family", "kind", "split"})
        self.assertEqual(set(runs[0]["outputs"]), {"observed_state", "outcome", "verification_level", "elapsed_ms"})
        feedback = [kwargs for method, _, kwargs in client.calls if method == "create_feedback"]
        self.assertEqual({item["key"]: item["score"] for item in feedback}, dev_eval.deterministic_scores(row))
        self.assertEqual({item["run_id"] for item in feedback}, {runs[0]["id"]})
        metadata = next(kwargs for method, _, kwargs in client.calls if method == "create_project")["metadata"]
        self.assertEqual(set(metadata), {"environment", "results_kind", "usage_kind", "adapter", "provider_kind",
                                         "fixture_digest", "git_revision", "git_dirty"})

    def test_upload_describes_the_given_report_with_scalar_metadata_only(self):
        secret = "PRIVATE-CONTENT-DO-NOT-UPLOAD"
        row = case(usage={"input_tokens": 120, "output_tokens": 30, "prompt": secret}, estimated_cost_usd=0.0125,
                   scores={"outcome_match": 1, "repair_correct": 0.5}, reason=secret, limitations=[secret],
                   fixture_tests={"stderr": secret}, patch=secret)
        value = report(row, adapter="engine-live", provider_kind="live", results_kind="repair_quality",
                       usage_kind="measured", model="fake-model", max_cost_usd=0.5,
                       provenance={"git_revision": "abc", "git_dirty": True, "evaluator_version": "x",
                                   "note": secret})
        client = RecordingClient()
        dev_eval.upload_report(value, client=client)
        self.assertNotIn(secret, json.dumps(client.calls, default=str))
        project = next(kwargs for method, _, kwargs in client.calls if method == "create_project")
        self.assertEqual(project["metadata"], {
            "environment": "development", "results_kind": "repair_quality", "usage_kind": "measured",
            "adapter": "engine-live", "provider_kind": "live", "fixture_digest": "abc123",
            "git_revision": "abc", "git_dirty": True, "model": "fake-model", "max_cost_usd": 0.5})
        run = next(kwargs for method, _, kwargs in client.calls if method == "create_run")
        self.assertEqual(set(run["outputs"]), {"observed_state", "outcome", "verification_level", "elapsed_ms",
                                               "input_tokens", "output_tokens", "estimated_cost_usd"})
        self.assertEqual((run["outputs"]["input_tokens"], run["outputs"]["output_tokens"],
                          run["outputs"]["estimated_cost_usd"]), (120, 30, 0.0125))
        feedback = [kwargs for method, _, kwargs in client.calls if method == "create_feedback"]
        self.assertEqual({item["key"]: item["score"] for item in feedback}, row["scores"])

    def test_missing_or_non_numeric_measurements_are_omitted_not_zeroed(self):
        rows = [case(fixture_id="a", usage={}), case(fixture_id="b", usage=None),
                case(fixture_id="c", usage={"input_tokens": "12", "output_tokens": True}, estimated_cost_usd=None),
                case(fixture_id="d", usage={"input_tokens": float("nan")}, estimated_cost_usd=[1])]
        client = RecordingClient()
        dev_eval.upload_report(report(*rows), client=client)
        runs = [kwargs for method, _, kwargs in client.calls if method == "create_run"]
        self.assertEqual(len(runs), 4)
        for run in runs:
            self.assertEqual(set(run["outputs"]), {"observed_state", "outcome", "verification_level", "elapsed_ms"})

    def test_non_numeric_scores_fall_back_to_deterministic_scores(self):
        for scores in ({}, {"repair_correct": "PRIVATE"}, {"repair_correct": True}, ["PRIVATE"], None):
            with self.subTest(scores=scores):
                row = case(scores=scores)
                client = RecordingClient()
                dev_eval.upload_report(report(row), client=client)
                feedback = [kwargs for method, _, kwargs in client.calls if method == "create_feedback"]
                self.assertEqual({item["key"]: item["score"] for item in feedback},
                                 dev_eval.deterministic_scores(row))

    def test_non_scalar_report_metadata_is_not_uploaded(self):
        secret = "PRIVATE-CONTENT-DO-NOT-UPLOAD"
        value = report(model={"prompt": secret}, max_cost_usd=[secret], usage_kind={"raw": secret},
                       provenance={"git_revision": [secret], "git_dirty": {"raw": secret}})
        client = RecordingClient()
        dev_eval.upload_report(value, client=client)
        self.assertNotIn(secret, json.dumps(client.calls, default=str))
        metadata = next(kwargs for method, _, kwargs in client.calls if method == "create_project")["metadata"]
        self.assertNotIn("model", metadata)
        self.assertNotIn("max_cost_usd", metadata)
        self.assertIsNone(metadata["usage_kind"])
        self.assertIsNone(metadata["git_revision"])

    def test_repeated_experiment_reuses_existing_dataset_and_examples(self):
        client = RecordingClient(existing=True)
        dev_eval.upload_report(report(), client=client)
        methods = [method for method, _, _ in client.calls]
        self.assertNotIn("create_dataset", methods)
        self.assertNotIn("create_example", methods)
        self.assertIn("create_project", methods)
        run = next(kwargs for method, _, kwargs in client.calls if method == "create_run")
        self.assertEqual(run["reference_example_id"], "example-id")


class EnvFileTests(unittest.TestCase):
    KEYS = ("LANGSMITH_API_KEY", "LANGSMITH_WORKSPACE_ID", "LANGCHAIN_PROJECT", "REPAIR_LLM_MODEL",
            "LANGSMITH_TRACING", "LANGSMITH_EMPTY", "OTHER_SECRET", "PATH_EXTRA")

    def write(self, directory, text):
        path = Path(directory) / "fake.env"
        path.write_text(text)
        return path

    def test_only_allowlisted_keys_apply_and_environment_is_restored(self):
        text = "\n".join(["# comment", "", "LANGSMITH_API_KEY=fake-key", "export LANGSMITH_WORKSPACE_ID='fake-workspace'",
                          'LANGCHAIN_PROJECT="fake project"', " REPAIR_LLM_MODEL = fake-model ", "LANGSMITH_EMPTY=",
                          "OTHER_SECRET=fake-other", "PATH_EXTRA=/fake", "not a pair", "=novalue",
                          "LANGSMITH_API_KEY=fake-key-last"])
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            for key in self.KEYS:
                os.environ.pop(key, None)
            with self.assertRaises(RuntimeError):
                with dev_eval.local_env_file(self.write(directory, text)) as applied:
                    self.assertEqual(applied, ["LANGCHAIN_PROJECT", "LANGSMITH_API_KEY", "LANGSMITH_WORKSPACE_ID",
                                               "REPAIR_LLM_MODEL"])
                    self.assertEqual(os.environ["LANGSMITH_API_KEY"], "fake-key-last")
                    self.assertEqual(os.environ["LANGSMITH_WORKSPACE_ID"], "fake-workspace")
                    self.assertEqual(os.environ["LANGCHAIN_PROJECT"], "fake project")
                    self.assertEqual(os.environ["REPAIR_LLM_MODEL"], "fake-model")
                    for key in ("OTHER_SECRET", "PATH_EXTRA", "LANGSMITH_EMPTY"):
                        self.assertNotIn(key, os.environ)
                    raise RuntimeError("exercise cleanup")
            for key in self.KEYS:
                self.assertNotIn(key, os.environ)

    def test_existing_non_empty_values_win_and_empty_values_are_filled_then_restored(self):
        text = "LANGSMITH_API_KEY=fake-file-key\nLANGSMITH_WORKSPACE_ID=fake-file-workspace\n"
        inherited = {"LANGSMITH_API_KEY": "fake-shell-key", "LANGSMITH_WORKSPACE_ID": ""}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, inherited):
            with dev_eval.local_env_file(self.write(directory, text)) as applied:
                self.assertEqual(applied, ["LANGSMITH_WORKSPACE_ID"])
                self.assertEqual(os.environ["LANGSMITH_API_KEY"], "fake-shell-key")
                self.assertEqual(os.environ["LANGSMITH_WORKSPACE_ID"], "fake-file-workspace")
            self.assertEqual(os.environ["LANGSMITH_API_KEY"], "fake-shell-key")
            self.assertEqual(os.environ["LANGSMITH_WORKSPACE_ID"], "")

    def test_missing_file_applies_nothing(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            before = dict(os.environ)
            with dev_eval.local_env_file(Path(directory) / "absent.env") as applied:
                self.assertEqual(applied, [])
                self.assertEqual(dict(os.environ), before)

    def test_default_env_file_is_the_gitignored_benchmark_file(self):
        self.assertEqual(dev_eval.DEFAULT_ENV_FILE, ROOT / "benchmarks" / "remediation" / ".env")


class ScannerRuntimeTests(unittest.TestCase):
    def test_explicit_certificate_and_state_settings_are_preserved(self):
        explicit = {"SSL_CERT_FILE": "/user/trusted-ca.pem", "SEMGREP_LOG_FILE": "/user/scan.log",
                    "SEMGREP_SETTINGS_FILE": "/user/settings.yml", "PATH": "/user/bin"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, explicit):
            with dev_eval.local_scanner_runtime(Path(directory)):
                for key in explicit.keys() - {"PATH"}:
                    self.assertEqual(os.environ[key], explicit[key])
            for key, value in explicit.items():
                self.assertEqual(os.environ[key], value)

    def test_defaults_use_trusted_ca_and_ephemeral_state_and_restore_after_failure(self):
        keys = ("SSL_CERT_FILE", "SEMGREP_LOG_FILE", "SEMGREP_SETTINGS_FILE")
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            for key in keys:
                os.environ.pop(key, None)
            original_path = os.environ.get("PATH")
            root = Path(directory)
            ca = root / "trusted-ca.pem"
            ca.write_text("fixture trust anchors")
            fake_certifi = SimpleNamespace(where=lambda: str(ca))
            with patch.dict(sys.modules, {"certifi": fake_certifi}), self.assertRaises(RuntimeError):
                with dev_eval.local_scanner_runtime(root):
                    self.assertEqual(os.environ["SSL_CERT_FILE"], str(ca))
                    self.assertEqual(Path(os.environ["SEMGREP_LOG_FILE"]).parent, root)
                    self.assertEqual(Path(os.environ["SEMGREP_SETTINGS_FILE"]).parent, root)
                    raise RuntimeError("exercise cleanup")
            for key in keys:
                self.assertNotIn(key, os.environ)
            self.assertEqual(os.environ.get("PATH"), original_path)

    def test_scanner_metrics_and_version_network_checks_are_disabled_and_restored(self):
        inherited = {"SEMGREP_SEND_METRICS": "on", "SEMGREP_ENABLE_VERSION_CHECK": "1"}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, inherited):
            with dev_eval.local_scanner_runtime(Path(directory)):
                self.assertEqual(os.environ["SEMGREP_SEND_METRICS"], "off")
                self.assertEqual(os.environ["SEMGREP_ENABLE_VERSION_CHECK"], "0")
            for key, value in inherited.items():
                self.assertEqual(os.environ[key], value)

    def test_missing_certifi_does_not_disable_tls_verification(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            os.environ.pop("SSL_CERT_FILE", None)
            before = {key: value for key, value in os.environ.items() if "SSL" in key or "CERT" in key}
            with patch.dict(sys.modules, {"certifi": None}), dev_eval.local_scanner_runtime(Path(directory)):
                after = {key: value for key, value in os.environ.items() if "SSL" in key or "CERT" in key}
                self.assertEqual(after, before)


class ScannerPreflightTests(unittest.TestCase):
    def test_missing_scanner_reports_unavailable_without_starting_process(self):
        with patch.object(dev_eval.shutil, "which", return_value=None), patch.object(dev_eval.subprocess, "run") as run:
            result = dev_eval.scanner_preflight()
        self.assertEqual(result, {"status": "unavailable", "reason": "scanner_not_on_path", "executable": None})
        run.assert_not_called()

    def test_scanner_timeout_is_bounded_and_does_not_persist_captured_content(self):
        secret = "PRIVATE-SCANNER-TIMEOUT-CONTENT"
        error = subprocess.TimeoutExpired("semgrep", 10, output=secret, stderr=secret)
        with patch.object(dev_eval.shutil, "which", return_value="/fixture/bin/semgrep"):
            with patch.object(dev_eval.subprocess, "run", side_effect=error) as run:
                result = dev_eval.scanner_preflight()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "scanner_startup_timeout")
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 10)
        self.assertNotIn(secret, json.dumps(result))

    def test_scanner_failures_are_classified_without_raw_stdout_or_stderr(self):
        secret = "PRIVATE-SCANNER-ERROR-CONTENT"
        for message, reason in (("empty trust anchors", "scanner_certificate_store_unavailable"),
                                ("Permission denied", "scanner_local_file_permission_denied"),
                                ("unknown error", "scanner_startup_failed")):
            with self.subTest(message=message):
                completed = subprocess.CompletedProcess(["semgrep"], 2, stdout=secret, stderr=message + secret)
                with patch.object(dev_eval.shutil, "which", return_value="/fixture/bin/semgrep"):
                    with patch.object(dev_eval.subprocess, "run", return_value=completed):
                        result = dev_eval.scanner_preflight()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["reason"], reason)
                self.assertEqual(result["exit_code"], 2)
                self.assertNotIn(secret, json.dumps(result))


class CliTests(unittest.TestCase):
    def invoke(self, directory, *arguments, evaluator=None):
        output = Path(directory) / "result.json"
        with patch.object(dev_eval.harness, "evaluate_fixture", side_effect=evaluator) if evaluator else patch.object(
            dev_eval.harness, "evaluate_fixture", return_value=dev_eval.harness.CaseResult(**case())
        ):
            with patch.object(dev_eval.harness, "load_service_modules", return_value={}), patch("sys.stdout", new_callable=io.StringIO):
                status = dev_eval.main(["--fixture", "sql-parameterized-001", "--output", str(output),
                                        *(() if "--env-file" in arguments else no_env_file(directory)), *arguments])
        return status, json.loads(output.read_text())

    def upload_only(self, path, *arguments, upload=None):
        stdout = io.StringIO()
        with patch.object(dev_eval, "upload_report", **(upload or {"return_value": {"status": "uploaded", "cases": 1}})) as uploader:
            with patch.object(dev_eval.harness, "evaluate_fixture") as evaluate, patch.object(
                dev_eval.harness, "load_service_modules") as modules, patch.object(
                dev_eval.harness, "load_fixtures") as fixtures, patch("sys.stdout", stdout):
                status = dev_eval.main(["--upload-only", str(path), *no_env_file(path.parent), *arguments])
        for unused in (evaluate, modules, fixtures):
            unused.assert_not_called()
        return status, json.loads(stdout.getvalue()), uploader

    def test_env_file_key_names_are_reported_without_values_and_tracing_stays_off(self):
        seen = {}
        def evaluate(*args, **kwargs):
            seen.update({key: os.environ.get(key) for key in ("LANGSMITH_TRACING", "LANGSMITH_API_KEY")})
            return dev_eval.harness.CaseResult(**case())
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            for key in ("LANGSMITH_TRACING", "LANGSMITH_API_KEY", "OTHER_SECRET"):
                os.environ.pop(key, None)
            env_file = Path(directory) / "fake.env"
            env_file.write_text("LANGSMITH_TRACING=true\nLANGSMITH_API_KEY=fake-env-file-value\nOTHER_SECRET=fake-other\n")
            def check_upload(value):
                self.assertEqual(os.environ.get("LANGSMITH_API_KEY"), "fake-env-file-value")
                return {"status": "uploaded", "cases": 1}
            stdout = io.StringIO()
            with patch.object(dev_eval, "upload_report", side_effect=check_upload), patch("sys.stdout", stdout):
                with patch.object(dev_eval.harness, "evaluate_fixture", side_effect=evaluate), patch.object(
                        dev_eval.harness, "load_service_modules", return_value={}):
                    output = Path(directory) / "result.json"
                    status = dev_eval.main(["--fixture", "sql-parameterized-001", "--output", str(output),
                                            "--env-file", str(env_file), "--upload"])
                text = output.read_text()
            self.assertEqual(status, 0)
            self.assertEqual(seen, {"LANGSMITH_TRACING": "false", "LANGSMITH_API_KEY": "fake-env-file-value"})
            self.assertEqual(json.loads(text)["env_file_keys"], ["LANGSMITH_API_KEY", "LANGSMITH_TRACING"])
            self.assertEqual(json.loads(stdout.getvalue())["env_file_keys"], ["LANGSMITH_API_KEY", "LANGSMITH_TRACING"])
            self.assertNotIn("fake-env-file-value", text + stdout.getvalue())
            for key in ("LANGSMITH_TRACING", "LANGSMITH_API_KEY", "OTHER_SECRET"):
                self.assertNotIn(key, os.environ)

    def test_upload_only_uploads_saved_report_and_records_status_without_running_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.json"
            saved = report(summary={"failures": 0}, upload={"status": "failed", "error_type": "RuntimeError"})
            path.write_text(json.dumps(saved))
            status, summary, uploader = self.upload_only(path)
            written = json.loads(path.read_text())
            leftovers = [item.name for item in Path(directory).iterdir()]
        self.assertEqual(status, 0)
        uploader.assert_called_once()
        self.assertEqual(uploader.call_args.args[0]["results"], saved["results"])
        self.assertEqual(written["upload"], {"status": "uploaded", "cases": 1})
        self.assertEqual(written["results"], saved["results"])
        self.assertEqual(summary["upload"], written["upload"])
        self.assertEqual((summary["cases"], summary["failures"], summary["env_file_keys"]), (1, 0, []))
        self.assertEqual(leftovers, ["saved.json"])

    def test_upload_only_failure_records_only_error_type_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.json"
            path.write_text(json.dumps(report()))
            status, summary, _ = self.upload_only(
                path, upload={"side_effect": RuntimeError("API_KEY=secret-upload-token")})
            text = path.read_text()
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(text)["upload"], {"status": "failed", "error_type": "RuntimeError"})
        self.assertNotIn("secret-upload-token", text + json.dumps(summary))

    def test_upload_only_rejects_invalid_reports_selection_flags_and_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.json"
            valid.write_text(json.dumps(report(case(), case(fixture_id="second"))))
            invalid = {"list.json": "[]", "schema.json": json.dumps(report(schema_version="other")),
                       "empty.json": json.dumps(report(results=[])), "rows.json": json.dumps(report(results=["x"])),
                       "broken.json": "{"}
            attempts = [[str(root / "absent.json")]]
            for name, text in invalid.items():
                (root / name).write_text(text)
                attempts.append([str(root / name)])
            attempts += [[str(valid), "--max-upload-cases", "1"], [str(valid), "--baseline", str(valid)],
                         [str(valid), "--fixture", "sql-parameterized-001"], [str(valid), "--split", "train"],
                         [str(valid), "--limit", "1"]]
            before = valid.read_text()
            for arguments in attempts:
                with self.subTest(arguments=arguments[1:] or arguments), patch.object(dev_eval, "upload_report") as upload:
                    with patch.object(dev_eval.harness, "load_fixtures") as fixtures:
                        with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                            dev_eval.main(["--upload-only", *arguments, *no_env_file(directory)])
                    self.assertEqual(error.exception.code, 2)
                    upload.assert_not_called()
                    fixtures.assert_not_called()
            self.assertEqual(valid.read_text(), before)

    def test_default_local_mode_requires_no_upload(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dev_eval, "upload_report") as upload:
            status, result = self.invoke(directory)
        self.assertEqual(status, 0)
        self.assertEqual(result["adapter"], "engine-local")
        self.assertEqual(result["upload"]["status"], "disabled")
        upload.assert_not_called()

    def test_local_scanner_temporary_files_are_cleaned_after_evaluation(self):
        observed_paths = []
        def evaluate(*args, **kwargs):
            for key in ("SEMGREP_LOG_FILE", "SEMGREP_SETTINGS_FILE"):
                path = Path(os.environ[key])
                path.write_text("temporary scanner state")
                observed_paths.append(path)
            self.assertEqual(os.environ["LANGSMITH_TRACING"], "false")
            self.assertFalse(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
            return dev_eval.harness.CaseResult(**case())
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            for key in ("SEMGREP_LOG_FILE", "SEMGREP_SETTINGS_FILE"):
                os.environ.pop(key, None)
            with patch.object(dev_eval, "scanner_preflight", return_value={"status": "available"}):
                status, _ = self.invoke(directory, evaluator=evaluate)
            self.assertEqual(status, 0)
            self.assertEqual(len(observed_paths), 2)
            for path in observed_paths:
                self.assertFalse(path.exists())
                self.assertFalse(path.parent.exists())

    def test_upload_failure_preserves_complete_local_report_without_exception_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            def fail_upload(value):
                saved = json.loads((Path(directory) / "result.json").read_text())
                self.assertEqual(len(saved["results"]), 1)
                self.assertEqual(saved["upload"]["status"], "disabled")
                raise RuntimeError("API_KEY=secret-upload-token")
            with patch.object(dev_eval, "upload_report", side_effect=fail_upload):
                status, result = self.invoke(directory, "--upload")
        self.assertEqual(status, 1)
        self.assertEqual(result["upload"], {"status": "failed", "error_type": "RuntimeError"})
        self.assertNotIn("secret-upload-token", json.dumps(result))

    def test_harness_exception_becomes_failed_observation_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            status, result = self.invoke(directory, evaluator=RuntimeError("private-source"))
        self.assertEqual(status, 1)
        self.assertEqual(result["results"][0]["outcome"], "failed")
        self.assertNotIn("private-source", json.dumps(result))

    def test_incompatible_baseline_is_persisted_and_fails_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.json"
            baseline.write_text(json.dumps(report(adapter="reference")))
            status, result = self.invoke(directory, "--baseline", str(baseline))
        self.assertEqual(status, 1)
        self.assertFalse(result["comparison"]["comparable"])

    def test_upload_cap_rejects_before_executing_or_uploading(self):
        with patch.object(dev_eval.harness, "evaluate_fixture") as evaluate, patch.object(dev_eval, "upload_report") as upload:
            with patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
                with tempfile.TemporaryDirectory() as directory:
                    dev_eval.main(["--upload", "--limit", "2", "--max-upload-cases", "1", *no_env_file(directory)])
            self.assertEqual(error.exception.code, 2)
            evaluate.assert_not_called()
            upload.assert_not_called()

    def test_local_observation_restores_inherited_environment_on_failure(self):
        inherited = {"LANGSMITH_TRACING": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:1",
                     "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:2", "ANALYSIS_SERVICE_URL": "http://localhost:3"}
        with patch.dict(os.environ, inherited):
            with self.assertRaises(RuntimeError):
                with dev_eval.local_observation_only():
                    self.assertEqual(os.environ["LANGSMITH_TRACING"], "false")
                    for key in inherited.keys() - {"LANGSMITH_TRACING"}:
                        self.assertFalse(os.environ.get(key), key)
                    raise RuntimeError("test cleanup")
            for key, value in inherited.items():
                self.assertEqual(os.environ[key], value)

    def test_unconfigured_live_and_remote_adapters_are_rejected(self):
        unset = {key: "" for key in os.environ if key.startswith("REPAIR_LLM_")}
        for adapter in ("engine-live", "engine"):
            with self.subTest(adapter=adapter), patch("sys.stderr", new_callable=io.StringIO), patch.dict(os.environ, unset):
                with tempfile.TemporaryDirectory() as directory, self.assertRaises(SystemExit) as error:
                    dev_eval.main(["--adapter", adapter, "--allow-host-execution", "--fixture", "sql-parameterized-001",
                                   *no_env_file(directory)])
                self.assertEqual(error.exception.code, 2)


LIVE_ENV = {"REPAIR_LLM_BASE_URL": "https://provider.invalid/v1", "REPAIR_LLM_API_KEY": "fake-key",
            "REPAIR_LLM_MODEL": "fake-model", "REPAIR_LLM_INPUT_USD_PER_MTOK": "1000",
            "REPAIR_LLM_OUTPUT_USD_PER_MTOK": "1000"}


class LiveCliTests(unittest.TestCase):
    """The live adapter with the harness faked: no provider, engine or network is reached."""

    def invoke(self, directory, results, *arguments, fixtures=("sql-parameterized-001",)):
        output = Path(directory) / "result.json"
        selection = [item for fixture in fixtures for item in ("--fixture", fixture)]
        with patch.dict(os.environ, LIVE_ENV), patch.object(dev_eval.harness, "evaluate_fixture", side_effect=results) as evaluate, \
                patch.object(dev_eval.harness, "load_service_modules", return_value={"build_repair_request": None}), \
                patch("sys.stdout", new_callable=io.StringIO):
            status = dev_eval.main(["--adapter", "engine-live", "--allow-host-execution", *selection,
                                    "--output", str(output), *no_env_file(directory), *arguments])
        return status, json.loads(output.read_text()), evaluate

    def test_live_report_is_labelled_priced_and_never_holds_the_key(self):
        usage = {"input_tokens": 100, "output_tokens": 10, "cost_usd": 0.00011}
        with tempfile.TemporaryDirectory() as directory:
            status, result, _ = self.invoke(directory, [dev_eval.harness.CaseResult(**case(usage=usage))])
            self.assertNotIn("fake-key", (Path(directory) / "result.json").read_text())
        self.assertEqual(status, 0)
        self.assertEqual((result["provider_kind"], result["results_kind"], result["usage_kind"], result["model"]),
                         (dev_eval.harness.LIVE_PROVIDER_KIND, "live_model_development", "provider_reported", "fake-model"))
        # Real configured price, not the harness's synthetic 1 USD per million tokens.
        self.assertEqual(result["results"][0]["estimated_cost_usd"], 0.11)
        self.assertEqual(result["spend"]["estimated_cost_usd"], 0.11)
        self.assertEqual(result["results"][0]["graded_by"], "reference_match")
        self.assertEqual((result["results"][0]["model_invoked"], result["model_invoked_cases"]), (True, 1))

    def test_static_assertion_pass_after_a_model_call_is_not_a_model_repair(self):
        usage = {"input_tokens": 50, "output_tokens": 5}
        runs = [dev_eval.harness.CaseResult(**case(usage=usage, verification_level="static_assertion")),
                dev_eval.harness.CaseResult(**case(usage=usage))]
        with tempfile.TemporaryDirectory() as directory:
            _, result, _ = self.invoke(directory, runs, "--repeats", "2")
        self.assertEqual([row["model_repair"] for row in result["results"]], [False, True])
        self.assertEqual((result["model_invoked_cases"], result["model_repair_runs"]), (2, 1))

    def test_live_pass_without_a_provider_call_is_not_counted_as_model_evidence(self):
        usage = {"input_tokens": 0, "output_tokens": 0}
        with tempfile.TemporaryDirectory() as directory:
            status, result, _ = self.invoke(directory, [dev_eval.harness.CaseResult(**case(usage=usage))])
        self.assertEqual(status, 0)
        self.assertEqual((result["results"][0]["model_invoked"], result["model_invoked_cases"]), (False, 0))

    def test_suite_budget_stops_before_starting_the_next_case(self):
        usage = {"input_tokens": 990, "output_tokens": 0}
        with tempfile.TemporaryDirectory() as directory:
            status, result, evaluate = self.invoke(
                directory, [dev_eval.harness.CaseResult(**case(usage=usage))], "--max-cost-usd", "1",
                "--max-case-cost-usd", "1", fixtures=("sql-parameterized-001", "python-sql-sqlite-001"))
        self.assertEqual(status, 1)
        self.assertEqual(evaluate.call_count, 1)
        skipped = [row for row in result["results"] if row["reason"] == "suite_budget_exhausted"]
        self.assertEqual(len(skipped), 1)
        self.assertNotIn("estimated_cost_usd", skipped[0])
        self.assertNotIn("cost_unknown", skipped[0])

    def test_lost_usage_is_unknown_in_the_row_but_charged_to_the_suite_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            status, result, _ = self.invoke(directory, [dev_eval.harness.CaseResult(**case(
                usage={}, outcome="failed", observed_state="inconclusive", reason="engine_local_error:X"))])
        self.assertEqual(status, 1)
        self.assertTrue(result["results"][0]["cost_unknown"])
        self.assertNotIn("estimated_cost_usd", result["results"][0])
        self.assertEqual(result["spend"]["estimated_cost_usd"], 0.25)

    def test_repeats_report_unstable_fixtures_and_count_against_the_case_cap(self):
        usage = {"input_tokens": 10, "output_tokens": 1}
        runs = [dev_eval.harness.CaseResult(**case(usage=usage)),
                dev_eval.harness.CaseResult(**case(usage=usage, outcome="failed", observed_state="unsupported", reason="not_repaired"))]
        with tempfile.TemporaryDirectory() as directory:
            status, result, evaluate = self.invoke(directory, runs, "--repeats", "2")
        self.assertEqual((status, evaluate.call_count), (1, 2))
        self.assertEqual([row["repeat"] for row in result["results"]], [1, 2])
        stores = [call.args[4]["state_dir"] for call in evaluate.call_args_list]
        self.assertEqual(len(set(stores)), 2)
        self.assertEqual(result["repeat_agreement"]["sql-parameterized-001"],
                         {"runs": 2, "passed": 1, "reasons": [None, "not_repaired"], "stable": False})
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr", new_callable=io.StringIO):
            with patch.dict(os.environ, LIVE_ENV), self.assertRaises(SystemExit) as error:
                dev_eval.main(["--adapter", "engine-live", "--allow-host-execution", "--fixture", "sql-parameterized-001", "--repeats", "11",
                               *no_env_file(directory)])
        self.assertEqual(error.exception.code, 2)

    def test_live_mode_refuses_host_execution_without_explicit_acceptance(self):
        # Fully configured, so the only thing stopping it is the missing acceptance flag.
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with patch.dict(os.environ, LIVE_ENV), patch.object(dev_eval.harness, "evaluate_fixture") as evaluate, \
                    patch.object(dev_eval.harness, "load_service_modules") as load:
                with self.assertRaises(SystemExit) as error:
                    dev_eval.main(["--adapter", "engine-live", "--fixture", "sql-parameterized-001",
                                   *no_env_file(directory)])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--allow-host-execution", stderr.getvalue())
        evaluate.assert_not_called()
        load.assert_not_called()

    def test_live_case_cap_rejects_before_any_request(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr", new_callable=io.StringIO):
            with patch.dict(os.environ, LIVE_ENV), patch.object(dev_eval.harness, "evaluate_fixture") as evaluate:
                with self.assertRaises(SystemExit) as error:
                    dev_eval.main(["--adapter", "engine-live", "--allow-host-execution", "--max-live-cases", "1", "--limit", "2",
                                   *no_env_file(directory)])
        self.assertEqual(error.exception.code, 2)
        evaluate.assert_not_called()

    def test_offline_adapters_do_not_import_sdk_or_connect_network(self):
        # A subprocess guards imports from the first instruction and runs a real fixture.
        script = '''
import builtins, os, socket, sys
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "langsmith" or name.startswith("langsmith."):
        raise AssertionError("offline mode imported LangSmith")
    return original_import(name, *args, **kwargs)
def no_network(*args, **kwargs):
    raise AssertionError("offline mode attempted a network connection")
builtins.__import__ = guarded_import
socket.socket.connect = no_network
socket.create_connection = no_network
from benchmarks.remediation.dev_eval import main
raise SystemExit(main(sys.argv[1:]))
'''
        inherited = dict(os.environ, LANGSMITH_TRACING="true", LANGCHAIN_TRACING_V2="true",
                         LANGSMITH_API_KEY="fake-key", OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:1",
                         OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://127.0.0.1:1")
        for adapter in ("reference", "engine-local"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "result.json"
                completed = subprocess.run([sys.executable, "-c", script, "--adapter", adapter,
                                            "--fixture", "sql-parameterized-001", "--output", str(output),
                                            *no_env_file(directory)],
                                           cwd=ROOT, env=inherited, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertEqual(json.loads(output.read_text())["upload"]["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
