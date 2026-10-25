"""Offline detection diagnostics, never a production-accuracy or release certificate.

The legacy replay scorer cannot distinguish missing coverage from a completed
negative observation. This stricter, standalone contract requires explicitly
identified observations; it does not upgrade or infer historical provenance.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from benchmarks.quality_gate import wilson_interval
from scripts.replay.score import CANONICAL_INTERNAL_TYPES, language_of


ROOT = Path(__file__).resolve().parents[1]
RUN_SCHEMA = "detection-observations-v1"
REVIEW_SCHEMA = "detection-adjudications-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
STAGE_STATUSES = {"complete", "partial", "error", "not_attempted"}


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def canonical_path(value: Any) -> bool:
    return (nonempty(value) and "\\" not in value and not value.startswith("/")
            and ".." not in value.split("/") and str(PurePosixPath(value)) == value)


def valid_span(value: Any) -> bool:
    return (isinstance(value, list) and len(value) == 2
            and all(type(item) is int for item in value) and 1 <= value[0] <= value[1])


def system_valid(system: Any) -> bool:
    return (isinstance(system, dict)
            and isinstance(system.get("source_revision"), str)
            and REVISION.fullmatch(system["source_revision"]) is not None
            and all(isinstance(system.get(key), str) and SHA256.fullmatch(system[key])
                    for key in ("artifact_sha256", "configuration_sha256", "publication_policy_sha256"))
            and type(system.get("triage_enabled")) is bool)


def observation_id(system: dict, repo: str, ref: str, source_sha256: str, finding: dict) -> str:
    """Bind a review to the whole observation, source file, tree, and system config."""
    return digest({"system": system, "repo": repo, "ref": ref,
                   "source_sha256": source_sha256, "finding": finding})


def _maximum_matching(candidates: list[list[str]]) -> dict[int, str]:
    """One alert cannot satisfy two vulnerabilities; duplicate alerts cannot inflate TP."""
    by_label: dict[str, int] = {}
    by_prediction: dict[int, str] = {}
    for start in range(len(candidates)):
        pending = deque([start])
        visited = {start}
        parent: dict[str, int] = {}
        unmatched = None
        while pending and unmatched is None:
            prediction = pending.popleft()
            for label in candidates[prediction]:
                if label in parent:
                    continue
                parent[label] = prediction
                if label not in by_label:
                    unmatched = label
                    break
                other = by_label[label]
                if other not in visited:
                    visited.add(other)
                    pending.append(other)
        while unmatched is not None:
            prediction = parent[unmatched]
            previous = by_prediction.get(prediction)
            by_label[unmatched] = prediction
            by_prediction[prediction] = unmatched
            unmatched = previous
    return by_prediction


def _rate(successes: int, total: int) -> dict:
    return {"numerator": successes, "denominator": total,
            "estimate": successes / total if total else None,
            "wilson_95_iid_reference": list(wilson_interval(successes, total)),
            "interval_interpretation": "IID assumption not established; not a production confidence interval"}


def _metrics(predictions: list[dict], states: list[dict]) -> dict:
    true = sum(row["judgment"] == "true" for row in predictions)
    false = sum(row["judgment"] == "false" for row in predictions)
    unread = len(predictions) - true - false
    hit = sum(state["state"] == "detected" for state in states)
    missed = sum(state["state"] == "missed_on_complete_scan" for state in states)
    unknown = len(states) - hit - missed
    return {
        "precision_reviewed_alerts": _rate(true, true + false),
        "precision_accepted_alerts_identification_bounds":
            [true / len(predictions), (true + unread) / len(predictions)] if predictions else [None, None],
        "recall_observed_labels": _rate(hit, hit + missed),
        "recall_all_labels_identification_bounds":
            [hit / len(states), (hit + unknown) / len(states)] if states else [None, None],
        "reviewed_true_alerts": true, "reviewed_false_alerts": false, "unresolved_alerts": unread,
        "detected_labels": hit, "missed_labels_on_complete_scans": missed, "unobserved_labels": unknown,
        "accuracy": None, "true_negatives": None, "f1": None,
        "not_reported_reason": "Corpus is not exhaustively labeled; alert precision and labeled-vulnerability recall have different units.",
        "population": "Accepted valid observations only; invalid inputs are reported separately, never silently certified.",
    }


def evaluate(corpus: Any, runs: list[Any], adjudications: Any = None) -> dict:
    """Compute bounded diagnostics. Locally asserted metadata never opens readiness."""
    report: dict = {
        "schema_version": "detection-evaluation-v1", "scope": "standalone_detection_diagnostics",
        "production_ready": False, "release_admissible": False,
        "release_blockers": ["independent_holdout_sampling_and_authenticated_system_provenance_not_established"],
        "evidence_identity": {"corpus_sha256": digest(corpus),
                              "observation_document_sha256": [digest(run) for run in runs],
                              "adjudications_sha256": digest(adjudications) if adjudications is not None else None,
                              "authentication": "unverified_local_inputs"},
        "errors": [], "observations": [], "labels": [],
        "limitations": [
            "No fixture pass rate is interpreted as accuracy or production reliability.",
            "Wilson intervals are IID reference calculations only; repository/lineage dependence and selection bias remain.",
            "Only explicitly complete file stages establish misses; absent/failed coverage remains unknown.",
            "Line overlap is exact, with zero slack; expected canonical vulnerability class must also match.",
            "One-to-one maximum matching prevents duplicate alerts or broad spans from inflating labeled hits.",
            "Label manifests do not enumerate every source file or every vulnerability; whole-system recall is not identified.",
            "A reported artifact/config/source digest is identity metadata, not authenticated execution evidence.",
        ],
    }

    def error(code: str, **location):
        report["errors"].append({"code": code, **location})

    labels = corpus.get("labels") if isinstance(corpus, dict) else None
    valid_labels = isinstance(labels, list) and bool(labels)
    seen = set()
    for index, label in enumerate(labels if isinstance(labels, list) else []):
        valid = (isinstance(label, dict) and all(nonempty(label.get(key)) for key in ("id", "repo", "cwe", "source", "evidence"))
                 and isinstance(label.get("ref"), str) and REVISION.fullmatch(label["ref"])
                 and canonical_path(label.get("path")) and valid_span(label.get("line_range"))
                 and isinstance(label.get("rule_classes_expected"), list) and bool(label["rule_classes_expected"])
                 and all(isinstance(kind, str) and kind in CANONICAL_INTERNAL_TYPES for kind in label["rule_classes_expected"]))
        if not valid or label["id"] in seen:
            error("invalid_or_duplicate_label", label_index=index)
            valid_labels = False
        else:
            seen.add(label["id"])
    if not valid_labels:
        error("invalid_corpus_manifest")
        report.update(data_contract_valid=False, observations_complete=False,
                      metrics=_metrics([], []), coverage={})
        return report

    planned_trees = {(label["repo"], label["ref"]) for label in labels}
    planned_files = {(label["repo"], label["ref"], label["path"]) for label in labels}
    tree_counts = Counter((run.get("repo"), run.get("ref")) for run in runs
                          if isinstance(run, dict) and nonempty(run.get("repo")) and nonempty(run.get("ref")))
    accepted_trees, complete_files = set(), set()
    predictions, stages_incomplete = [], 0
    system_ids = {digest(run["system"]) for run in runs if isinstance(run, dict) and system_valid(run.get("system"))}
    if len(system_ids) > 1:
        error("mixed_system_identities")
    for run_index, run in enumerate(runs):
        where = {"run_index": run_index}
        if not isinstance(run, dict) or run.get("schema_version") != RUN_SCHEMA:
            error("missing_or_unsupported_observation_schema", **where)
            continue
        repo, ref = run.get("repo"), run.get("ref")
        if (not nonempty(repo) or not isinstance(ref, str) or not REVISION.fullmatch(ref)
                or (repo, ref) not in planned_trees):
            error("unexpected_or_unpinned_repository_tree", **where)
            continue
        if tree_counts[(repo, ref)] != 1:
            error("duplicate_repository_tree_observation", **where)
            continue
        if run.get("corpus_sha256") != report["evidence_identity"]["corpus_sha256"]:
            error("observation_for_different_corpus", **where)
            continue
        if not system_valid(run.get("system")) or len(system_ids) != 1:
            error("missing_invalid_or_mixed_system_identity", **where)
            continue
        if run.get("scope") != "published_detection":
            error("not_published_detection_scope", **where)
            continue
        files = run.get("files")
        if not isinstance(files, list):
            error("missing_file_observations", **where)
            continue
        accepted_trees.add((repo, ref))
        path_counts = Counter(file.get("path") for file in files
                              if isinstance(file, dict) and nonempty(file.get("path")))
        required_stages = {"tier1", "tier2"} | ({"tier3"} if run["system"]["triage_enabled"] else set())
        for file_index, file in enumerate(files):
            location = {**where, "file_index": file_index}
            if (not isinstance(file, dict) or not canonical_path(file.get("path"))
                    or path_counts[file["path"]] != 1):
                error("invalid_or_duplicate_file_observation", **location)
                continue
            path = file["path"]
            stages = file.get("stages")
            if (not isinstance(file.get("source_sha256"), str) or not SHA256.fullmatch(file["source_sha256"])
                    or not isinstance(stages, dict) or set(stages) != required_stages
                    or any(not isinstance(status, str) or status not in STAGE_STATUSES for status in stages.values())
                    or not isinstance(file.get("findings"), list)):
                error("invalid_file_identity_stages_or_findings", **location)
                continue
            if all(status == "complete" for status in stages.values()):
                complete_files.add((repo, ref, path))
            else:
                stages_incomplete += 1
            fingerprints = Counter(finding.get("fingerprint") for finding in file["findings"]
                                   if isinstance(finding, dict) and nonempty(finding.get("fingerprint")))
            invalid_findings = False
            for finding_index, finding in enumerate(file["findings"]):
                at = {**location, "finding_index": finding_index}
                if (not isinstance(finding, dict) or not nonempty(finding.get("fingerprint"))
                        or fingerprints[finding["fingerprint"]] != 1 or not nonempty(finding.get("rule_id"))
                        or finding.get("file_path") != path
                        or not valid_span([finding.get("line_start"), finding.get("line_end")])
                        or not isinstance(finding.get("internal_type"), str)
                        or finding["internal_type"] not in CANONICAL_INTERNAL_TYPES):
                    error("invalid_or_duplicate_finding", **at)
                    invalid_findings = True
                    continue
                predictions.append({
                    "observation_id": observation_id(run["system"], repo, ref, file["source_sha256"], finding),
                    "repo": repo, "ref": ref, "path": path, "rule_id": finding["rule_id"],
                    "fingerprint": finding["fingerprint"], "class": finding["internal_type"],
                    "span": [finding["line_start"], finding["line_end"]], "judgment": "unresolved",
                })
            if invalid_findings:
                # A malformed observation cannot support a negative claim either.
                complete_files.discard((repo, ref, path))

    reviews: dict[str, dict] = {}
    if adjudications is not None:
        if (not isinstance(adjudications, dict) or adjudications.get("schema_version") != REVIEW_SCHEMA
                or adjudications.get("corpus_sha256") != report["evidence_identity"]["corpus_sha256"]
                or not isinstance(adjudications.get("observations"), list)):
            error("invalid_or_legacy_adjudication_identity")
        else:
            review_ids = Counter(row.get("observation_id") for row in adjudications["observations"]
                                 if isinstance(row, dict) and nonempty(row.get("observation_id")))
            known_ids = {row["observation_id"] for row in predictions}
            for index, review in enumerate(adjudications["observations"]):
                if (not isinstance(review, dict) or not nonempty(review.get("observation_id"))
                        or review["observation_id"] not in known_ids
                        or review_ids[review["observation_id"]] != 1
                        or not isinstance(review.get("verdict"), str)
                        or review["verdict"] not in {"true", "false", "uncertain"}
                        or not all(nonempty(review.get(key)) for key in ("reviewer", "source", "sampling_unit"))):
                    error("invalid_duplicate_or_stale_adjudication", review_index=index)
                    continue
                reviews[review["observation_id"]] = review

    candidates = []
    for row in predictions:
        candidates.append(sorted(label["id"] for label in labels
                                 if (row["repo"], row["ref"], row["path"]) == (label["repo"], label["ref"], label["path"])
                                 and row["class"] in label["rule_classes_expected"]
                                 and row["span"][0] <= label["line_range"][1]
                                 and label["line_range"][0] <= row["span"][1]))
    # Contradictory judgments are not silently overruled by a location match.
    for index, row in enumerate(predictions):
        review = reviews.get(row["observation_id"])
        if candidates[index] and review and review["verdict"] != "true":
            error("label_adjudication_disagreement", observation_id=row["observation_id"])
            row["disputed"] = True
            complete_files.discard((row["repo"], row["ref"], row["path"]))
            candidates[index] = []
    matched = _maximum_matching(candidates)
    for index, row in enumerate(predictions):
        review = reviews.get(row["observation_id"])
        if row.get("disputed"):
            row.update(judgment="uncertain", judgment_source="label_adjudication_disagreement")
        elif index in matched:
            row.update(judgment="true", judgment_source="matched_label", label_id=matched[index])
        elif review:
            row.update(judgment=review["verdict"], judgment_source="scoped_human_adjudication")
        else:
            row["judgment_source"] = "missing_scoped_adjudication"
    hits = set(matched.values())
    states = [{"id": label["id"], "state": "detected" if label["id"] in hits else
               "missed_on_complete_scan" if (label["repo"], label["ref"], label["path"]) in complete_files else
               "unobserved"} for label in labels]
    report.update(
        data_contract_valid=not report["errors"], observations=predictions, labels=states,
        metrics=_metrics(predictions, states),
        coverage={"planned_repository_trees": len(planned_trees), "accepted_repository_trees": len(accepted_trees),
                  "missing_repository_trees": len(planned_trees - accepted_trees),
                  "planned_labeled_files": len(planned_files),
                  "complete_labeled_files": len(planned_files & complete_files),
                  "missing_or_incomplete_labeled_files": len(planned_files - complete_files),
                  "file_observations_with_incomplete_stages": stages_incomplete,
                  "invalid_observations_or_inputs": len(report["errors"]),
                  "whole_source_tree_coverage": "not_established_by_label_manifest"},
    )
    report["observations_complete"] = (not report["errors"] and planned_files <= complete_files
                                       and stages_incomplete == 0 and report["metrics"]["unresolved_alerts"] == 0)
    report["coverage"]["labeled_file_completion_rate"] = len(planned_files & complete_files) / len(planned_files)
    if report["errors"]:
        report["release_blockers"].append("invalid_observations_or_inputs")
    if planned_files - complete_files or stages_incomplete:
        report["release_blockers"].append("missing_or_incomplete_scan_coverage")
    if report["metrics"]["unresolved_alerts"]:
        report["release_blockers"].append("unresolved_alert_judgments")
    report["by_language"] = {}
    for language in sorted({language_of(label["path"]) for label in labels}):
        selected_ids = {label["id"] for label in labels if language_of(label["path"]) == language}
        report["by_language"][language] = _metrics(
            [row for row in predictions if language_of(row["path"]) == language],
            [state for state in states if state["id"] in selected_ids])
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=ROOT / "benchmarks/vulnerable-corpus/labels.json")
    parser.add_argument("--observations", type=Path, nargs="*", default=[])
    parser.add_argument("--adjudications", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report-only", action="store_true", help="Diagnostic exit 0 only; never admission")
    args = parser.parse_args(argv)
    try:
        report = evaluate(json.loads(args.labels.read_text()),
                          [json.loads(path.read_text()) for path in args.observations],
                          json.loads(args.adjudications.read_text()) if args.adjudications else None)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {"schema_version": "detection-evaluation-v1", "production_ready": False,
                  "release_admissible": False, "data_contract_valid": False,
                  "errors": [{"code": "unreadable_or_invalid_input", "error_type": type(error).__name__}]}
    rendered = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if args.report_only else 2


if __name__ == "__main__":
    raise SystemExit(main())
