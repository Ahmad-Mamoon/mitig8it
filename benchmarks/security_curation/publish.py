"""Dataset-only LangSmith publisher for curated security cases.

The default is a local dry run.  ``--publish`` is the only path that imports the optional
LangSmith SDK or makes network calls; it creates examples, never runs models or traces.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path

from .validate import load_and_validate

WORKSPACE_ID = "779b5011-7837-4605-bdfb-2057895981c9"
ALLOWED_ENV = {"LANGSMITH_API_KEY", "LANGCHAIN_API_KEY", "LANGSMITH_WORKSPACE_ID"}
DATASET_NAMES = {
    "application": "mitig8it-application-security-v1",
    "agent": "mitig8it-ai-reviewer-security-v1",
}
DATASET_NAMES_V2 = {
    "application": "mitig8it-application-security-v2",
    "agent": "mitig8it-ai-reviewer-security-v2",
}
PRIVATE_KEYS = {"expected_verdict", "expected_outcome", "expected_fix_terms", "human_review_rubric",
               "expected_safe_behavior", "reference_repair", "expected_contract", "label", "rubric",
               "rationale", "known_limitations"}
OUTPUT_KEYS = {"expected_verdict", "expected_outcome", "expected_fix_terms", "human_review_rubric",
               "expected_safe_behavior", "reference_repair", "expected_contract", "label", "rubric"}


def _read_env(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key in ALLOWED_ENV:
            values[key] = value
    return values


@contextmanager
def scoped_environment(env_file: Path | None):
    values = _read_env(env_file) if env_file else {}
    if values.get("LANGSMITH_WORKSPACE_ID") not in (None, WORKSPACE_ID):
        raise ValueError("LANGSMITH_WORKSPACE_ID does not match the approved workspace")
    before = {key: os.environ.get(key) for key in ALLOWED_ENV}
    try:
        os.environ.update(values)
        os.environ["LANGSMITH_WORKSPACE_ID"] = WORKSPACE_ID
        # Dataset examples must never inherit ambient tracing configuration.
        os.environ["LANGSMITH_TRACING"] = "false"
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        yield sorted(values)
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _dataset_kind(payload: dict, explicit: str | None) -> str:
    if explicit:
        return explicit
    suites = {str(c.get("suite", "application")) for c in payload["cases"]}
    return "agent" if suites == {"agent"} else "application"


def dataset_name(kind: str, version: int) -> str:
    return (DATASET_NAMES_V2 if version == 2 else DATASET_NAMES)[kind]


def _example(case: dict) -> tuple[dict, dict, dict]:
    # Keep expected labels and human rubric in outputs.  Inputs contain the complete synthetic
    # finding/diff needed for a later evaluation, while split/source lineage live in metadata.
    metadata_keys = {"split", "lineage", "source_refs", "provenance", "variant", "suite", "execution_adapter", "scenario_basis"}
    inputs = {k: v for k, v in case.items() if k not in PRIVATE_KEYS and k not in metadata_keys}
    # Scanner evidence/remediation is frequently written after the expected label and can
    # directly say "safe", "unsafe", or "uncertain". Keep the finding identity and code,
    # but prevent those answer-bearing annotations from becoming model input.
    finding = copy.deepcopy(inputs.get("finding"))
    if isinstance(finding, dict):
        for key in ("evidence", "remediation", "evidence_details"):
            finding.pop(key, None)
        inputs["finding"] = finding
    outputs = {k: v for k, v in case.items() if k in OUTPUT_KEYS}
    metadata = {"case_id": case["id"], "split": case.get("split"), "lineage": case.get("lineage"),
                "variant": case.get("variant"), "suite": case.get("suite"),
                "execution_adapter": case.get("execution_adapter"), "scenario_basis": case.get("scenario_basis"),
                "source_refs": case.get("source_refs", case.get("provenance")),
                "fixture_digest": _digest(case)}
    return {"case_id": case["id"], "fixture": inputs}, outputs, metadata


def publish_dataset(payload: dict, *, kind: str, env_file: Path) -> dict:
    # Import only on the explicit publishing path, keeping validation and dry runs offline.
    try:
        from langsmith import Client
    except ImportError as exc:
        raise RuntimeError("LangSmith SDK is required only for --publish") from exc
    with scoped_environment(env_file):
        if not (os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY")):
            raise ValueError("approved LangSmith API key is missing from the scoped env file")
        client = Client(auto_batch_tracing=False)
        version = int(payload.get("dataset_version", 1))
        name = dataset_name(kind, version)
        dataset = client.read_dataset(dataset_name=name) if client.has_dataset(dataset_name=name) else client.create_dataset(
            dataset_name=name, description=f"Mitig8it {kind} security curation v{version}; labels are evaluator outputs."
        )
        existing = {e.inputs.get("case_id"): e for e in client.list_examples(dataset_id=dataset.id)}
        created, skipped = [], []
        for case in payload["cases"]:
            inputs, outputs, metadata = _example(case)
            old = existing.get(case["id"])
            if old:
                old_digest = (old.metadata or {}).get("fixture_digest") if hasattr(old, "metadata") else None
                if old_digest and old_digest != metadata["fixture_digest"]:
                    raise ValueError(f"conflicting existing fixture {case['id']}; refusing overwrite")
                skipped.append(case["id"])
                continue
            client.create_example(dataset_id=dataset.id, inputs=inputs, outputs=outputs, metadata=metadata)
            created.append(case["id"])
        return {"status": "published", "dataset_name": name, "dataset_id": str(dataset.id),
                "created": created, "skipped_existing": skipped}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or explicitly publish curation datasets")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--kind", choices=sorted(DATASET_NAMES))
    parser.add_argument("--env-file", type=Path, default=Path("benchmarks/remediation/.env"))
    parser.add_argument("--publish", action="store_true", help="Make dataset-only LangSmith writes")
    args = parser.parse_args()
    payload = json.loads(args.dataset.read_text())
    summary = load_and_validate(args.dataset)
    kind = _dataset_kind(payload, args.kind)
    if not args.publish:
        print(json.dumps({"status": "dry_run", "dataset_name": dataset_name(kind, summary["dataset_version"]), **{k: v for k, v in summary.items() if k != "summaries"}}, indent=2, sort_keys=True))
        return 0
    print(json.dumps(publish_dataset(payload, kind=kind, env_file=args.env_file), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
