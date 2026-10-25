"""Authenticate external remediation review receipts; never establish readiness alone.

Protocol v1 signs DOMAIN + canonical_json(payload) with Ed25519. Public keys come
only from the locally configured trust store, never from the receipt or an env var.
Callers must supply the *current* complete evaluation inputs, not copy bindings out
of a receipt. Statistical quality and live sandbox admission remain separate gates.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[2]
TRUST_STORE = Path(__file__).resolve().parent / "release/trusted-keys.json"
DOMAIN = b"mitig8it/remediation-release-evidence/v1\x00"
PURPOSE = "mitig8it/remediation-release-evidence"
MAX_RECEIPT_AGE_SECONDS = 30 * 24 * 60 * 60
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_REVISION = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9./_:-]*@sha256:[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/@+-]{0,255}\Z")
RELEASE_INPUT_PATHS = (
    "benchmarks/quality_gate.py",
    "benchmarks/remediation/evaluate.py",
    "benchmarks/remediation/fixtures",
    "benchmarks/remediation/release-manifest.json",
    "benchmarks/remediation/release/trusted-keys.json",
    "benchmarks/remediation/release_evidence.py",
    "benchmarks/requirements-quality.txt",
    "services/remediation-service",
)


class ReleaseEvidenceError(ValueError):
    """Invalid, incomplete, stale, or unauthenticated release evidence."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReleaseEvidenceError(reason)


def canonical_json(value: Any) -> bytes:
    """Protocol encoding: sorted string keys, ASCII escapes, compact JSON, no NaN.

    Arrays retain their order. Reject non-JSON Python values rather than silently
    coercing keys, tuples, or non-finite numbers into a different signed document.
    """
    def validate(item: Any) -> None:
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            require(math.isfinite(item), "non_finite_json_number")
        elif type(item) is list:
            for child in item:
                validate(child)
        elif type(item) is dict:
            require(all(type(key) is str for key in item), "non_string_json_key")
            for child in item.values():
                validate(child)
        else:
            raise ReleaseEvidenceError("non_json_value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def signing_bytes(payload: dict[str, Any]) -> bytes:
    return DOMAIN + canonical_json(payload)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ReleaseEvidenceError("non_finite_json_number")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReleaseEvidenceError("unreadable_evidence_document") from error


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _base64(value: Any, length: int, reason: str) -> bytes:
    require(isinstance(value, str), reason)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReleaseEvidenceError(reason) from error
    require(len(decoded) == length and base64.b64encode(decoded).decode("ascii") == value, reason)
    return decoded


def _timestamp(value: Any) -> datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "invalid_receipt_timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ReleaseEvidenceError("invalid_receipt_timestamp") from error


def fixture_inventory(directory: Path) -> dict[str, Any]:
    """Commit to every fixture metadata/source/reference/check file, not IDs alone.

    Only interpreter/test caches are excluded. Symlinks are refused, including a
    fixture directory symlink, so a receipt cannot silently hash outside its corpus.
    """
    inventory: dict[str, Any] = {}
    for child in sorted(directory.iterdir()):
        require(not child.is_symlink(), "fixture_symlink_not_allowed")
        if not child.is_dir() or not (child / "fixture.json").is_file():
            continue
        metadata = read_json(child / "fixture.json")
        require(isinstance(metadata, dict) and _identifier(metadata.get("id")), "invalid_fixture_metadata")
        fixture_id = metadata["id"]
        require(fixture_id not in inventory, "duplicate_fixture_id")
        files = {}
        for path in sorted(child.rglob("*")):
            if any(part in {"__pycache__", ".pytest_cache"} for part in path.relative_to(child).parts):
                continue
            require(not path.is_symlink(), "fixture_symlink_not_allowed")
            if path.is_file():
                files[path.relative_to(child).as_posix()] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        inventory[fixture_id] = {"metadata": metadata, "files": files}
    require(bool(inventory), "empty_fixture_inventory")
    return inventory


def expected_bindings(*, source_revision: str, manifest: dict, fixtures: dict,
                      results: list, provider_id: str, model_id: str,
                      configuration: dict, sandbox_image_digest: str) -> dict:
    """Build independently supplied current bindings, never trust receipt bindings.

    `results` is the full evaluation result array, including evidence, usage, and
    limitations, not a summary/count or a precomputed hash. Its metadata must agree
    with the current complete fixture inventory. No input executes candidate code.
    """
    require(isinstance(source_revision, str) and SOURCE_REVISION.fullmatch(source_revision) is not None,
            "invalid_source_revision")
    require(isinstance(manifest, dict) and manifest.get("schema_version") == "v1", "invalid_manifest")
    require(isinstance(fixtures, dict) and bool(fixtures), "empty_fixture_inventory")
    require(isinstance(results, list) and bool(results), "empty_evaluation_results")
    require(_identifier(provider_id) and _identifier(model_id), "invalid_provider_or_model_identity")
    require(isinstance(configuration, dict) and bool(configuration), "missing_provider_configuration")
    require(isinstance(sandbox_image_digest, str) and IMAGE.fullmatch(sandbox_image_digest) is not None,
            "sandbox_image_must_be_digest_pinned")
    result_ids = set()
    for result in results:
        require(isinstance(result, dict) and _identifier(result.get("fixture_id")), "invalid_result_record")
        fixture_id = result["fixture_id"]
        require(fixture_id not in result_ids, "duplicate_result_id")
        result_ids.add(fixture_id)
        fixture = fixtures.get(fixture_id)
        require(isinstance(fixture, dict) and isinstance(fixture.get("metadata"), dict)
                and isinstance(fixture.get("files"), dict) and bool(fixture["files"]), "missing_complete_fixture")
        metadata = fixture["metadata"]
        require(metadata.get("id") == fixture_id, "fixture_identity_mismatch")
        require(metadata.get("kind") in ("supported", "negative", "adversarial")
                and metadata.get("split") in ("train", "validation", "holdout")
                and metadata.get("expected_state") == ("ready" if metadata.get("kind") == "supported" else "unsupported"),
                "invalid_fixture_metadata")
        for field in ("repository_id", "split", "family", "kind"):
            require(isinstance(metadata.get(field), str) and result.get(field) == metadata[field],
                    "result_fixture_metadata_mismatch")
        require(result.get("outcome") == "passed", "evaluation_result_not_passed")
        require(result.get("observed_state") == metadata.get("expected_state"), "evaluation_state_mismatch")
        if result["observed_state"] == "ready":
            require(result.get("verification_level") == "independent_sandbox", "production_sandbox_evidence_required")
        for content_digest in fixture["files"].values():
            require(isinstance(content_digest, str) and DIGEST.fullmatch(content_digest) is not None,
                    "invalid_fixture_content_digest")
    require(result_ids == set(fixtures), "fixture_results_missing_or_unexpected")
    return {
        "source_revision": source_revision,
        "manifest_digest": digest(manifest), "fixtures_digest": digest(fixtures), "results_digest": digest(results),
        "provider": {"kind": "live-provider", "provider_id": provider_id, "model_id": model_id,
                     "configuration_digest": digest(configuration)},
        "sandbox": {"verification_level": "independent_sandbox", "image_digest": sandbox_image_digest},
    }


def _trusted_keys(store: Any) -> tuple[dict[str, dict], int, int]:
    require(isinstance(store, dict) and set(store) == {"schema_version", "minimum_reviewers", "max_receipt_age_seconds", "keys"}
            and store["schema_version"] == "v1", "invalid_trust_store")
    minimum, age = store["minimum_reviewers"], store["max_receipt_age_seconds"]
    require(type(minimum) is int and minimum >= 1, "invalid_reviewer_threshold")
    require(type(age) is int and 1 <= age <= MAX_RECEIPT_AGE_SECONDS, "invalid_receipt_age_policy")
    require(isinstance(store["keys"], list) and bool(store["keys"]), "no_trusted_review_keys")
    keys, materials = {}, set()
    for entry in store["keys"]:
        require(isinstance(entry, dict) and set(entry) == {"key_id", "reviewer_id", "algorithm", "status", "public_key_base64"},
                "invalid_trusted_key")
        key_id = entry["key_id"]
        require(_identifier(key_id) and _identifier(entry["reviewer_id"]) and entry["algorithm"] == "ed25519"
                and isinstance(entry["status"], str) and entry["status"] in {"active", "revoked"}, "invalid_trusted_key")
        material = _base64(entry["public_key_base64"], 32, "invalid_public_key")
        require(key_id not in keys and material not in materials, "duplicate_trusted_key")
        keys[key_id] = entry
        materials.add(material)
    return keys, minimum, age


def verify_release_evidence(receipt: Any, *, source_revision: str, manifest: dict,
                            fixtures: dict, results: list, provider_id: str, model_id: str,
                            configuration: dict, sandbox_image_digest: str,
                            trust_store_path: Path = TRUST_STORE, now: datetime | None = None) -> dict:
    """Verify a complete receipt against current inputs and explicitly trusted keys.

    The return value authenticates review evidence ONLY. It is deliberately not a
    `passed` or `production_ready` flag, and must not enable packaged admission.
    """
    bindings = expected_bindings(source_revision=source_revision, manifest=manifest, fixtures=fixtures,
                                 results=results, provider_id=provider_id, model_id=model_id,
                                 configuration=configuration, sandbox_image_digest=sandbox_image_digest)
    require(isinstance(receipt, dict) and set(receipt) == {"schema_version", "payload", "signatures"}
            and receipt["schema_version"] == "v1", "invalid_release_receipt")
    payload = receipt["payload"]
    require(isinstance(payload, dict) and set(payload) == {"purpose", "schema_version", "issued_at", "expires_at", "reviews", *bindings}
            and payload["purpose"] == PURPOSE and payload["schema_version"] == "v1", "invalid_release_payload")
    for field, value in bindings.items():
        require(canonical_json(payload[field]) == canonical_json(value), f"binding_mismatch:{field}")
    keys, minimum, max_age = _trusted_keys(read_json(trust_store_path))
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    current = now or datetime.now(timezone.utc)
    require(isinstance(current, datetime) and current.tzinfo is not None, "verification_time_must_be_timezone_aware")
    require(issued <= current < expires and 0 < (expires - issued).total_seconds() <= max_age
            and (current - issued).total_seconds() <= max_age, "stale_or_future_release_receipt")
    signatures = receipt["signatures"]
    require(isinstance(signatures, list) and bool(signatures), "missing_review_signatures")
    signed_keys, reviewers = set(), set()
    message = signing_bytes(payload)
    for entry in signatures:
        require(isinstance(entry, dict) and set(entry) == {"algorithm", "key_id", "reviewer_id", "signature"}, "invalid_signature_record")
        require(entry["algorithm"] == "ed25519" and _identifier(entry["key_id"])
                and _identifier(entry["reviewer_id"]), "invalid_signature_record")
        key_id, reviewer_id = entry["key_id"], entry["reviewer_id"]
        require(key_id not in signed_keys and reviewer_id not in reviewers, "duplicate_review_signature")
        key = keys.get(key_id)
        require(key is not None, "unknown_review_key")
        require(key["status"] == "active", "revoked_review_key")
        require(key["reviewer_id"] == reviewer_id, "reviewer_key_identity_mismatch")
        signature = _base64(entry["signature"], 64, "invalid_signature_base64")
        public = Ed25519PublicKey.from_public_bytes(_base64(key["public_key_base64"], 32, "invalid_public_key"))
        try:
            public.verify(signature, message)
        except InvalidSignature as error:
            raise ReleaseEvidenceError("invalid_review_signature") from error
        signed_keys.add(key_id)
        reviewers.add(reviewer_id)
    require(len(reviewers) >= minimum, "insufficient_independent_reviewers")
    reviews = payload["reviews"]
    require(isinstance(reviews, list) and bool(reviews), "missing_fixture_reviews")
    results_by_id = {item["fixture_id"]: item for item in results}
    reviewed, review_owners = set(), set()
    for review in reviews:
        require(isinstance(review, dict) and set(review) == {"fixture_id", "reviewer_id", "verdict", "fixture_digest", "result_digest"},
                "invalid_fixture_review")
        fixture_id, reviewer_id = review["fixture_id"], review["reviewer_id"]
        require(_identifier(fixture_id) and fixture_id not in reviewed and fixture_id in fixtures, "duplicate_or_unknown_fixture_review")
        require(_identifier(reviewer_id) and reviewer_id in reviewers, "fixture_reviewer_not_authenticated")
        require(review["verdict"] == "approved", "fixture_review_not_approved")
        require(review["fixture_digest"] == digest(fixtures[fixture_id])
                and review["result_digest"] == digest(results_by_id[fixture_id]), "fixture_review_binding_mismatch")
        reviewed.add(fixture_id)
        review_owners.add(reviewer_id)
    require(reviewed == set(fixtures), "fixture_review_coverage_incomplete")
    require(review_owners == reviewers, "signature_without_attributed_reviews")
    return {"schema_version": "v1", "receipt_digest": digest(receipt), "source_revision": source_revision,
            "authenticated_reviewers": sorted(reviewers), "reviewed_fixtures": len(reviewed),
            "expires_at": payload["expires_at"], "scope": "external_review_authentication_only"}


def clean_checkout_revision() -> str:
    """Return HEAD only when all source-bound release inputs are tracked and clean."""
    require(not TRUST_STORE.is_symlink(), "trust_store_symlink_not_allowed")
    relative_trust = TRUST_STORE.relative_to(ROOT).as_posix()
    subprocess.run(["git", "ls-files", "--error-unmatch", relative_trust], cwd=ROOT,
                   check=True, capture_output=True)
    # Unlike `git diff HEAD`, porcelain status also reports untracked fixture or
    # engine files. Those cannot be reviewed under a commit that omits them.
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *RELEASE_INPUT_PATHS],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    require(not status.stdout.strip(), "dirty_or_untracked_release_inputs")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    require(SOURCE_REVISION.fullmatch(revision) is not None, "invalid_source_revision")
    return revision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evaluation", type=Path, required=True, help="Complete current evaluation JSON containing results")
    parser.add_argument("--identity", type=Path, required=True, help="Non-secret provider_id, model_id, configuration, sandbox_image_digest JSON")
    args = parser.parse_args()
    try:
        # The production CLI cannot substitute a trust store, source SHA or corpus.
        # Register public keys in the checked-in policy by a separately approved PR.
        revision = clean_checkout_revision()
        evaluation, identity = read_json(args.evaluation), read_json(args.identity)
        require(isinstance(evaluation, dict) and isinstance(evaluation.get("results"), list), "invalid_evaluation_document")
        require(isinstance(identity, dict) and set(identity) == {"provider_id", "model_id", "configuration", "sandbox_image_digest"},
                "invalid_evaluation_identity")
        authenticated = verify_release_evidence(read_json(args.receipt), source_revision=revision,
            manifest=read_json(ROOT / "benchmarks/remediation/release-manifest.json"),
            fixtures=fixture_inventory(ROOT / "benchmarks/remediation/fixtures"), results=evaluation["results"], **identity)
        print(json.dumps(authenticated, indent=2, sort_keys=True))
        return 0
    except (ReleaseEvidenceError, OSError, subprocess.SubprocessError, TypeError, KeyError, RecursionError):
        # Do not print caller-controlled documents or provider configuration to logs.
        print("Release review authentication refused: missing, dirty, stale, invalid or untrusted evidence.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
