"""Runtime admission for exact rule definitions approved by the release evidence gate."""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

SOURCE = Path(__file__).resolve().parent
POLICY_FILE = SOURCE / "publication-policy.json"

def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _normalized(value: Any) -> Any:
    if isinstance(value, re.Pattern):
        return {"pattern": value.pattern, "flags": value.flags}
    if isinstance(value, dict):
        return {key: _normalized(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalized(item) for item in value]
    return value


def current_rules() -> dict[str, dict[str, str]]:
    """Read definitions without importing main, initializing clients, or running scans."""
    source = SOURCE
    sys.path.insert(0, str(source))
    try:
        from security_rules import DEPENDENCY_RISK_PATTERNS, SECURITY_RULES
        from secret_detection import POSTING
    finally:
        sys.path.remove(str(source))
    rules = {}

    def add(rule_id: str, posting: str, definition: Any) -> None:
        if rule_id in rules:
            raise ValueError(f"duplicate rule id: {rule_id}")
        if posting not in {"post", "quarantine"}:
            raise ValueError(f"invalid posting policy: {rule_id}")
        rules[rule_id] = {"posting": posting, "rule_digest": digest(_normalized(definition))}

    for rule in SECURITY_RULES:
        definition = {field.name: getattr(rule, field.name) for field in dataclasses.fields(rule)
                      if field.name not in {"posting", "precision", "precision_evidence"}}
        add(rule.rule_id, rule.posting, definition)
    add("dependency.risk.version", "post", DEPENDENCY_RISK_PATTERNS)
    for path in sorted((source / "opengrep_rules").glob("*.y*ml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise ValueError(f"invalid rule document: {path.name}")
        for rule in document["rules"]:
            definition = dict(rule)
            metadata = dict(rule.get("metadata") or {})
            posting = str(metadata.pop("posting", "post")).strip().lower()
            for field in ("posting_evidence", "precision_evidence"):
                metadata.pop(field, None)
            definition["metadata"] = metadata
            add("opengrep." + rule["id"], posting, definition)
    # Both secret signals share implementation; an implementation change requires
    # revalidation of both. AST hashing ignores formatting and the posting declaration.
    tree = ast.parse((source / "secret_detection.py").read_text(encoding="utf-8"))
    tree.body = [node for node in tree.body if not (
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "POSTING"
                                            for target in node.targets))]
    for rule_id, posting in POSTING.items():
        add(rule_id, posting, ast.dump(tree, include_attributes=False))
    return rules


@lru_cache(maxsize=1)
def postable_rule_ids() -> frozenset[str]:
    """An absent, malformed, stale or unapproved definition never reaches a reviewer."""
    try:
        policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        if policy.get("schema_version") != "v1" or not isinstance(policy.get("rules"), dict):
            return frozenset()
        return frozenset(rule_id for rule_id, rule in current_rules().items()
                         if rule["posting"] == "post"
                         and policy["rules"].get(rule_id, {}).get("rule_digest") == rule["rule_digest"]
                         and policy["rules"][rule_id].get("status") in {"validated", "legacy_unvalidated"})
    except (OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError):
        return frozenset()


def remediation_publication_ready() -> bool:
    try:
        policy = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
        return policy.get("schema_version") == "v1" and policy.get("remediation_release_verified") is True
    except (OSError, ValueError, AttributeError):
        return False
