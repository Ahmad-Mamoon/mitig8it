"""Offline validation for curated application and agent security cases.

This module deliberately does not fetch URLs, execute fixture code, install dependencies,
or contact LangSmith.  It validates the shared ``{schema_version: 1, cases: [...]}``
container used by the application and agent curation datasets.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "js", "ts"}
SPLITS = {"dev", "development", "validation", "holdout", "train"}
VERDICTS = {"true_positive", "false_positive", "uncertain"}
HUNK_RE = re.compile(r"^@@ -(?:\d+)(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
URL_RE = re.compile(r"^https://[^\s]+$")


class ValidationError(ValueError):
    pass


def _err(case_id: str, message: str) -> None:
    raise ValidationError(f"{case_id}: {message}")


def _urls(value):
    if isinstance(value, str):
        return [value] if value.startswith("https://") else []
    if isinstance(value, dict):
        out = []
        for v in value.values():
            out.extend(_urls(v))
        return out
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_urls(v))
        return out
    return []


def _patch_lines(patch: str):
    """Return new-file line number -> line text for a unified diff."""
    lines = {}
    current = None
    for raw in patch.splitlines():
        match = HUNK_RE.match(raw)
        if match:
            current = int(match.group(1))
            continue
        if current is None or raw.startswith(("---", "+++")):
            continue
        if raw.startswith("+"):
            lines[current] = raw[1:]
            current += 1
        elif raw.startswith(" "):
            lines[current] = raw[1:]
            current += 1
        elif raw.startswith("-"):
            continue
    return lines


def _check_syntax(case_id: str, language: str, source: str) -> None:
    if language == "python":
        try:
            ast.parse(source)
        except SyntaxError as exc:
            _err(case_id, f"Python source is not syntactically valid: {exc.msg}")
    elif language in {"javascript", "typescript", "js", "ts"}:
        # This is intentionally only a plausibility check.  Running an arbitrary fixture or
        # installing a JS parser would make validation unsafe and non-reproducible.
        pairs = {"(": ")", "[": "]", "{": "}"}
        stack = []
        quote = None
        escaped = False
        for char in source:
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in "'\"`":
                quote = char
            elif char in pairs:
                stack.append(pairs[char])
            elif char in pairs.values():
                if not stack or stack.pop() != char:
                    _err(case_id, "JavaScript/TypeScript delimiters are unbalanced")
        if quote or stack:
            _err(case_id, "JavaScript/TypeScript delimiters are unbalanced")


def _changed_patch_lines(left: str, right: str) -> list[str]:
    changes = []
    for line in difflib.ndiff(left.splitlines(), right.splitlines()):
        if line.startswith(("+ ", "- ")):
            changes.append(line[2:].strip())
    return changes


def _is_prose_line(line: str) -> bool:
    return line.startswith(("#", "//", "/*", "*", "<!--")) or "review" in line.lower() or "assistant" in line.lower()


def _pair_review(cases: list[dict], version: int) -> list[str]:
    """Return hard errors for v2 agent-pair contracts and warnings for near duplicates."""
    flags = []
    groups = defaultdict(list)
    for case in cases:
        if case.get("suite") == "agent" or case.get("variant") in {"attack", "control"}:
            groups[case.get("lineage")].append(case)
    for lineage, members in groups.items():
        if len(members) != 2:
            flags.append(f"{lineage}: expected exactly one attack/control pair")
            continue
        a, b = members
        if a.get("expected_verdict") != b.get("expected_verdict"):
            flags.append(f"{lineage}: attack/control labels differ")
        if a.get("repo_profile") != b.get("repo_profile"):
            flags.append(f"{lineage}: attack/control repo_profile differs")
        af, bf = a.get("finding", {}), b.get("finding", {})
        for key in ("rule_id", "title", "category", "cwe_id", "severity", "file_path", "line_start", "line_end", "code_snippet", "evidence", "evidence_details"):
            if af.get(key) != bf.get(key):
                flags.append(f"{lineage}: finding field {key} differs")
        if a.get("file_patch") != b.get("file_patch"):
            changed = _changed_patch_lines(a.get("file_patch", ""), b.get("file_patch", ""))
            if len(changed) != 2 or not all(_is_prose_line(line.lstrip("+- ")) for line in changed):
                flags.append(f"{lineage}: patch pair is not exactly one prose/comment-line replacement")
        if version >= 2 and (af.get("title") != bf.get("title") or af.get("confidence") != bf.get("confidence")):
            flags.append(f"{lineage}: title/confidence leaks pair label")
    return flags


def _application_lineage_review(cases: list[dict], version: int) -> list[str]:
    """Reject scanner annotations that reveal a triplet's expected label."""
    if version < 2:
        return []
    groups = defaultdict(list)
    for case in cases:
        if case.get("suite", "application") == "application":
            groups[case.get("lineage")].append(case)
    flags = []
    for lineage, members in groups.items():
        if len(members) < 2:
            continue
        findings = [member.get("finding", {}) for member in members]
        if len({finding.get("evidence") for finding in findings}) > 1:
            flags.append(f"{lineage}: finding evidence differs within application lineage")
        if len({finding.get("remediation") for finding in findings}) > 1:
            flags.append(f"{lineage}: finding remediation differs within application lineage")
        detail_keys = set().union(*(finding.get("evidence_details", {}).keys() for finding in findings))
        for key in detail_keys - {"source_expr", "sink_expr"}:
            if len({finding.get("evidence_details", {}).get(key) for finding in findings}) > 1:
                flags.append(f"{lineage}: evidence_details.{key} differs within application lineage")
    return flags


def validate_case(case: dict, *, seen_ids: set[str] | None = None, seen_fingerprints: set[str] | None = None) -> dict:
    if not isinstance(case, dict):
        raise ValidationError("case must be an object")
    case_id = case.get("id")
    if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,127}", case_id):
        raise ValidationError("case id must match [A-Za-z0-9][A-Za-z0-9_.-]{1,127}")
    if seen_ids is not None:
        if case_id in seen_ids:
            _err(case_id, "duplicate id")
        seen_ids.add(case_id)
    split = case.get("split")
    if split not in SPLITS:
        _err(case_id, f"split must be one of {sorted(SPLITS)}")
    lineage = case.get("lineage")
    if not isinstance(lineage, str) or not lineage.strip():
        _err(case_id, "non-empty lineage is required")
    language = case.get("language") or (case.get("repo_profile") or {}).get("language")
    if language not in SUPPORTED_LANGUAGES:
        _err(case_id, f"unsupported language {language!r}")
    verdict = case.get("expected_verdict", case.get("expected_outcome"))
    if not isinstance(verdict, str) or not verdict.strip():
        _err(case_id, "expected_verdict or expected_outcome is required")
    finding = case.get("finding")
    if not isinstance(finding, dict):
        _err(case_id, "finding must be an object")
    fingerprint = finding.get("fingerprint") or case.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        _err(case_id, "finding fingerprint is required")
    if seen_fingerprints is not None:
        if fingerprint in seen_fingerprints:
            _err(case_id, f"duplicate fingerprint {fingerprint!r}")
        seen_fingerprints.add(fingerprint)
    provenance = case.get("provenance")
    source_refs = case.get("source_refs")
    if provenance is None and source_refs is None:
        _err(case_id, "provenance or source_refs is required")
    if source_refs is not None and not isinstance(source_refs, list):
        _err(case_id, "source_refs must be a list")
    if isinstance(source_refs, list):
        for ref in source_refs:
            if not isinstance(ref, dict) or not isinstance(ref.get("url"), str) or not isinstance(ref.get("title"), str):
                _err(case_id, "each source_ref requires url and title")
            if ref.get("published") is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(ref["published"])):
                _err(case_id, "source_ref published must use YYYY-MM-DD")
    urls = _urls(provenance if provenance is not None else source_refs)
    if not urls:
        _err(case_id, "provenance must include at least one HTTPS primary-source URL")
    for url in urls:
        if not URL_RE.match(url) or urlparse(url).netloc == "":
            _err(case_id, f"invalid HTTPS provenance URL {url!r}")
    patch = case.get("file_patch")
    if not isinstance(patch, str) or "@@" not in patch:
        _err(case_id, "file_patch must be a unified diff with at least one hunk")
    path = finding.get("file_path")
    start, end = finding.get("line_start"), finding.get("line_end")
    snippet = finding.get("code_snippet")
    if not isinstance(path, str) or not path or not isinstance(start, int) or not isinstance(end, int) or end < start:
        _err(case_id, "finding file_path and valid line_start/line_end are required")
    if not isinstance(snippet, str) or not snippet.strip():
        _err(case_id, "finding code_snippet is required")
    mapped = _patch_lines(patch)
    expected = snippet.splitlines()
    if [mapped.get(n) for n in range(start, end + 1)] != expected:
        _err(case_id, "finding code_snippet does not exactly match file_patch at its line range")
    _check_syntax(case_id, language, "\n".join(mapped[n] for n in sorted(mapped)))
    return {"id": case_id, "split": split, "lineage": lineage, "language": language, "verdict": verdict, "fingerprint": fingerprint}


def validate_dataset(payload: dict) -> dict:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("cases"), list):
        raise ValidationError("dataset must be {schema_version: 1, cases: [...]}")
    version = payload.get("dataset_version", 1)
    if version not in {1, 2}:
        raise ValidationError("dataset_version must be 1 or 2")
    cases = payload["cases"]
    if not cases:
        raise ValidationError("dataset cases must not be empty")
    inherited_ids = payload.get("inherited_seed_ids", [])
    if not isinstance(inherited_ids, list) or not all(isinstance(value, str) and value for value in inherited_ids):
        raise ValidationError("inherited_seed_ids must be a list of non-empty strings")
    inherited_set = set(inherited_ids)
    ids, fingerprints, lineages, isolation_groups = set(), set(), {}, {}
    summaries = []
    for case in cases:
        summary = validate_case(case, seen_ids=ids, seen_fingerprints=fingerprints)
        prior = lineages.setdefault(summary["lineage"], summary["split"])
        if prior != summary["split"]:
            _err(summary["id"], f"lineage {summary['lineage']!r} crosses splits ({prior}, {summary['split']})")
        isolation = case.get("isolation_group")
        if version >= 2 and (not isinstance(isolation, str) or not isolation.strip()):
            _err(summary["id"], "dataset v2 requires a non-empty isolation_group")
        if isolation:
            prior_isolation = isolation_groups.setdefault(isolation, summary["split"])
            if prior_isolation != summary["split"]:
                _err(summary["id"], f"isolation_group {isolation!r} crosses splits")
        if version >= 2 and (not isinstance(case.get("scenario_id"), str) or not case.get("scenario_id").strip()):
            _err(summary["id"], "dataset v2 cases require scenario_id; migrated seeds must be normalized")
        summaries.append(summary)
    missing_inherited = inherited_set - ids
    if missing_inherited:
        raise ValidationError(f"inherited_seed_ids not present in cases: {sorted(missing_inherited)}")
    pair_flags = _pair_review(cases, version)
    if version >= 2 and pair_flags:
        raise ValidationError("v2 agent-pair contract failed: " + "; ".join(pair_flags))
    application_flags = _application_lineage_review(cases, version)
    if application_flags:
        raise ValidationError("v2 application-lineage annotation contract failed: " + "; ".join(application_flags))
    # Title/confidence must not reveal a triplet's label. This applies to migrated seeds too;
    # v2 is a normalized catalog while v1 remains the frozen comparison corpus.
    leakage_flags = []
    by_lineage = defaultdict(list)
    for case in cases:
        by_lineage[case.get("lineage")].append(case)
    for lineage, members in by_lineage.items():
        if version < 2:
            continue
        pairs = {(member.get("finding", {}).get("title"), member.get("finding", {}).get("confidence")) for member in members}
        if len(pairs) > 1:
            raise ValidationError(f"{lineage}: v2 finding title/confidence must be identical within a lineage")
    # Near-duplicate content across splits is a review warning, not an automatic rejection:
    # shared boilerplate is common, and a human should decide whether the scenario leaked.
    normalized = defaultdict(set)
    for case in cases:
        patch = "\n".join(line for line in case.get("file_patch", "").splitlines() if not _is_prose_line(line.lstrip("+- ")))
        key = hashlib.sha256(patch.encode()).hexdigest()
        normalized[key].add(case.get("split"))
    near_duplicate_flags = [f"normalized fixture content appears across splits: {splits}" for splits in normalized.values() if len(splits) > 1]
    manual_review = pair_flags + near_duplicate_flags + leakage_flags
    counts = {split: sum(s["split"] == split for s in summaries) for split in sorted(SPLITS)}
    source_urls = _urls([case.get("source_refs", case.get("provenance")) for case in cases])
    domains = sorted({urlparse(url).netloc for url in source_urls})
    return {"cases": len(summaries), "lineages": len(lineages), "split_counts": counts,
            "verdict_counts": {v: sum(s["verdict"] == v for s in summaries) for v in sorted(VERDICTS)},
            "languages": {lang: sum(s["language"] == lang for s in summaries) for lang in sorted(SUPPORTED_LANGUAGES)},
            "dataset_version": version, "inherited_seed_ids": sorted(inherited_set),
            "inherited_case_count": sum(s["id"] in inherited_set for s in summaries),
            "new_case_count": sum(s["id"] not in inherited_set for s in summaries),
            "source_url_count": len(source_urls), "source_domains": domains,
            "runnable_contracts": sum("runnable" in c or "verification" in c for c in cases),
            "unverified_gap_cases": sum(bool(c.get("known_limitations")) or c.get("expected_verdict") == "uncertain" for c in cases),
            "manual_review_flags": manual_review,
            "summaries": summaries}


def load_and_validate(path: Path) -> dict:
    payload = json.loads(path.read_text())
    summary = validate_dataset(payload)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a security curation dataset offline")
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()
    summary = load_and_validate(args.dataset)
    print(json.dumps({k: v for k, v in summary.items() if k != "summaries"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
