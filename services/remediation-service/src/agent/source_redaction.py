"""A one-run, non-reversible credential boundary for repair-provider context.

Scan complete source before taking windows or truncating it. Known values are then scrubbed
wherever they reappear (metadata, test output, provider echoes, and durable checkpoints).
This is deliberately conservative, not a claim to recognize arbitrary encoded secrets.
"""
from __future__ import annotations

import ast
import copy
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from ..patches import PatchPolicyError, locate_hunk
from ..retrieval import Snapshot


REDACTION_MARKER = "__MITIG8IT_REDACTED_SECRET__"
_NAME = r"[\w$]*(?:api[_-]?key|access[_-]?key|account[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|password|passwd|passphrase|pwd|secret|token|credential|authorization|dsn)[\w$]*"
_NAME_RE = re.compile(rf"\A{_NAME}\Z", re.I)
_ASSIGNMENT = re.compile(rf"(?<![\w$])(?P<name>{_NAME})[\"']?\s*\]?\s*[:=]\s*", re.I)
_BARE_ASSIGNMENT = re.compile(rf"(?im)^[ \t]*(?:export[ \t]+)?(?P<name>{_NAME})[ \t]*[:=][ \t]*(?P<value>[^\r\n]*)")
_QUOTED = re.compile(r"(?:[rubf]{0,2})?(\"\"\"|'''|[\"'`])", re.I)
_KNOWN_KEY = re.compile(
    r"(?<![\w])(?:sk[-_][A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{10,}|"
    r"(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-|xapp-)[A-Za-z0-9_-]{8,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)
_AUTH = re.compile(r"\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)", re.I)
# URLs are masked in their entirety: userinfo, signed queries, webhook paths, and custom
# connection-string schemes all carry credentials. No allowlist of supposedly safe hosts.
_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'`<>\\]+")
_KEY_BEGIN = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----")


class SourceRedactionError(ValueError):
    """A credential-bearing context cannot safely cross the boundary."""


def _credential_name(name: str) -> bool:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    tokens = re.findall(r"[a-z]+", words)
    if not tokens:
        return False
    return tokens[-1] in {"password", "passwd", "pwd", "passphrase", "secret", "token", "credential", "credentials", "authorization", "dsn", "apikey"} or (
        tokens[-1] == "key" and bool(set(tokens[:-1]) & {"api", "access", "account", "private", "secret", "signing", "encryption"})
    )


def _masked(value: str) -> str:
    # Keep every physical line boundary, including CRLF and blank lines. Source locations and
    # original_lines anchors must not drift when a multiline private key is hidden.
    return "".join(part if part in {"\r", "\n", "\r\n"} else REDACTION_MARKER
                   for part in re.split(r"(\r\n|\r|\n)", value) if part)


def _json_field(container: dict[str, Any], key: str) -> bool:
    return key == "content" and container.get("role") in {"system", "user", "assistant", "tool"} or (
        key == "arguments" and isinstance(container.get("name"), str)
    )


class SourceRedactor:
    def __init__(self, snapshot: Snapshot, *context: Any):
        self._secrets: set[str] = set()
        for path in snapshot.paths:
            content = snapshot.full_content(path)
            if REDACTION_MARKER in content:
                raise SourceRedactionError("reserved_redaction_marker_in_source")
            self._learn(content)
        for value in context:
            self._learn(value)

    def _remember(self, value: str) -> None:
        if not value or REDACTION_MARKER in value:
            return
        if len(value.strip()) < 4:
            # Short credentials cannot be propagated safely without destroying identifiers and
            # protocol fields. Refuse the run instead of leaking them or guessing their scope.
            raise SourceRedactionError("credential_too_short_to_redact_safely")
        self._secrets.add(value)
        self._secrets.add(unquote(value))
        for line in value.splitlines():
            if len(line.strip()) >= 4:
                self._secrets.add(line)
        if len(self._secrets) > 1_000:
            raise SourceRedactionError("credential_redaction_limit_exceeded")

    def _spans(self, text: str) -> list[tuple[int, int]]:
        spans = [match.span() for match in _KNOWN_KEY.finditer(text)]
        for match in _URL.finditer(text):
            spans.append(match.span())
            try:
                parsed = urlsplit(match.group())
                values = [value for _, value in parse_qsl(parsed.query)]
            except ValueError as exc:
                raise SourceRedactionError("malformed_repository_url") from exc
            for value in values:
                if value and len(value.strip()) >= 4:
                    self._remember(value)
            if parsed.password:
                self._remember(parsed.password)
            if parsed.username and len(parsed.username.strip()) >= 4:
                self._remember(parsed.username)
        spans.extend(match.span(1) for match in _AUTH.finditer(text) if match.group(1) != REDACTION_MARKER)
        for begin in _KEY_BEGIN.finditer(text):
            marker = f"-----END {begin.group(1)}-----"
            end = text.find(marker, begin.end())
            if end < 0:
                raise SourceRedactionError("unterminated_private_key")
            spans.append((begin.start(), end + len(marker)))
        for assignment in _ASSIGNMENT.finditer(text):
            if not _credential_name(assignment.group("name")):
                continue
            quote_match = _QUOTED.match(text, assignment.end())
            if quote_match is None:
                continue  # Dynamic expressions are not treated as literal credentials.
            quote = quote_match.group(1)
            start = quote_match.end()
            cursor = start
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                elif text.startswith(quote, cursor):
                    break
                else:
                    cursor += 1
            else:
                raise SourceRedactionError("unterminated_credential_literal")
            value = text[start:cursor]
            tail = text[cursor + len(quote):].lstrip(" \t")
            if tail.startswith(("+", "\\\n", "\\\r")):
                raise SourceRedactionError("concatenated_credential_literal")
            if value and value != REDACTION_MARKER:
                spans.append((start, cursor))
                # The decoded form can reappear in findings or failure output without the
                # source string's escapes. literal_eval parses literals; it never runs code.
                if quote != "`":
                    try:
                        decoded = ast.literal_eval(text[quote_match.start():cursor + len(quote)])
                    except (SyntaxError, ValueError):
                        decoded = None
                    if isinstance(decoded, str):
                        self._remember(decoded)
        for assignment in _BARE_ASSIGNMENT.finditer(text):
            if not _credential_name(assignment.group("name")):
                continue
            value = assignment.group("value").strip()
            if not value or _QUOTED.match(value):
                continue
            # These explicit environment reads contain no credential literal. All other bare
            # .env/YAML values are hidden conservatively, even when they resemble identifiers.
            if re.match(r"(?:process\.env\b|os\.environ\b|os\.getenv\(|\$\{[A-Za-z_]\w*\})", value):
                continue
            if value in {"None", "null", "undefined", "true", "false"}:
                continue
            spans.append(assignment.span("value"))
        return spans

    def _learn(self, value: Any, depth: int = 0) -> None:
        if depth > 100:
            raise SourceRedactionError("credential_context_depth_exceeded")
        if isinstance(value, str):
            for start, end in self._spans(value):
                self._remember(value[start:end])
        elif isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise SourceRedactionError("non_string_context_key")
                if _NAME_RE.fullmatch(key) and _credential_name(key) and isinstance(item, str) and item:
                    self._remember(item)
                if _json_field(value, key) and isinstance(item, str):
                    try:
                        parsed = json.loads(item)
                    except (ValueError, TypeError):
                        pass
                    else:
                        self._learn(parsed, depth + 1)
                self._learn(key, depth + 1)
                self._learn(item, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._learn(item, depth + 1)
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise SourceRedactionError("unsupported_credential_context_type")

    def sanitize(self, value: Any) -> Any:
        """Return a fresh JSON-compatible value; never mutate source, actions, or checkpoints."""
        self._learn(value)
        return self._sanitize(value)

    def _sanitize(self, value: Any, *, decode_json: bool = False) -> Any:
        if isinstance(value, str):
            # A message content or tool-call arguments field often already contains JSON.
            # Decode first so credentials cannot survive behind JSON escaping.
            if decode_json and value.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(value)
                except (ValueError, TypeError):
                    pass
                else:
                    return json.dumps(self.sanitize(parsed), sort_keys=True, ensure_ascii=False)
            spans = sorted(self._spans(value))
            merged: list[tuple[int, int]] = []
            for start, end in spans:
                if merged and start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            for start, end in reversed(merged):
                value = value[:start] + _masked(value[start:end]) + value[end:]
            for secret in sorted(self._secrets, key=lambda item: (-len(item), item)):
                # A credential such as "SECRET" must not recursively expand the reserved
                # marker that replaced it. Only operate on non-marker segments.
                value = REDACTION_MARKER.join(part.replace(secret, _masked(secret)) for part in value.split(REDACTION_MARKER))
                for escaped in {json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]}:
                    if escaped != secret:
                        value = REDACTION_MARKER.join(part.replace(escaped, json.dumps(_masked(secret))[1:-1]) for part in value.split(REDACTION_MARKER))
            return value
        if isinstance(value, dict):
            result = {
                self._sanitize(key): _masked(item) if _credential_name(key) and isinstance(item, str) and item else self._sanitize(item, decode_json=_json_field(value, key))
                for key, item in value.items()
            }
            if len(result) != len(value):
                raise SourceRedactionError("redacted_context_key_collision")
            return result
        if isinstance(value, (list, tuple)):
            return [self._sanitize(item) for item in value]
        return value

    def snapshot_view(self, snapshot: Snapshot) -> Snapshot:
        """A retrieval-only copy; exact original snapshot/tree identities remain authoritative."""
        view = copy.copy(snapshot)
        view._files = {path: self.sanitize(snapshot.full_content(path)) for path in snapshot.paths}
        return view

    def restore_anchors(self, changes: list[dict[str, Any]], snapshot: Snapshot) -> list[dict[str, Any]]:
        """Rebind masked quotes to exact snapshot lines, never restore replacement code."""
        restored = copy.deepcopy(changes)
        for change in restored:
            if not isinstance(change, dict):
                continue  # The ordinary patch-policy validator reports its schema error.
            replacements = change.get("replacement_lines", [])
            if REDACTION_MARKER in json.dumps(replacements):
                raise PatchPolicyError("redacted_secret_in_replacement", "Do not copy credential placeholders into code; narrow the hunk or abstain.")
            quoted = change.get("original_lines", [])
            if REDACTION_MARKER not in json.dumps(quoted):
                continue
            path = str(change.get("path", ""))
            original = snapshot.full_content(path).splitlines(keepends=True)
            masked = self.sanitize(snapshot.full_content(path)).splitlines(keepends=True)
            anchor = {key: item for key, item in change.items() if key != "replaced_sha256"}
            start, end = locate_hunk(path, masked, anchor)
            change["original_lines"] = [line.rstrip("\r\n") for line in original[start - 1:end]]
            change["start_line"] = start
        return restored
