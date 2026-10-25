from __future__ import annotations

import copy
import json
from dataclasses import asdict

import pytest

from src.agent import ProviderAction, RepairAgent
from src.agent.source_redaction import REDACTION_MARKER, SourceRedactor
from src.models import RepairRequest
from src.patches import PatchPolicyError
from src.retrieval import Snapshot
from src.verification import VerificationResult, Verifier
from tests.conftest import regression_test_spec, whole_file_change
from tests.test_agent_budget import FailingVerifier, RecordingProvider, SettlingCheckpointStore, _abstain, _read
from tests.test_agent_context import _finding, _payload_with
from tests.test_engine import PassingBroker


CANARY = "canary_Credential_7xZp9vQ2"
KEY_CANARY = "sk_canary_DO_NOT_USE_0123456789"


def snapshot_with(request_payload, source):
    request = RepairRequest.model_validate(_payload_with(request_payload, source, [_finding(1, 2)]))
    return request, Snapshot(request)


@pytest.mark.parametrize("source,secret", [
    (f'const API_KEY = "{CANARY}";\n', CANARY),
    (f"password = '{CANARY}'\n", CANARY),
    (f'{{"accessToken": "{CANARY}"}}\n', CANARY),
    (f"export AWS_SECRET_ACCESS_KEY={CANARY}\n", CANARY),
    (f"  password: {CANARY}\n", CANARY),
    (f'// {KEY_CANARY}\n', KEY_CANARY),
    ("// ghp_abcdefghijklmnop0123456789\n", "ghp_abcdefghijklmnop0123456789"),
    ("// AKIAABCDEFGHIJKLMNOP\n", "AKIAABCDEFGHIJKLMNOP"),
    (f'// Authorization: Bearer {CANARY}\n', CANARY),
    (f'// Authorization: Basic {CANARY}\n', CANARY),
    (f'const endpoint = "postgresql://user:{CANARY}@db.internal/app";\n', CANARY),
    (f'const endpoint = "https://example.invalid/hook/{CANARY}?token={CANARY}";\n', CANARY),
    (f'const endpoint = "https://example.invalid/?key=canary%5FCredential%5F7xZp9vQ2";\n', CANARY),
])
def test_common_source_credentials_and_urls_are_scrubbed_without_mutating_originals(request_payload, source, secret):
    request, snapshot = snapshot_with(request_payload, source)
    before = request.model_dump(mode="json")
    redactor = SourceRedactor(snapshot)
    view = redactor.snapshot_view(snapshot)
    safe = view.full_content("src/db.ts")
    assert secret not in safe and REDACTION_MARKER in safe
    assert len(safe.splitlines(keepends=True)) == len(source.splitlines(keepends=True))
    # Values found inside URLs must also be scrubbed when they appear outside a URL.
    assert secret not in json.dumps(redactor.sanitize({"echo": secret}))
    assert snapshot.full_content("src/db.ts") == source
    assert request.model_dump(mode="json") == before
    assert view.manifest_digest == snapshot.manifest_digest


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_multiline_private_keys_preserve_physical_lines_and_scrub_body_echoes(request_payload, newline):
    body = "MIIEcanaryPrivateKeyBody0123456789"
    source = newline.join(['const key = `-----BEGIN RSA PRIVATE KEY-----', body,
                           '-----END RSA PRIVATE KEY-----`;', '// next line', ''])
    _, snapshot = snapshot_with(request_payload, source)
    redactor = SourceRedactor(snapshot)
    safe = redactor.snapshot_view(snapshot).full_content("src/db.ts")
    assert body not in safe and "PRIVATE KEY" not in safe
    assert [len(line) - len(line.rstrip("\r\n")) for line in safe.splitlines(keepends=True)] == [
        len(line) - len(line.rstrip("\r\n")) for line in source.splitlines(keepends=True)
    ]
    assert redactor.sanitize(body) == REDACTION_MARKER
    assert safe.splitlines()[-1] == "// next line"


def test_escaped_secret_literals_are_also_scrubbed_after_decoding_and_json_encoding(request_payload):
    source = 'const API_KEY = "canary\\u005fCredential_7xZp9vQ2";\n'
    _, snapshot = snapshot_with(request_payload, source)
    redactor = SourceRedactor(snapshot)
    value = {"nested": json.dumps({"echo": CANARY, "code": source})}
    original = copy.deepcopy(value)
    safe = json.dumps(redactor.sanitize(value))
    assert CANARY not in safe and "7xZp9vQ2" not in safe
    assert value == original


def test_marker_substrings_do_not_expand_recursively_or_hide_adjacent_credentials(request_payload):
    _, snapshot = snapshot_with(request_payload, 'const API_KEY = "SECRET";\n')
    redactor = SourceRedactor(snapshot)
    once = redactor.sanitize(snapshot.full_content("src/db.ts"))
    assert once.count(REDACTION_MARKER) == 1
    assert redactor.sanitize(once) == once
    suspicious = {"api_key": REDACTION_MARKER + CANARY, "code": 'password = "' + REDACTION_MARKER + CANARY + '"'}
    safe = redactor.sanitize(suspicious)
    assert CANARY not in json.dumps(safe)


def test_json_source_and_numbered_source_lines_keep_their_layout(request_payload):
    original = '{\n  "api_key": "' + CANARY + '",\n  "safe": {"nested": true}\n}\n'
    _, snapshot = snapshot_with(request_payload, original)
    redactor = SourceRedactor(snapshot)
    expected = original.replace(CANARY, REDACTION_MARKER)
    assert redactor.snapshot_view(snapshot).full_content("src/db.ts") == expected
    message = {"role": "tool", "content": json.dumps({"lines": [[3, '  {"nested": true}']]})}
    assert json.loads(redactor.sanitize(message)["content"])["lines"] == [[3, '  {"nested": true}']]


class Checkpoints(SettlingCheckpointStore):
    def __init__(self, checkpoint=None):
        super().__init__()
        self.checkpoint = checkpoint
        self.pending = []
        self.completed = []

    async def load(self):
        return copy.deepcopy(self.checkpoint)

    async def save_provider_action(self, state, action, actual_tokens, actual_usd):
        self.pending.append(copy.deepcopy(state) | {"pending_action": asdict(action)})
        return await super().save_provider_action(state, action, actual_tokens, actual_usd)

    async def save_completed_step(self, state):
        self.completed.append(copy.deepcopy(state))


@pytest.mark.asyncio
async def test_provider_reads_metadata_echoes_and_all_checkpoint_writes_are_redacted(request_payload, source):
    original = source + f'// API_KEY = "{CANARY}"\n// {KEY_CANARY}\n'
    request, snapshot = snapshot_with(request_payload, original)
    request.profile = {"credential": CANARY, "notes": f"echo {KEY_CANARY}"}
    before = request.model_dump(mode="json")
    echo = ProviderAction("search_code", {"query": CANARY})
    original_action = copy.deepcopy(asdict(echo))
    provider = RecordingProvider([_read(1, 20), echo, _abstain()])
    checkpoints = Checkpoints()
    result = await RepairAgent(provider, FailingVerifier(), checkpoints).run(request, snapshot)
    assert result.reason_code == "no_repair"
    serialized = json.dumps([provider.last_messages, checkpoints.pending, checkpoints.completed])
    assert CANARY not in serialized and KEY_CANARY not in serialized
    assert REDACTION_MARKER in serialized
    read = json.loads(next(message["content"] for message in provider.last_messages if message["role"] == "tool"))
    assert [number for number, _ in read["lines"]] == list(range(1, len(original.splitlines()) + 1))
    assert asdict(echo) == original_action
    assert request.model_dump(mode="json") == before
    assert snapshot.full_content("src/db.ts") == original


@pytest.mark.asyncio
async def test_redaction_happens_before_truncation_so_partial_secrets_never_escape(request_payload, source):
    long_secret = "sk_canary_" + "abcdefg1234567" * 80
    original = source + f'// {long_secret}\n'
    request, snapshot = snapshot_with(request_payload, original)
    request.policy.max_tool_result_chars = 100
    provider = RecordingProvider([_read(4, 4), _abstain()])
    await RepairAgent(provider, FailingVerifier()).run(request, snapshot)
    serialized = json.dumps(provider.last_messages)
    assert "sk_canary_" not in serialized and "abcdefg1234567" not in serialized


@pytest.mark.asyncio
async def test_all_repository_retrieval_tools_share_the_redacted_snapshot(request_payload, source):
    original = source + f'// loadUser token: {KEY_CANARY}\n'
    request, snapshot = snapshot_with(request_payload, original)
    # These are validated in-memory retrieval fixtures, never materialized or executed.
    snapshot._files["src/db.test.ts"] = f'// test loadUser {KEY_CANARY}\n'
    snapshot._files["package.json"] = '{"repository":"https://user:' + CANARY + '@example.invalid/repo"}'
    actions = [
        ProviderAction("search_code", {"query": "loadUser"}),
        ProviderAction("find_references", {"symbol": "loadUser"}),
        ProviderAction("read_tests", {"source_path": "src/db.ts"}),
        ProviderAction("read_dependency", {"path": "package.json"}),
        _abstain(),
    ]
    provider = RecordingProvider(actions)
    checkpoints = Checkpoints()
    await RepairAgent(provider, FailingVerifier(), checkpoints).run(request, snapshot)
    serialized = json.dumps([provider.last_messages, checkpoints.pending, checkpoints.completed])
    assert KEY_CANARY not in serialized and CANARY not in serialized
    assert sum(message["role"] == "tool" for message in provider.last_messages) == 4


@pytest.mark.asyncio
async def test_legacy_checkpoint_is_sanitized_before_resumed_provider_call(request_payload, source):
    request, snapshot = snapshot_with(request_payload, source + f'// API_KEY = "{CANARY}"\n')
    legacy = {"context_manifest_digest": snapshot.manifest_digest, "messages": [
        {"role": "system", "content": "legacy"},
        {"role": "tool", "content": json.dumps({"lines": [[4, CANARY]]})},
    ], "trace": [{"reason": CANARY}]}
    before = copy.deepcopy(legacy)
    checkpoints = Checkpoints(legacy)
    provider = RecordingProvider([_abstain()])
    await RepairAgent(provider, FailingVerifier(), checkpoints).run(request, snapshot)
    assert CANARY not in json.dumps([provider.last_messages, checkpoints.pending])
    assert legacy == before


def test_masked_anchors_rebind_only_exact_authoritative_source_ranges(request_payload):
    original = f'const API_KEY = "{CANARY}";\nconst API_KEY = "second_canary_0123456789";\n'
    _, snapshot = snapshot_with(request_payload, original)
    redactor = SourceRedactor(snapshot)
    masked_line = redactor.snapshot_view(snapshot).full_content("src/db.ts").splitlines()[0]
    hunk = {"path": "src/db.ts", "start_line": 2, "original_lines": [masked_line], "replacement_lines": ["const API_KEY = process.env.API_KEY;"]}
    before = copy.deepcopy(hunk)
    restored = redactor.restore_anchors([hunk], snapshot)[0]
    assert restored["original_lines"] == original.splitlines()[1:2]
    assert hunk == before
    with pytest.raises(PatchPolicyError, match="original_lines_ambiguous"):
        redactor.restore_anchors([{key: value for key, value in hunk.items() if key != "start_line"}], snapshot)
    with pytest.raises(PatchPolicyError, match="original_lines_not_found"):
        redactor.restore_anchors([hunk | {"original_lines": ["not source " + REDACTION_MARKER]}], snapshot)
    with pytest.raises(PatchPolicyError, match="redacted_secret_in_replacement"):
        redactor.restore_anchors([hunk | {"replacement_lines": [masked_line]}], snapshot)


def propose(source, replacement, tests=None):
    return ProviderAction("propose_patch", {
        "hypothesis": "Untrusted input reaches SQL.", "intended_behavior": "Preserve lookups.",
        "assumptions": ["pg parameters"], "citations": [{"path": "src/db.ts", "line_start": 1, "line_end": len(source.splitlines())}],
        "changes": [whole_file_change("src/db.ts", source, replacement)],
        "regression_tests": [regression_test_spec()] if tests is None else tests,
    })


@pytest.mark.asyncio
async def test_masked_anchor_builds_exact_patch_and_checkpoints_never_restore_original_secret(request_payload, source):
    original = source.replace("${id}`);", '${id}`); // API_KEY = "' + CANARY + '"')
    request, snapshot = snapshot_with(request_payload, original)
    masked = SourceRedactor(snapshot).snapshot_view(snapshot).full_content("src/db.ts")
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    action = propose(masked, replacement)
    provider = RecordingProvider([action, ProviderAction("request_verification", {})])
    checkpoints = Checkpoints()
    result = await RepairAgent(provider, Verifier(PassingBroker()), checkpoints).run(request, snapshot)
    assert result.state == "ready", result.explanation
    assert result.bundle.patches[0].replacement_content == replacement
    assert CANARY not in json.dumps([provider.last_messages, checkpoints.pending, checkpoints.completed])
    # Rebinding is local, not a mutation of the provider's original masked action.
    assert REDACTION_MARKER in json.dumps(action.arguments["changes"])


@pytest.mark.asyncio
async def test_masked_model_test_is_refused_before_verifier(request_payload, source):
    request, snapshot = snapshot_with(request_payload, source + f'// API_KEY = "{CANARY}"\n')
    masked = SourceRedactor(snapshot).sanitize(snapshot.full_content("src/db.ts"))
    # Narrow the hunk to avoid also copying the source's masked credential comment.
    action = propose(masked, source.replace("${id}", "$1"), [regression_test_spec("// " + REDACTION_MARKER)])
    provider = RecordingProvider([action, _abstain()])
    result = await RepairAgent(provider, FailingVerifier()).run(request, snapshot)
    assert result.state != "ready"
    assert any(step["reason"] == "redacted_secret_in_regression_test" for step in result.trace)


@pytest.mark.asyncio
async def test_authoritative_service_proof_stays_exact_in_sandbox_but_redacted_in_checkpoint_and_resume(request_payload, source):
    original = source.replace("${id}`);", '${id}`); // API_KEY = "' + CANARY + '"')
    request, snapshot = snapshot_with(request_payload, original)
    masked = SourceRedactor(snapshot).sanitize(original)
    replacement = source.replace("db.query(`SELECT * FROM users WHERE id = ${id}`)", "db.query('SELECT * FROM users WHERE id = $1', [id])")
    spec = regression_test_spec()
    proofs = {"finding-1": {"path": spec["path"], "content": spec["content"] + "// " + CANARY + "\n"}}
    before = copy.deepcopy(proofs)

    class ProofBroker(PassingBroker):
        async def verify(self, payload, timeout_seconds):
            tests = [item["content"] for item in payload["snapshot"] if item["path"] == spec["path"]]
            assert tests == [proofs["finding-1"]["content"]], "the trusted test must not be weakened by redaction"
            return await super().verify(payload, timeout_seconds)

    checkpoints = Checkpoints()
    provider = RecordingProvider([propose(masked, replacement, []), ProviderAction("request_verification", {})])
    result = await RepairAgent(provider, Verifier(ProofBroker()), checkpoints).run(request, snapshot, proofs=proofs)
    assert result.state == "ready", result.explanation
    serialized = json.dumps([provider.last_messages, checkpoints.pending, checkpoints.completed])
    assert CANARY not in serialized
    resumed = Checkpoints(checkpoints.completed[0])
    result = await RepairAgent(RecordingProvider([ProviderAction("request_verification", {})]), Verifier(ProofBroker()), resumed).run(
        request, snapshot, proofs=proofs,
    )
    assert result.state == "ready", result.explanation
    assert CANARY not in json.dumps([resumed.pending, resumed.completed])
    assert proofs == before


@pytest.mark.asyncio
async def test_unsafe_paid_provider_response_is_settled_with_only_a_fixed_safe_refusal(request_payload, source):
    request, snapshot = snapshot_with(request_payload, source)
    provider = RecordingProvider([ProviderAction("propose_patch", {"api_key": "abc"}, output_tokens=12)])
    checkpoints = Checkpoints()
    result = await RepairAgent(provider, FailingVerifier(), checkpoints).run(request, snapshot)
    assert result.reason_code == "source_secret_redaction_failed" and provider.calls == 1
    assert len(checkpoints.settled) == 1
    assert checkpoints.pending[0]["pending_action"]["name"] == "abstain"
    assert "abc" not in json.dumps(checkpoints.pending)


def test_redacted_verification_is_discarded_not_reused_under_its_original_digest(request_payload, source):
    _, snapshot = snapshot_with(request_payload, source + f'// API_KEY = "{CANARY}"\n')
    agent = RepairAgent(RecordingProvider([]), FailingVerifier())
    agent._redactor = SourceRedactor(snapshot)
    verification = asdict(VerificationResult("passed", {"output_tail": CANARY}, "sha256:" + "a" * 64))
    state = {"last_verification": verification, "coverage": {"best": {"verification": verification}}}
    safe = agent._redact_checkpoint(state)
    assert safe["last_verification"] is None and safe["coverage"]["best"] is None
    assert state["last_verification"] == verification


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", [
    "-----BEGIN PRIVATE KEY-----\ncanary incomplete body\n",
    'const API_KEY = "first_canary" + "second_canary";\n',
    'const API_KEY = "abc";\n',
    '// ' + REDACTION_MARKER + '\n',
])
async def test_unsafe_redaction_refuses_before_any_provider_or_checkpoint_write(request_payload, source, unsafe):
    request, snapshot = snapshot_with(request_payload, source + unsafe)
    provider = RecordingProvider([_abstain()])
    checkpoints = Checkpoints()
    result = await RepairAgent(provider, FailingVerifier(), checkpoints).run(request, snapshot)
    assert result.reason_code == "source_secret_redaction_failed"
    assert provider.calls == 0 and checkpoints.pending == checkpoints.completed == []
