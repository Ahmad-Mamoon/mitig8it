"""Exact-PR collection, with no GitHub requests, scanners, or remediation runs."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts.replay import replay


def pull(number, **overrides):
    return {"number": number, "merged_at": "2026-01-01T00:00:00Z",
            "merge_commit_sha": "a" * 40, "head": {"sha": "b" * 40},
            "base": {"sha": "c" * 40}, **overrides}


@pytest.fixture
def collection(monkeypatch, tmp_path):
    reader = Mock(calls=0, cache_hits=0)
    reader.get.side_effect = lambda path: pull(int(path.rsplit("/", 1)[1]))
    reader.merged_pull_requests.return_value = [pull(999)]
    factory = Mock(return_value=reader)
    monkeypatch.setattr(replay, "GitHubReader", factory)
    builder = Mock(side_effect=lambda _reader, repo, item: {
        "repo": repo, "number": item["number"], "head_sha": item["merge_commit_sha"],
        "files": [], "rejected": False,
    })
    worker = Mock(side_effect=lambda payload, *_args: {
        "number": payload["number"], "head_sha": payload["head_sha"],
        "files": 0, "findings": [], "wall_ms": 1,
    })
    monkeypatch.setattr(replay, "build_payload", builder)
    monkeypatch.setattr(replay, "run_pull_request", worker)
    output = tmp_path / "result.json"
    return SimpleNamespace(reader=reader, factory=factory, builder=builder, worker=worker,
                           output=output, args=["--repo", "owner/repo", "--cache", str(tmp_path / "cache"),
                                                "--out", str(output)])


def test_exact_old_prs_are_fetched_directly_in_manifest_order_without_recent_prefix(collection):
    c = collection
    assert replay.main(c.args + ["--prs", "1", "--only-pr", "42", "--only-pr", "1"]) == 0
    assert [call.args[0] for call in c.reader.get.call_args_list] == [
        "repos/owner/repo/pulls/42", "repos/owner/repo/pulls/1"]
    c.reader.merged_pull_requests.assert_not_called()
    assert [call.args[0]["number"] for call in c.worker.call_args_list] == [42, 1]
    report = json.loads(c.output.read_text())
    assert report["requested_prs"] == report["replayed_prs"] == 2
    assert report["requested_pr_numbers"] == [42, 1]
    assert [record["number"] for record in report["records"]] == [42, 1]


def test_missing_requested_pr_fails_before_any_work_and_does_not_overwrite_previous_output(collection, capsys):
    c = collection
    c.reader.get.side_effect = [pull(42), replay.GitHubError("not found: repos/owner/repo/pulls/1")]
    c.output.write_text("previous report")
    assert replay.main(c.args + ["--only-pr", "42", "--only-pr", "1"]) == 2
    error = capsys.readouterr().err
    assert "requested PR #1 could not be fetched" in error
    assert "output not updated" in error
    c.reader.merged_pull_requests.assert_not_called()
    c.builder.assert_not_called()
    c.worker.assert_not_called()
    assert c.output.read_text() == "previous report"


@pytest.mark.parametrize("response", [None, [], {}, pull(2), pull(True),
                                      pull(1, merged_at=None), pull(1, merged_at=""),
                                      pull(1, merged_at=True)])
def test_malformed_mismatched_or_unmerged_requested_pr_cannot_be_silently_skipped(collection, capsys, response):
    c = collection
    c.reader.get.return_value = response
    c.reader.get.side_effect = None
    assert replay.main(c.args + ["--only-pr", "1"]) == 2
    assert "requested PR #1" in capsys.readouterr().err
    assert not c.output.exists()
    c.worker.assert_not_called()


@pytest.mark.parametrize("options", [["--only-pr", "0"], ["--only-pr", "-1"],
                                    ["--only-pr", "1", "--only-pr", "1"],
                                    ["--only-pr", "1", "--snapshot", "--ref", "a" * 40],
                                    ["--only-pr", "1", "--pairs", "--results", "unused.json"]])
def test_invalid_or_ignored_manifest_selection_is_rejected_before_reading(collection, options):
    with pytest.raises(SystemExit) as error:
        replay.main(collection.args + options)
    assert error.value.code == 2
    collection.factory.assert_not_called()
    collection.worker.assert_not_called()


def test_recent_merged_pr_selection_remains_unchanged_without_only_pr(collection):
    c = collection
    assert replay.main(c.args + ["--prs", "3", "--refresh"]) == 0
    c.reader.merged_pull_requests.assert_called_once_with("owner/repo", 3)
    c.reader.get.assert_not_called()
    assert c.factory.call_args.kwargs["refresh"] is True
    report = json.loads(c.output.read_text())
    assert report["requested_prs"] == 3 and report["replayed_prs"] == 1
    assert "requested_pr_numbers" not in report


def test_direct_selection_uses_existing_disk_cache_and_refresh_behavior(monkeypatch, tmp_path):
    import ghcache

    command = Mock(return_value=SimpleNamespace(returncode=0, stdout=json.dumps(pull(1)), stderr=""))
    monkeypatch.setattr(ghcache.subprocess, "run", command)
    reader = replay.GitHubReader(tmp_path)
    assert replay.requested_pull_requests(reader, "owner/repo", [1]) == [pull(1)]
    assert replay.requested_pull_requests(reader, "owner/repo", [1]) == [pull(1)]
    assert reader.calls == 1 and reader.cache_hits == 1
    assert command.call_args.args[0] == ["gh", "api", "--method", "GET", "repos/owner/repo/pulls/1"]
    refreshed = replay.GitHubReader(tmp_path, refresh=True)
    assert replay.requested_pull_requests(refreshed, "owner/repo", [1]) == [pull(1)]
    assert command.call_count == 2 and refreshed.calls == 1 and refreshed.cache_hits == 0


def test_direct_selection_preserves_rate_limit_retry_backoff(monkeypatch, tmp_path):
    import ghcache

    command = Mock(side_effect=[
        SimpleNamespace(returncode=1, stdout="", stderr="API rate limit exceeded"),
        SimpleNamespace(returncode=0, stdout=json.dumps(pull(1)), stderr=""),
    ])
    sleep = Mock()
    monkeypatch.setattr(ghcache.subprocess, "run", command)
    monkeypatch.setattr(ghcache.time, "sleep", sleep)
    reader = replay.GitHubReader(tmp_path)
    assert replay.requested_pull_requests(reader, "owner/repo", [1]) == [pull(1)]
    assert reader.calls == command.call_count == 2
    sleep.assert_called_once_with(20)


@pytest.mark.parametrize("cached", ["not JSON", "{}", "[]"])
def test_corrupt_cached_pr_is_a_named_selection_error_not_an_unhandled_exception(tmp_path, cached):
    reader = replay.GitHubReader(tmp_path)
    cache_path = reader._cache_path("repos/owner/repo/pulls/1")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(cached)
    with pytest.raises(replay.GitHubError, match="requested PR #1 could not be fetched"):
        replay.requested_pull_requests(reader, "owner/repo", [1])
    assert reader.calls == 0
