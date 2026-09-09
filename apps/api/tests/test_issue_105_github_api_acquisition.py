"""Regression tests for scoped GitHub Trees/Blobs acquisition (issue #105)."""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from src.routers import trust


class _BytesResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        declared_length: int | None = None,
    ) -> None:
        self._payload = payload
        self.headers = {
            "Content-Length": str(
                len(payload) if declared_length is None else declared_length
            )
        }

    def __enter__(self) -> "_BytesResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if not self._payload:
            return b""
        if size < 0:
            size = len(self._payload)
        chunk, self._payload = self._payload[:size], self._payload[size:]
        return chunk


class _InterruptedResponse:
    headers: dict[str, str] = {}

    def __enter__(self) -> "_InterruptedResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        raise http.client.IncompleteRead(b"partial", 10)


@pytest.fixture(autouse=True)
def _reset_github_rate_limit_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trust, "_GITHUB_RATE_LIMIT_UNTIL", 0.0)


def _sha(character: str) -> str:
    return character * 40


def _blob(path: str, data: bytes, *, mode: str = "100644") -> dict[str, object]:
    return {
        "path": path,
        "mode": mode,
        "type": "blob",
        "sha": trust._git_blob_sha(data),
        "size": len(data),
    }


def _tree(path: str, sha: str) -> dict[str, object]:
    return {"path": path, "mode": "040000", "type": "tree", "sha": sha}


def _tree_response(
    sha: str,
    entries: list[dict[str, object]],
    *,
    truncated: bool = False,
) -> bytes:
    return json.dumps(
        {"sha": sha, "tree": entries, "truncated": truncated},
        separators=(",", ":"),
    ).encode("utf-8")


def _install_fake_github(
    monkeypatch: pytest.MonkeyPatch,
    responses: dict[str, bytes],
) -> list[str]:
    requested_urls: list[str] = []
    lock = threading.Lock()

    def fake_urlopen(request, timeout: int):
        assert timeout == trust._GITHUB_API_TIMEOUT_SECONDS
        url = request.full_url
        with lock:
            requested_urls.append(url)
        if url not in responses:
            raise AssertionError(f"unexpected GitHub request: {url}")
        return _BytesResponse(responses[url])

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)
    return requested_urls


def _materialized_files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_tree_url_downloads_only_skill_and_required_ancestor_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    files = {
        "manifest.json": b"{}\n",
        "package.json": b'{"author":{"name":"Root"}}\n',
        "LICENSE": b"root license\n",
        "skills/package.json": b'{"author":{"name":"Skills"}}\n',
        "skills/NOTICE": b"skills notice\n",
        "skills/hallmark/SKILL.md": b"# Hallmark\n",
        "skills/hallmark/scripts/run.py": b"print('ok')\n",
        "skills/hallmark/references/guide.md": b"# Guide\n",
        "skills/other/SKILL.md": b"# Other\n",
    }
    entries = [
        _tree("skills", _sha("c")),
        _tree("skills/hallmark", _sha("d")),
        _tree("skills/hallmark/scripts", _sha("e")),
        _tree("skills/hallmark/references", _sha("f")),
        _tree("skills/other", _sha("1")),
        *[_blob(path, data) for path, data in files.items()],
        {
            "path": "unrelated-large.bin",
            "mode": "100644",
            "type": "blob",
            "sha": _sha("2"),
            "size": 13_200_000,
        },
    ]
    tree_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    selected_paths = {
        "manifest.json",
        "package.json",
        "LICENSE",
        "skills/package.json",
        "skills/NOTICE",
        "skills/hallmark/SKILL.md",
        "skills/hallmark/scripts/run.py",
        "skills/hallmark/references/guide.md",
    }
    responses = {tree_url: _tree_response(root_tree_sha, entries)}
    for path in selected_paths:
        sha = trust._git_blob_sha(files[path])
        responses[
            f"https://api.github.com/repos/acme/demo/git/blobs/{sha}"
        ] = files[path]
    requested = _install_fake_github(monkeypatch, responses)

    assert trust._download_github_repository_files(
        {
            "owner": "acme",
            "repo": "demo",
            "ref": commit_sha,
            "subdir": "skills/hallmark",
        },
        str(tmp_path),
        max_attempts=1,
    )

    assert _materialized_files(tmp_path) == selected_paths
    assert not (tmp_path / "skills" / "other").exists()
    assert all("/zipball/" not in url for url in requested)
    assert (
        f"https://api.github.com/repos/acme/demo/git/blobs/"
        f"{trust._git_blob_sha(files['skills/other/SKILL.md'])}"
    ) not in requested
    assert (
        "https://api.github.com/repos/acme/demo/git/blobs/" + _sha("2")
    ) not in requested


def test_repository_url_without_subdir_downloads_all_regular_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    files = {
        "SKILL.md": b"# Root skill\n",
        "docs/readme.md": b"hello\n",
        "src/main.py": b"value = 1\n",
    }
    entries = [
        _tree("docs", _sha("c")),
        _tree("src", _sha("d")),
        *[_blob(path, data) for path, data in files.items()],
        {
            "path": "link",
            "mode": "120000",
            "type": "blob",
            "sha": _sha("e"),
            "size": 6,
        },
        {
            "path": "vendor/submodule",
            "mode": "160000",
            "type": "commit",
            "sha": _sha("f"),
        },
    ]
    tree_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    responses = {tree_url: _tree_response(root_tree_sha, entries)}
    for path, data in files.items():
        responses[
            "https://api.github.com/repos/acme/demo/git/blobs/"
            + trust._git_blob_sha(data)
        ] = data
    requested = _install_fake_github(monkeypatch, responses)

    assert trust._download_github_repository_files(
        {"owner": "acme", "repo": "demo", "ref": commit_sha, "subdir": None},
        str(tmp_path),
        max_attempts=1,
    )

    assert _materialized_files(tmp_path) == set(files)
    assert all("/zipball/" not in url for url in requested)


def test_root_manifest_can_narrow_a_repository_url_to_its_declared_subdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    files = {
        "manifest.json": b'{"source":{"subdirectory":"skills/hallmark"}}\n',
        "LICENSE": b"license\n",
        "skills/package.json": b'{"author":{"name":"Skills"}}\n',
        "skills/hallmark/SKILL.md": b"# Hallmark\n",
        "skills/other/SKILL.md": b"# Other\n",
    }
    entries = [
        _tree("skills", _sha("c")),
        _tree("skills/hallmark", _sha("d")),
        _tree("skills/other", _sha("e")),
        *[_blob(path, data) for path, data in files.items()],
    ]
    tree_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    selected_paths = {
        "manifest.json",
        "LICENSE",
        "skills/package.json",
        "skills/hallmark/SKILL.md",
    }
    responses = {tree_url: _tree_response(root_tree_sha, entries)}
    for path in selected_paths:
        data = files[path]
        responses[
            "https://api.github.com/repos/acme/demo/git/blobs/"
            + trust._git_blob_sha(data)
        ] = data
    requested = _install_fake_github(monkeypatch, responses)

    assert trust._download_github_repository_files(
        {"owner": "acme", "repo": "demo", "ref": commit_sha, "subdir": None},
        str(tmp_path),
        max_attempts=1,
    )

    assert _materialized_files(tmp_path) == selected_paths
    other_blob_url = (
        "https://api.github.com/repos/acme/demo/git/blobs/"
        + trust._git_blob_sha(files["skills/other/SKILL.md"])
    )
    assert other_blob_url not in requested


def test_truncated_recursive_tree_falls_back_to_scoped_tree_walk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    skills_tree_sha = _sha("c")
    target_tree_sha = _sha("d")
    scripts_tree_sha = _sha("e")
    files = {
        "LICENSE": b"license\n",
        "skills/package.json": b"{}\n",
        "skills/NOTICE": b"notice\n",
        "skills/hallmark/SKILL.md": b"# Hallmark\n",
        "skills/hallmark/scripts/run.py": b"print('ok')\n",
    }
    initial_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    root_url = (
        "https://api.github.com/repos/acme/demo/git/trees/" + root_tree_sha
    )
    skills_url = (
        "https://api.github.com/repos/acme/demo/git/trees/" + skills_tree_sha
    )
    target_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{target_tree_sha}?recursive=1"
    )
    responses = {
        initial_url: _tree_response(root_tree_sha, [], truncated=True),
        root_url: _tree_response(
            root_tree_sha,
            [_tree("skills", skills_tree_sha), _blob("LICENSE", files["LICENSE"])],
        ),
        skills_url: _tree_response(
            skills_tree_sha,
            [
                _blob("package.json", files["skills/package.json"]),
                _blob("NOTICE", files["skills/NOTICE"]),
                _tree("hallmark", target_tree_sha),
            ],
        ),
        target_url: _tree_response(
            target_tree_sha,
            [
                _blob("SKILL.md", files["skills/hallmark/SKILL.md"]),
                _tree("scripts", scripts_tree_sha),
                _blob("scripts/run.py", files["skills/hallmark/scripts/run.py"]),
            ],
        ),
    }
    for data in files.values():
        responses[
            "https://api.github.com/repos/acme/demo/git/blobs/"
            + trust._git_blob_sha(data)
        ] = data
    requested = _install_fake_github(monkeypatch, responses)

    assert trust._download_github_repository_files(
        {
            "owner": "acme",
            "repo": "demo",
            "ref": commit_sha,
            "subdir": "skills/hallmark",
        },
        str(tmp_path),
        max_attempts=1,
    )

    assert _materialized_files(tmp_path) == set(files)
    assert requested.count(root_url) == 1
    assert skills_url in requested
    assert target_url in requested


def test_github_request_retries_incomplete_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    request_budget = trust._GitHubRequestBudget(2)

    def fake_urlopen(_request, timeout: int):
        nonlocal attempts
        assert timeout == trust._GITHUB_API_TIMEOUT_SECONDS
        attempts += 1
        if attempts == 1:
            return _InterruptedResponse()
        return _BytesResponse(b"ok")

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(trust._time, "sleep", lambda _seconds: None)

    assert trust._github_request_bytes(
        "https://api.github.com/example",
        max_bytes=2,
        max_attempts=2,
        request_budget=request_budget,
    ) == b"ok"
    assert attempts == 2
    assert request_budget.used == 2


def test_json_request_retries_when_body_ends_before_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    truncated_but_valid = b'{"value":1}'
    complete = b'{"value":2}'

    def fake_urlopen(_request, timeout: int):
        nonlocal attempts
        assert timeout == trust._GITHUB_API_TIMEOUT_SECONDS
        attempts += 1
        if attempts == 1:
            return _BytesResponse(
                truncated_but_valid,
                declared_length=len(truncated_but_valid) + 10,
            )
        return _BytesResponse(complete)

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(trust._time, "sleep", lambda _seconds: None)

    assert trust._github_json_payload(
        "https://api.github.com/example",
        max_bytes=1024,
        max_attempts=2,
    ) == {"value": 2}
    assert attempts == 2


def test_acquisition_rejects_request_budget_before_blob_downloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    skill = b"# Demo\n"
    tree_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    blob_url = (
        "https://api.github.com/repos/acme/demo/git/blobs/"
        + trust._git_blob_sha(skill)
    )
    requested = _install_fake_github(
        monkeypatch,
        {
            tree_url: _tree_response(
                root_tree_sha,
                [_blob("SKILL.md", skill)],
            ),
            blob_url: skill,
        },
    )

    with pytest.raises(
        trust._DeterministicAcquisitionError,
        match="per-scan GitHub API request budget",
    ):
        trust._download_github_repository_files(
            {
                "owner": "acme",
                "repo": "demo",
                "ref": commit_sha,
                "subdir": None,
            },
            str(tmp_path),
            max_attempts=1,
            request_budget=trust._GitHubRequestBudget(1),
        )

    assert requested == [tree_url]
    assert not tmp_path.joinpath("SKILL.md").exists()


def test_authenticated_request_budget_keeps_rate_limit_headroom() -> None:
    assert trust._new_github_request_budget().limit == 1_000


def test_retry_after_defers_all_github_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []
    api_url = "https://api.github.com/example"

    def fake_urlopen(_request, timeout: int):
        nonlocal attempts
        assert timeout == trust._GITHUB_API_TIMEOUT_SECONDS
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError(
                api_url,
                429,
                "rate limited",
                {"Retry-After": "7"},
                None,
            )
        return _BytesResponse(b"ok")

    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(trust._time, "sleep", sleeps.append)

    assert trust._github_request_bytes(
        api_url,
        max_bytes=2,
        max_attempts=2,
    ) == b"ok"
    assert attempts == 2
    assert len(sleeps) == 1
    assert 6.0 <= sleeps[0] <= 7.0


def test_primary_rate_limit_uses_reset_epoch() -> None:
    assert trust._github_rate_limit_deadline(
        {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1030",
        },
        403,
        now=1000.0,
    ) == 1031.0


def test_github_requests_share_a_process_wide_concurrency_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = threading.Lock()
    active = 0
    maximum_active = 0

    class _TrackedResponse(_BytesResponse):
        def __exit__(self, *_args: object) -> None:
            nonlocal active
            with lock:
                active -= 1

        def read(self, size: int = -1) -> bytes:
            time.sleep(0.02)
            return super().read(size)

    def fake_urlopen(_request, timeout: int):
        nonlocal active, maximum_active
        assert timeout == trust._GITHUB_API_TIMEOUT_SECONDS
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        return _TrackedResponse(b"ok")

    monkeypatch.setattr(
        trust,
        "_GITHUB_API_CONCURRENCY_GATE",
        threading.BoundedSemaphore(2),
    )
    monkeypatch.setattr(trust.urllib.request, "urlopen", fake_urlopen)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda index: trust._github_request_bytes(
                    f"https://api.github.com/example/{index}",
                    max_bytes=2,
                    max_attempts=1,
                ),
                range(8),
            )
        )

    assert results == [b"ok"] * 8
    assert maximum_active == 2


def test_blob_hash_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_sha = _sha("a")
    root_tree_sha = _sha("b")
    declared_sha = _sha("c")
    tree_url = (
        "https://api.github.com/repos/acme/demo/git/trees/"
        f"{commit_sha}?recursive=1"
    )
    blob_url = (
        "https://api.github.com/repos/acme/demo/git/blobs/" + declared_sha
    )
    _install_fake_github(
        monkeypatch,
        {
            tree_url: _tree_response(
                root_tree_sha,
                [
                    {
                        "path": "SKILL.md",
                        "mode": "100644",
                        "type": "blob",
                        "sha": declared_sha,
                        "size": 4,
                    }
                ],
            ),
            blob_url: b"oops",
        },
    )

    with pytest.raises(
        trust._DeterministicAcquisitionError,
        match="blob hash mismatch",
    ):
        trust._download_github_repository_files(
            {
                "owner": "acme",
                "repo": "demo",
                "ref": commit_sha,
                "subdir": None,
            },
            str(tmp_path),
            max_attempts=1,
        )
