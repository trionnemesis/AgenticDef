from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "tools" / "first_release.py"
SPEC = importlib.util.spec_from_file_location("first_release", MODULE_PATH)
assert SPEC and SPEC.loader
first_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_release)


def result(returncode: int, *, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_existing_release_is_left_unchanged() -> None:
    calls: list[list[str]] = []

    def runner(args):
        calls.append(list(args))
        return result(0)

    first_release.ensure_first_release(
        repo="owner/repo",
        release_sha="abc123",
        package_version="0.2.1",
        runner=runner,
    )

    assert len(calls) == 1
    assert calls[0][:2] == ["gh", "api"]


def test_absent_release_rejects_mismatched_package_before_create() -> None:
    calls: list[list[str]] = []

    def runner(args):
        calls.append(list(args))
        return result(1, stderr="gh: Not Found (HTTP 404)")

    with pytest.raises(first_release.GuardError, match="Package/tag mismatch"):
        first_release.ensure_first_release(
            repo="owner/repo",
            release_sha="abc123",
            package_version="0.2.1",
            runner=runner,
        )

    assert len(calls) == 1
    assert calls[0][:2] == ["gh", "api"]


def test_absent_release_allows_fixed_version_create_path_with_mocked_gh() -> None:
    calls: list[list[str]] = []

    def runner(args):
        calls.append(list(args))
        if args[:2] == ["gh", "api"]:
            return result(1, stderr="gh: Not Found (HTTP 404)")
        return result(0)

    first_release.ensure_first_release(
        repo="owner/repo",
        release_sha="abc123",
        package_version="0.2.0",
        runner=runner,
    )

    assert len(calls) == 2
    assert calls[1][:4] == ["gh", "release", "create", "v0.2.0"]
    assert calls[1][calls[1].index("--target") + 1] == "abc123"


def test_lookup_uncertainty_fails_closed_before_create() -> None:
    calls: list[list[str]] = []

    def runner(args):
        calls.append(list(args))
        return result(1, stderr="gh: HTTP 403: Resource not accessible by integration")

    with pytest.raises(first_release.GuardError, match="Cannot prove"):
        first_release.ensure_first_release(
            repo="owner/repo",
            release_sha="abc123",
            package_version="0.2.0",
            runner=runner,
        )

    assert len(calls) == 1
    assert calls[0][:2] == ["gh", "api"]


def test_workflow_delegates_mutation_to_guard() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text()
    assert "python tools/first_release.py" in workflow
    assert "gh release create" not in workflow
