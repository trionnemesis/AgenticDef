from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "tools" / "release.py"
SPEC = importlib.util.spec_from_file_location("release", MODULE_PATH)
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

ABSENT = "gh: Not Found (HTTP 404)"


def result(returncode: int, *, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def recorder(lookup: subprocess.CompletedProcess[str], create: subprocess.CompletedProcess[str] | None = None):
    calls: list[list[str]] = []

    def runner(args):
        calls.append(list(args))
        return lookup if args[:2] == ["gh", "api"] else (create or result(0))

    return calls, runner


def layout(tmp_path: Path, version: str = "0.2.1", *, dist_names=None, notes=True, evidence=True):
    dist, docs = tmp_path / "dist", tmp_path / "docs"
    dist.mkdir()
    docs.mkdir()
    for name in dist_names or [f"agenticdef-{version}-py3-none-any.whl", f"agenticdef-{version}.tar.gz"]:
        (dist / name).write_text("x")
    if evidence:
        (dist / "SHA256SUMS").write_text("x")
        (dist / "replay-summary.json").write_text("{}")
    if notes:
        (docs / f"release-v{version}.md").write_text("notes")
    return {"dist": dist, "docs": docs}


def ensure(tmp_path, runner, version="0.2.1", **paths):
    release.ensure_release(repo="owner/repo", release_sha="abc123", package_version=version,
                           runner=runner, **(paths or layout(tmp_path, version)))


def test_existing_release_is_left_unchanged(tmp_path) -> None:
    calls, runner = recorder(result(0))
    ensure(tmp_path, runner)
    assert calls == [["gh", "api", "repos/owner/repo/releases/tags/v0.2.1", "--silent"]]


def test_absent_release_creates_tag_from_package_version(tmp_path) -> None:
    calls, runner = recorder(result(1, stderr=ABSENT))
    paths = layout(tmp_path)
    ensure(tmp_path, runner, **paths)
    assert len(calls) == 2
    create = calls[1]
    assert create[:4] == ["gh", "release", "create", "v0.2.1"]
    assert create[create.index("--target") + 1] == "abc123"
    assert create[create.index("--notes-file") + 1] == str(paths["docs"] / "release-v0.2.1.md")
    assert {Path(a).name for a in create[4:create.index("--target")]} == {
        "agenticdef-0.2.1-py3-none-any.whl", "agenticdef-0.2.1.tar.gz", "SHA256SUMS", "replay-summary.json"}


def test_lookup_uncertainty_fails_closed_before_create(tmp_path) -> None:
    calls, runner = recorder(result(1, stderr="gh: HTTP 403: Resource not accessible by integration"))
    with pytest.raises(release.GuardError, match="Cannot prove"):
        ensure(tmp_path, runner)
    assert len(calls) == 1 and calls[0][:2] == ["gh", "api"]


@pytest.mark.parametrize("version", ["0.2", "v0.2.1", "0.2.1rc1", "0.2.1\n", ""])
def test_unsupported_version_fails_before_any_call(tmp_path, version) -> None:
    calls, runner = recorder(result(1, stderr=ABSENT))
    with pytest.raises(release.GuardError, match="Unsupported package version"):
        ensure(tmp_path, runner, version, **layout(tmp_path, "0.2.1"))
    assert calls == []


def test_missing_notes_fail_before_any_call(tmp_path) -> None:
    calls, runner = recorder(result(1, stderr=ABSENT))
    with pytest.raises(release.GuardError, match="Release notes required"):
        ensure(tmp_path, runner, **layout(tmp_path, notes=False))
    assert calls == []


@pytest.mark.parametrize("names", [
    ["agenticdef-0.2.0-py3-none-any.whl", "agenticdef-0.2.1.tar.gz"],
    ["agenticdef-0.2.1-py3-none-any.whl", "agenticdef-0.2.10.tar.gz"],
    ["agenticdef-0.2.1-py3-none-any.whl", "agenticdef-0.2.1.tar.gz", "agenticdef-0.2.0.tar.gz"],
    ["agenticdef-0.2.1-py3-none-any.whl"],
])
def test_mismatched_or_missing_distributions_fail_before_create(tmp_path, names) -> None:
    calls, runner = recorder(result(1, stderr=ABSENT))
    with pytest.raises(release.GuardError, match="Distribution/version mismatch|Wheel and source"):
        ensure(tmp_path, runner, **layout(tmp_path, dist_names=names))
    assert all(c[:2] == ["gh", "api"] for c in calls)


def test_missing_release_evidence_fails_before_create(tmp_path) -> None:
    calls, runner = recorder(result(1, stderr=ABSENT))
    with pytest.raises(release.GuardError, match="Release evidence missing"):
        ensure(tmp_path, runner, **layout(tmp_path, evidence=False))
    assert all(c[:2] == ["gh", "api"] for c in calls)


def test_create_failure_is_loud(tmp_path) -> None:
    _, runner = recorder(result(1, stderr=ABSENT), result(1, stderr="HTTP 422"))
    with pytest.raises(release.GuardError, match="Release creation failed"):
        ensure(tmp_path, runner)


def test_current_version_has_release_notes() -> None:
    version = release.read_project_version(ROOT / "pyproject.toml")
    assert release.VERSION.fullmatch(version)
    assert (ROOT / "docs" / f"release-v{version}.md").is_file()


def test_only_manual_dispatch_on_main_can_publish() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    jobs = yaml.safe_load(text)["jobs"]
    job = jobs["release"]
    assert job["if"] == "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'"
    assert set(job["needs"]) == {"test", "dev-extra"}
    assert job["steps"][-1]["run"] == "python tools/release.py"
    assert "gh release" not in text
    writers = [name for name, j in jobs.items() if j.get("permissions", {}).get("contents") == "write"]
    assert writers == ["release"]
