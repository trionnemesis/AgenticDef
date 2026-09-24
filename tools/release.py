"""Manually dispatched release of the package's current version.

Only a human-started `workflow_dispatch` run on `main` reaches this helper.
The tag is derived from `pyproject.toml`; nothing here overwrites, deletes or
moves an existing release or tag.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Callable, Sequence

VERSION = re.compile(r"\d+\.\d+\.\d+")


class GuardError(RuntimeError):
    """Stop the release path before any remote mutation."""


def read_project_version(project_file: Path = Path("pyproject.toml")) -> str:
    with project_file.open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def run_command(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)


def _lookup_is_confirmed_absent(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode != 0 and re.search(r"\bHTTP 404\b", result.stderr or "") is not None


def _assets(dist: Path, version: str) -> list[str]:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if not wheels or not sdists:
        raise GuardError("Wheel and source distribution required / 缺少 wheel 或原始碼套件")
    stale = [p.name for p in (*wheels, *sdists) if f"-{version}-" not in p.name and not p.name.endswith(f"-{version}.tar.gz")]
    if stale:
        raise GuardError(f"Distribution/version mismatch / 套件與版本不一致: {', '.join(stale)}")
    extra = [dist / "SHA256SUMS", dist / "replay-summary.json"]
    missing = [p.name for p in extra if not p.is_file()]
    if missing:
        raise GuardError(f"Release evidence missing / 缺少發布證據: {', '.join(missing)}")
    return [*map(str, wheels), *map(str, sdists), *map(str, extra)]


def ensure_release(
    *,
    repo: str,
    release_sha: str,
    package_version: str,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = run_command,
    dist: Path = Path("dist"),
    docs: Path = Path("docs"),
) -> None:
    if not VERSION.fullmatch(package_version):
        raise GuardError(f"Unsupported package version / 不支援的套件版本: {package_version!r}")
    tag = f"v{package_version}"
    notes = docs / f"release-{tag}.md"
    if not notes.is_file():
        raise GuardError(f"Release notes required before publishing / 發布前必須有版本說明: {notes}")

    lookup = runner(["gh", "api", f"repos/{repo}/releases/tags/{tag}", "--silent"])
    if lookup.returncode == 0:
        print(f"Release {tag} exists; unchanged / 版本已存在，保留原狀")
        return

    if not _lookup_is_confirmed_absent(lookup):
        detail = (lookup.stderr or lookup.stdout or "unknown lookup failure").strip()
        raise GuardError(
            f"Cannot prove {tag} is absent; refusing mutation / "
            f"無法確認 {tag} 不存在，拒絕任何變更: {detail}"
        )

    create = runner(
        [
            "gh",
            "release",
            "create",
            tag,
            *_assets(dist, package_version),
            "--target",
            release_sha,
            "--title",
            f"AgenticDef {tag}",
            "--notes-file",
            str(notes),
        ]
    )
    if create.returncode != 0:
        detail = (create.stderr or create.stdout or "release creation failed").strip()
        raise GuardError(f"Release creation failed / 版本建立失敗: {detail}")
    print(f"Release {tag} created at {release_sha} / 已建立版本")


def main() -> int:
    repo = os.environ.get("GH_REPO", "")
    release_sha = os.environ.get("RELEASE_SHA", "")
    if not repo or not release_sha:
        print("GH_REPO and RELEASE_SHA are required / 必須提供 GH_REPO 與 RELEASE_SHA", file=sys.stderr)
        return 2

    try:
        ensure_release(repo=repo, release_sha=release_sha, package_version=read_project_version())
    except (GuardError, KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
