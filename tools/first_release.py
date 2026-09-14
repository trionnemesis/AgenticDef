from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Callable, Sequence

TARGET_TAG = "v0.2.0"
TARGET_VERSION = "0.2.0"


class GuardError(RuntimeError):
    """Stop the fixed first-release path before any remote mutation."""


def read_project_version(project_file: Path = Path("pyproject.toml")) -> str:
    with project_file.open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def run_command(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)


def _lookup_is_confirmed_absent(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode != 0 and re.search(r"\bHTTP 404\b", result.stderr or "") is not None


def ensure_first_release(
    *,
    repo: str,
    release_sha: str,
    package_version: str,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = run_command,
) -> None:
    lookup = runner(["gh", "api", f"repos/{repo}/releases/tags/{TARGET_TAG}", "--silent"])
    if lookup.returncode == 0:
        print("Release exists; unchanged / 版本已存在，保留原狀")
        return

    if not _lookup_is_confirmed_absent(lookup):
        detail = (lookup.stderr or lookup.stdout or "unknown lookup failure").strip()
        raise GuardError(
            "Cannot prove the fixed first release is absent; refusing mutation / "
            f"無法確認固定首次版本不存在，拒絕任何變更: {detail}"
        )

    if package_version != TARGET_VERSION:
        raise GuardError(
            f"Package/tag mismatch: package {package_version} cannot publish as {TARGET_TAG}; "
            f"expected {TARGET_VERSION} / 套件與標籤版本不一致：{package_version} 不得發布為 {TARGET_TAG}，"
            f"固定版本必須是 {TARGET_VERSION}"
        )

    dist = Path("dist")
    assets = [
        *sorted(str(path) for path in dist.glob("*.whl")),
        *sorted(str(path) for path in dist.glob("*.tar.gz")),
        str(dist / "SHA256SUMS"),
        str(dist / "replay-summary.json"),
    ]
    create = runner(
        [
            "gh",
            "release",
            "create",
            TARGET_TAG,
            *assets,
            "--target",
            release_sha,
            "--title",
            "AgenticDef v0.2.0",
            "--notes-file",
            "docs/release-v0.2.0.md",
        ]
    )
    if create.returncode != 0:
        detail = (create.stderr or create.stdout or "release creation failed").strip()
        raise GuardError(f"Release creation failed / 版本建立失敗: {detail}")


def main() -> int:
    repo = os.environ.get("GH_REPO", "")
    release_sha = os.environ.get("RELEASE_SHA", "")
    if not repo or not release_sha:
        print("GH_REPO and RELEASE_SHA are required / 必須提供 GH_REPO 與 RELEASE_SHA", file=sys.stderr)
        return 2

    try:
        ensure_first_release(
            repo=repo,
            release_sha=release_sha,
            package_version=read_project_version(),
        )
    except (GuardError, KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
