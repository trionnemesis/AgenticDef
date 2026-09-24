# Publication / 發布

The user authorized a public repository, initial implementation commit, GitHub Pages and a release. The static site contains project documentation only, no credentials or live incident data.

`ci.yml` runs tests and replay on Python 3.11 and 3.12. Only a passing matrix on `main` enables publication jobs. Each run preserves JUnit, replay output and persisted evidence as artifacts. Third-party Actions are pinned to verified full commit SHAs.

## Pages

Set repository **Settings → Pages → Source → GitHub Actions**. The Pages job uploads `site/` and deploys it with `pages: write` and `id-token: write` in the `github-pages` environment. It does not attempt to grant itself repository administration permissions. See [GitHub's custom workflow requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

The intended URL is `https://trionnemesis.github.io/AgenticDef/`. A successful workflow deployment and reachable page, not this written URL, establish that it is live.

## Release

Only a human can publish. The release job runs when someone starts the CI
workflow manually (`workflow_dispatch`) on `main`; pushes and pull requests
never reach it. It waits for the full test matrix and the clean `.[dev]` job,
then builds the wheel and source distribution, replays S01–S08 into
`replay-summary.json` and computes SHA-256 checksums.

`tools/release.py` then publishes the version in `pyproject.toml` as tag
`v<version>` at the exact tested commit, using the job's scoped `GITHUB_TOKEN`
and `docs/release-v<version>.md` as notes. It fails closed before any mutation
when:

* the version is not `MAJOR.MINOR.PATCH`, or its notes file is missing;
* GitHub cannot confirm the release is absent (anything other than HTTP 404);
* a built distribution does not match the version, or checksums/replay summary are missing.

If the release already exists it is left unchanged. The helper never
overwrites, deletes or force-moves a release or tag, and no personal token is
required. A permission/setup failure stays visible in Actions and is not
bypassed with alternate credentials.

A new product release therefore needs three deliberate steps: bump the version,
add its notes, and start the workflow. `v0.2.0` and its assets remain as
originally published.
