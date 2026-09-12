# Publication / 發布

The user authorized a public repository, initial implementation commit, GitHub Pages and a release. The static site contains project documentation only, no credentials or live incident data.

`ci.yml` runs tests and replay on Python 3.11 and 3.12. Only a passing matrix on `main` enables publication jobs. Each run preserves JUnit, replay output and persisted evidence as artifacts. Third-party Actions are pinned to verified full commit SHAs.

## Pages

Set repository **Settings → Pages → Source → GitHub Actions**. The Pages job uploads `site/` and deploys it with `pages: write` and `id-token: write` in the `github-pages` environment. It does not attempt to grant itself repository administration permissions. See [GitHub's custom workflow requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

The intended URL is `https://trionnemesis.github.io/AgenticDef/`. A successful workflow deployment and reachable page, not this written URL, establish that it is live.

## Release

The release job builds wheel and source distribution, computes SHA-256 checksums and creates v0.2.0 at the exact tested commit using the job's scoped `GITHUB_TOKEN`. It attaches the distributions, checksums and replay summary, and uses [v0.2.0 notes](release-v0.2.0.md). It never overwrites an existing release or force-moves a tag. No personal token is required.

Subsequent commits continue running CI and Pages. A new product release needs a deliberate version/notes change; it is not automatically inferred from every commit. A permission/setup failure remains visible in Actions and is not bypassed with alternate credentials.
