# Releasing SentinelDeck

Releases are published to PyPI automatically by
[`.github/workflows/publish.yml`](.github/workflows/publish.yml) whenever a
GitHub Release is published. Publishing uses [PyPI Trusted Publishing][tp]
(OIDC), so no API token or secret is ever stored in the repository.

## PyPI setup (already configured)

> **Status: complete.** The trusted publisher below is live for this repository,
> so this section does not need to be repeated. It is kept as a record and for
> anyone forking the project.

The repository publishes through a GitHub Actions trusted publisher configured
on PyPI with these values:

| Field | Value |
| --- | --- |
| PyPI project name | `sentineldeck` |
| Owner | `sanmaxdev` |
| Repository | `SentinelDeck` |
| Workflow | `publish.yml` |
| Environment | `pypi` |

To reproduce it on a fork: create a PyPI account, then go to PyPI >
*Your projects* > *Publishing* > *Add a pending publisher* and enter the values
above, and create a matching GitHub Actions environment named `pypi` under
*Settings > Environments*. Adding required reviewers to that environment gives
you a manual approval gate before each publish.

## Cutting a release

1. Bump `version` in `pyproject.toml`, following
   [semantic versioning](https://semver.org).
2. In `CHANGELOG.md`, move the `[Unreleased]` notes under a new dated heading for
   the version, and leave a fresh empty `[Unreleased]` section above it.
3. Commit both changes to `main`.
4. Tag the release and push the tag (replace the version):
   ```bash
   git tag v0.1.1
   git push origin v0.1.1
   ```
5. On GitHub, draft a **Release** for that tag and publish it. Publishing
   triggers `publish.yml`, which builds the sdist and wheel, runs `twine check`,
   and uploads to PyPI over OIDC.
6. Confirm the new version appears at
   <https://pypi.org/project/sentineldeck/> and that `pip install -U sentineldeck`
   pulls it.

> Steps 4 and 5 can be done in one command with the GitHub CLI:
> `gh release create v0.1.1 --title "SentinelDeck 0.1.1" --notes "..."`.

## Verifying the build locally

Before tagging, you can confirm the package builds cleanly:

```bash
pip install build twine
python -m build
twine check dist/*
```

[tp]: https://docs.pypi.org/trusted-publishers/
