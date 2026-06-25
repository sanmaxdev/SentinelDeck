# Releasing SentinelDeck

Releases are published to PyPI automatically by
[`.github/workflows/publish.yml`](.github/workflows/publish.yml) when a GitHub
Release is published. Publishing uses [PyPI Trusted Publishing][tp] (OIDC), so
no API token or secret is stored in the repository.

## One-time setup (PyPI side)

Do this once, before the first release.

1. Create the project owner account on [PyPI](https://pypi.org) if you do not
   have one.
2. Add a **pending trusted publisher** so PyPI will accept the very first upload
   from GitHub Actions:
   - PyPI > *Your projects* > *Publishing* > *Add a pending
     publisher*.
   - PyPI Project Name: `sentineldeck`
   - Owner: `sanmaxdev`
   - Repository name: `SentinelDeck`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. (Recommended) In the GitHub repo, create an Actions environment named `pypi`
   (*Settings > Environments > New environment*) and add required
   reviewers so a human approves each publish.

> The distribution name `sentineldeck` must be available on PyPI. If it is
> taken, change `name` in `pyproject.toml` and the workflow URL before
> releasing.

## Cutting a release

1. Bump `version` in `pyproject.toml` (semantic versioning) and move the
   `[Unreleased]` notes in `CHANGELOG.md` under the new version.
2. Commit, then tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. On GitHub, draft a **Release** for that tag and publish it. The
   `Publish to PyPI` workflow builds the sdist and wheel, runs `twine check`,
   and uploads to PyPI.
4. Confirm the new version appears at
   <https://pypi.org/project/sentineldeck/> and that `pip install sentineldeck`
   pulls it.

## Verifying the build locally

```bash
pip install build twine
python -m build
twine check dist/*
```

[tp]: https://docs.pypi.org/trusted-publishers/
