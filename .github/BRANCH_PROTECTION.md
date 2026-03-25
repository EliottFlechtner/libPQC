# Branch Protection Recommendations

Apply these settings to `main` and `dev` in GitHub:

## Required status checks

Enable `Require status checks to pass before merging` and add these checks:

- `Tests (Python 3.10)`
- `Tests (Python 3.11)`
- `Tests (Python 3.12)`
- `Smoke (entrypoint)`
- `Dependency Review (PR)`
- `Analyze (CodeQL)`

## Pull request quality gates

Enable:

- `Require a pull request before merging`
- `Require approvals` (recommended: at least 1)
- `Dismiss stale pull request approvals when new commits are pushed`
- `Require conversation resolution before merging`
- `Require branches to be up to date before merging`

## Branch safety

Enable:

- `Restrict who can push to matching branches` (maintainers only)
- `Do not allow force pushes`
- `Do not allow deletions`

## Optional

- `Require signed commits`
- `Require linear history`
- `Require merge queue` (for larger contributor volume)

## Notes

GitHub Actions workflows are defined in:

- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/release.yml`

Branch protection itself must be configured in repository settings.
