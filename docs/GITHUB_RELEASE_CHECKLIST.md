# GitHub Release Checklist

Use this before making the repository public or tagging a release.

## Repository setup

- [ ] Replace `your-username` in `pyproject.toml` project URLs.
- [ ] Choose the final repository name.
- [ ] Confirm the package name is available or rename it if needed.
- [ ] Enable GitHub Actions.
- [ ] Confirm the CI workflow passes.
- [ ] Add a short repository description.
- [ ] Add repository topics, for example:
  - cybersecurity
  - forensics
  - osint
  - ctf
  - malware-analysis
  - reconnaissance
  - python

## Files to verify

- [ ] `README.md`
- [ ] `LICENSE`
- [ ] `CONTRIBUTING.md`
- [ ] `SECURITY.md`
- [ ] `CODE_OF_CONDUCT.md`
- [ ] `CHANGELOG.md`
- [ ] `.gitignore`
- [ ] `.env.example`
- [ ] `.github/workflows/ci.yml`
- [ ] issue templates
- [ ] pull request template

## Local checks

```bash
python -m pip install -e ".[dev,dns]"
python -m unittest discover -s tests -v
spectre --list-plugins
spectre analyze SGVsbG8= --format json
```

## Do not commit

- API keys
- `.env`
- SQLite databases
- investigation reports
- generated caches
- malware samples
- private investigation data
- credentials

## Release notes

For each release, update:

- version in `spectre/__init__.py`
- version in `pyproject.toml`
- `CHANGELOG.md`
