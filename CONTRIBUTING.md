# Contributing to VulnRank

Thank you for your interest in improving VulnRank!

## Ways to contribute

### 1. Add or update seed packages

Edit [config/seed_packages.yaml](config/seed_packages.yaml) to add packages you want tracked. Requirements:

- Package must exist on the target ecosystem registry.
- Open a PR with a brief justification (Why is this package important to track?).
- PRs adding more than 20 packages at once will be reviewed by a maintainer.

### 2. Propose scoring weight changes

Edit [config/weights.yaml](config/weights.yaml). **Data-backed justifications required.** Your PR description must include:

- The change you are proposing (before/after values).
- A quantitative justification (e.g. correlation data, false-positive/false-negative analysis).
- The dataset or methodology used to derive the new weights.

Weight PRs without data backing will be closed.

### 3. Report ranking issues

If a package is mis-ranked or missing CVE associations, open an issue with:

- Ecosystem and package name (PURL preferred).
- The expected behavior with a source reference (deps.dev, OSV.dev, CVSSv3 vector, or KEV/EPSS link).

## Licensing

- **Code** (`*.py`, `*.yml`, `*.yaml`, `*.json` schemas): Apache 2.0.
- **Ranking data** (`data/rankings/`, `data/combined/`, `data/threats/`): CC BY 4.0.

By submitting a PR, you agree that your contribution will be licensed under the same terms as the file(s) you modify.

## Development setup

```bash
git clone https://github.com/plexicus/vulnrank
cd vulnrank
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/
```

## Commit convention

```
chore: routine data update
feat: add RubyGems ecosystem support
fix: correct EPSS score normalisation
docs: update README
```
