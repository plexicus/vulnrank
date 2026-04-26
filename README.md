# VulnRank

> Weekly composite-risk ranking of the most vulnerable open-source libraries across 7 ecosystems.

[![Weekly Ranking](https://github.com/plexicus/vulnrank/actions/workflows/weekly_ranking.yml/badge.svg)](https://github.com/plexicus/vulnrank/actions/workflows/weekly_ranking.yml)
[![Daily Threats](https://github.com/plexicus/vulnrank/actions/workflows/daily_threats.yml/badge.svg)](https://github.com/plexicus/vulnrank/actions/workflows/daily_threats.yml)
[![License](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE)
[![Data License](https://img.shields.io/badge/data-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

## What is this?

VulnRank is a community-maintained dataset that does one thing:

**Weekly Ranking** — Ranks the most vulnerable open-source libraries by composite risk score using public data from [deps.dev](https://deps.dev), [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/). Updated every Monday.

## Ecosystems covered

| Ecosystem | File | Packages tracked |
|-----------|------|-----------------|
| npm       | [data/rankings/npm.json](data/rankings/npm.json)           | 80+ |
| PyPI      | [data/rankings/pypi.json](data/rankings/pypi.json)         | 80+ |
| Go        | [data/rankings/go.json](data/rankings/go.json)             | 50+ |
| Maven     | [data/rankings/maven.json](data/rankings/maven.json)       | 50+ |
| Cargo     | [data/rankings/cargo.json](data/rankings/cargo.json)       | 50+ |
| NuGet     | [data/rankings/nuget.json](data/rankings/nuget.json)       | 35+ |
| RubyGems  | [data/rankings/rubygems.json](data/rankings/rubygems.json) | 50+ |

A combined global top-500 across ecosystems is at [data/combined/top_500_global.json](data/combined/top_500_global.json).

## Composite score formula

```
composite = 0.50 × score_deps_dev + 0.30 × score_github + 0.20 × score_threat
```

All sub-scores are log-normalised to `[0, 1]`. Weights are community-editable via PR with data-backed justification — see [config/weights.yaml](config/weights.yaml).

Sub-scores:

- **score_deps_dev** — dependency centrality from [deps.dev](https://deps.dev) (dependents count, version churn).
- **score_github** — repository signal (stars, forks, recent commit activity).
- **score_threat** — CVE-derived risk:
  - 50% mean CVSS of associated CVEs
  - 30% max EPSS (FIRST.org)
  - 20% CISA KEV presence

## Using the ranking data

```python
import json, urllib.request

url = "https://raw.githubusercontent.com/plexicus/vulnrank/main/data/rankings/npm.json"
with urllib.request.urlopen(url) as r:
    npm_ranking = json.loads(r.read())

top_10 = npm_ranking[:10]
for entry in top_10:
    print(f"{entry['name']:30s}  composite={entry['scores']['composite_score']:.3f}")
```

Each ranking entry validates against [schemas/library_rank.schema.json](schemas/library_rank.schema.json).

## Data refresh cadence

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| [weekly_ranking.yml](.github/workflows/weekly_ranking.yml) | Mon 02:00 UTC | Full ranking refresh (deps.dev + OSV + GitHub) |
| [daily_threats.yml](.github/workflows/daily_threats.yml)   | Daily 06:00 UTC | CISA KEV + EPSS refresh and threat-score recompute |
| [validate_pr.yml](.github/workflows/validate_pr.yml)       | On PR | Schema + weights validation, unit tests |

## Running locally

```bash
git clone https://github.com/plexicus/vulnrank
cd vulnrank
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Fetch threat intel
python -m collectors.cisa_kev
python -m collectors.epss

# Run the full ranking pipeline
python scripts/run_ranking.py

# Run tests
pytest tests/ -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add packages or propose weight changes.

## License

- **Code**: [Apache 2.0](LICENSE)
- **Ranking data** (`data/rankings/`, `data/combined/`, `data/threats/`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — attribution required
