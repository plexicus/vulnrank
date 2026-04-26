# VulnRank

> Weekly vulnerability risk ranking for 500+ open-source libraries across 7 ecosystems, with AI-powered CVE knowledge packs for VEX generation.

[![Weekly Ranking](https://github.com/plexicus/vulnrank/actions/workflows/weekly_ranking.yml/badge.svg)](https://github.com/plexicus/vulnrank/actions/workflows/weekly_ranking.yml)
[![Daily Threats](https://github.com/plexicus/vulnrank/actions/workflows/daily_threats.yml/badge.svg)](https://github.com/plexicus/vulnrank/actions/workflows/daily_threats.yml)
[![License](https://img.shields.io/badge/code-Apache%202.0-blue)](LICENSE)
[![Data License](https://img.shields.io/badge/data-CC%20BY%204.0-green)](https://creativecommons.org/licenses/by/4.0/)

## What is this?

VulnRank is a community-maintained dataset that does two things:

1. **Weekly Ranking** — Ranks the most vulnerable open-source libraries by composite risk score using public data from [deps.dev](https://deps.dev), [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/). Updated every Monday.

2. **CVE Knowledge Packs** — An AI pipeline (MiniMax M2.5) generates structured knowledge packs for high-priority CVEs, containing vulnerable symbol identification, exploitability conditions, and VEX statement templates. Stored privately in Hetzner S3 and used by [Reticulum](https://github.com/plexicus/reticulum) for automated VEX generation.

## Ecosystems covered

| Ecosystem | File | Packages tracked |
|-----------|------|-----------------|
| npm | [data/rankings/npm.json](data/rankings/npm.json) | 80+ |
| PyPI | [data/rankings/pypi.json](data/rankings/pypi.json) | 80+ |
| Go | [data/rankings/go.json](data/rankings/go.json) | 50+ |
| Maven | [data/rankings/maven.json](data/rankings/maven.json) | 50+ |
| Cargo | [data/rankings/cargo.json](data/rankings/cargo.json) | 50+ |
| NuGet | [data/rankings/nuget.json](data/rankings/nuget.json) | 35+ |
| RubyGems | [data/rankings/rubygems.json](data/rankings/rubygems.json) | 50+ |

## Composite score formula

```
composite = 0.50 × score_deps_dev + 0.30 × score_github + 0.20 × score_threat
```

All sub-scores are log-normalised to [0, 1]. Weights are community-editable via PR with data-backed justification — see [config/weights.yaml](config/weights.yaml).

## Using the ranking data

```python
import json, urllib.request

url = "https://raw.githubusercontent.com/plexicus/vulnrank/main/data/rankings/npm.json"
with urllib.request.urlopen(url) as r:
    npm_ranking = json.loads(r.read())

top_10 = npm_ranking[:10]
for entry in top_10:
    print(f"{entry['name']:30s}  composite={entry['scores']['composite_score']:.3f}  priority={entry['curation']['priority']}")
```

## Knowledge pack schema (summary)

Knowledge packs contain 7 semantic layers:

| Layer | Content |
|-------|---------|
| 1 — Identification | CVE ID, GHSA, aliases, package, PURL, summary |
| 2 — Versions | Vulnerable ranges, fixed version, fix commit SHA |
| 3 — Vulnerable symbols | Function/method-level analysis with diff evidence |
| 4 — Exploitability | Auth, network, user-interaction requirements |
| 5 — VEX templates | Ready-to-use not_affected / affected statements |
| 6 — Detection patterns | Import/call/config patterns for SAST |
| 7 — Provenance | Model, prompt version, confidence, human review status |

> ⚠️ Knowledge packs are AI-generated. See [ACCURACY.md](ACCURACY.md) for limitations and confidence level definitions.

## Curation status

The public curation status index is at [data/curation_status/index.json](data/curation_status/index.json).
It shows the curation status (`pending`, `curating`, `curated`, `failed`) and confidence level for each tracked CVE.
**It does not contain knowledge pack content** — packs are stored privately.

## Running locally

```bash
pip install -r requirements.txt

# Fetch threat intel
python -m collectors.cisa_kev
python -m collectors.epss

# Fetch rankings for npm
python -c "
from collectors.deps_dev import fetch_ecosystem
from collectors.osv_advisories import enrich_packages
import yaml

with open('config/seed_packages.yaml') as f:
    seeds = yaml.safe_load(f)

packages = fetch_ecosystem('npm', seeds['npm'][:10])
enriched = enrich_packages(packages)
print(enriched[0])
"

# Run tests
pytest tests/ -v
```

## Workflows

| Workflow | Schedule | Purpose |
|----------|----------|---------|
| [weekly_ranking.yml](.github/workflows/weekly_ranking.yml) | Mon 02:00 UTC | Full ranking refresh |
| [daily_threats.yml](.github/workflows/daily_threats.yml) | Daily 06:00 UTC | CISA KEV + EPSS refresh |
| [curate_batch.yml](.github/workflows/curate_batch.yml) | Mon 04:00 UTC | Batch AI curation |
| [curate_single.yml](.github/workflows/curate_single.yml) | Manual | Single CVE curation |
| [validate_pr.yml](.github/workflows/validate_pr.yml) | On PR | Schema + test validation |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add packages, propose weight changes, or report inaccuracies.

## License

- **Code**: [Apache 2.0](LICENSE)
- **Ranking data**: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — attribution required
- **Knowledge packs**: Proprietary (Plexicus AI)

## Related projects

- [Reticulum](https://github.com/plexicus/reticulum) — OSS VEX engine (Go) that consumes VulnRank knowledge packs
- [Plexicus ASPM Platform](https://plexicus.ai) — Application Security Posture Management
