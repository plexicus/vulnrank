# Deep Interview Spec: VulnRank

## Metadata
- Interview ID: vulnrank-2026-04-26
- Rounds: 1 (--quick mode, PRD v1.1 provided)
- Final Ambiguity Score: 8.6%
- Type: greenfield
- Generated: 2026-04-26
- Threshold: 20%
- Status: PASSED

## Clarity Breakdown
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| Goal Clarity | 0.95 | 40% | 0.38 |
| Constraint Clarity | 0.90 | 30% | 0.27 |
| Success Criteria | 0.88 | 30% | 0.264 |
| **Total Clarity** | | | **0.914** |
| **Ambiguity** | | | **8.6%** |

## Goal
Build a public GitHub repository (`github.com/plexicus/vulnrank`) that:
1. Publishes a weekly-updated vulnerability risk ranking of 500+ open-source libraries across 7 ecosystems (npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems) as versioned JSON data.
2. Runs an AI-powered (MiniMax M2.5) curation pipeline that enriches high-priority CVEs into structured knowledge packs stored privately in Hetzner S3 (primary) and Google Drive (backup).
3. Serves as a lookup database for Trivy-based VEX generation: given a package name + version + CVE-ID, return rich exploitability context to determine if a finding is truly exploitable.

## Storage Key Architecture (resolved via interview)
- Regular packages: `knowledge_packs/{ecosystem}/{CVE-ID}/{package-slug}.json`
- Maven packages: `knowledge_packs/maven/{CVE-ID}/{groupId}/{artifactId}.json`
- Master index: `index/master.json`
- Logs: `logs/{date}.jsonl`, `logs/errors/{date}-errors.jsonl`

## Resolved Decisions
| Decision | Resolution |
|----------|-----------|
| Maven S3 key encoding | Use `/` separator mirroring PURL: `groupId/artifactId` |
| RubyGems scope | In scope as 7th ecosystem from Phase 1 |
| One CVE → multiple packages | One pack per CVE-package pair: `{ecosystem}/{CVE-ID}/{package-slug}.json` |
| data/raw/ files | Ephemeral — gitignored, never committed |
| Docker Hub Layer 8c | Static minimal mapping for Phase 2, dynamic Phase 4+ |
| Non-GitHub packages | Advisory-only curation at confidence=low |
| ACCURACY.md | Add to repo structure (referenced in mandatory warning) |

## Constraints
- Python 3.12 only
- GitHub Actions free tier (public repo = unlimited minutes)
- LLM: MiniMax M2.5 via OpenAI-compatible API
- Primary storage: Hetzner S3 `hel1.your-objectstorage.com`, bucket `vulnrank`
- Backup storage: Google Drive folder `1MB38IaiRaw31C9Q4H4-tN5j_IC78QzKg`
- GHA auth to Google Drive via Workload Identity Federation (keyless)
- No public API — storage accessed directly via SDK
- Knowledge pack content never enters the public repository
- Apache 2.0 (code), CC BY 4.0 (ranking data), Proprietary (knowledge packs)

## Non-Goals
- No user-facing web API or dashboard
- No real-time vulnerability scanning
- No NVD as primary source (fallback only, non-retried)
- No Docker Hub dynamic manifest lookup in Phase 1-3
- No RubyGems dynamic manifest lookup in Phase 1-3 (wait, RubyGems IS in scope)

## Acceptance Criteria
- [ ] `gh repo create plexicus/vulnrank --public` succeeds
- [ ] All 5 GitHub Actions workflows are syntactically valid (validate_pr.yml passes on PR)
- [ ] weekly_ranking.yml produces valid `data/rankings/{ecosystem}.json` for all 7 ecosystems
- [ ] daily_threats.yml produces `data/threats/cisa_kev.json` and `data/threats/epss_top5000.json`
- [ ] Composite score formula: `w_deps*score_deps + w_github*score_github + w_threat*score_threat` matches PRD weights
- [ ] curate_batch.yml successfully calls MiniMax, validates output, uploads to S3
- [ ] Knowledge packs pass JSON schema validation (Layer A)
- [ ] Knowledge packs pass all 7 semantic guardrails (Layer B)
- [ ] curate_single.yml is idempotent: second run with same CVE makes zero new LLM calls
- [ ] data/curation_status/index.json (public) contains NO knowledge pack content
- [ ] S3 master.json and public index.json CVE counts match after curate_batch run

## Technical Stack
- Python 3.12, httpx, boto3, jsonschema, google-auth, google-api-python-client, openai (for MiniMax OpenAI-compat)
- PyYAML for config
- GitHub Actions ubuntu-latest

## Repository Structure
```
vulnrank/
  README.md
  CONTRIBUTING.md
  ACCURACY.md
  LICENSE
  .gitignore
  requirements.txt
  .github/workflows/
    weekly_ranking.yml
    daily_threats.yml
    curate_batch.yml
    curate_single.yml
    validate_pr.yml
  collectors/
    __init__.py
    deps_dev.py
    osv_advisories.py
    github_diff.py
    cisa_kev.py
    epss.py
  curator/
    __init__.py
    fetch_context.py
    preprocess.py
    generate.py
    validate.py
    mark_curated.py
    storage/
      __init__.py
      index.py
      s3.py
      drive.py
  ranker/
    __init__.py
    normalizer.py
    scorer.py
    threat_recompute.py
  schemas/
    knowledge_pack.schema.json
    library_rank.schema.json
    curation_status.schema.json
  config/
    ecosystems.yaml
    seed_packages.yaml
    weights.yaml
  tests/
    test_collectors.py
    test_ranker.py
    test_curator.py
    fixtures/
      sample_osv_advisory.json
      sample_github_diff.txt
  data/
    rankings/
      npm.json
      pypi.json
      go.json
      maven.json
      cargo.json
      nuget.json
      rubygems.json
    threats/
      cisa_kev.json
      epss_top5000.json
    combined/
      top_500_global.json
    curation_status/
      index.json
```
