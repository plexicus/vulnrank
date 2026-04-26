# Accuracy Statement

**VulnRank knowledge packs are AI-generated and may contain errors.**

## What this means

The curation pipeline uses the MiniMax M2.5 language model to analyse vulnerability advisories and code diffs. While the pipeline applies anti-hallucination rules and multi-layer validation, AI-generated content can still be incorrect, incomplete, or misleading.

## Anti-hallucination measures

1. **Deterministic pre-fill**: CVE ID, ecosystem, package name, affected versions, attack vector, and attack complexity are populated directly from public sources (OSV.dev, CVSS vectors) — the LLM cannot modify these.
2. **Mandatory diff evidence**: Any vulnerable symbol claim at `high` or `medium` confidence must include a verbatim excerpt from the actual code diff.
3. **Structural ceiling**: The pipeline independently scores structural signals (diff availability, symbol count, evidence coverage) and caps the LLM's confidence claim to this ceiling.
4. **Semantic guardrails**: Eight rules automatically downgrade confidence when evidence is missing or contradictory.

## Confidence levels

| Level | Meaning |
|-------|---------|
| `high` | Diff available + all symbols have evidence + no corrections needed + structural score ≥ 0.9 |
| `medium` | Partial evidence available or correction pass was used |
| `low` | No diff available, symbols claimed without evidence, or any guardrail triggered |

## What you should do

- **Do not use VEX statements from this dataset as-is in production** without human review for `high`-impact decisions.
- For `low` confidence packs: treat as advisory context only.
- For `medium` confidence packs: verify vulnerable symbols against your own code before accepting VEX.
- For `high` confidence packs with `human_reviewed: true`: these have been manually validated by a maintainer.

## Reporting inaccuracies

If you find an error in a knowledge pack, please open an issue at:
https://github.com/plexicus/vulnrank/issues

Include the CVE ID, the incorrect field, and the correct value with a source reference.

## Data sources

All knowledge packs are derived exclusively from:
- [OSV.dev](https://osv.dev) — vulnerability advisories
- [GitHub Compare API](https://docs.github.com/en/rest/commits/commits#compare-two-commits) — code diffs between versions
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — known exploitation status
- [FIRST EPSS](https://www.first.org/epss/) — exploitation probability scores
- [deps.dev](https://deps.dev) — ecosystem dependency signals

No proprietary threat intelligence is used. Knowledge packs do **not** contain exploit code or proof-of-concept.
