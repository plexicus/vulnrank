#!/usr/bin/env python3
"""Entry point for curate_batch workflow.

Two-queue design so each run makes progress on both new high-severity CVEs AND
widely-used legacy packages that only carry older/lower-EPSS vulnerabilities:

  PRIMARY (primary_pct % of MAX_CVES):
    critical + high priority entries, sorted by (KEV first, EPSS desc).

  LEGACY (remaining budget):
    All priorities, uncurated only, sorted by score_deps desc.
    Ensures popular old libraries get continuous coverage even when their CVEs
    have low EPSS scores (e.g., decade-old RCEs in foundational packages).

The two queues are de-duplicated so a CVE-package pair never appears twice.
"""

import glob
import json
import logging
import math
import os
import sys

from curator.storage.index import MasterIndex
from curator.mark_curated import curate_one
from collectors.cisa_kev import load_cve_set
from collectors.epss import load_epss_map

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)

# What fraction of the total budget is reserved for the primary (critical/high) queue.
# The remainder fills from the legacy (all-priority, sort-by-usage) queue.
PRIMARY_FRACTION = float(os.environ.get("PRIMARY_FRACTION", "0.6"))


def _load_candidates_from_rankings() -> list[dict]:
    """Return every (CVE, ecosystem, package, github_repo, score_deps, priority, epss) tuple."""
    rows = []
    for path in glob.glob("data/rankings/*.json"):
        with open(path) as f:
            entries = json.load(f)
        for entry in entries:
            eco = entry["ecosystem"]
            pkg = entry["name"]
            repo = entry.get("github_repo")
            priority = entry.get("curation", {}).get("priority", "low")
            score_deps = entry.get("scores", {}).get("score_deps", 0.0)
            for cve_id in entry.get("threat", {}).get("associated_cves", []):
                rows.append({
                    "cve_id": cve_id,
                    "ecosystem": eco,
                    "package": pkg,
                    "github_repo": repo,
                    "priority": priority,
                    "score_deps": score_deps,
                })
    return rows


def _build_queues(
    rows: list[dict],
    master: MasterIndex,
    epss_map: dict,
    kev_set: set,
    force: bool,
    max_cves: int,
) -> list[dict]:
    """Return the merged, de-duplicated candidate list respecting PRIMARY_FRACTION."""
    seen: set[tuple] = set()

    def _key(r: dict) -> tuple:
        return (r["cve_id"], r["ecosystem"], r["package"])

    def _enqueue(r: dict) -> dict | None:
        k = _key(r)
        if k in seen:
            return None
        decision = master.decide(r["cve_id"], r["ecosystem"], r["package"], force=force)
        if decision not in ("process", "retry", "reprocess"):
            return None
        seen.add(k)
        return {
            **r,
            "epss": epss_map.get(r["cve_id"], 0.0),
            "in_kev": r["cve_id"] in kev_set,
        }

    primary_budget = max(1, math.ceil(max_cves * PRIMARY_FRACTION))
    legacy_budget = max_cves - primary_budget

    # ── Primary queue: critical + high, most dangerous first ────────────────
    primary_rows = sorted(
        [r for r in rows if r["priority"] in ("critical", "high")],
        key=lambda r: (r["cve_id"] not in kev_set, -epss_map.get(r["cve_id"], 0.0)),
    )
    primary: list[dict] = []
    for r in primary_rows:
        if len(primary) >= primary_budget:
            break
        c = _enqueue(r)
        if c:
            primary.append(c)

    # ── Legacy queue: all priorities, most-used packages first ──────────────
    legacy_rows = sorted(rows, key=lambda r: -r["score_deps"])
    legacy: list[dict] = []
    for r in legacy_rows:
        if len(legacy) >= legacy_budget:
            break
        c = _enqueue(r)
        if c:
            legacy.append(c)

    log.info(
        "Queue sizes — primary: %d (budget %d), legacy: %d (budget %d)",
        len(primary), primary_budget, len(legacy), legacy_budget,
    )
    return primary + legacy


def main():
    max_cves = int(os.environ.get("MAX_CVES", "100"))
    force = os.environ.get("FORCE", "false").lower() == "true"

    master = MasterIndex()
    master.load()

    kev_set = load_cve_set()
    epss_map = load_epss_map()

    rows = _load_candidates_from_rankings()
    candidates = _build_queues(rows, master, epss_map, kev_set, force, max_cves)

    log.info("Curating %d CVEs (max=%d, force=%s)", len(candidates), max_cves, force)

    results = {"curated": 0, "skipped": 0, "failed": 0}
    try:
        for i, c in enumerate(candidates, start=1):
            r = curate_one(
                cve_id=c["cve_id"], ecosystem=c["ecosystem"], package=c["package"],
                vuln_version=None, fix_version=None, github_repo=c.get("github_repo"),
                master_index=master, force=force,
            )
            status = r["status"] if r["status"] in results else "failed"
            results[status] += 1

            # Persist after every pair so a mid-batch interruption (LLM token
            # budget exhausted, workflow timeout, runner OOM) leaves a recoverable
            # state in S3. Next run resumes from the unprocessed remainder.
            try:
                master.save()
            except Exception as save_err:  # noqa: BLE001
                log.warning("Master index save failed at %d/%d: %s", i, len(candidates), save_err)

            log.info("Progress %d/%d — %s", i, len(candidates), results)
    except KeyboardInterrupt:
        log.warning("Interrupted; persisting master index before exit")
        master.save()
        raise

    log.info("Final results: %s", results)
    master.save()

    failure_rate = results["failed"] / max(len(candidates), 1)
    if failure_rate > 0.1:
        log.error("Failure rate %.0f%% exceeds 10%% threshold", failure_rate * 100)
        sys.exit(1)


if __name__ == "__main__":
    main()
