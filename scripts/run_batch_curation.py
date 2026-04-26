#!/usr/bin/env python3
"""Entry point for curate_batch workflow."""

import glob
import json
import logging
import os
import sys

from curator.storage.index import MasterIndex
from curator.mark_curated import curate_one, save_public_status
from collectors.cisa_kev import load_cve_set
from collectors.epss import load_epss_map

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    max_cves = int(os.environ.get("MAX_CVES", "50"))
    force = os.environ.get("FORCE", "false").lower() == "true"

    master = MasterIndex()
    master.load()

    kev_set = load_cve_set()
    epss_map = load_epss_map()

    candidates = []
    for path in glob.glob("data/rankings/*.json"):
        with open(path) as f:
            entries = json.load(f)
        for entry in entries:
            priority = entry.get("curation", {}).get("priority", "low")
            if priority not in ("critical", "high"):
                continue
            eco = entry["ecosystem"]
            pkg = entry["name"]
            repo = entry.get("github_repo")
            for cve_id in entry.get("threat", {}).get("associated_cves", []):
                decision = master.decide(cve_id, eco, pkg, force=force)
                if decision in ("process", "retry", "reprocess"):
                    epss_score = epss_map.get(cve_id, 0.0)
                    in_kev = cve_id in kev_set
                    candidates.append({
                        "cve_id": cve_id, "ecosystem": eco, "package": pkg,
                        "github_repo": repo, "epss": epss_score, "in_kev": in_kev,
                    })

    candidates.sort(key=lambda x: (not x["in_kev"], -x["epss"]))
    candidates = candidates[:max_cves]
    log.info("Curating %d CVEs (max=%d, force=%s)", len(candidates), max_cves, force)

    results = {"curated": 0, "skipped": 0, "failed": 0}
    for c in candidates:
        r = curate_one(
            cve_id=c["cve_id"], ecosystem=c["ecosystem"], package=c["package"],
            vuln_version=None, fix_version=None, github_repo=c.get("github_repo"),
            master_index=master, force=force,
        )
        status = r["status"] if r["status"] in results else "failed"
        results[status] += 1

    log.info("Results: %s", results)
    master.save()
    save_public_status(master)

    failure_rate = results["failed"] / max(len(candidates), 1)
    if failure_rate > 0.1:
        log.error("Failure rate %.0f%% exceeds 10%% threshold", failure_rate * 100)
        sys.exit(1)


if __name__ == "__main__":
    main()
