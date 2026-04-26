#!/usr/bin/env python3
"""Entry point for weekly_ranking workflow: fetch signals, enrich, score, save."""

import glob
import json
import logging
import os

import yaml

from collectors.deps_dev import fetch_all
from collectors.osv_advisories import enrich_packages
from collectors.cisa_kev import load_cve_set
from collectors.epss import load_epss_map
from ranker.scorer import score_ecosystem, save_rankings, save_global, build_global_top500, _load_weights

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    weights = _load_weights()
    kev_set = load_cve_set()
    epss_map = load_epss_map()

    log.info("Fetching deps.dev signals for all ecosystems…")
    raw_data = fetch_all()

    os.makedirs("data/raw/deps_dev", exist_ok=True)
    for eco, entries in raw_data.items():
        with open(f"data/raw/deps_dev/{eco}.json", "w") as f:
            json.dump(entries, f)

    log.info("Enriching with OSV advisories and scoring…")
    ecosystem_data = {}
    for eco, packages in raw_data.items():
        enriched = enrich_packages(packages)
        scored = score_ecosystem(enriched, kev_set, epss_map, weights)
        ecosystem_data[eco] = scored
        log.info("%s: %d packages scored", eco, len(scored))

    save_rankings(ecosystem_data)
    save_global(build_global_top500(ecosystem_data))
    log.info("Ranking complete.")


if __name__ == "__main__":
    main()
