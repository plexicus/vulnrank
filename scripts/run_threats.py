#!/usr/bin/env python3
"""Entry point for daily_threats workflow: fetch CISA KEV + EPSS, recompute scores."""

import logging

from collectors.cisa_kev import fetch as fetch_kev, save as save_kev
from collectors.epss import fetch as fetch_epss, save as save_epss
from ranker.threat_recompute import recompute_all

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    log.info("Fetching CISA KEV…")
    save_kev(fetch_kev())

    log.info("Fetching EPSS top 5000…")
    save_epss(fetch_epss())

    log.info("Recomputing threat scores on existing rankings…")
    recompute_all()
    log.info("Threat refresh complete.")


if __name__ == "__main__":
    main()
