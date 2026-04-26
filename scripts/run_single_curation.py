#!/usr/bin/env python3
"""Entry point for curate_single workflow — reads CVE params from env vars."""

import json
import logging
import os
import sys

from curator.storage.index import MasterIndex
from curator.mark_curated import curate_one

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def main():
    cve_id    = os.environ["CVE_ID"]
    ecosystem = os.environ["ECOSYSTEM"]
    package   = os.environ["PACKAGE"]
    vuln_ver  = os.environ.get("VULN_VERSION") or None
    fix_ver   = os.environ.get("FIX_VERSION") or None
    gh_repo   = os.environ.get("GITHUB_REPO") or None
    force     = os.environ.get("FORCE", "false").lower() == "true"

    master = MasterIndex()
    master.load()

    result = curate_one(
        cve_id=cve_id, ecosystem=ecosystem, package=package,
        vuln_version=vuln_ver, fix_version=fix_ver,
        github_repo=gh_repo, master_index=master, force=force,
    )

    print(json.dumps(result, indent=2))
    master.save()

    if result["status"] == "failed":
        log.error("Curation failed: %s", result["error"])
        sys.exit(1)


if __name__ == "__main__":
    main()
