"""Re-applies latest threat intelligence (KEV + EPSS) to existing rankings."""

import json
import logging
import os
import glob

from collectors.cisa_kev import load_cve_set
from collectors.epss import load_epss_map
from ranker.scorer import _load_weights, score_ecosystem

logger = logging.getLogger(__name__)


def recompute_all(rankings_dir: str = "data/rankings",
                  kev_path: str = "data/threats/cisa_kev.json",
                  epss_path: str = "data/threats/epss_top5000.json") -> None:
    """Load existing per-ecosystem rankings and recompute threat scores."""
    kev_set = load_cve_set(kev_path)
    epss_map = load_epss_map(epss_path)
    weights = _load_weights()

    for path in glob.glob(os.path.join(rankings_dir, "*.json")):
        ecosystem = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            entries = json.load(f)

        if not entries:
            continue

        # Convert ranking entries back to the flat format scorer expects
        packages = []
        for e in entries:
            packages.append({
                "name": e["name"],
                "ecosystem": e["ecosystem"],
                "default_version": e.get("default_version"),
                "github_repo": e.get("github_repo"),
                "deps_dev_dependent_count": e["signals"].get("deps_dev_dependent_count", 0),
                "github_stars": e["signals"].get("github_stars", 0),
                "github_forks": e["signals"].get("github_forks", 0),
                "associated_cves": e["threat"].get("associated_cves", []),
                "max_cvss": e["threat"].get("max_cvss"),
            })

        updated = score_ecosystem(packages, kev_set, epss_map, weights)

        with open(path, "w") as f:
            json.dump(updated, f, indent=2)
        logger.info("Recomputed threat scores for %s (%d entries)", ecosystem, len(updated))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    recompute_all()
