"""Downloads the CISA Known Exploited Vulnerabilities catalogue."""

import json
import logging
import os
from typing import Any
import httpx

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 30
OUTPUT_PATH = "data/threats/cisa_kev.json"


def fetch() -> list[dict[str, Any]]:
    """Download and normalise the KEV catalogue. Returns list of normalised entries."""
    logger.info("Downloading CISA KEV catalogue…")
    with httpx.Client() as client:
        resp = client.get(KEV_URL, timeout=TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        raw = resp.json()

    entries = []
    for v in raw.get("vulnerabilities", []):
        entries.append({
            "cve_id": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "date_added": v.get("dateAdded"),
            "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown").lower() == "known",
        })

    logger.info("KEV catalogue: %d entries", len(entries))
    return entries


def save(entries: list[dict], path: str = OUTPUT_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    logger.info("Saved KEV catalogue to %s", path)


def load_cve_set(path: str = OUTPUT_PATH) -> set[str]:
    """Return set of CVE IDs present in the local KEV file."""
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        data = json.load(f)
    return {e["cve_id"] for e in data if e.get("cve_id")}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    entries = fetch()
    save(entries)
    print(f"KEV CVEs: {len(entries)}")
