"""Fetches top 5000 CVEs by EPSS score from FIRST.org."""

import json
import logging
import os
from typing import Any
import httpx

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 30
TOP_N = 5000
OUTPUT_PATH = "data/threats/epss_top5000.json"


def fetch(top_n: int = TOP_N) -> list[dict[str, Any]]:
    """Return top_n CVEs sorted by EPSS score descending."""
    logger.info("Fetching EPSS top %d from FIRST.org…", top_n)
    params = {"limit": top_n, "order": "!epss"}
    with httpx.Client() as client:
        resp = client.get(EPSS_URL, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

    entries = []
    for item in data.get("data", []):
        entries.append({
            "cve_id": item.get("cve"),
            "epss":   float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
            "date":  item.get("date"),
        })

    logger.info("EPSS: %d entries fetched", len(entries))
    return entries


def save(entries: list[dict], path: str = OUTPUT_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    logger.info("Saved EPSS data to %s", path)


def load_epss_map(path: str = OUTPUT_PATH) -> dict[str, float]:
    """Return {cve_id: epss_score} from local file."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    return {e["cve_id"]: e["epss"] for e in data if e.get("cve_id")}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    entries = fetch()
    save(entries)
    print(f"Top EPSS CVE: {entries[0] if entries else 'none'}")
