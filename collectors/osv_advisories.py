"""Fetches CVE/advisory data per library from OSV.dev."""

import logging
import time
from typing import Any
import httpx

logger = logging.getLogger(__name__)

OSV_BASE = "https://api.osv.dev/v1"
TIMEOUT = 15
BATCH_SLEEP = 0.2


def query_package(ecosystem: str, package: str) -> list[dict[str, Any]]:
    """Return all OSV advisories affecting a package in an ecosystem."""
    url = f"{OSV_BASE}/query"
    payload = {"package": {"name": package, "ecosystem": _osv_ecosystem(ecosystem)}}
    try:
        with httpx.Client() as client:
            resp = client.post(url, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulns", [])
    except httpx.HTTPStatusError as e:
        logger.warning("OSV query failed for %s/%s: %s", ecosystem, package, e)
        return []
    except httpx.TimeoutException:
        logger.warning("OSV timeout for %s/%s", ecosystem, package)
        return []


def fetch_advisory(cve_id: str) -> dict[str, Any] | None:
    """Fetch a specific advisory by CVE ID."""
    url = f"{OSV_BASE}/vulns/{cve_id}"
    try:
        with httpx.Client() as client:
            resp = client.get(url, timeout=TIMEOUT)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("Failed to fetch advisory %s: %s", cve_id, e)
        return None


def _osv_ecosystem(ecosystem: str) -> str:
    mapping = {
        "npm": "npm", "pypi": "PyPI", "go": "Go", "maven": "Maven",
        "cargo": "crates.io", "nuget": "NuGet", "rubygems": "RubyGems",
    }
    return mapping.get(ecosystem, ecosystem)


def extract_cves(advisories: list[dict]) -> list[str]:
    """Extract CVE IDs from OSV advisory list."""
    cves = []
    for adv in advisories:
        for alias in adv.get("aliases", []):
            if alias.startswith("CVE-"):
                cves.append(alias)
        if adv.get("id", "").startswith("CVE-"):
            cves.append(adv["id"])
    return list(set(cves))


def enrich_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add CVE list and max CVSS to each package dict."""
    enriched = []
    for pkg in packages:
        eco = pkg["ecosystem"]
        name = pkg["name"]
        advisories = query_package(eco, name)
        cves = extract_cves(advisories)

        max_cvss = None
        for adv in advisories:
            for sev in adv.get("severity", []):
                score = sev.get("score")
                if score is not None:
                    try:
                        score_float = float(score)
                        if max_cvss is None or score_float > max_cvss:
                            max_cvss = score_float
                    except ValueError:
                        pass

        pkg["associated_cves"] = cves
        pkg["max_cvss"] = max_cvss
        enriched.append(pkg)
        time.sleep(BATCH_SLEEP)
    return enriched


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    advs = query_package("npm", "lodash")
    print(f"lodash advisories: {len(advs)}")
    cves = extract_cves(advs)
    print(f"CVEs: {cves}")
