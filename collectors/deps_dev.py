"""Fetches package metadata from api.deps.dev for seed packages."""

import time
import logging
from typing import Any
import httpx
import yaml

logger = logging.getLogger(__name__)

DEPS_DEV_BASE = "https://api.deps.dev/v3"
BATCH_SIZE = 10
BATCH_SLEEP = 0.5
TIMEOUT = 15
MAX_RETRIES = 3


def _system_name(ecosystem: str) -> str:
    mapping = {
        "npm": "NPM", "pypi": "PYPI", "go": "GO",
        "maven": "MAVEN", "cargo": "CARGO", "nuget": "NUGET", "rubygems": "RUBYGEMS",
    }
    return mapping[ecosystem]


def _encode_package(ecosystem: str, name: str) -> str:
    """URL-encode package name for deps.dev path segment."""
    import urllib.parse
    return urllib.parse.quote(name, safe="")


def _fetch_package(client: httpx.Client, ecosystem: str, name: str) -> dict[str, Any] | None:
    system = _system_name(ecosystem)
    encoded = _encode_package(ecosystem, name)
    url = f"{DEPS_DEV_BASE}/systems/{system}/packages/{encoded}"

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.get(url, timeout=TIMEOUT)
            if resp.status_code == 404:
                logger.warning("Package not found on deps.dev: %s/%s", ecosystem, name)
                return None
            if resp.status_code >= 500:
                wait = 2 ** attempt
                logger.warning("deps.dev 5xx (attempt %d), retrying in %ds", attempt + 1, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException:
            logger.warning("Timeout fetching %s/%s (attempt %d)", ecosystem, name, attempt + 1)
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
    return None


def _extract_signals(raw: dict, ecosystem: str, name: str) -> dict[str, Any]:
    """Pull dependent_count, default_version, github_repo from deps.dev response."""
    result: dict[str, Any] = {
        "name": name,
        "ecosystem": ecosystem,
        "default_version": None,
        "github_repo": None,
        "deps_dev_dependent_count": 0,
    }

    # default_version
    result["default_version"] = raw.get("defaultVersion", raw.get("latestVersion"))

    # github repo from links
    for link in raw.get("links", []):
        url = link.get("url", "")
        if "github.com" in url:
            # Normalise to owner/repo
            parts = url.rstrip("/").split("github.com/")
            if len(parts) == 2:
                result["github_repo"] = parts[1].rstrip("/")
            break

    # dependent count: use the advisories-level version count as proxy when direct field absent
    result["deps_dev_dependent_count"] = raw.get("dependentCount", raw.get("dependentsCount", 0)) or 0

    return result


def fetch_ecosystem(ecosystem: str, packages: list[str]) -> list[dict[str, Any]]:
    """Fetch deps.dev metadata for a list of packages in one ecosystem."""
    results = []
    with httpx.Client() as client:
        for i in range(0, len(packages), BATCH_SIZE):
            batch = packages[i: i + BATCH_SIZE]
            for pkg in batch:
                raw = _fetch_package(client, ecosystem, pkg)
                if raw:
                    signals = _extract_signals(raw, ecosystem, pkg)
                    results.append(signals)
                    logger.debug("Fetched %s/%s: %d dependents", ecosystem, pkg, signals["deps_dev_dependent_count"])
            if i + BATCH_SIZE < len(packages):
                time.sleep(BATCH_SLEEP)
    return results


def fetch_all(config_path: str = "config/ecosystems.yaml",
              seeds_path: str = "config/seed_packages.yaml") -> dict[str, list[dict]]:
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    with open(seeds_path) as f:
        seeds = yaml.safe_load(f)

    all_results: dict[str, list] = {}
    for ecosystem in cfg["ecosystems"]:
        pkgs = seeds.get(ecosystem, [])
        if not pkgs:
            logger.info("No seed packages for %s, skipping", ecosystem)
            continue
        logger.info("Fetching deps.dev data for %d %s packages…", len(pkgs), ecosystem)
        all_results[ecosystem] = fetch_ecosystem(ecosystem, pkgs)
    return all_results


if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)
    data = fetch_all()
    for eco, entries in data.items():
        print(f"{eco}: {len(entries)} packages fetched")
