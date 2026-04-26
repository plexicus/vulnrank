"""Composite risk scorer for library ranking."""

import json
import logging
import os
from typing import Any
import yaml

from ranker.normalizer import log_normalize, normalize_series

logger = logging.getLogger(__name__)

WEIGHTS_PATH = "config/weights.yaml"


def _load_weights(path: str = WEIGHTS_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _build_purl(ecosystem: str, name: str) -> str:
    type_map = {
        "npm": "npm", "pypi": "pypi", "go": "golang",
        "maven": "maven", "cargo": "cargo", "nuget": "nuget", "rubygems": "gem",
    }
    purl_type = type_map.get(ecosystem, ecosystem)
    if ecosystem == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}"
    return f"pkg:{purl_type}/{name}"


def score_ecosystem(packages: list[dict[str, Any]], kev_set: set[str],
                    epss_map: dict[str, float], weights: dict) -> list[dict[str, Any]]:
    """Compute composite scores for a list of enriched package dicts."""
    w = weights["weights"]
    tw = weights["threat_weights"]

    # Compute raw signal series for normalisation
    dep_counts = [p.get("deps_dev_dependent_count", 0) for p in packages]
    stars = [p.get("github_stars") or 0 for p in packages]
    forks = [p.get("github_forks") or 0 for p in packages]

    max_deps = max(dep_counts) if dep_counts else 1
    max_stars = max(stars) if stars else 1
    max_forks = max(forks) if forks else 1

    scored = []
    for i, pkg in enumerate(packages):
        # deps_dev score
        s_deps = log_normalize(dep_counts[i], max_deps)

        # github score (blend stars + forks equally)
        s_stars = log_normalize(stars[i], max_stars)
        s_forks = log_normalize(forks[i], max_forks)
        s_github = 0.6 * s_stars + 0.4 * s_forks

        # threat score
        cves = pkg.get("associated_cves", [])
        in_kev = any(c in kev_set for c in cves)
        max_epss = max((epss_map.get(c, 0.0) for c in cves), default=0.0)
        cve_count_score = log_normalize(len(cves), 20)

        s_threat = min(1.0,
            (tw["kev_bonus"] if in_kev else 0.0) +
            max_epss * tw["max_epss"] +
            cve_count_score * tw["cve_count_log"]
        )

        composite = (
            w["deps_dev"] * s_deps +
            w["github"] * s_github +
            w["threat"] * s_threat
        )

        # priority
        th = weights.get("priority", {})
        if in_kev or max_epss >= th.get("critical_epss_min", 0.5):
            priority = "critical"
        elif composite >= th.get("high_composite_min", 0.7) or len(cves) >= th.get("high_cve_count_min", 5):
            priority = "high"
        elif composite >= th.get("medium_composite_min", 0.4):
            priority = "medium"
        else:
            priority = "low"

        ecosystem = pkg["ecosystem"]
        name = pkg["name"]

        entry: dict[str, Any] = {
            "name": name,
            "ecosystem": ecosystem,
            "purl": _build_purl(ecosystem, name),
            "default_version": pkg.get("default_version"),
            "github_repo": pkg.get("github_repo"),
            "signals": {
                "deps_dev_dependent_count": int(dep_counts[i]),
                "github_stars": int(stars[i]) if stars[i] else None,
                "github_forks": int(forks[i]) if forks[i] else None,
            },
            "scores": {
                "score_deps_dev":  round(s_deps, 6),
                "score_github":    round(s_github, 6),
                "score_threat":    round(s_threat, 6),
                "composite_score": round(composite, 6),
            },
            "threat": {
                "associated_cves": cves[:20],  # cap at 20 for storage
                "max_cvss": pkg.get("max_cvss"),
                "in_cisa_kev": in_kev,
                "max_epss": round(max_epss, 6),
            },
            "curation": {
                "priority": priority,
                "status": "pending",
                "coverage_pct": 0.0,
            },
        }
        scored.append(entry)

    # Sort by composite score descending
    scored.sort(key=lambda x: x["scores"]["composite_score"], reverse=True)
    return scored


def build_global_top500(ecosystem_data: dict[str, list[dict]], top_n: int = 500) -> list[dict]:
    """Merge all ecosystems and return top_n by composite score."""
    all_entries = []
    for entries in ecosystem_data.values():
        all_entries.extend(entries)
    all_entries.sort(key=lambda x: x["scores"]["composite_score"], reverse=True)
    return all_entries[:top_n]


def save_rankings(ecosystem_data: dict[str, list], out_dir: str = "data/rankings") -> None:
    os.makedirs(out_dir, exist_ok=True)
    for ecosystem, entries in ecosystem_data.items():
        path = os.path.join(out_dir, f"{ecosystem}.json")
        with open(path, "w") as f:
            json.dump(entries, f, indent=2)
        logger.info("Saved %d entries to %s", len(entries), path)


def save_global(entries: list, path: str = "data/combined/top_500_global.json") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)
    logger.info("Saved global top %d to %s", len(entries), path)
