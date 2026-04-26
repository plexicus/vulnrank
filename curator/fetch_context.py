"""Fetches all context needed for curation: OSV advisory + GitHub diff."""

import logging
from typing import Any

from collectors.osv_advisories import fetch_advisory
from collectors.github_diff import fetch_diff

logger = logging.getLogger(__name__)


def fetch(cve_id: str, ecosystem: str, package: str,
          vuln_version: str | None, fix_version: str | None,
          github_repo: str | None) -> dict[str, Any]:
    """
    Returns:
        advisory: raw OSV advisory dict (or None)
        diff_available: bool
        diff_text: str | None
        fix_commit_sha: str | None
        vuln_tag: str | None
        fix_tag: str | None
        diff_error: str | None
    """
    ctx: dict[str, Any] = {
        "advisory": None,
        "diff_available": False,
        "diff_text": None,
        "fix_commit_sha": None,
        "vuln_tag": None,
        "fix_tag": None,
        "diff_error": None,
    }

    # --- advisory
    adv = fetch_advisory(cve_id)
    if adv:
        ctx["advisory"] = adv
    else:
        logger.warning("No OSV advisory found for %s", cve_id)

    # --- diff (only if we have a github_repo and both versions)
    if github_repo and vuln_version and fix_version:
        diff_result = fetch_diff(github_repo, vuln_version, fix_version)
        ctx["diff_available"] = diff_result["available"]
        ctx["diff_text"] = diff_result["diff_text"]
        ctx["fix_commit_sha"] = diff_result["fix_commit_sha"]
        ctx["vuln_tag"] = diff_result["vuln_tag"]
        ctx["fix_tag"] = diff_result["fix_tag"]
        ctx["diff_error"] = diff_result["error"]
    elif not github_repo:
        ctx["diff_error"] = "no_github_repo"
        logger.info("No GitHub repo for %s/%s — will curate from advisory only (low confidence)",
                    ecosystem, package)
    else:
        ctx["diff_error"] = "missing_versions"

    return ctx
