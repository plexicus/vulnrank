"""Fetches diffs between vulnerable and fixed version tags via GitHub compare API."""

import logging
import os
import time
from typing import Any
import httpx

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
TIMEOUT = 30
MAX_DIFF_CHARS = 24000   # ~6000 tokens


def _headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _normalise_repo(github_repo: str) -> str:
    """Strip any URL prefix, return owner/repo."""
    return github_repo.replace("https://github.com/", "").strip("/")


def _tag_candidates(version: str) -> list[str]:
    """Return tag name variants to try (v-prefix, release-prefix, bare)."""
    v = version.lstrip("v")
    return [f"v{v}", version, f"release-{v}", f"release/{v}"]


def _resolve_ref(client: httpx.Client, repo: str, version: str) -> str | None:
    """Try tag candidates; fall back to finding commit SHA from releases."""
    for tag in _tag_candidates(version):
        url = f"{GITHUB_API}/repos/{repo}/git/ref/tags/{tag}"
        resp = client.get(url, headers=_headers(), timeout=TIMEOUT)
        if resp.status_code == 200:
            return tag
    # fallback: check releases
    url = f"{GITHUB_API}/repos/{repo}/releases"
    resp = client.get(url, headers=_headers(), timeout=TIMEOUT)
    if resp.status_code == 200:
        for release in resp.json():
            if release.get("tag_name", "").lstrip("v") == version.lstrip("v"):
                return release["tag_name"]
    return None


def fetch_diff(github_repo: str, vuln_version: str, fix_version: str) -> dict[str, Any]:
    """
    Returns dict with keys:
      available (bool), diff_text (str|None), fix_commit_sha (str|None),
      vuln_tag (str|None), fix_tag (str|None), error (str|None)
    """
    result: dict[str, Any] = {
        "available": False, "diff_text": None,
        "fix_commit_sha": None, "vuln_tag": None, "fix_tag": None, "error": None,
    }
    if not github_repo:
        result["error"] = "no_github_repo"
        return result

    repo = _normalise_repo(github_repo)

    with httpx.Client() as client:
        vuln_ref = _resolve_ref(client, repo, vuln_version)
        fix_ref = _resolve_ref(client, repo, fix_version)

        if not vuln_ref or not fix_ref:
            result["error"] = "tags_not_found"
            logger.warning("Could not resolve tags for %s %s..%s", repo, vuln_version, fix_version)
            return result

        result["vuln_tag"] = vuln_ref
        result["fix_tag"] = fix_ref

        url = f"{GITHUB_API}/repos/{repo}/compare/{vuln_ref}...{fix_ref}"
        resp = client.get(url, headers=_headers(), timeout=TIMEOUT,
                          params={"mediaType": {"format": "diff"}})

        if resp.status_code == 404:
            result["error"] = "repo_not_accessible"
            return result
        if resp.status_code == 403:
            result["error"] = "rate_limited"
            return result

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            result["error"] = str(e)
            return result

        data = resp.json()
        result["fix_commit_sha"] = data.get("merge_base_commit", {}).get("sha")

        # Aggregate file diffs
        diff_parts = []
        for f in data.get("files", []):
            patch = f.get("patch", "")
            if patch:
                diff_parts.append(f"--- a/{f['filename']}\n+++ b/{f['filename']}\n{patch}")

        diff_text = "\n".join(diff_parts)
        if len(diff_text) > MAX_DIFF_CHARS:
            logger.warning("Diff for %s truncated from %d to %d chars", repo, len(diff_text), MAX_DIFF_CHARS)
            diff_text = diff_text[:MAX_DIFF_CHARS] + "\n[TRUNCATED]"

        result["available"] = bool(diff_text)
        result["diff_text"] = diff_text or None

    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = fetch_diff("advisories/github-osv-2021-0001", "2.14.0", "2.15.0")
    print(r)
