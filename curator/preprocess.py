"""Preprocesses raw context into a compact, token-efficient prompt payload."""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

MAX_DIFF_CHARS = 24_000
MAX_ADVISORY_CHARS = 8_000


def _strip_boilerplate(text: str) -> str:
    """Remove license headers, copyright notices, and blank-line runs."""
    lines = text.splitlines()
    cleaned = []
    skip_next = 0
    for line in lines:
        if skip_next > 0:
            skip_next -= 1
            continue
        stripped = line.strip()
        if any(kw in stripped.lower() for kw in ["copyright", "license", "spdx", "apache", "mit license"]):
            continue
        if not stripped and cleaned and not cleaned[-1]:
            continue  # collapse double blank lines
        cleaned.append(line)
    return "\n".join(cleaned)


def _extract_relevant_hunks(diff_text: str, max_chars: int = MAX_DIFF_CHARS) -> str:
    """Keep only diff hunks that touch interesting patterns (security-relevant)."""
    security_patterns = re.compile(
        r"(?i)(exec|eval|deserializ|pickle|yaml\.load|input|auth|token|secret|password|"
        r"hash|encrypt|decrypt|sql|query|escape|sanitize|validate|verify|csrf|xss|injection|"
        r"overflow|format|printf|sprintf|strcpy|strcat|memcpy|memmove|alloc|free|null)",
        re.IGNORECASE,
    )

    if len(diff_text) <= max_chars:
        return diff_text

    # Split into hunks and score them
    hunks = re.split(r"(^@@.+?@@.*$)", diff_text, flags=re.MULTILINE)
    scored = []
    for i in range(0, len(hunks) - 1, 2):
        header = hunks[i] if i < len(hunks) else ""
        body = hunks[i + 1] if (i + 1) < len(hunks) else ""
        score = len(security_patterns.findall(body))
        scored.append((score, header + body))

    scored.sort(key=lambda x: x[0], reverse=True)

    result_parts = []
    total = 0
    for score, hunk in scored:
        if total + len(hunk) > max_chars:
            break
        result_parts.append(hunk)
        total += len(hunk)

    combined = "\n".join(result_parts)
    if len(combined) < len(diff_text):
        logger.info("Diff filtered from %d to %d chars (%.0f%% reduction)",
                    len(diff_text), len(combined),
                    100 * (1 - len(combined) / max(len(diff_text), 1)))
    return combined


def build_payload(ctx: dict[str, Any], cve_id: str, ecosystem: str,
                  package: str, vuln_version: str | None,
                  fix_version: str | None) -> dict[str, Any]:
    """
    Returns a compact payload for the LLM prompt chain containing:
      - deterministic pre-fill fields (anti-hallucination Rule 1)
      - preprocessed diff
      - advisory text
    """
    advisory = ctx.get("advisory") or {}

    # Extract CVSS fields deterministically
    attack_vector = "UNKNOWN"
    attack_complexity = "UNKNOWN"
    for metric in advisory.get("severity", []):
        v = metric.get("score", "")
        av_match = re.search(r"AV:([NALP])", v)
        ac_match = re.search(r"AC:([LH])", v)
        if av_match:
            av_map = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
            attack_vector = av_map.get(av_match.group(1), "UNKNOWN")
        if ac_match:
            attack_complexity = "LOW" if ac_match.group(1) == "L" else "HIGH"

    # Build advisory summary text
    adv_text = ""
    if advisory:
        adv_text = f"ID: {advisory.get('id', cve_id)}\n"
        adv_text += f"Summary: {advisory.get('summary', '')}\n"
        adv_text += f"Details: {advisory.get('details', '')[:MAX_ADVISORY_CHARS]}\n"
        refs = [r.get("url", "") for r in advisory.get("references", [])[:5]]
        adv_text += f"References: {', '.join(refs)}\n"

    # Preprocess diff
    raw_diff = ctx.get("diff_text") or ""
    clean_diff = _strip_boilerplate(raw_diff)
    filtered_diff = _extract_relevant_hunks(clean_diff)

    # Pre-fill deterministic fields (Rule 1 — filled before any LLM call)
    prefill = {
        "cve_id": cve_id,
        "ecosystem": ecosystem,
        "package": package,
        "vuln_version": vuln_version,
        "fix_version": fix_version,
        "fix_commit_sha": ctx.get("fix_commit_sha"),
        "vuln_tag": ctx.get("vuln_tag"),
        "fix_tag": ctx.get("fix_tag"),
        "attack_vector": attack_vector,
        "attack_complexity": attack_complexity,
        "diff_available": ctx.get("diff_available", False),
    }

    return {
        "prefill": prefill,
        "advisory_text": adv_text,
        "diff_text": filtered_diff,
        "diff_available": ctx.get("diff_available", False),
        "diff_char_count": len(filtered_diff),
    }
