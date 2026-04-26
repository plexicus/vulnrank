"""Two-layer validation: JSON schema (Layer A) + semantic guardrails (Layer B)."""

import json
import logging
import os
from typing import Any
import jsonschema

logger = logging.getLogger(__name__)

SCHEMA_PATH = "schemas/knowledge_pack.schema.json"
_schema_cache: dict | None = None


def _schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        with open(SCHEMA_PATH) as f:
            _schema_cache = json.load(f)
    return _schema_cache


# ──────────────────────────────────────────────────────────────── Layer A


def validate_schema(pack: dict) -> list[str]:
    """Return list of schema validation errors (empty = pass)."""
    errors = []
    try:
        jsonschema.validate(pack, _schema())
    except jsonschema.ValidationError as e:
        errors.append(f"schema: {e.message} at {list(e.absolute_path)}")
    except jsonschema.SchemaError as e:
        errors.append(f"schema_error: {e.message}")
    return errors


# ──────────────────────────────────────────────────────────────── Layer B


def validate_semantics(pack: dict, prefill: dict, retry_count: int,
                        correction_used: bool) -> tuple[dict, list[str]]:
    """
    Apply 7 semantic guardrail rules. Mutates pack in place.
    Returns (mutated_pack, list_of_applied_rules).
    """
    applied: list[str] = []
    l3 = pack.get("layer3", {})
    l7 = pack.get("layer7", {})
    symbols = l3.get("vulnerable_symbols", [])
    diff_available = l7.get("source_diff_available", False)
    confidence = l7.get("confidence_overall", "low")

    # Rule 1: no diff + high/medium confidence → force low
    if not diff_available and confidence in ("high", "medium"):
        l7["confidence_overall"] = "low"
        applied.append("R1: no_diff+high_confidence→low")

    # Rule 2: symbol without diff_evidence → force symbol to low confidence
    for sym in symbols:
        if sym.get("confidence") in ("high", "medium") and not sym.get("diff_evidence"):
            sym["confidence"] = "low"
            applied.append(f"R2: symbol {sym.get('name')} evidence missing→low")

    # After Rule 2, if ALL symbols are low and overall is high → cap to medium
    if symbols and all(s.get("confidence") == "low" for s in symbols):
        if l7.get("confidence_overall") == "high":
            l7["confidence_overall"] = "medium"
            applied.append("R2b: all_symbols_low→cap_pack_to_medium")

    # Rule 3: symbols claimed but no diff available → cap overall to low, flag
    if symbols and not diff_available:
        l7["confidence_overall"] = "low"
        l7["review_notes"] = (l7.get("review_notes") or "") + " [FLAGGED: symbols claimed without diff]"
        applied.append("R3: symbols_no_diff→low+flag")

    # Rule 4: high confidence with empty symbols → hard fail
    if l7.get("confidence_overall") == "high" and not symbols:
        raise ValueError("R4: high confidence with zero vulnerable symbols — hard fail")

    # Rule 5: correction prompt used → cap to medium
    if correction_used and l7.get("confidence_overall") == "high":
        l7["confidence_overall"] = "medium"
        applied.append("R5: correction_used→cap_to_medium")

    # Rule 6: retry_count > 0 → cap to medium
    if retry_count > 0 and l7.get("confidence_overall") == "high":
        l7["confidence_overall"] = "medium"
        applied.append(f"R6: retry_count={retry_count}→cap_to_medium")

    # Rule 7: deterministic field mismatch → hard fail
    l1 = pack.get("layer1", {})
    l4 = pack.get("layer4", {})
    mismatches = []
    if l1.get("cve_id") != prefill.get("cve_id"):
        mismatches.append("cve_id")
    if l1.get("affected_ecosystem") != prefill.get("ecosystem"):
        mismatches.append("ecosystem")
    if l4.get("attack_vector") != prefill.get("attack_vector"):
        mismatches.append("attack_vector")
    if mismatches:
        raise ValueError(f"R7: deterministic field mismatch {mismatches} — hard fail")

    # Rule 8: typical_fix_effort without evidence → reset to unknown
    tfe = l3.get("typical_fix_effort")
    if tfe and tfe.get("level") not in ("unknown", None) and not tfe.get("diff_evidence"):
        tfe["level"] = "unknown"
        tfe["description"] = None
        applied.append("R8: typical_fix_effort_no_evidence→unknown")

    # Structural confidence cross-check
    structural = _structural_score(pack)
    if _confidence_rank(l7.get("confidence_overall", "low")) > _confidence_rank(structural):
        l7["confidence_overall"] = structural
        applied.append(f"R_structural: LLM confidence capped to structural ceiling {structural}")

    if applied:
        logger.info("Semantic guardrails applied: %s", applied)

    return pack, applied


def _structural_score(pack: dict) -> str:
    score = 0.0
    l3 = pack.get("layer3", {})
    l7 = pack.get("layer7", {})
    if l7.get("source_diff_available"):
        score += 0.4
    symbols = l3.get("vulnerable_symbols", [])
    if symbols:
        score += 0.3
    if symbols and all(s.get("diff_evidence") for s in symbols):
        score += 0.2
    if not l7.get("review_notes", ""):
        score += 0.1
    if score >= 0.9:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _confidence_rank(c: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(c, 0)


# ──────────────────────────────────────────────────────────────── Full pipeline


def validate_pack(pack: dict, prefill: dict, retry_count: int = 0,
                  correction_used: bool = False) -> dict:
    """
    Run both validation layers. Returns validated (possibly mutated) pack.
    Raises ValueError on hard fail.
    """
    schema_errors = validate_schema(pack)
    if schema_errors:
        raise ValueError(f"Schema validation failed: {schema_errors}")

    pack, rules = validate_semantics(pack, prefill, retry_count, correction_used)
    logger.debug("Validation complete. Rules applied: %s", rules)
    return pack
