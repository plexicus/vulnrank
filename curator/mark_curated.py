"""Orchestrates the full curation pipeline for one CVE-package pair."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from curator.fetch_context import fetch as fetch_context
from curator.preprocess import build_payload
from curator.generate import run_chain, assemble_pack, PROMPT_VERSION, MODEL
from curator.validate import validate_pack
from curator.storage.s3 import upload_pack as s3_upload
from curator.storage.drive import upload_pack as drive_upload
from curator.storage.index import MasterIndex, DECISION_SKIP, DECISION_PROCESS, DECISION_RETRY, DECISION_REPROCESS

logger = logging.getLogger(__name__)


def curate_one(
    cve_id: str,
    ecosystem: str,
    package: str,
    vuln_version: str | None,
    fix_version: str | None,
    github_repo: str | None,
    master_index: MasterIndex,
    force: bool = False,
) -> dict[str, Any]:
    """
    Curate a single CVE-package pair.
    Returns result dict with keys: status, s3_key, confidence, error.
    """
    result: dict[str, Any] = {
        "cve_id": cve_id, "ecosystem": ecosystem, "package": package,
        "status": "failed", "s3_key": None, "confidence": "low", "error": None,
    }

    decision = master_index.decide(cve_id, ecosystem, package, force=force)
    if decision == DECISION_SKIP:
        logger.info("SKIP %s/%s/%s (already curated or max retries exceeded)", ecosystem, package, cve_id)
        result["status"] = "skipped"
        return result

    logger.info("START curation: %s/%s/%s (decision=%s)", ecosystem, package, cve_id, decision)
    master_index.mark_curating(cve_id, ecosystem, package)

    try:
        # 1. Fetch context
        ctx = fetch_context(cve_id, ecosystem, package, vuln_version, fix_version, github_repo)

        # 2. Preprocess
        payload = build_payload(ctx, cve_id, ecosystem, package, vuln_version, fix_version)

        # 3. LLM generation
        llm_output, retry_count = run_chain(payload)

        # 4. Assemble pack
        pack = assemble_pack(payload, llm_output, retry_count)

        # 5. Validate
        pack = validate_pack(
            pack,
            payload["prefill"],
            retry_count=retry_count,
            correction_used=llm_output.get("correction_used", False),
        )

        confidence = pack["layer7"]["confidence_overall"]

        # 6. Upload to S3 (required)
        s3_key = s3_upload(pack, ecosystem, cve_id, package)

        # 7. Upload to Drive (non-fatal)
        drive_upload(pack, ecosystem, cve_id, package)

        # 8. Update master index
        master_index.mark_curated(
            cve_id, ecosystem, package, s3_key,
            MODEL, PROMPT_VERSION, confidence,
        )

        result.update({"status": "curated", "s3_key": s3_key, "confidence": confidence})
        logger.info("DONE %s/%s/%s confidence=%s s3=%s", ecosystem, package, cve_id, confidence, s3_key)

    except ValueError as e:
        error_msg = str(e)
        logger.error("HARD FAIL %s/%s/%s: %s", ecosystem, package, cve_id, error_msg)
        master_index.mark_failed(cve_id, ecosystem, package, error_msg)
        result["error"] = error_msg

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.error("FAIL %s/%s/%s: %s", ecosystem, package, cve_id, error_msg, exc_info=True)
        master_index.mark_failed(cve_id, ecosystem, package, error_msg)
        result["error"] = error_msg

    return result


def save_public_status(master_index: MasterIndex,
                        path: str = "data/curation_status/index.json") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    status = master_index.export_public_status()
    with open(path, "w") as f:
        json.dump(status, f, indent=2)
    logger.info("Public curation status saved to %s", path)
