"""MasterIndex: idempotency control and curation status tracking."""

import copy
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from curator.storage import s3 as s3_store
from curator.storage import drive as drive_store

logger = logging.getLogger(__name__)

LOCAL_CACHE_PATH = "/tmp/vulnrank_master_index.json"

DECISION_SKIP = "skip"
DECISION_RETRY = "retry"
DECISION_PROCESS = "process"
DECISION_REPROCESS = "reprocess"
MAX_AUTO_RETRY = 3


class MasterIndex:
    """Thread-local in-memory copy of the master index, synced from/to S3."""

    def __init__(self):
        self._data: dict[str, Any] = {"entries": {}}

    # ------------------------------------------------------------------ load/save

    def load(self) -> None:
        self._data = s3_store.download_master_index()
        with open(LOCAL_CACHE_PATH, "w") as f:
            json.dump(self._data, f)
        logger.info("Master index loaded: %d entries", len(self._data["entries"]))

    def save(self) -> None:
        s3_store.upload_master_index(self._data)
        drive_store.upload_master_index(self._data)

    # ------------------------------------------------------------------ decisions

    def decide(self, cve_id: str, ecosystem: str, package: str,
               force: bool = False) -> str:
        key = _entry_key(cve_id, ecosystem, package)
        entry = self._data["entries"].get(key)

        if force:
            return DECISION_REPROCESS

        if entry is None:
            return DECISION_PROCESS

        status = entry.get("status")
        if status == "curated":
            return DECISION_SKIP
        if status == "failed":
            retries = entry.get("retry_count", 0)
            if retries >= MAX_AUTO_RETRY:
                return DECISION_SKIP
            return DECISION_RETRY
        return DECISION_PROCESS

    # ------------------------------------------------------------------ mutations

    def mark_curating(self, cve_id: str, ecosystem: str, package: str) -> None:
        key = _entry_key(cve_id, ecosystem, package)
        self._data["entries"][key] = {
            **self._data["entries"].get(key, {}),
            "cve_id": cve_id, "ecosystem": ecosystem, "package": package,
            "status": "curating",
        }

    def mark_curated(self, cve_id: str, ecosystem: str, package: str,
                     s3_key: str, model: str, prompt_version: str,
                     confidence: str, human_reviewed: bool = False) -> None:
        key = _entry_key(cve_id, ecosystem, package)
        self._data["entries"][key] = {
            "cve_id": cve_id, "ecosystem": ecosystem, "package": package,
            "status": "curated",
            "confidence": confidence,
            "curated_at": _now(),
            "model": model,
            "prompt_version": prompt_version,
            "human_reviewed": human_reviewed,
            "s3_key": s3_key,
            "retry_count": 0,
            "error": None,
        }

    def mark_failed(self, cve_id: str, ecosystem: str, package: str,
                    error: str) -> None:
        key = _entry_key(cve_id, ecosystem, package)
        existing = self._data["entries"].get(key, {})
        self._data["entries"][key] = {
            **existing,
            "cve_id": cve_id, "ecosystem": ecosystem, "package": package,
            "status": "failed",
            "error": error,
            "attempted_at": _now(),
            "retry_count": existing.get("retry_count", 0) + 1,
        }

    # ------------------------------------------------------------------ public status export

    def export_public_status(self) -> dict:
        """Return curation_status/index.json safe subset (no s3_key or review_notes)."""
        entries: dict[str, Any] = {}
        for k, v in self._data["entries"].items():
            entries[k] = {
                "ecosystem": v.get("ecosystem"),
                "package": v.get("package"),
                "status": v.get("status"),
                "confidence": v.get("confidence", "low"),
                "curated_at": v.get("curated_at"),
                "model": v.get("model"),
                "prompt_version": v.get("prompt_version"),
                "human_reviewed": v.get("human_reviewed", False),
                "error": v.get("error") if v.get("status") == "failed" else None,
                "attempted_at": v.get("attempted_at"),
                "retry_count": v.get("retry_count", 0),
            }
        return {
            "WARNING": (
                "AI-generated content. Accuracy not guaranteed. "
                "See https://github.com/plexicus/vulnrank/blob/main/ACCURACY.md"
            ),
            "generated_at": _now(),
            "schema_version": "1.0",
            "entries": entries,
        }

    def __len__(self) -> int:
        return len(self._data["entries"])


def _entry_key(cve_id: str, ecosystem: str, package: str) -> str:
    return f"{ecosystem}/{cve_id}/{package}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
