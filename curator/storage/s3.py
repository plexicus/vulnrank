"""S3 storage client for Hetzner object storage."""

import json
import logging
import os
import time
from typing import Any
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 2


def _client():
    return boto3.client(
        "s3",
        endpoint_url=f"https://{os.environ['HETZNER_S3_ENDPOINT']}",
        aws_access_key_id=os.environ["HETZNER_S3_KEY"],
        aws_secret_access_key=os.environ["HETZNER_S3_SECRET"],
        region_name="eu-central-1",
    )


def _bucket() -> str:
    return os.environ["HETZNER_S3_BUCKET"]


def pack_s3_key(ecosystem: str, cve_id: str, package: str) -> str:
    """
    Build the S3 key for a knowledge pack.
    Maven: knowledge_packs/maven/{CVE-ID}/{groupId}/{artifactId}.json
    Others: knowledge_packs/{ecosystem}/{CVE-ID}/{package-slug}.json
    """
    slug = _package_slug(ecosystem, package)
    return f"knowledge_packs/{ecosystem}/{cve_id}/{slug}.json"


def _package_slug(ecosystem: str, package: str) -> str:
    """Convert package name to a safe S3 path segment."""
    if ecosystem == "maven" and ":" in package:
        # org.apache.logging.log4j:log4j-core → org.apache.logging.log4j/log4j-core
        return package.replace(":", "/")
    return package.replace("/", "__")


def upload_pack(pack: dict[str, Any], ecosystem: str, cve_id: str, package: str) -> str:
    """Upload knowledge pack to S3. Returns the S3 key on success."""
    key = pack_s3_key(ecosystem, cve_id, package)
    body = json.dumps(pack, indent=2).encode()

    for attempt in range(MAX_RETRIES):
        try:
            s3 = _client()
            s3.put_object(
                Bucket=_bucket(),
                Key=key,
                Body=body,
                ContentType="application/json",
            )
            # Verify upload
            s3.head_object(Bucket=_bucket(), Key=key)
            logger.info("Uploaded %s to s3://%s/%s", cve_id, _bucket(), key)
            return key
        except ClientError as e:
            logger.warning("S3 upload attempt %d failed for %s: %s", attempt + 1, key, e)
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))

    raise RuntimeError(f"S3 upload failed after {MAX_RETRIES} attempts: {key}")


def download_pack(ecosystem: str, cve_id: str, package: str) -> dict[str, Any] | None:
    """Download a knowledge pack from S3. Returns None if not found."""
    key = pack_s3_key(ecosystem, cve_id, package)
    try:
        s3 = _client()
        resp = s3.get_object(Bucket=_bucket(), Key=key)
        return json.loads(resp["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise


def upload_master_index(index: dict, key: str = "index/master.json") -> None:
    body = json.dumps(index, indent=2).encode()
    for attempt in range(MAX_RETRIES):
        try:
            _client().put_object(
                Bucket=_bucket(), Key=key, Body=body, ContentType="application/json"
            )
            logger.info("Uploaded master index to s3://%s/%s", _bucket(), key)
            return
        except ClientError as e:
            logger.warning("Master index upload attempt %d failed: %s", attempt + 1, e)
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    raise RuntimeError("Failed to upload master index to S3")


def download_master_index(key: str = "index/master.json") -> dict:
    """Download master index; return empty structure if not found."""
    try:
        s3 = _client()
        resp = s3.get_object(Bucket=_bucket(), Key=key)
        return json.loads(resp["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            logger.info("Master index not found in S3, starting fresh")
            return {"entries": {}}
        raise


def upload_log(log_lines: list[str], date_str: str, error: bool = False) -> None:
    prefix = "logs/errors" if error else "logs"
    suffix = "-errors" if error else ""
    key = f"{prefix}/{date_str}{suffix}.jsonl"
    body = "\n".join(log_lines).encode()
    try:
        _client().put_object(Bucket=_bucket(), Key=key, Body=body, ContentType="application/x-ndjson")
    except ClientError as e:
        logger.warning("Failed to upload log %s: %s", key, e)
