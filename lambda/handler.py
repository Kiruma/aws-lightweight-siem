"""Lightweight SIEM, finding processor.

Triggered by EventBridge on Security Hub "Security Hub Findings - Imported"
events (filtered to new, active, HIGH/CRITICAL findings). For each finding it:

  1. archives the raw ASFF record to S3 (searchable later with Athena), and
  2. posts a human-readable alert to a Slack/Teams incoming webhook.

The webhook URL is read once per container from Secrets Manager, never from
source control. boto3 ships in the Lambda runtime, and urllib is standard
library, so this function has no third-party dependencies and deploys as a
single file.
"""

import json
import logging
import os
import urllib.error
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
secrets = boto3.client("secretsmanager")

ARCHIVE_BUCKET = os.environ["ARCHIVE_BUCKET"]
WEBHOOK_SECRET_ARN = os.environ["WEBHOOK_SECRET_ARN"]

# Cache the webhook URL across invocations in the same container.
_webhook_url = None


def _get_webhook_url():
    global _webhook_url
    if _webhook_url is None:
        resp = secrets.get_secret_value(SecretId=WEBHOOK_SECRET_ARN)
        _webhook_url = resp["SecretString"].strip()
    return _webhook_url


def handler(event, _context):
    findings = event.get("detail", {}).get("findings", [])
    logger.info("Received %d finding(s)", len(findings))

    processed = 0
    for finding in findings:
        # One bad finding should never drop the rest of the batch.
        try:
            archive_finding(finding)
            notify(finding)
            processed += 1
        except Exception:
            logger.exception("Failed to process finding %s", finding.get("Id"))

    return {"received": len(findings), "processed": processed}


def archive_finding(finding):
    """Store the raw ASFF record in S3, partitioned by date and account."""
    finding_id = finding["Id"].rsplit("/", 1)[-1].replace(":", "_")
    created = (finding.get("CreatedAt") or "")[:10] or "unknown-date"
    account = finding.get("AwsAccountId", "unknown-account")
    key = f"findings/{created}/{account}/{finding_id}.json"

    s3.put_object(
        Bucket=ARCHIVE_BUCKET,
        Key=key,
        Body=json.dumps(finding).encode("utf-8"),
        ContentType="application/json",
    )
    logger.info("Archived finding to s3://%s/%s", ARCHIVE_BUCKET, key)


def notify(finding):
    """Post a concise, human-readable alert to the Slack/Teams webhook."""
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    title = finding.get("Title", "Untitled finding")
    account = finding.get("AwsAccountId", "unknown")
    region = finding.get("Region", "unknown")
    types = ", ".join(finding.get("Types") or ["n/a"])
    resources = ", ".join(r.get("Id", "?") for r in finding.get("Resources", [])) or "n/a"

    text = (
        f":rotating_light: *{severity}*  {title}\n"
        f"*account* `{account}`   *region* `{region}`\n"
        f"*type* {types}\n"
        f"*resource* `{resources}`"
    )

    payload = json.dumps({"text": text}).encode("utf-8")
    request = urllib.request.Request(
        _get_webhook_url(),
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            resp.read()
    except urllib.error.URLError:
        logger.exception("Failed to post alert to webhook")
        raise
