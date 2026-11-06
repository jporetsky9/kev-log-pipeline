"""Daily ingest of CISA's Known Exploited Vulnerabilities (KEV) catalog into S3.

Triggered by an EventBridge schedule. Each run:
  1. downloads the public KEV JSON feed (with retries),
  2. stores the raw snapshot in S3 under a date-partitioned key,
  3. compares CVE IDs against the set seen on previous runs,
  4. writes any newly added entries to S3 as JSON Lines and logs one
     structured line per new entry (easy to query in CloudWatch Logs Insights,
     or to forward to a monitoring tool such as Datadog).

The very first run only records a baseline, so ~1,500 existing entries are
not reported as "new".
"""
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
STATE_KEY = "state/seen_cve_ids.json"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_s3_client = None


def get_s3():
    """Create the S3 client once per container so warm invocations reuse it.

    boto3 is imported lazily: the Lambda runtime provides it, and unit tests
    can run without it installed.
    """
    global _s3_client
    if _s3_client is None:
        import boto3

        _s3_client = boto3.client("s3")
    return _s3_client


def log(event_name, **fields):
    """Emit one JSON object per line so logs can be filtered by field."""
    logger.info(json.dumps({"event": event_name, **fields}))


def fetch_feed(url, retries=3, timeout=15):
    """Download and parse the feed, retrying transient failures with backoff."""
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "kev-log-pipeline/1.0"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            last_error = err
            log("fetch_failed", attempt=attempt, error=str(err))
            if attempt < retries:
                time.sleep(2**attempt)
    raise RuntimeError(f"feed download failed after {retries} attempts") from last_error


def load_seen_ids(s3, bucket):
    """Return the set of CVE IDs from earlier runs, or None on the first run."""
    try:
        obj = s3.get_object(Bucket=bucket, Key=STATE_KEY)
    except s3.exceptions.NoSuchKey:
        return None
    return set(json.loads(obj["Body"].read()))


def lambda_handler(event, context):
    bucket = os.environ["BUCKET_NAME"]
    feed_url = os.environ.get("FEED_URL", DEFAULT_FEED_URL)
    day_prefix = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    s3 = get_s3()

    feed = fetch_feed(feed_url)
    vulnerabilities = feed.get("vulnerabilities", [])
    if not vulnerabilities:
        # Never overwrite saved state because of a bad or truncated download.
        raise ValueError("feed contained no vulnerabilities; aborting before any writes")

    s3.put_object(
        Bucket=bucket,
        Key=f"raw/{day_prefix}/kev.json",
        Body=json.dumps(feed).encode("utf-8"),
        ContentType="application/json",
    )

    current_ids = {v["cveID"] for v in vulnerabilities}
    seen_ids = load_seen_ids(s3, bucket)
    baseline_run = seen_ids is None
    new_entries = [] if baseline_run else [
        v for v in vulnerabilities if v["cveID"] not in seen_ids
    ]

    if new_entries:
        body = "".join(json.dumps(entry) + "\n" for entry in new_entries)
        s3.put_object(
            Bucket=bucket,
            Key=f"new/{day_prefix}/new_entries.jsonl",
            Body=body.encode("utf-8"),
            ContentType="application/x-ndjson",
        )
        for entry in new_entries:
            log(
                "new_kev_entry",
                cve=entry["cveID"],
                vendor=entry.get("vendorProject"),
                product=entry.get("product"),
                ransomware=entry.get("knownRansomwareCampaignUse"),
                due_date=entry.get("dueDate"),
            )

    # State is written last. If anything above fails, the next run re-detects
    # the same new entries (at-least-once), instead of silently dropping them.
    s3.put_object(
        Bucket=bucket,
        Key=STATE_KEY,
        Body=json.dumps(sorted(current_ids)).encode("utf-8"),
        ContentType="application/json",
    )

    summary = {
        "total_entries": len(current_ids),
        "new_entries": len(new_entries),
        "baseline_run": baseline_run,
    }
    log("run_complete", **summary)
    return summary
