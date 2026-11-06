# kev-log-pipeline

A small serverless pipeline on AWS that pulls CISA's public
[Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog every day, stores each snapshot in S3, and reports which CVEs were newly added.

Python, AWS Lambda, EventBridge, S3, CloudWatch, CloudFormation (SAM), CircleCI.

> **Background.** I built a similar log pipeline in a professional DevSecOps role
> (Snowflake and SnapLogic logs into S3, monitored in Datadog). This repo is a clean
> rewrite against a public data source. It contains no employer code or data.

## How it works

```
EventBridge (daily) --> Lambda (Python) --> S3 bucket
                            |                 raw/YYYY/MM/DD/kev.json          full snapshot
                            |                 new/YYYY/MM/DD/new_entries.jsonl newly added CVEs
                            |                 state/seen_cve_ids.json          IDs seen so far
                            v
                    CloudWatch Logs (one JSON line per new CVE)
                            |
                    CloudWatch Alarm on Lambda errors
```

Each run downloads the feed, saves the raw snapshot, compares CVE IDs with the saved state,
writes new entries to S3 as JSON Lines, and logs one structured line per new entry.
The first run only records a baseline so the existing catalog isn't reported as new.

## Repo layout

| Path | Purpose |
| --- | --- |
| `src/handler.py` | Lambda function |
| `template.yaml` | SAM/CloudFormation: bucket, function, schedule, IAM, alarm |
| `tests/` | Unit tests (no AWS account needed) |
| `.circleci/config.yml` | CI: runs tests and lints the template |

## Run the tests

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The tests use an in-memory fake of the S3 client, so they run offline.

## Deploy

Requires an AWS account, the AWS CLI configured, and the [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

```bash
sam build
sam deploy --guided
```

Trigger a run without waiting for the schedule:

```bash
aws lambda invoke --function-name <FunctionName from stack outputs> out.json && cat out.json
```

Run it twice. The first invoke records a baseline. After that, new entries show up
whenever CISA adds one.

Find newly added CVEs in CloudWatch Logs Insights:

```
fields @timestamp, @message
| filter @message like /new_kev_entry/
| parse @message '"cve": "*"' as cve
| parse @message '"vendor": "*"' as vendor
| sort @timestamp desc
```

## Design decisions

- **Idempotent keys.** Snapshots are keyed by UTC date, so a retry on the same day
  overwrites rather than duplicates.
- **State is written last.** If a run fails partway, the next run re-detects the same new
  entries instead of losing them (at-least-once delivery).
- **Bad downloads can't wipe state.** An empty or truncated feed raises an error before any
  S3 write.
- **Least-privilege IAM.** The function can read and write only its own bucket. It also
  needs `s3:ListBucket`: without it, S3 returns `AccessDenied` instead of `NoSuchKey` for a
  missing state file, which would break first-run detection.
- **Standard library HTTP client.** `urllib` means there's nothing to package; `boto3` is
  already in the Lambda runtime.
- **Structured logs.** One JSON object per line makes the logs queryable and easy to
  forward to Datadog or another monitoring tool.
- **Bucket hygiene.** Encryption at rest, public access fully blocked, and a lifecycle rule
  that expires raw snapshots and new-entry files after 90 days (configurable).

## Possible next steps

- Forward the logs to Datadog and alert on new entries with `ransomware` set to `Known`.
- Publish new entries to SNS or Slack.
- Add a Terraform version of `template.yaml`.
- Add a dashboard of CVEs added per month from the stored snapshots.

## Cost

One short Lambda invocation per day plus a few small S3 objects. This should cost very
little, but check current AWS pricing for your region.
