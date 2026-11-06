# kev-log-pipeline

A small serverless pipeline on AWS that pulls CISA's public
[Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog every day, stores each snapshot in S3, detects newly added CVEs, and emails an alert
when CISA adds one.

Python, AWS Lambda, EventBridge, S3, SNS, CloudWatch, CloudFormation (SAM), CircleCI.

> **Background.** I built a similar log pipeline in a professional DevSecOps role
> (Snowflake and SnapLogic logs into S3, monitored in Datadog with OpsGenie alerts). This
> repo is a clean rewrite against a public data source, with SNS standing in for
> Datadog and OpsGenie. It contains no employer code or data.

## How it works

```
EventBridge (daily) --> Lambda (Python) --> S3 bucket
                          |   |               raw/YYYY/MM/DD/kev.json                  full snapshot
                          |   |               new/YYYY/MM/DD/new_entries_HHMMSS.jsonl  newly added CVEs
                          |   |               state/seen_cve_ids.json                  IDs seen so far
                          |   v
                          |  CloudWatch Logs (one JSON line per new CVE)
                          v
                     SNS topic  <--  CloudWatch Alarm on Lambda errors
                          |
                     email alert
```

Each run downloads the feed, checks it against the saved state, saves the raw snapshot,
writes new entries to S3 as JSON Lines, logs one structured line per new entry, and
publishes one alert listing them (flagging any CISA marks as used in ransomware).
The first run only records a baseline so the existing catalog isn't reported as new.

Example alert:

```
Subject: 2 new CISA KEV entries (1 used in ransomware)

CISA added 2 entries to the KEV catalog:

CVE-2026-0002  Globex Gateway  (due 2026-12-01)  [ransomware]
CVE-2026-0003  Acme Widget  (due 2026-12-01)
```

## Repo layout

| Path | Purpose |
| --- | --- |
| `src/handler.py` | Lambda function |
| `template.yaml` | SAM/CloudFormation: bucket, function, schedule, IAM, SNS topic, alarm |
| `tests/` | Unit tests (no AWS account needed) |
| `.circleci/config.yml` | CI: runs tests and lints the template |

## Run the tests

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The tests use in-memory fakes of the S3 and SNS clients, so they run offline.

## Deploy

Requires an AWS account, the AWS CLI configured, and the [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

```bash
sam build
sam deploy --guided
```

When prompted for `AlertEmail`, enter your address (or leave it blank to skip email).
AWS then sends a confirmation email; click the link in it or no alerts arrive.

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

- **Keys that don't collide.** Snapshots are keyed by UTC date, so a retry on the same day
  overwrites rather than duplicates. New-entry files also include the time, so a second
  run on the same day can't overwrite the first run's CVEs.
- **State is written last.** If a run fails partway, the next run re-detects the same new
  entries instead of losing them (at-least-once delivery).
- **Bad downloads can't wipe state.** An empty feed, or one with under 90% of the entries
  seen before, raises an error before any S3 write. CISA rarely removes entries, so a big
  drop means a partial download. Otherwise the next run would report hundreds of
  existing CVEs as new.
- **One alert per run, not per CVE.** A busy day sends one email. The message lists up to
  50 entries and stays far below SNS's size limit.
- **Errors reach a person.** The CloudWatch alarm on Lambda errors notifies the same SNS
  topic, so a broken pipeline isn't silent. The topic doesn't use the AWS-managed SNS
  KMS key, because CloudWatch alarms can't publish to a topic encrypted with it.
- **Least-privilege IAM.** The function can read and write only its own bucket and publish
  only to its own topic. It also
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
- Send alerts to Slack or OpsGenie by subscribing them to the SNS topic.
- Deploy from CircleCI on merges to `main` using OIDC credentials instead of stored keys.
- Add a Terraform version of `template.yaml`.
- Add a dashboard of CVEs added per month from the stored snapshots.

## Cost

One short Lambda invocation per day, a few small S3 objects, and an occasional email. This should cost very
little, but check current AWS pricing for your region.
