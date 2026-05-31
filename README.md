# aws-lightweight-siem

A lightweight SIEM on AWS, built from services you may already run. It routes
HIGH and CRITICAL **AWS Security Hub** findings to a **Slack/Teams** webhook in
real time, and archives every finding to **S3** so you can search the history
later with **Athena**. No third-party SIEM, no license.

Companion code for the *Least Privilege* article
**"A Lightweight SIEM on AWS Without Buying Anything."**

## Architecture

```
GuardDuty / Inspector / Config / Access Analyzer
      └─► Security Hub (normalizes to ASFF)
            └─► EventBridge (matches HIGH/CRITICAL, NEW, ACTIVE)
                  └─► Lambda
                        ├─► Slack/Teams webhook   (real-time alert)
                        └─► S3 archive ─► Athena   (searchable history)
```

## What is here

| File | Purpose |
|------|---------|
| `template.yaml` | SAM/CloudFormation: S3 archive bucket, Lambda, least-privilege role, EventBridge rule |
| `lambda/handler.py` | Parses the ASFF finding, posts to the webhook, archives the raw JSON to S3 |
| `siem-test-commands.sh` | Deploys, fires a synthetic finding through the whole pipeline, asserts the archive, tears down |

## Prerequisites

1. **GuardDuty and Security Hub enabled** in the target region:
   ```bash
   aws guardduty create-detector --enable --region us-east-1
   aws securityhub enable-security-hub --enable-default-standards --region us-east-1
   ```
2. **A Slack/Teams incoming webhook URL stored in Secrets Manager** (never in code):
   ```bash
   aws secretsmanager create-secret \
     --name lightweight-siem/webhook \
     --secret-string "https://hooks.slack.com/services/XXX/YYY/ZZZ" \
     --region us-east-1
   ```
   Note the returned ARN. You pass it to the stack as `WebhookSecretArn`.
3. **SAM CLI** for the one-command path, or just the AWS CLI for the plain
   CloudFormation path below. `jq` is needed for the test script.

## Deploy

With SAM:
```bash
sam build
sam deploy --guided --parameter-overrides WebhookSecretArn=<your-secret-arn>
```

Or plain CloudFormation, no SAM CLI:
```bash
aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket <an-existing-artifact-bucket> \
  --output-template-file packaged.yaml
aws cloudformation deploy \
  --template-file packaged.yaml \
  --stack-name lightweight-siem \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides WebhookSecretArn=<your-secret-arn>
```

## Test the whole pipeline

```bash
WEBHOOK_SECRET_ARN=<your-secret-arn> ./siem-test-commands.sh
```
It deploys a throwaway stack, imports a synthetic CRITICAL finding, waits for the
Lambda to archive it to S3 (asserted), tells you to check your chat channel, then
tears everything down.

## Tune what gets routed

The severity filter lives in the EventBridge pattern in `template.yaml`. Start
narrow. To widen it later, add `MEDIUM`:
```yaml
Severity:
  Label:
    - CRITICAL
    - HIGH
    - MEDIUM
```
Widening is a one-line change. Earning back a muted channel is not.

## Search the archive with Athena

Define a table over `s3://<archive-bucket>/findings/` using a JSON SerDe, then
query your history:
```sql
SELECT severity.label, title, awsaccountid, createdat
FROM securityhub_findings
WHERE severity.label IN ('HIGH', 'CRITICAL')
  AND createdat > '2026-01-01'
ORDER BY createdat DESC;
```

## Cost

No license and no new product, but not free. Security Hub bills per finding and
per check, GuardDuty per analyzed event and GB, Lambda and EventBridge are
effectively free at this volume, S3 and Athena are pennies. Tens of USD per month
at small to mid scale.

## Teardown

The test script cleans up after itself. For a manual deploy, empty the versioned
bucket first, then:
```bash
sam delete --stack-name lightweight-siem
```

## Security notes

- **Least privilege.** The Lambda role can only `s3:PutObject` under `findings/`
  in its own bucket, and read the one webhook secret. Nothing else.
- **No secrets in source.** The webhook URL lives in Secrets Manager.
- **The bucket** blocks public access, disables ACLs (`BucketOwnerEnforced`),
  enforces TLS, encrypts at rest (SSE-S3), and versions objects.

### Deliberate tradeoffs (a scanner will flag these)

To stay lightweight, the template leaves three production controls off on purpose.
Add them when the data justifies it:

- **Object Lock (WORM)** makes the archive tamper-proof, which is the right call
  for forensic evidence. It is off here because a retention lock would stop the
  test script from tearing the bucket down. Turn it on for a real deployment.
- **Server access logging** needs a second bucket. Worth it in production, skipped
  here to keep the stack to one bucket.
- **Cross-region replication** is durability and DR. Overkill for a demo. Add it
  if this archive becomes your system of record.

TLS-only and no-public-access are enforced (bucket policy + public access block +
`BucketOwnerEnforced`), even if a generic scanner reports them against the bucket
resource in isolation.
