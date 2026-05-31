#!/usr/bin/env bash
# Lightweight SIEM, deploy + test + tear down.
#
# Exercises the whole pipeline end to end:
#   batch-import a CRITICAL Security Hub finding
#     -> EventBridge rule matches (HIGH/CRITICAL, NEW, ACTIVE)
#       -> Lambda fires
#         -> posts to the Slack/Teams webhook   (check your channel)
#         -> archives the raw finding to S3      (asserted below)
#   then empties the bucket, deletes the stack, and resolves the test finding.
#
# Usage:
#   WEBHOOK_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123:secret:siem-webhook ./siem-test-commands.sh
# Optional env: AWS_PROFILE, REGION (default us-east-1), STACK (default lightweight-siem-test)
#
# Requires: aws CLI, sam CLI, jq.

set -euo pipefail
cd "$(dirname "$0")"

REGION="${REGION:-us-east-1}"
STACK="${STACK:-lightweight-siem-test}"
WEBHOOK_SECRET_ARN="${WEBHOOK_SECRET_ARN:-}"
PROFILE_ARG=""
[[ -n "${AWS_PROFILE:-}" ]] && PROFILE_ARG="--profile ${AWS_PROFILE}"

separator() { echo; echo "--- $1 ---"; echo; }
pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

command -v sam >/dev/null 2>&1 || { echo "ERROR: SAM CLI not found (or deploy with plain CloudFormation, see README)."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }
[[ -n "$WEBHOOK_SECRET_ARN" ]] || { echo "ERROR: set WEBHOOK_SECRET_ARN to your Secrets Manager webhook secret ARN."; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text $PROFILE_ARG)
echo "Account: ${ACCOUNT_ID}   Region: ${REGION}   Stack: ${STACK}"

# ─────────────────────────────────────────────────────────────
separator "STEP 1: Deploy the stack"
sam build
sam deploy \
  --stack-name "$STACK" \
  --region "$REGION" \
  --resolve-s3 \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides "WebhookSecretArn=${WEBHOOK_SECRET_ARN}" \
  $PROFILE_ARG

BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" $PROFILE_ARG \
  --query "Stacks[0].Outputs[?OutputKey=='ArchiveBucketName'].OutputValue" --output text)
echo "Archive bucket: ${BUCKET}"

# ─────────────────────────────────────────────────────────────
separator "STEP 2: Confirm Security Hub is enabled"
if ! aws securityhub describe-hub --region "$REGION" $PROFILE_ARG >/dev/null 2>&1; then
  echo "Security Hub is not enabled in ${REGION}. Enable it first:"
  echo "  aws securityhub enable-security-hub --enable-default-standards --region ${REGION}"
  fail "Security Hub not enabled"
fi
pass "Security Hub enabled"

# ─────────────────────────────────────────────────────────────
separator "STEP 3: Import a synthetic CRITICAL finding"
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
FINDING_ID="lightweight-siem-test/$(date -u +%s)"
PRODUCT_ARN="arn:aws:securityhub:${REGION}:${ACCOUNT_ID}:product/${ACCOUNT_ID}/default"

aws securityhub batch-import-findings --region "$REGION" $PROFILE_ARG --findings "$(cat <<JSON
[
  {
    "SchemaVersion": "2018-10-08",
    "Id": "${FINDING_ID}",
    "ProductArn": "${PRODUCT_ARN}",
    "GeneratorId": "lightweight-siem-test",
    "AwsAccountId": "${ACCOUNT_ID}",
    "Types": ["Unusual Behaviors/User"],
    "CreatedAt": "${NOW}",
    "UpdatedAt": "${NOW}",
    "Severity": {"Label": "CRITICAL"},
    "Title": "TEST: lightweight SIEM pipeline check",
    "Description": "Synthetic finding from siem-test-commands.sh to exercise the alert and archive pipeline. Safe to resolve.",
    "Resources": [{"Type": "Other", "Id": "test-resource", "Region": "${REGION}"}],
    "RecordState": "ACTIVE",
    "Workflow": {"Status": "NEW"}
  }
]
JSON
)" >/dev/null
pass "Imported finding ${FINDING_ID}"

# ─────────────────────────────────────────────────────────────
separator "STEP 4: Wait for the pipeline and assert the archive"
EXPECT_PREFIX="findings/${NOW:0:10}/${ACCOUNT_ID}/"
echo "Looking for an object under s3://${BUCKET}/${EXPECT_PREFIX} ..."
FOUND=""
for i in $(seq 1 12); do
  sleep 10
  if aws s3 ls "s3://${BUCKET}/${EXPECT_PREFIX}" --region "$REGION" $PROFILE_ARG 2>/dev/null | grep -q '\.json'; then
    FOUND=1; break
  fi
  echo "  ... not yet (attempt ${i}/12)"
done
if [[ -n "$FOUND" ]]; then
  pass "Finding archived to S3, pipeline works end to end"
  echo "Now check your Slack/Teams channel for the :rotating_light: CRITICAL alert."
else
  echo "No archived object after ~120s. Inspect the Lambda logs:"
  echo "  aws logs tail /aws/lambda/security-lightweight-siem-finding-router --since 10m --region ${REGION}"
  fail "Pipeline did not deliver"
fi

# ─────────────────────────────────────────────────────────────
separator "STEP 5: Cleanup"
echo "Emptying versioned bucket ${BUCKET} ..."
VERSIONS=$(aws s3api list-object-versions --bucket "$BUCKET" --region "$REGION" $PROFILE_ARG \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":null}')
if [[ "$(echo "$VERSIONS" | jq '.Objects | length // 0')" -gt 0 ]]; then
  aws s3api delete-objects --bucket "$BUCKET" --region "$REGION" $PROFILE_ARG --delete "$VERSIONS" >/dev/null
fi
MARKERS=$(aws s3api list-object-versions --bucket "$BUCKET" --region "$REGION" $PROFILE_ARG \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}' --output json 2>/dev/null || echo '{"Objects":null}')
if [[ "$(echo "$MARKERS" | jq '.Objects | length // 0')" -gt 0 ]]; then
  aws s3api delete-objects --bucket "$BUCKET" --region "$REGION" $PROFILE_ARG --delete "$MARKERS" >/dev/null
fi

echo "Deleting stack ${STACK} ..."
sam delete --stack-name "$STACK" --region "$REGION" --no-prompts $PROFILE_ARG

echo "Resolving the synthetic finding in Security Hub ..."
aws securityhub batch-update-findings --region "$REGION" $PROFILE_ARG \
  --finding-identifiers "[{\"Id\":\"${FINDING_ID}\",\"ProductArn\":\"${PRODUCT_ARN}\"}]" \
  --workflow Status=RESOLVED >/dev/null 2>&1 || true

separator "Done"
