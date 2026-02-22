#!/usr/bin/env bash
set -euo pipefail

# Cleanup script for observability/security stack resources.
#
# Usage:
#   export AWS_REGION=us-east-1
#   export MONITORING_INSTANCE_ID=i-xxxxxxxx
#   export CLOUDTRAIL_NAME=prod-org-trail
#   export CLOUDTRAIL_BUCKET=my-cloudtrail-logs-bucket
#   export GUARDDUTY_DETECTOR_ID=<detector-id>
#   export LOG_GROUP_PREFIX=/aws/ec2/prod
#   export CONFIRM=true
#   ./scripts/cleanup_observability_security.sh

: "${AWS_REGION:=us-east-1}"
: "${LOG_GROUP_PREFIX:=/aws/ec2/prod}"

if [[ "${CONFIRM:-false}" != "true" ]]; then
  echo "Set CONFIRM=true to execute destructive cleanup."
  exit 1
fi

if [[ -n "${MONITORING_INSTANCE_ID:-}" ]]; then
  aws ec2 terminate-instances --instance-ids "${MONITORING_INSTANCE_ID}" --region "${AWS_REGION}" >/dev/null
  echo "Requested termination for monitoring instance: ${MONITORING_INSTANCE_ID}"
fi

if [[ -n "${GUARDDUTY_DETECTOR_ID:-}" ]]; then
  aws guardduty update-detector --detector-id "${GUARDDUTY_DETECTOR_ID}" --no-enable --region "${AWS_REGION}" >/dev/null
  echo "Disabled GuardDuty detector: ${GUARDDUTY_DETECTOR_ID}"
fi

if [[ -n "${CLOUDTRAIL_NAME:-}" ]]; then
  aws cloudtrail stop-logging --name "${CLOUDTRAIL_NAME}" --region "${AWS_REGION}" >/dev/null || true
  aws cloudtrail delete-trail --name "${CLOUDTRAIL_NAME}" --region "${AWS_REGION}" >/dev/null || true
  echo "Removed CloudTrail trail: ${CLOUDTRAIL_NAME}"
fi

LOG_GROUPS=$(aws logs describe-log-groups \
  --log-group-name-prefix "${LOG_GROUP_PREFIX}" \
  --query 'logGroups[].logGroupName' \
  --output text \
  --region "${AWS_REGION}" || true)

if [[ -n "${LOG_GROUPS}" ]]; then
  for group in ${LOG_GROUPS}; do
    aws logs delete-log-group --log-group-name "${group}" --region "${AWS_REGION}" >/dev/null || true
    echo "Deleted log group: ${group}"
  done
fi

if [[ -n "${CLOUDTRAIL_BUCKET:-}" ]]; then
  aws s3 rm "s3://${CLOUDTRAIL_BUCKET}" --recursive --region "${AWS_REGION}" || true
  aws s3api delete-bucket --bucket "${CLOUDTRAIL_BUCKET}" --region "${AWS_REGION}" || true
  echo "Deleted bucket (if empty and owned): ${CLOUDTRAIL_BUCKET}"
fi

echo "Cleanup complete."
