#!/usr/bin/env bash
set -euo pipefail

# Run the application container with CloudWatch Logs driver.
#
# Prerequisites:
#   - EC2 IAM role must include: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
#   - Replace <ACCOUNT_ID> with your 12-digit AWS account ID.
#
# Usage: AWS_REGION=us-east-1 ./docker-awslogs-example.sh

AWS_REGION="${AWS_REGION:-us-east-1}"
LOG_GROUP="/aws/ec2/prod/secure-flask-app"
CONTAINER_NAME="secure-flask-app"
IMAGE="<ACCOUNT_ID>.dkr.ecr.${AWS_REGION}.amazonaws.com/secure-flask-app:latest"

aws logs create-log-group \
  --log-group-name "${LOG_GROUP}" \
  --region "${AWS_REGION}" 2>/dev/null || true

aws logs put-retention-policy \
  --log-group-name "${LOG_GROUP}" \
  --retention-in-days 30 \
  --region "${AWS_REGION}"

docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p 3000:3000 \
  --restart unless-stopped \
  --log-driver=awslogs \
  --log-opt awslogs-region="${AWS_REGION}" \
  --log-opt awslogs-group="${LOG_GROUP}" \
  --log-opt awslogs-create-group=true \
  --log-opt awslogs-stream="${CONTAINER_NAME}-$(hostname -s)" \
  "${IMAGE}"

echo "Container logs streaming to CloudWatch log group: ${LOG_GROUP}"
