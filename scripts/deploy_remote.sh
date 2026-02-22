#!/usr/bin/env bash
set -euo pipefail

APP_PORT=3000
ACTIVE_CONTAINER="${DEPLOY_CONTAINER}"
STAGING_CONTAINER="${DEPLOY_CONTAINER}-staging"

if [ "${USE_ECR}" = "true" ]; then
  aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
fi

docker pull "${IMAGE_NAME}"

if docker ps --format '{{.Names}}' | grep -q "^${ACTIVE_CONTAINER}$"; then
  OLD_IMAGE=$(docker inspect -f '{{.Config.Image}}' "${ACTIVE_CONTAINER}")
else
  OLD_IMAGE=""
fi

if docker ps --format '{{.Names}}' | grep -q "^${STAGING_CONTAINER}$"; then
  docker rm -f "${STAGING_CONTAINER}"
fi

docker run -d --name "${STAGING_CONTAINER}" -p 3001:${APP_PORT} \
  --read-only \
  --tmpfs /tmp:size=10M,mode=1777 \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  -e ENVIRONMENT=production \
  -e DEBUG=false \
  "${IMAGE_NAME}"

for i in {1..10}; do
  if curl -fsS "http://localhost:3001/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! curl -fsS "http://localhost:3001/health" >/dev/null 2>&1; then
  docker logs "${STAGING_CONTAINER}" || true
  docker rm -f "${STAGING_CONTAINER}" || true
  exit 1
fi

if docker ps --format '{{.Names}}' | grep -q "^${ACTIVE_CONTAINER}$"; then
  docker rm -f "${ACTIVE_CONTAINER}"
fi

docker run -d --name "${ACTIVE_CONTAINER}" -p 80:${APP_PORT} \
  --read-only \
  --tmpfs /tmp:size=10M,mode=1777 \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  -e ENVIRONMENT=production \
  -e DEBUG=false \
  "${IMAGE_NAME}"

docker rm -f "${STAGING_CONTAINER}" || true

for i in {1..10}; do
  if curl -fsS "http://localhost/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! curl -fsS "http://localhost/health" >/dev/null 2>&1; then
  docker rm -f "${ACTIVE_CONTAINER}" || true
  if [ -n "${OLD_IMAGE}" ]; then
    docker run -d --name "${ACTIVE_CONTAINER}" -p 80:${APP_PORT} \
      --read-only \
      --tmpfs /tmp:size=10M,mode=1777 \
      --security-opt=no-new-privileges:true \
      --cap-drop=ALL \
      -e ENVIRONMENT=production \
      -e DEBUG=false \
      "${OLD_IMAGE}"
  fi
  exit 1
fi

docker container prune -f
KEEP=3
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}' \
  | grep "^${REGISTRY}/${APP_NAME}:" \
  | tail -n +$((KEEP + 1)) \
  | awk '{print $2}' \
  | xargs -r docker rmi -f || true
