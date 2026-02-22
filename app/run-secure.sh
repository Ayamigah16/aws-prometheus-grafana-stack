#!/bin/bash
# Script to run Flask app with production-ready security settings

# Fail-safe scripting
set -euo pipefail

# Configuration
readonly CONTAINER_NAME="flask-app"
readonly IMAGE_NAME="flask-app"
readonly PORT="3000"
readonly LOG_PREFIX="[$(date +%H:%M:%S)]"

# Logging functions
log_info() { echo "${LOG_PREFIX} ℹ $*"; }
log_success() { echo "${LOG_PREFIX} ✓ $*"; }
log_error() { echo "${LOG_PREFIX} ✗ $*" >&2; }

# Cleanup function for error handling
cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "Deployment failed (exit code: ${exit_code})"
        log_info "Cleaning up..."
        docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
        exit "${exit_code}"
    fi
}

trap cleanup EXIT ERR

# Dependency checks
command -v docker >/dev/null 2>&1 || { log_error "Docker not found. Install Docker first."; exit 1; }
command -v curl >/dev/null 2>&1 || { log_error "curl not found. Install curl first."; exit 1; }

# Stop and remove existing container
if docker ps -a --filter "name=${CONTAINER_NAME}" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}"; then
    log_info "Removing existing container..."
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

# Build image
log_info "Building image..."
docker build -t "${IMAGE_NAME}" . >/dev/null || {
    log_error "Build failed"
    exit 1
}
log_success "Image built"

# Run container with security hardening
log_info "Starting container..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${PORT}:${PORT}" \
  --read-only \
  --tmpfs /tmp:size=10M,mode=1777 \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  -e ENVIRONMENT=production \
  -e DEBUG=false \
  "${IMAGE_NAME}" >/dev/null
log_success "Container started"

# Health check
log_info "Testing endpoints..."
sleep 2

if response=$(curl -sf "http://localhost:${PORT}" 2>/dev/null); then
    log_success "App responding: ${response}"
else
    log_error "Health check failed"
    docker logs "${CONTAINER_NAME}"
    exit 1
fi

if curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    log_success "Health endpoint OK"
else
    log_error "Health endpoint failed"
    exit 1
fi

# Success summary
echo ""
log_success "Deployment complete"
echo "  • URL: http://localhost:${PORT}"
echo "  • Logs: docker logs ${CONTAINER_NAME}"
echo "  • Stop: docker stop ${CONTAINER_NAME}"
