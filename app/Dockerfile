# Stage 1: Builder stage
FROM python:3.12-alpine AS builder

WORKDIR /app

# Copy only requirements first for better layer caching
COPY requirements.txt .

# Install dependencies to /opt/venv
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# Stage 2: Runtime stage
FROM python:3.12-alpine

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN addgroup -S appuser && adduser -S -G appuser appuser

# Copy application code with correct ownership
COPY --chown=appuser:appuser . .

ENV APP_HOST=0.0.0.0 \
    APP_PORT=3000 \
    ENVIRONMENT=production \
    DEBUG=false \
    PYTHONUNBUFFERED=1

# Build metadata labels
ARG BUILD_NUMBER=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIMESTAMP=unknown

LABEL org.opencontainers.image.title="secure-flask-app" \
      org.opencontainers.image.version="${BUILD_NUMBER}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_TIMESTAMP}" \
      org.opencontainers.image.source="https://github.com/your-org/your-repo"

# Activate virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Switch to non-root user
USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["python", "app.py"]
