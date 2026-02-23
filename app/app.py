import json
import logging
import os
import signal
import sys
import time

from flask import Flask, jsonify, g, request
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# OpenTelemetry — always imported; only activated when OTEL_EXPORTER_OTLP_ENDPOINT is set
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor

# ---------------------------------------------------------------------------
# Prometheus RED metrics (Rate / Errors / Duration)
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)

# ---------------------------------------------------------------------------
# Structured JSON logging with OpenTelemetry trace correlation
# ---------------------------------------------------------------------------
class _TraceContextFilter(logging.Filter):
    """Injects trace_id and span_id from the active OTel span into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.is_valid:
            record.trace_id = format(ctx.trace_id, "032x")
            record.span_id = format(ctx.span_id, "016x")
        else:
            record.trace_id = "0" * 32
            record.span_id = "0" * 16
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": self.formatTime(record, self.datefmt),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "trace_id": getattr(record, "trace_id", "0" * 32),
                "span_id": getattr(record, "span_id", "0" * 16),
            }
        )


def _configure_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_TraceContextFilter())
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = []
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return logging.getLogger(__name__)


logger = _configure_logging()

# ---------------------------------------------------------------------------
# OpenTelemetry initialisation
# ---------------------------------------------------------------------------
def _setup_otel(service_name: str, otlp_endpoint: str) -> None:
    """Register an OTLP-gRPC trace exporter and instrument Flask + Requests.

    No-ops when *otlp_endpoint* is empty so the app and tests work without
    a running Jaeger instance.
    """
    # Reject empty string or a URL with no host (e.g. "http://:4317" produced
    # when MONITORING_HOST_DNS is unset) — either would activate the SDK but
    # silently drop all spans, making the Jaeger panel show no data.
    from urllib.parse import urlparse
    parsed = urlparse(otlp_endpoint)
    if not otlp_endpoint or not parsed.hostname:
        return
    resource = Resource.create({"service.name": service_name})
    exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FlaskInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    logger.info(
        f"OpenTelemetry initialised — exporting to {otlp_endpoint} "
        f"as service '{service_name}'"
    )


_setup_otel(
    service_name=os.getenv("OTEL_SERVICE_NAME", "secure-flask-app"),
    otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
)


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)

    # Externalized configuration via environment variables
    app.config["APP_HOST"] = os.getenv("APP_HOST", "0.0.0.0")
    app.config["APP_PORT"] = int(os.getenv("APP_PORT", "3000"))
    app.config["ENVIRONMENT"] = os.getenv("ENVIRONMENT", "production")
    app.config["DEBUG_MODE"] = os.getenv("DEBUG", "false").lower() == "true"
    app.config["APP_NAME"] = os.getenv("APP_NAME", "secure-flask-app")

    @app.before_request
    def _track_request_start_time():
        g.request_start_time = time.perf_counter()

    @app.after_request
    def _record_metrics(response):
        endpoint = getattr(request, "path", "unknown")
        method = getattr(request, "method", "UNKNOWN")
        status = str(response.status_code)

        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()

        duration = 0.0
        if endpoint != "/metrics" and hasattr(g, "request_start_time"):
            duration = max(time.perf_counter() - g.request_start_time, 0)
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)

        # Structured log line — trace_id/span_id injected by _TraceContextFilter
        logger.info(
            f"{method} {endpoint} {status} {round(duration * 1000, 2)}ms"
        )
        return response

    @app.route("/")
    def home():
        environment = app.config["ENVIRONMENT"]
        return f"Hello from Docker! Running in {environment} mode."

    @app.route("/health")
    def health():
        return (
            jsonify(
                status="healthy",
                environment=app.config["ENVIRONMENT"],
                app=app.config["APP_NAME"],
            ),
            200,
        )

    @app.route("/error")
    def error():
        logger.error("Simulated error endpoint called")
        return "failure", 500

    @app.route("/metrics")
    def metrics():
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    return app


def _handle_shutdown(signum, frame):
    logger.info(f"Received signal {signum}. Shutting down gracefully.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)
    application = create_app()
    application.run(
        host=application.config["APP_HOST"],
        port=application.config["APP_PORT"],
        debug=application.config["DEBUG_MODE"],
    )
