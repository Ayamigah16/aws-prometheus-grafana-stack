import os
import signal
import sys
import time
from flask import Flask, jsonify, g, request
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

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

def create_app():
    app = Flask(__name__)

    # Externalized configuration via environment variables
    app.config['APP_HOST'] = os.getenv('APP_HOST', '0.0.0.0')
    app.config['APP_PORT'] = int(os.getenv('APP_PORT', '3000'))
    app.config['ENVIRONMENT'] = os.getenv('ENVIRONMENT', 'production')
    app.config['DEBUG_MODE'] = os.getenv('DEBUG', 'false').lower() == 'true'
    app.config['APP_NAME'] = os.getenv('APP_NAME', 'secure-flask-app')

    @app.before_request
    def _track_request_start_time():
        g.request_start_time = time.perf_counter()

    @app.after_request
    def _record_metrics(response):
        endpoint = getattr(request, "path", "unknown")
        method = getattr(request, "method", "UNKNOWN")
        status = str(response.status_code)

        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()

        if endpoint != "/metrics" and hasattr(g, "request_start_time"):
            duration = max(time.perf_counter() - g.request_start_time, 0)
            REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)

        return response

    @app.route('/')
    def home():
        environment = app.config['ENVIRONMENT']
        return f"Hello from Docker! Running in {environment} mode."

    @app.route('/health')
    def health():
        return jsonify(
            status='healthy',
            environment=app.config['ENVIRONMENT'],
            app=app.config['APP_NAME'],
        ), 200
        
    @app.route("/error")
    def error():
        return "failure", 500

    @app.route('/metrics')
    def metrics():
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    return app


def _handle_shutdown(signum, frame):
    print(f"Received signal {signum}. Shutting down gracefully...", flush=True)
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)
    application = create_app()
    application.run(
        host=application.config['APP_HOST'],
        port=application.config['APP_PORT'],
        debug=application.config['DEBUG_MODE'],
    )
