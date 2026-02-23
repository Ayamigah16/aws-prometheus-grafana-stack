import signal

import pytest

from app import create_app
from app.app import _handle_shutdown


def test_health_endpoint_returns_ok():
    app = create_app()
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "healthy"


def test_home_includes_environment(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "staging")
    app = create_app()
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert "staging" in response.get_data(as_text=True)


def test_env_configuration_overrides_defaults(monkeypatch):
    monkeypatch.setenv("APP_PORT", "7777")
    monkeypatch.setenv("APP_NAME", "unit-test-app")
    app = create_app()

    assert app.config["APP_PORT"] == 7777
    assert app.config["APP_NAME"] == "unit-test-app"


def test_health_endpoint_includes_metadata():
    app = create_app()
    client = app.test_client()

    response = client.get("/health")
    payload = response.get_json()

    assert payload["environment"] == app.config["ENVIRONMENT"]
    assert payload["app"] == app.config["APP_NAME"]


def test_shutdown_handler_exits_cleanly():
    with pytest.raises(SystemExit) as exc:
        _handle_shutdown(signal.SIGTERM, None)

    assert exc.value.code == 0


def test_metrics_endpoint_exposes_prometheus_metrics():
    app = create_app()
    client = app.test_client()

    # Warm up a request so counters are populated
    client.get("/")
    response = client.get("/metrics")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "http_requests_total" in body
    assert "http_request_duration_seconds_bucket" in body


def test_error_endpoint_returns_500():
    app = create_app()
    client = app.test_client()

    response = client.get("/error")

    assert response.status_code == 500


def test_otel_disabled_without_endpoint(monkeypatch):
    """App boots and serves requests normally when OTEL endpoint is not set."""
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    app = create_app()
    client = app.test_client()

    response = client.get("/health")
    assert response.status_code == 200


def test_otel_disabled_with_broken_endpoint(monkeypatch):
    """App boots normally when MONITORING_HOST_DNS is empty, producing http://:4317.

    That URL is truthy but has no hostname, so _setup_otel must skip OTel
    entirely rather than activating the SDK with an invalid exporter.
    """
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://:4317")
    app = create_app()
    client = app.test_client()

    response = client.get("/health")
    assert response.status_code == 200
