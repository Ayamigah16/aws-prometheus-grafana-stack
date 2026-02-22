# Evidence Screenshots Checklist

Capture and store screenshots with the following filenames:

1. `01-grafana-dashboard-overview.png` — Dashboard showing RPS, error rate %, latency p95, CPU/memory.
2. `02-prometheus-active-alerts.png` — Prometheus Alerts page with at least one firing alert.
3. `03-cloudwatch-log-stream.png` — CloudWatch Logs stream with live container logs.
4. `04-cloudtrail-s3-log-delivery.png` — S3 bucket path with CloudTrail log objects under `AWSLogs/`.
5. `05-guardduty-findings.png` — GuardDuty findings list page.

Optional:
- `06-prometheus-targets-up.png` (Targets page showing all jobs as `UP`)
- `07-grafana-alert-validation.png` (Alert stat panel showing firing count)

## Notes
- Redact account IDs or sensitive metadata before sharing externally.
- Preserve timestamps in screenshots for auditability.
