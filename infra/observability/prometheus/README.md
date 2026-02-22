# Prometheus Configuration

## Files
- `prometheus.yml`: Scrape configuration for app metrics and host metrics.
- `alert_rules.yml`: Alerting rules for error rate, latency p95, and host CPU utilization.

## Deployment Notes
1. Copy `prometheus.yml` to `/etc/prometheus/prometheus.yml`.
2. Copy `alert_rules.yml` to `/etc/prometheus/alert_rules.yml`.
3. Replace `APP_EC2_PRIVATE_IP` with the private IP (or private DNS) of your application EC2 instance.
4. Ensure security groups allow:
   - Monitoring EC2 -> App EC2 on `3000/tcp` (`/metrics`)
   - Monitoring EC2 -> App EC2 on `9100/tcp` (Node Exporter)
5. Restart Prometheus: `sudo systemctl restart prometheus`

## Target Validation
- Open Prometheus UI: `http://<monitoring-host>:9090/targets`
- Expected state: all targets `UP`.
