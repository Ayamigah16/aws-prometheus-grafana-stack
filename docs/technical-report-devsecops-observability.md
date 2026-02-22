# Technical Report: DevSecOps Observability & Security Stack

## Executive Summary

This implementation introduces a production-grade DevSecOps observability and security architecture for a containerized Python web application on Amazon EC2 (Amazon Linux 2). The stack integrates Prometheus and Grafana for runtime observability, CloudWatch Logs for centralized operational logs, CloudTrail for account-level audit telemetry, and GuardDuty for managed threat detection.

The objective is not only to collect telemetry, but to operationalize it. The architecture therefore includes alert thresholds tied to service behavior (error rate, latency p95, host CPU), dashboard visualizations for fast diagnosis, and explicit verification procedures that prove end-to-end functionality. Security controls are configured with least-privilege assumptions, encryption-at-rest requirements, and lifecycle-driven retention for cost-aware compliance.

## Architecture and Rationale

The stack uses two logical planes:

1. **Runtime plane (application and host):**
   - Flask app container publishes `/metrics`
   - Node Exporter publishes host metrics
   - Docker streams logs to CloudWatch Logs

2. **Control and audit plane (AWS-native security):**
   - CloudTrail captures management events across all regions
   - Trail logs are written to encrypted S3 with public access blocked
   - GuardDuty continuously evaluates account and resource telemetry

A dedicated monitoring instance (or equivalent containerized deployment) hosts Prometheus and Grafana. This separation improves fault isolation and protects operational visibility when application nodes are degraded.

## Implementation Details

### Metrics and Alerting

Prometheus is configured to scrape:
- Application endpoint: `APP_EC2_PRIVATE_IP:3000/metrics`
- Node Exporter endpoint: `APP_EC2_PRIVATE_IP:9100/metrics`

Alert rules encode core reliability risks:
- **HighErrorRate** when 5xx error ratio exceeds 5%
- **HighLatencyP95** when p95 latency exceeds 500ms
- **HighCPUUsage** when host CPU remains above 80%

These rules are intended to catch user-impacting incidents early while filtering transient spikes through `for` durations.

### Visualization and Operational Triage

Grafana dashboard export includes panels for:
- Request throughput (RPS)
- Error rate percentage
- p95 latency
- CPU/memory utilization
- Current firing-alert count

This layout supports a practical triage sequence: verify load pattern (RPS), inspect symptom (error/latency), then identify likely bottleneck (host utilization) and alert status.

### Logging and Evidence

The Docker `awslogs` driver streams container stdout/stderr to structured CloudWatch log groups. Retention policy is set to 30 days for application logs by default, with longer retention recommended for platform and compliance-related logs.

CloudWatch is essential for post-incident evidence because it preserves event chronology independent of instance lifecycle and supports near-real-time viewing.

### Security and Audit Controls

CloudTrail is configured as a multi-region trail with management events and log-file validation enabled. Logs are stored in an S3 bucket with:
- Server-side encryption
- Full public access block
- Lifecycle transition to Glacier and eventual deletion after policy-defined retention

GuardDuty is enabled to detect anomalous account and infrastructure behavior. Findings validation is part of the verification workflow.

## Verification Results Framework

The implementation defines explicit acceptance checks:
- Prometheus targets show `UP`
- PromQL queries return live data
- Grafana panels update continuously
- Error alert fires when synthetic 5xx load exceeds threshold
- CloudWatch log streams receive container logs
- CloudTrail objects are delivered to S3
- GuardDuty detector and findings API are operational

This approach aligns with DevSecOps by treating observability and security controls as testable release criteria rather than passive infrastructure.

## Security Observations

1. **Telemetry hardening matters:** Metrics and logs should remain private; expose only through secured network paths.
2. **Audit immutability is critical:** CloudTrail log validation and encrypted S3 reduce tampering risk.
3. **Detection without response is incomplete:** GuardDuty findings should feed an incident workflow (SNS, ticketing, or SIEM).
4. **Least privilege is foundational:** IAM permissions for CloudWatch and CloudTrail delivery should be narrowly scoped.

## Cost Considerations

Primary ongoing costs come from:
- Monitoring EC2 runtime (Prometheus/Grafana)
- CloudWatch Logs ingestion and retention
- S3 storage for CloudTrail logs (plus Glacier archive)
- GuardDuty analysis charges

Cost optimization recommendations:
- Right-size monitoring instance and retention windows
- Use lifecycle transitions aggressively for audit archives
- Remove unused log groups and stale trails
- Execute cleanup steps after test runs to avoid residual spend

## Conclusion

The delivered stack provides layered visibility and defense for a containerized Python service on EC2. It unifies operational telemetry with AWS-native security and auditing, while preserving pragmatic production concerns: alert quality, forensic readiness, least-privilege design, and lifecycle-driven cost control. The result is a DevSecOps implementation that is actionable, measurable, and suitable as a baseline for regulated or high-availability workloads.
