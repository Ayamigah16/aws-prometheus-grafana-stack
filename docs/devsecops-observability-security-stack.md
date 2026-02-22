# DevSecOps Observability and Security Stack (AWS EC2 + Docker + Python)

## 1) Architecture Overview

This architecture implements a production-grade DevSecOps stack for a containerized Python web application on Amazon EC2 (Amazon Linux 2). It combines runtime observability with AWS-native security controls and auditable evidence collection.

### Components and Why They Exist

1. **Application EC2 (Amazon Linux 2 + Docker)**  
   Hosts the Flask container and exposes:
   - `/:` business endpoint
   - `/health`: liveness endpoint
   - `/metrics`: Prometheus metrics endpoint

   **Why:** Keeps the application runtime isolated and observable using standard Prometheus telemetry.

2. **Monitoring EC2 (Prometheus + Grafana)**  
   Prometheus scrapes app and host metrics; Grafana visualizes operational health and alert state.

   **Why:** Separates monitoring blast radius from the app host and supports production troubleshooting.

3. **Node Exporter on app EC2**  
   Exposes host CPU/memory/system metrics on `:9100`.

   **Why:** Enables infrastructure-level alerting and correlation with app-level SLOs.

4. **CloudWatch Logs**  
   Docker uses `awslogs` log driver to stream container stdout/stderr to structured log groups.

   **Why:** Centralized, durable logging with IAM control and retention policies.

5. **CloudTrail + encrypted S3 bucket**  
   Multi-region CloudTrail captures management events and delivers tamper-evident logs to S3.

   **Why:** Audit trail for governance, incident response, and forensic investigations.

6. **GuardDuty**  
   Threat detection for suspicious account/resource behavior.

   **Why:** Continuous security monitoring and prioritized findings.

---

## 2) Data Flow

1. Client traffic reaches application container (`3000/tcp`).
2. App emits Prometheus-compatible metrics (`/metrics`), including request count, status labels, and latency histogram.
3. Prometheus on monitoring EC2 scrapes:
   - `APP_EC2_PRIVATE_IP:3000/metrics`
   - `APP_EC2_PRIVATE_IP:9100/metrics`
4. Prometheus evaluates alert rules every 15s and marks alert state when thresholds are exceeded.
5. Grafana queries Prometheus and renders dashboards (RPS, error %, latency p95, CPU/memory, alert state).
6. Docker forwards container logs to CloudWatch Logs log group `/aws/ec2/prod/secure-flask-app`.
7. CloudTrail records account management API activity in all regions and stores logs in encrypted S3.
8. GuardDuty analyzes account telemetry and emits findings for suspicious events.

---

## 3) Implementation Guide

## 3.1 Prometheus + Alerts

Artifacts:
- `infra/observability/prometheus/prometheus.yml`
- `infra/observability/prometheus/alert_rules.yml`

Steps:
1. Copy configs to monitoring EC2:
   - `/etc/prometheus/prometheus.yml`
   - `/etc/prometheus/alert_rules.yml`
2. Replace placeholder `APP_EC2_PRIVATE_IP` with actual private endpoint.
3. Restart Prometheus:
   ```bash
   sudo systemctl restart prometheus
   ```
4. Verify target health in UI: `http://<monitoring-ec2>:9090/targets`.

Alert rules implemented:
- **HighErrorRate:** error % > 5 for 5m
- **HighLatencyP95:** p95 > 500ms for 10m
- **HighCPUUsage:** CPU > 80% for 10m

## 3.2 Grafana Dashboards

Artifact:
- `infra/observability/grafana/dashboards/devsecops-observability-dashboard.json`

Steps:
1. Add Prometheus datasource in Grafana (`http://localhost:9090` if same host).
2. Import dashboard JSON.
3. Confirm panels populate with live series:
   - RPS
   - Error rate %
   - Latency p95
   - CPU/memory utilization
   - Active alert count

## 3.3 CloudWatch Logging

Artifact:
- `infra/observability/cloudwatch/docker-awslogs-example.sh`

Steps:
1. Ensure app EC2 role has CloudWatch Logs permissions.
2. Run script on app EC2 to start container with `awslogs` driver.
3. Validate:
   ```bash
   aws logs describe-log-groups --log-group-name-prefix /aws/ec2/prod/secure-flask-app
   aws logs tail /aws/ec2/prod/secure-flask-app --follow
   ```

Recommended log-group structure:
- `/aws/ec2/prod/secure-flask-app`
- `/aws/ec2/prod/node-exporter` (if containerized)
- `/aws/ec2/prod/prometheus`
- `/aws/ec2/prod/grafana`

Retention baseline:
- 30 days for app runtime logs
- 90+ days for platform logs (adjust for compliance)

## 3.4 CloudTrail + S3 (encrypted)

Create S3 bucket controls (example commands):
```bash
aws s3api create-bucket --bucket <cloudtrail-log-bucket> --region us-east-1
aws s3api put-public-access-block \
  --bucket <cloudtrail-log-bucket> \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption \
  --bucket <cloudtrail-log-bucket> \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

Enable CloudTrail (all regions, management events, log validation):
```bash
aws cloudtrail create-trail \
  --name prod-org-trail \
  --s3-bucket-name <cloudtrail-log-bucket> \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail put-event-selectors \
  --trail-name prod-org-trail \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]'

aws cloudtrail start-logging --name prod-org-trail
```

Lifecycle policy recommendation for the CloudTrail bucket:
- Transition to Glacier after 90 days
- Permanent deletion after 365+ days (per policy/compliance)

## 3.5 GuardDuty

Enable and verify findings:
```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
if [ "$DETECTOR_ID" = "None" ]; then
  aws guardduty create-detector --enable
  DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
fi
aws guardduty list-findings --detector-id "$DETECTOR_ID"
aws guardduty get-findings --detector-id "$DETECTOR_ID" --finding-ids $(aws guardduty list-findings --detector-id "$DETECTOR_ID" --query 'FindingIds[:5]' --output text)
```

---

## 4) Verification and Validation Checklist

1. **Prometheus targets UP**  
   `Status -> Targets` shows app + node exporter as `UP`.
2. **Metrics scraped successfully**  
   PromQL checks return data:
   - `sum(rate(http_requests_total[1m]))`
   - `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`
3. **Grafana live dashboards**  
   RPS/error/latency/CPU-memory panels update every refresh interval.
4. **Alert trigger validation (>5% error)**  
   Generate synthetic 5xx responses and verify `HighErrorRate` enters firing state.
5. **CloudWatch logs present**  
   App container logs visible in expected log group/stream.
6. **CloudTrail logs delivered to S3**  
   New log objects appear under AWSLogs prefix.
7. **GuardDuty findings retrievable**  
   Findings list/get commands return records (or zero findings with detector active).

---

## 5) Cleanup Phase (Cost Control)

1. Terminate monitoring EC2 instance(s).
2. Stop and remove Prometheus/Grafana containers/services.
3. Delete CloudWatch log groups created for this stack.
4. Disable GuardDuty detector.
5. Stop and delete CloudTrail trail.
6. Empty and delete CloudTrail S3 bucket.
7. Confirm no residual resources:
   - EC2 instances
   - EBS volumes
   - Elastic IPs
   - CloudWatch log groups
   - S3 buckets
   - GuardDuty detectors

---

## 6) Security Best Practices Applied

- Principle of least privilege IAM roles for EC2 and logging actions.
- Private network scraping where possible; avoid public metrics endpoints.
- Encrypted audit storage and blocked public access for CloudTrail bucket.
- Log-file validation enabled for tamper detection.
- Security detections (GuardDuty) integrated with operations checks.
- Alert thresholds tied to service health indicators and host resource risk.

---

## 7) DevSecOps Principles Demonstrated

- **Shift-left security:** measurable runtime health and security controls are codified.
- **Continuous verification:** alerts, dashboards, and log pipelines are validated through evidence.
- **Auditability:** CloudTrail + encrypted S3 + retention policies provide traceability.
- **Operational resilience:** layered telemetry (metrics + logs + threat detection) improves MTTR.
