# Runbook

## Purpose
Ordered setup and operations guide for the full DevSecOps stack:
Terraform (IaC) → Ansible (configuration) → Jenkins (CI/CD) → Observability (Prometheus + Alertmanager + Grafana + Node Exporter + **Jaeger + OpenTelemetry**) → Security (CloudTrail, GuardDuty, CloudWatch Logs).

### Why we added distributed tracing
Prometheus metrics show *aggregate* behaviour — they tell you the p95 latency is 800ms, but not *which* requests were slow or *why*. Log lines tell you an error occurred, but without a `trace_id` you cannot link a specific log entry back to the request that caused it.

OpenTelemetry + Jaeger solves this by:
- Assigning every HTTP request a unique `trace_id` at the entry point
- Propagating that ID through all downstream calls automatically (Flask auto-instrumentation)
- Injecting `trace_id` and `span_id` into every structured JSON log line the app emits
- Storing the full span tree in Jaeger, accessible by clicking a trace link in Grafana

The result: an alert fires → you open Grafana → find the spike on the latency graph → click into the Jaeger trace panel → see exactly which endpoint was slow and for how long → copy the `trace_id` → filter CloudWatch Logs to read the exact log lines for that request. The entire symptom → trace → root cause path takes under two minutes.

---

## Prerequisites

### Tools (install once on your workstation)
| Tool | Minimum version | Install |
|------|----------------|---------|
| Terraform | 1.6 | https://developer.hashicorp.com/terraform/downloads |
| Ansible | 2.15 | `pip install ansible` |
| AWS CLI | 2.x | https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html |
| Git | any | OS package manager |

```bash
# Verify
terraform version      # >= 1.6
ansible --version      # >= 2.15
aws --version          # >= 2.0
```

### AWS permissions required
The IAM identity running Terraform needs at minimum:
- `EC2`, `VPC`, `IAM`, `ECR`, `S3`, `DynamoDB` — for core infrastructure
- `CloudTrail`, `S3` (trail bucket) — for audit logging
- `GuardDuty` — for threat detection
- `CloudWatch Logs` — for container log shipping
- `SSM` — for monitoring host managed access (optional but recommended)

### SSH key
Generate the key pair that Terraform will import:
```bash
ssh-keygen -t ed25519 -f infra/keys/jenkins-pipeline-key -N ""
# infra/keys/jenkins-pipeline-key.pub is already referenced in terraform.tfvars
```

---

## Step 1 — Bootstrap Terraform State Backend

Creates the S3 bucket + DynamoDB table used for all subsequent Terraform state.
Run this **once per environment**; never run it again unless tearing everything down.

```bash
cd infra/terraform/bootstrap

terraform init
terraform apply \
  -var='state_bucket_name=<globally-unique-name>-tf-state' \
  -var='lock_table_name=jenkins-pipeline-tf-locks'
```

Note the bucket name — you will need it in the next step.

---

## Step 2 — Provision AWS Infrastructure

Provisions: VPC, Jenkins EC2, Deploy EC2, **Monitoring EC2**, ECR, IAM roles/profiles, Security Groups, key pair.

```bash
cd infra/terraform/aws

# 1. Copy and fill in the variable files
cp terraform.tfvars.example terraform.tfvars
cp backend.hcl.example backend.hcl
```

Edit `terraform.tfvars`:
```hcl
aws_region              = "us-east-1"
project_name            = "jenkins-pipeline"
environment             = "prod"
admin_cidrs             = ["<YOUR_IP>/32"]   # your workstation IP for SSH/UI access
key_pair_name           = "jenkins-pipeline-key"
jenkins_instance_type   = "t3.medium"
deploy_instance_type    = "t3.small"
monitoring_instance_type = "t3.small"        # hosts Prometheus + Alertmanager + Grafana
ecr_repository_name     = "secure-flask-app"
```

Edit `backend.hcl`:
```hcl
bucket         = "<globally-unique-name>-tf-state"
key            = "jenkins-pipeline/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "jenkins-pipeline-tf-locks"
encrypt        = true
```

```bash
# 2. Initialise and apply
terraform init -backend-config=backend.hcl
terraform apply
```

After `apply` completes, Terraform writes `infra/ansible/.env` and `infra/ansible/inventory/hosts.ini`
with the public/private IPs of all three hosts.

Verify outputs:
```bash
terraform output
# Expected: jenkins_public_dns, deploy_public_dns, monitoring_public_ip, monitoring_public_dns
```

---

## Step 3 — Prepare Ansible Secrets

All sensitive values are stored in an ansible-vault encrypted file and **never committed in plaintext**.

```bash
cd infra/ansible

# Copy the example and fill in real values
cp group_vars/all/vault.yml.example group_vars/all/vault.yml
```

Edit `group_vars/all/vault.yml`:
```yaml
vault_jenkins_admin_password: "<strong-random-password>"

# Grafana
vault_grafana_admin_password: "<strong-random-password>"

# Alertmanager — Slack incoming webhook
# Create one at: https://api.slack.com/messaging/webhooks
vault_alertmanager_slack_webhook_url: "https://hooks.slack.com/services/T.../B.../..."

# Alertmanager — SMTP credentials (used for oncall email escalation)
vault_alertmanager_smtp_username: "alerts@example.com"
vault_alertmanager_smtp_password: "<smtp-app-password>"
```

Encrypt the file:
```bash
ansible-vault encrypt group_vars/all/vault.yml
# You will be prompted for a vault password — store it in a password manager
```

Review `group_vars/all.yml` for any non-secret values you want to override (Slack channels, SMTP host/from address, alert thresholds, software versions).

---

## Step 4 — Configure All Hosts with Ansible

`run-playbook.sh` sources `infra/ansible/.env` (written by Terraform) to populate the inventory and
then runs `playbooks/site.yml` against all three hosts in order.

**Roles applied per host:**

| Host | Roles |
|------|-------|
| Jenkins EC2 | `common`, `jenkins` |
| Deploy EC2 | `common`, `deploy`, `node_exporter` |
| Monitoring EC2 | `common`, `monitoring` |

The `monitoring` role installs and starts:
- Prometheus 2.50.1 — scrapes flask-app (`:80/metrics`), Node Exporter (`:9100`), Alertmanager (`:9093`), and Jaeger metrics (`:14269`)
- Alertmanager 0.27.0 — routes `warning` alerts to Slack `#alerts-warning`, `critical` alerts to Slack `#alerts-critical` **and** oncall email; alert thresholds: error rate > 5% for 10 min, p95 latency > 300ms for 10 min
- Grafana (latest from YUM repo) — admin credentials pre-configured; two dashboards auto-provisioned: *DevSecOps Observability* and *Advanced Observability — Distributed Tracing*; Prometheus and Jaeger datasources both provisioned automatically
- Node Exporter 1.7.0 — installed on the Deploy EC2 host, scraped by Prometheus over the VPC private network
- **Jaeger 1.57.0 all-in-one** — receives OTLP gRPC traces from the app container on port `4317`; UI available on port `16686`; metrics exposed on port `14269` for Prometheus to scrape

```bash
cd infra/ansible

# Run with vault password prompt (recommended for first run)
./run-playbook.sh --ask-vault-pass

# Or supply a vault password file
./run-playbook.sh --vault-password-file ~/.vault-pass
```

Expected result: `PLAY RECAP` shows `failed=0 unreachable=0` for all three hosts.

---

## Step 5 — Configure Jenkins

### 5a. Create credentials in the Jenkins UI

Open `http://<JENKINS_PUBLIC_DNS>:8080` → **Manage Jenkins → Credentials → System → Global**.

| ID | Kind | Value |
|----|------|-------|
| `git_credentials` | Username with password | GitHub username + personal access token |
| `ec2_ssh` | SSH private key | Contents of `infra/keys/jenkins-pipeline-key` |
| `registry_creds` | Username with password | Only needed if `USE_ECR=false` |

### 5b. Create pipeline job

1. **New Item** → **Pipeline** → name it `secure-flask-app`
2. Under **Pipeline** → **Definition**: select *Pipeline script from SCM*
3. SCM: Git, repository URL, credentials: `git_credentials`
4. Branch: `*/main` (or `*/develop`)
5. Script Path: `Jenkinsfile`

### 5c. Set Jenkinsfile runtime values

Edit `Jenkinsfile` or set them as pipeline parameters:

```groovy
REGISTRY             = "<account_id>.dkr.ecr.<region>.amazonaws.com"
EC2_HOST             = "<DEPLOY_PUBLIC_DNS from terraform output>"
MONITORING_HOST_DNS  = "<MONITORING_PUBLIC_DNS from terraform output>"  // used to configure OTLP endpoint in the app container
USE_ECR              = true
```

`MONITORING_HOST_DNS` is passed to the deploy script via SSH and set as `OTEL_EXPORTER_OTLP_ENDPOINT=http://<MONITORING_HOST_DNS>:4317` on the running container. Without it, the app starts without tracing (metrics and logs still work).

---

## Step 6 — AWS Security Services (automated by Terraform)

CloudTrail, GuardDuty, and CloudWatch Logs IAM policy are all provisioned automatically during `terraform apply` in Step 2. No manual AWS CLI commands are required.

**What was created:**
- **CloudTrail** — multi-region trail (`<project>-trail`) writing to an AES-256-encrypted, versioned S3 bucket (`<project>-cloudtrail-<account_id>`). Log file integrity validation is enabled. Lifecycle policy transitions logs to Glacier at 90 days and expires at 365 days.
- **GuardDuty** — detector enabled with S3 data event protection and EBS malware scanning; findings published every 15 minutes.
- **CloudWatch Logs IAM** — inline policy on the deploy instance role grants `logs:CreateLogGroup/Stream/PutLogEvents/DescribeLogStreams` on `/docker/*`. The Docker daemon on the deploy host is configured with the `awslogs` driver so all container stdout/stderr ships to log group `/docker/secure-flask-app` automatically on container start.

**Why CloudWatch Logs + structured JSON matters for tracing:** Every log line the app emits includes `trace_id` and `span_id` fields (injected by `_TraceContextFilter` in `app.py`). Because those logs land in CloudWatch, you can filter by `trace_id` in the CloudWatch Logs Insights console to retrieve all log lines for a specific request identified in Jaeger.

Verify the services are active:

```bash
# CloudTrail logging
aws cloudtrail get-trail-status --name <project>-trail \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'

# GuardDuty
aws guardduty list-detectors

# CloudWatch log group exists (populated after first container start)
aws logs describe-log-groups --log-group-name-prefix /docker/secure-flask-app
```

---

## Step 7 — Verify Observability Stack

After Ansible completes, verify each component from your workstation.

### Prometheus

```bash
# UI — check targets and alerts
open http://<MONITORING_PUBLIC_DNS>:9090/targets
# All three targets (python-app, node-exporter, alertmanager) should show State: UP

# Check rules are loaded
open http://<MONITORING_PUBLIC_DNS>:9090/rules
```

### Alertmanager

```bash
open http://<MONITORING_PUBLIC_DNS>:9093
# Status page should show "ready"

# Fire a test alert manually to verify routing:
curl -X POST http://<MONITORING_PUBLIC_DNS>:9093/api/v2/alerts \
  -H "Content-Type: application/json" \
  -d '[{
    "labels": {"alertname":"TestAlert","severity":"warning","service":"test"},
    "annotations": {"summary":"Manual test","description":"Routing test"},
    "generatorURL": "http://localhost"
  }]'
# Expect a message to appear in #alerts-warning within ~30 seconds
```

### Grafana

```bash
open http://<MONITORING_PUBLIC_DNS>:3000
# Login: admin / <vault_grafana_admin_password>
# Two dashboards are auto-provisioned in the sidebar:
#   • DevSecOps Observability — original RED metrics + CPU/memory
#   • Advanced Observability — Distributed Tracing — adds Jaeger trace panel
#
# No manual import needed.
```

### Jaeger UI

```bash
open http://<MONITORING_PUBLIC_DNS>:16686
# ‘Service’ dropdown should show ‘secure-flask-app’ after the first request is processed
# If the dropdown is empty, send a test request first:
curl http://<DEPLOY_PUBLIC_DNS>/health
curl http://<DEPLOY_PUBLIC_DNS>/
```

### Node Exporter

```bash
# Verify metrics are reachable from the monitoring host
ssh ec2-user@<MONITORING_PUBLIC_DNS> \
  "curl -fsS http://<DEPLOY_PRIVATE_IP>:9100/metrics | head -5"
```

### Flask app metrics

```bash
curl http://<DEPLOY_PUBLIC_DNS>/metrics | grep http_requests_total
curl http://<DEPLOY_PUBLIC_DNS>/health
```

### CloudWatch log correlation

```bash
# Fetch the most recent log stream and inspect structured JSON log lines
LATEST_STREAM=$(aws logs describe-log-streams \
  --log-group-name /docker/secure-flask-app \
  --order-by LastEventTime --descending \
  --query 'logStreams[0].logStreamName' --output text)

aws logs get-log-events \
  --log-group-name /docker/secure-flask-app \
  --log-stream-name "${LATEST_STREAM}" \
  --limit 5 \
  --query 'events[].message' --output text

# Each line is a JSON object. Example:
# {"timestamp": "2026-02-23 10:01:43,123", "level": "INFO", "message": "GET /health 200 1.2ms",
#  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7"}
#
# Take the trace_id, open Jaeger UI, and paste it into the Trace ID search box.
```

---

## Symptom → Trace → Root Cause Workflow

This workflow links a Grafana alert to the exact request and log lines that caused it.

1. **Alert fires** — Alertmanager sends a Slack message: *"HighLatencyP95: p95 > 300ms for 10m"*
2. **Open Grafana** → `http://<MONITORING_PUBLIC_DNS>:3000` → *Advanced Observability — Distributed Tracing* dashboard
3. **Latency Percentiles panel** — identify the time window where p95 spiked
4. **Jaeger traces panel** — scroll to the same time window; slow traces appear in orange/red; click one to open the span waterfall in the Jaeger UI
5. **Span waterfall** — identify the span with the longest duration (e.g. a slow `/api/items` handler); copy the `Trace ID` from the URL
6. **CloudWatch Logs Insights** (AWS Console) — open log group `/docker/secure-flask-app`, run:
   ```
   fields @timestamp, message, trace_id, span_id
   | filter trace_id = "<paste-trace-id>"
   | sort @timestamp asc
   ```
7. **Root cause** — the filtered log lines show every log statement emitted during that request, in order, with timing. Correlate with the span name from Jaeger to pinpoint the function or query responsible.

---

## Step 8 — Verify Security Stack

```bash
# CloudTrail logging active
aws cloudtrail get-trail-status --name <project>-trail \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'

# GuardDuty enabled
aws guardduty list-detectors

# Confirm no public S3 buckets
aws s3api list-buckets --query 'Buckets[].Name' --output text | \
  xargs -I{} aws s3api get-public-access-block --bucket {}

# Confirm trail bucket encryption
aws s3api get-bucket-encryption --bucket <project>-cloudtrail-logs
```

---

## Standard CI/CD Flow

Once everything is wired up, all deployments run automatically:

1. Push to `main` (or open a PR) → Jenkins pipeline triggers
2. Stages: checkout → unit tests → `bandit` SAST → `pip-audit` dependency check → Docker build → `trivy fs` + `trivy image` scan → ECR push → deploy to staging (`:3001`) → health check → cutover to production (`:80`) → post-deploy verify → cleanup
3. Grafana dashboard reflects new request traffic within one `scrape_interval` (15 s)

---

## Manual Rollback

Automatic rollback runs on pipeline failure. For manual intervention:

```bash
ssh ec2-user@<DEPLOY_PUBLIC_DNS> "docker ps --format '{{.Names}} {{.Image}}'"
ssh ec2-user@<DEPLOY_PUBLIC_DNS> 'docker rm -f secure-flask-app'
ssh ec2-user@<DEPLOY_PUBLIC_DNS> 'docker run -d --name secure-flask-app -p 80:3000 <previous-image-tag>'
curl -fsS http://<DEPLOY_PUBLIC_DNS>/health
```

---

## Teardown / Cleanup

```bash
# Remove observability and security resources (CloudTrail, GuardDuty, CloudWatch)
bash scripts/cleanup_observability_security.sh

# Destroy AWS infrastructure
cd infra/terraform/aws
terraform destroy

# Optionally destroy state backend last (this deletes the state itself)
cd ../bootstrap
terraform destroy
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `terraform init` backend error | Bucket/table name wrong or doesn't exist | Re-run bootstrap; verify `backend.hcl` values |
| `ansible unreachable` | SG rules block SSH, wrong IP in inventory | Check `admin_cidrs` in `terraform.tfvars`; verify `.env` was generated |
| Prometheus target DOWN | SG blocking port 3000 or 9100 from monitoring SG | Check cross-SG `aws_security_group_rule` resources in `security/main.tf` |
| Jaeger target DOWN in Prometheus | Jaeger service not started | SSH to monitoring host: `sudo systemctl status jaeger`; check `/tmp/jaeger-*.tar.gz` download |
| Jaeger UI empty (no services) | App container not exporting traces | Verify `OTEL_EXPORTER_OTLP_ENDPOINT` env var is set on the container; check SG rule `monitoring_otlp_from_deploy` (port 4317) |
| `trace_id` missing from CloudWatch logs | App running without OTel endpoint | Set `MONITORING_HOST_DNS` in Jenkins job env; redeploy via pipeline |
| Alertmanager not receiving | `prometheus.yml` alertmanager target wrong | Confirm `localhost:9093` or monitoring-private-IP |
| Slack alerts not firing | Webhook URL wrong or secret not decrypted | Check `vault_alertmanager_slack_webhook_url` in vault; `amtool check-config` on monitoring host |
| ECR login failed | Instance role lacks ECR permissions | Confirm `iam/main.tf` jenkins role has ECR policy |
| Trivy not found on Jenkins | Ansible Jenkins role didn't complete | Re-run `./run-playbook.sh --tags trivy` |
| Container logs missing in CloudWatch | `awslogs` driver not configured | Re-run deploy Ansible role; check Docker daemon.json on deploy host |

---

## Incident Response

1. Rotate any compromised secret: vault password → edit `vault.yml` → `ansible-vault rekey` → redeploy with `./run-playbook.sh`
2. Revoke IAM sessions: `aws iam create-access-key` (new) → `aws iam delete-access-key` (old)
3. Audit events: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<principal>`
4. GuardDuty findings: `aws guardduty list-findings --detector-id <id>` → investigate → archive
5. Rebuild from clean commit after all security scans pass
