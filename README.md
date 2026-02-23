# Jenkins LTS CI/CD Pipeline (DevSecOps + IaC)

## Overview
This project implements a secure CI/CD pipeline for a containerized Flask app, with:
- Terraform for AWS infrastructure provisioning
- Ansible for server configuration
- Jenkins declarative pipeline for build, test, scan, push, deploy, verify, and cleanup
- S3 + DynamoDB backend for Terraform remote state and locking
- End-to-end observability: RED metrics (Prometheus), structured JSON logs (CloudWatch), and distributed tracing (OpenTelemetry → Jaeger)

### Why end-to-end observability matters
Metrics alone tell you *that* something is wrong (e.g. error rate spiked). Logs tell you *what* the error message was. But neither tells you *where* in the call path the problem originated or *why* a particular request was slow.

Distributed tracing closes this gap: every inbound HTTP request receives a `trace_id` and `span_id`. Those IDs are propagated through the app and embedded in every log line it emits, so a single click from an alert → Grafana panel → Jaeger trace → CloudWatch log stream gives you the full lifecycle of a failing or slow request — no manual log-grepping across systems.

Adding OpenTelemetry also future-proofs the instrumentation: the OTel SDK is vendor-neutral, so switching trace backends (Jaeger → Tempo → X-Ray) requires only a config change, not an app rewrite.

## Repository Layout
- `app` Flask application (Prometheus metrics + OTel instrumented)
- `tests` unit tests
- `Jenkinsfile` Jenkins declarative pipeline (14 stages, 4 security gates)
- `infra/terraform/bootstrap` Terraform state backend bootstrap (S3 + DynamoDB)
- `infra/terraform/aws` Terraform AWS stack (VPC, EC2 ×3, IAM, ECR, ECS, ALB, Security Groups, CloudTrail, GuardDuty)
  - `modules/compute` EC2 instances (Jenkins, Deploy, Monitoring)
  - `modules/network` VPC, subnets (two AZs), routing
  - `modules/security` Security groups (EC2 hosts, ALB, ECS tasks)
  - `modules/iam` Instance profiles and roles
  - `modules/ecr` Container registry with tightened lifecycle policy
  - `modules/key_pair` SSH key pair
  - `modules/security_services` CloudTrail trail + encrypted S3 bucket, GuardDuty detector
  - `modules/ecs` ECS Fargate cluster, ALB, service, task definition, CloudWatch alarms, IAM task roles
- `infra/ecs/task-definition.json` ECS task definition template (rendered by Jenkins at deploy time)
- `infra/ansible` Ansible playbooks and roles
  - `roles/common` OS baseline
  - `roles/jenkins` Jenkins LTS + plugins + Docker
  - `roles/deploy` Docker daemon (awslogs driver) + EC2 user setup
  - `roles/node_exporter` Prometheus Node Exporter (systemd)
  - `roles/monitoring` Prometheus + Alertmanager + Grafana + **Jaeger** (systemd)
- `infra/observability` Prometheus, Alertmanager, and Grafana config references
  - `grafana/dashboards/devsecops-observability-dashboard.json` — original RED metrics + host dashboard
  - `grafana/dashboards/advanced-observability-dashboard.json` — extended dashboard with Jaeger trace table panel
- `.gitleaks.toml` Gitleaks configuration (allowlist for ansible-vault ciphertext)
- `docs/` architecture reference and technical reports
  - `docs/devsecops-observability-security-stack.md` — original stack design
  - `docs/secure-cicd-ecs-pipeline.md` — **ECS Fargate + SAST/SCA/SBOM pipeline** (this extension)
- `scripts/cleanup_observability_security.sh` full teardown script
- `runbook.md` ordered setup and operations guide
- `screenshots` evidence placeholders

## Deployment Architecture
- **Jenkins EC2** (Amazon Linux 2) — runs CI/CD stages, pushes image to ECR, registers ECS task definition revisions, and triggers rolling ECS service updates.
- **ECR** — stores immutable, versioned image tags (`<build>-<commit>`); scan-on-push enabled; lifecycle keeps last 10 tagged images.
- **ECS Fargate cluster** — serverless container runtime; rolling update deployment; Container Insights enabled for per-task metrics.
- **Application Load Balancer** — internet-facing, HTTP/80; routes to ECS tasks only after they pass `/health` health checks; provides stable DNS regardless of task replacement.
- **Deploy EC2** (Amazon Linux 2) — still present for EC2-direct deployments; Docker daemon configured with the `awslogs` log driver. Node Exporter on port `9100` exposes host metrics.
- **Monitoring EC2** (Amazon Linux 2) — runs Prometheus (`:9090`), Alertmanager (`:9093`), Grafana (`:3000`), and **Jaeger all-in-one** (UI `:16686`, OTLP gRPC `:4317`, OTLP HTTP `:4318`). Prometheus scrapes the Flask app `/metrics` on port `80`, Node Exporter, Alertmanager, and Jaeger's own metrics endpoint. Alertmanager routes `warning` alerts to Slack and `critical` alerts to Slack + email.
- **OpenTelemetry instrumentation** — the Flask app is auto-instrumented via `opentelemetry-instrumentation-flask`. Every request creates a root span exported over OTLP gRPC to Jaeger. Trace IDs and span IDs are injected into every structured JSON log line by `_TraceContextFilter`, so CloudWatch log events are directly correlated to Jaeger traces.
- **CloudTrail** — multi-region trail logging all API calls to an encrypted, versioned S3 bucket (`<project>-cloudtrail-<account_id>`); lifecycle transitions logs to Glacier at 90 days and expires at 365 days.
- **GuardDuty** — detector enabled with S3 protection and EBS malware scanning; findings published every 15 minutes.
- **CloudWatch Logs** — Docker awslogs driver configured on deploy host; IAM inline policy on deploy role grants `logs:CreateLogGroup/Stream/PutLogEvents`.
- Jenkins deploys over SSH with health-checked staging (`3001`) and automatic rollback.

## Setup Steps
See [`runbook.md`](runbook.md) for the full step-by-step guide. Summary:

1. **Bootstrap state backend** — `cd infra/terraform/bootstrap && terraform init && terraform apply`
2. **Provision AWS infrastructure** — fill in `terraform.tfvars` and `backend.hcl`, then `terraform apply` in `infra/terraform/aws` (creates Jenkins EC2, Deploy EC2, Monitoring EC2, VPC, IAM, ECR, CloudTrail trail + S3 bucket, GuardDuty detector, CloudWatch Logs IAM policy — all automated)
3. **Prepare secrets** — copy `group_vars/all/vault.yml.example` → `vault.yml`, fill in passwords/webhooks, encrypt with `ansible-vault encrypt`
4. **Configure all hosts** — `cd infra/ansible && ./run-playbook.sh` (configures Jenkins, Deploy host with Docker awslogs driver, Node Exporter, and Monitoring stack with Prometheus + Alertmanager + Grafana + Jaeger)
5. **Configure Jenkins** — create `git_credentials`, `ec2_ssh`; set `REGISTRY`, `EC2_HOST`, `MONITORING_HOST_DNS`, and the six new ECS env vars from Terraform outputs (`ALB_DNS_NAME`, `ECS_CLUSTER_NAME`, `ECS_SERVICE_NAME`, `ECS_EXECUTION_ROLE_ARN`, `ECS_TASK_ROLE_ARN`, `ECS_LOG_GROUP`) — see [`infra/terraform/aws/terraform.tfvars.example`](infra/terraform/aws/terraform.tfvars.example) for the full mapping
6. **Verify observability and security** — Prometheus targets UP at `:9090/targets` (including `jaeger`), Alertmanager ready at `:9093`, Grafana at `:3000` (both dashboards auto-provisioned), Jaeger UI at `:16686`; CloudTrail trail active, GuardDuty detector enabled; ECS service running at `http://<ALB_DNS_NAME>/health`

## Observability Stack

| Signal | Tool | Where | What it answers |
|--------|------|--------|-----------------|
| Metrics (RED) | Prometheus + Grafana | Monitoring EC2 | *Is the service healthy? What is the rate/error/latency right now?* |
| Traces | OpenTelemetry SDK → Jaeger | Monitoring EC2 | *Which specific request was slow? Which code path was hit?* |
| Logs | CloudWatch Logs (awslogs) | AWS CloudWatch | *What did the app print for this exact request?* |
| Host metrics | Node Exporter → Prometheus | Deploy EC2 | *Is the host resource-constrained?* |

**Alert thresholds** (defined in `prometheus-alert-rules.yml.j2`):
- Error rate > 5% for **10 minutes** → `critical` → Slack + email
- p95 latency > **300 ms** for 10 minutes → `warning` → Slack
- CPU > 80% for 10 minutes → `warning`

**Correlation workflow**: Alert fires in Grafana → open the *Advanced Observability* dashboard → click a high-latency data point → Jaeger trace panel shows the slow span → copy `trace_id` → filter CloudWatch Logs by `trace_id` to find the exact log lines for that request.

## Security Controls

See [`docs/secure-cicd-ecs-pipeline.md`](docs/secure-cicd-ecs-pipeline.md) for detailed rationale on each gate.

**Pipeline gates (any failure blocks deployment):**
- **Secret scanning**: Gitleaks v8.24.0 — runs first, before any build work; blocks on any committed credential
- **SAST**: Bandit — HIGH+ severity Python static analysis; report archived
- **SCA**: pip-audit — any CVE in `requirements.txt` against OSV/PyPA databases; report archived
- **Image scan**: Trivy v0.60.0 — CRITICAL/HIGH CVEs in final container image, runs before ECR push; report archived
- **SBOM**: Syft v1.19.0 — CycloneDX JSON archived per build for supply chain provenance

**Infrastructure security:**
- **Container hardening**: non-root user, read-only FS, ALL capabilities dropped, no-exec `/tmp`
- **ECS IAM**: separate execution role (ECR pull + log group creation) and task role (log writes only — scoped to one log group ARN)
- **ECS task SG**: inbound only from ALB security group on port 3000 — no direct internet access to tasks
- **Remote state**: S3 encryption + public access block + DynamoDB locking
- **EC2 IAM**: Jenkins (ECR PowerUser + SSM), deploy host (ECR ReadOnly + SSM + CloudWatch Logs write)
- **CloudTrail**: multi-region API audit trail, log file integrity validation, AES-256-encrypted versioned S3 bucket
- **GuardDuty**: threat detection with S3 protection and EBS malware scanning
- **CloudWatch Logs**: ECS `awslogs` driver to `/ecs/<project>/<app>`; EC2 Docker `awslogs` driver to `/docker/secure-flask-app`

## Rollback Process
- Deployment uses staging container on `3001` before cutover.
- If staging health check fails, production remains unchanged.
- If production post-switch check fails, pipeline restarts previous image automatically.

## Verification Checklist
- Terraform apply succeeds for backend and AWS stack
- Ansible playbook succeeds for all three hosts (Jenkins, Deploy, Monitoring)
- Jenkins pipeline stages complete successfully
- ECR contains build tag and `latest`
- App responds at `http://<deploy_public_dns>/health`
- Prometheus targets UP at `http://<monitoring_public_dns>:9090/targets` (python-app, node-exporter, alertmanager, **jaeger**)
- Grafana dashboard loads at `http://<monitoring_public_dns>:3000` — both dashboards visible in the sidebar
- Jaeger UI accessible at `http://<monitoring_public_dns>:16686` — `secure-flask-app` appears in the *Service* dropdown after first request
- CloudWatch log group `/docker/secure-flask-app` contains structured JSON lines with `trace_id` field after first deploy
- CloudTrail trail status active in AWS Console (CloudTrail → Trails)
- GuardDuty detector enabled in AWS Console (GuardDuty → Summary)
