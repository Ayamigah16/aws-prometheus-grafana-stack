# Jenkins LTS CI/CD Pipeline — DevSecOps + IaC + Observability

![Branch](https://img.shields.io/badge/branch-feat%2Fsecurity--gitops-blue)
![IaC](https://img.shields.io/badge/IaC-Terraform-7B42BC)
![Config](https://img.shields.io/badge/Config-Ansible-EE0000)
![Runtime](https://img.shields.io/badge/Runtime-ECS%20Fargate-FF9900)
![SAST](https://img.shields.io/badge/SAST-Bandit%20%2B%20SonarQube-4E9BCD)
![SCA](https://img.shields.io/badge/SCA-pip--audit%20%2B%20OWASP%20DC-green)

A production-grade, security-first CI/CD pipeline for a containerised Flask application on AWS.
The project spans infrastructure provisioning, configuration management, a 17-stage Jenkins pipeline
with five enforced security gates, ECS Fargate deployment, and full-stack observability (metrics,
traces, and logs).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Repository Layout](#2-repository-layout)
3. [Pipeline Stages](#3-pipeline-stages)
4. [Security Controls](#4-security-controls)
5. [Observability Stack](#5-observability-stack)
6. [Infrastructure](#6-infrastructure)
7. [Setup Guide](#7-setup-guide)
8. [Verification Checklist](#8-verification-checklist)
9. [Rollback Procedure](#9-rollback-procedure)
10. [Reference Documentation](#10-reference-documentation)

---

## 1. Architecture Overview

```
  Developer Workstation
  ┌───────────────────────────────────┐
  │  git commit                       │
  │    → pre-commit hooks             │
  │        • Bandit (HIGH blocks)     │
  │        • Gitleaks (secrets)       │
  │        • terraform fmt/validate   │
  │        • ansible-lint             │
  └────────────┬──────────────────────┘
               │ git push
               ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  Jenkins EC2  (17-stage declarative pipeline)                   │
  │                                                                 │
  │  Secret Scan → Install → Tests → Bandit Report                 │
  │    → pip-audit → OWASP DC → SonarQube → Quality Gate           │
  │    → Docker Build → SBOM → Trivy → Push → ECS Deploy           │
  │    → Smoke Test → Cleanup                                       │
  └────────┬─────────────────────┬───────────────────┬─────────────┘
           │                     │                   │
           ▼                     ▼                   ▼
  ┌────────────────┐   ┌──────────────────┐  ┌──────────────────────┐
  │  Amazon ECR    │   │  ECS Fargate     │  │  Monitoring EC2      │
  │  (immutable    │   │  Cluster         │  │  • Prometheus :9090  │
  │   image tags)  │   │  ┌────────────┐  │  │  • Grafana    :3000  │
  │  Scan-on-push  │   │  │ Tasks (×N) │  │  │  • Alertmanager:9093 │
  │  Lifecycle:    │   │  └─────┬──────┘  │  │  • Jaeger     :16686 │
  │  keep 10 tags  │   │        │         │  │  • SonarQube  :9000  │
  └────────────────┘   │  ┌─────▼──────┐  │  └────────────┬─────────┘
                        │  │    ALB     │  │               │
                        │  │  HTTP :80  │  │  ◄────────────┘
                        │  └────────────┘  │  Prometheus scrapes
                        └──────────────────┘  OTLP traces ingest
```

**Key design decisions:**

- **Shift-left security** — Bandit and Gitleaks run as pre-commit hooks on the developer's
  workstation, before code ever reaches the pipeline queue. CI reinforces and extends these
  checks rather than being the first line of defence.
- **Layered SCA** — pip-audit provides a fast (<10 s) early exit on known CVEs; OWASP
  Dependency-Check then performs a deep NVD-backed scan for compliance-grade evidence.
- **SonarQube Quality Gate as the CI gate** — Bandit findings, coverage data, and native
  analysis are consolidated in SonarQube. One gate, one dashboard, one place to tune noise.
- **ECS Fargate** — no instance management, per-task IAM roles, rolling updates with automatic
  rollback via `aws ecs wait services-stable`.
- **Immutable image tags** — ECR `IMMUTABLE` mutability setting ensures a deployed image
  cannot be silently overwritten.

---

## 2. Repository Layout

```
.
├── app/                            Flask application
│   ├── app.py                      OTel-instrumented Flask app
│   ├── Dockerfile                  Multi-stage, non-root, read-only FS
│   ├── .dockerignore               Excludes dev deps, .venv, secrets
│   ├── requirements.txt            Production dependencies
│   └── requirements-dev.txt        pytest, bandit, pip-audit, pre-commit
│
├── tests/                          pytest unit tests
│
├── Jenkinsfile                     17-stage declarative pipeline
├── .pre-commit-config.yaml         Local dev security hooks
├── .gitleaks.toml                  Secret scan config (allowlist for vault)
├── sonar-project.properties        SonarQube scanner config
│
├── infra/
│   ├── ecs/
│   │   └── task-definition.json    ECS task def template (rendered at deploy)
│   │
│   ├── terraform/
│   │   ├── bootstrap/              S3 + DynamoDB remote state backend
│   │   └── aws/                    Full AWS stack
│   │       ├── modules/
│   │       │   ├── compute/        EC2 instances (Jenkins, Monitoring)
│   │       │   ├── network/        VPC, two public subnets (multi-AZ for ALB)
│   │       │   ├── security/       Security groups (EC2, ALB, ECS tasks)
│   │       │   ├── iam/            Instance profiles + roles
│   │       │   ├── ecr/            Container registry + lifecycle policy
│   │       │   ├── key_pair/       SSH key pair
│   │       │   ├── security_services/  CloudTrail + GuardDuty
│   │       │   └── ecs/            Fargate cluster, ALB, service, CW alarms
│   │       ├── terraform.tfvars.example
│   │       └── backend.hcl.example
│   │
│   ├── ansible/
│   │   ├── playbooks/site.yml      Runs all roles in order
│   │   ├── group_vars/all.yml      Stack-wide variables
│   │   ├── group_vars/all/
│   │   │   └── vault.yml.example   Secret template (encrypt before committing)
│   │   └── roles/
│   │       ├── common/             OS baseline packages
│   │       ├── jenkins/            Jenkins LTS + Docker + plugins
│   │       ├── monitoring/         Prometheus + Alertmanager + Grafana + Jaeger
│   │       ├── node_exporter/      Prometheus Node Exporter (systemd)
│   │       └── sonarqube/          SonarQube 9.9 LTS + PostgreSQL 15 (Docker Compose)
│   │
│   └── observability/              Prometheus rules + Grafana dashboards
│       ├── grafana/dashboards/
│       │   ├── devsecops-observability-dashboard.json
│       │   └── advanced-observability-dashboard.json
│       └── alertmanager/alertmanager.yml
│
├── docs/
│   ├── devsecops-observability-security-stack.md
│   └── secure-cicd-ecs-pipeline.md
│
├── runbook.md                      Ordered operations guide
└── scripts/
    └── deploy_remote.sh            EC2 utility (kept for reference)
```

---

## 3. Pipeline Stages

The `Jenkinsfile` defines 17 stages executed in order. Security gates are marked — a gate
failure aborts the pipeline before reaching deployment.

| # | Stage | Gate? | Output |
|---|-------|-------|--------|
| 1 | **Checkout** | Branch policy check | — |
| 2 | **Initialize** | Env var validation | — |
| 3 | **Secret Scan** | ✅ Any credential → FAIL | `reports/gitleaks-report.json` |
| 4 | **Install / Build** | `pip check` (dependency conflict) | `.venv/` |
| 5 | **Unit Tests** | ✅ Coverage < 80% → FAIL | `reports/coverage.xml` |
| 6 | **SAST — Bandit (Report)** | Report only (all severities) | `reports/bandit-report.json` |
| 7 | **SCA — pip-audit** | ✅ Any CVE → FAIL | `reports/pip-audit-report.json` |
| 8 | **SCA — OWASP Dependency-Check** | ✅ CVSS ≥ 7.0 → FAIL | `reports/dependency-check-report.*` |
| 9 | **SAST — SonarQube** | Imports Bandit + coverage; submits scan | — |
| 10 | **Quality Gate** | ✅ SonarQube QG failed → FAIL | — |
| 11 | **Docker Build** | Build-arg provenance labels | Local image |
| 12 | **SBOM — Syft** | No gate (supply chain provenance) | `reports/sbom.json` |
| 13 | **Image Scan — Trivy** | ✅ CRITICAL/HIGH CVE in image → FAIL | `reports/trivy-report.json` |
| 14 | **Push Image** | ECR push with immutable tag | `<registry>/<app>:<build>-<sha>` |
| 15 | **ECS Deploy** | Rolling update → wait stable | `task-def-arn.txt` |
| 16 | **Smoke Test** | ✅ `GET /health` ≠ 200 (12 attempts) → FAIL | — |
| 17 | **Cleanup** | Deregister old task def revisions; prune Docker | — |

All reports are archived as Jenkins build artefacts. OWASP DC findings are also rendered as a
trend graph on the build page via the `dependency-check-jenkins-plugin`.

---

## 4. Security Controls

### 4a. Pre-commit (developer workstation)

Install once per workstation after cloning:

```bash
pip install pre-commit   # included in requirements-dev.txt
pre-commit install
```

| Hook | Trigger | Version |
|------|---------|---------|
| Bandit SAST | HIGH severity Python finding blocks commit | `bandit==1.7.7` |
| Gitleaks | Any committed credential blocks commit | `v8.24.0` |
| Terraform format | HCL formatting drift | `pre-commit-terraform v1.92.0` |
| Terraform validate | Broken HCL syntax | — |
| Ansible Lint | Playbook/role best-practice violations | `v24.2.0` |
| Standard hooks | Trailing whitespace, YAML/JSON syntax, large files, private keys | `v4.6.0` |

### 4b. CI/CD pipeline gates

| Gate | Tool | Threshold | Rationale |
|------|------|-----------|-----------|
| Secret scan | Gitleaks v8.24.0 | Any finding | Secrets in git history cannot be cleanly expunged |
| SCA (fast) | pip-audit | Any CVE | OSV/PyPI advisories; fails early before slow OWASP DC run |
| SCA (deep) | OWASP DC v10.0.4 | CVSS ≥ 7.0 | NVD-backed scan; HIGH + CRITICAL to reduce noise |
| SAST | SonarQube 9.9 Quality Gate | Configured in SQ UI | Consolidates Bandit findings + coverage; one authoritative gate |
| Coverage | pytest-cov | < 80% | Before Bandit report — low coverage must not hide unscanned code |
| Image scan | Trivy v0.60.0 | CRITICAL/HIGH CVE | Runs pre-push; blocks shipping a known-vulnerable image to ECR |

### 4c. Infrastructure security

| Control | Implementation |
|---------|---------------|
| Container hardening | Non-root user, `readonlyRootFilesystem: true`, all capabilities dropped |
| ECS IAM | Execution role: ECR pull + log group management only. Task role: CW log writes scoped to one ARN |
| ECS network | Task SG accepts inbound only from ALB SG on port 3000 |
| Remote state | S3 AES-256 encryption + versioning + public access block + DynamoDB locking |
| EC2 IAM | Least-privilege instance profiles; SSM access for ops |
| ECR | `IMMUTABLE` tags; `scan_on_push = true`; lifecycle keeps 10 tagged; expires untagged after 1 day |
| CloudTrail | Multi-region trail; log file integrity validation; encrypted S3; Glacier at 90 d / expiry at 365 d |
| GuardDuty | Detector with S3 protection and EBS malware scanning; findings every 15 min |
| SBOM | CycloneDX JSON generated by Syft v1.19.0 per build; archived for supply chain audit |

---

## 5. Observability Stack

All components run on the **Monitoring EC2** host (t3.large).

### Signal coverage

| Signal | Tool | Port | What it answers |
|--------|------|------|-----------------|
| RED metrics | Prometheus + Grafana | `:9090` / `:3000` | Is the service healthy? Rate / error / latency right now? |
| Distributed traces | OpenTelemetry SDK → Jaeger | `:16686` (UI) | Which request was slow? Which code path was hit? |
| Structured logs | CloudWatch Logs (awslogs) | — | What did the app print for this exact request? |
| Host metrics | Node Exporter → Prometheus | `:9100` | Is the host resource-constrained? |
| Code quality | SonarQube | `:9000` | What are the open security hotspots and bugs? |
| Alerting | Alertmanager | `:9093` | Who gets notified and when? |

### Alert thresholds

| Metric | Threshold | Duration | Severity |
|--------|-----------|----------|----------|
| HTTP error rate | > 5% | 10 min | `critical` → Slack + email |
| p95 latency | > 300 ms | 10 min | `warning` → Slack |
| Host CPU | > 80% | 10 min | `warning` → Slack |
| ECS CPU high | > 80% | 5 min | CloudWatch alarm |
| ECS task count low | < 1 | 5 min | CloudWatch alarm |
| ALB 5xx rate | > 10% | 5 min | CloudWatch alarm |

### Trace-to-log correlation

Every HTTP request receives a `trace_id` and `span_id` via the OTel SDK. A `_TraceContextFilter`
injects both IDs into every structured JSON log line. Correlation workflow:

```
Alert fires in Grafana
  → open Advanced Observability dashboard
  → click high-latency data point
  → Jaeger trace panel shows the slow span
  → copy trace_id
  → filter CloudWatch Logs by trace_id
  → see exact log lines for that request
```

---

## 6. Infrastructure

### AWS resources (Terraform-provisioned)

| Resource | Module | Notes |
|----------|--------|-------|
| VPC + 2 public subnets (multi-AZ) | `network` | Two AZs required by ALB |
| Jenkins EC2 (t3.medium) | `compute` | Amazon Linux 2; Docker + Jenkins |
| Monitoring EC2 (t3.large) | `compute` | Prometheus, Grafana, Jaeger, SonarQube co-located |
| ECR repository | `ecr` | `IMMUTABLE` tags; scan-on-push |
| ECS Fargate cluster + ALB | `ecs` | Rolling update; Container Insights; CW alarms |
| Security groups | `security` | EC2 hosts, ALB, ECS tasks, cross-SG rules |
| IAM instance profiles + task roles | `iam` + `ecs` | Least-privilege per-role |
| SSH key pair | `key_pair` | Terraform-managed; private key gitignored |
| CloudTrail trail | `security_services` | Multi-region; encrypted S3 |
| GuardDuty detector | `security_services` | S3 + EBS protection |
| S3 + DynamoDB state backend | `bootstrap/` | Remote state with locking |

### Ansible roles

| Role | Applied to | Installs |
|------|-----------|---------|
| `common` | All hosts | Git, curl, jq, Python 3, AWS CLI |
| `jenkins` | Jenkins EC2 | Jenkins LTS, Docker Engine, Jenkins plugins |
| `monitoring` | Monitoring EC2 | Prometheus, Alertmanager, Grafana, Jaeger |
| `node_exporter` | Monitoring EC2 | Node Exporter (systemd) |
| `sonarqube` | Monitoring EC2 | SonarQube 9.9 LTS + PostgreSQL 15 (Docker Compose) |

---

## 7. Setup Guide

See [`runbook.md`](runbook.md) for full step-by-step instructions.

### Phase 1 — Bootstrap state backend

```bash
cd infra/terraform/bootstrap
terraform init && terraform apply
```

Creates the S3 bucket and DynamoDB table for remote state.

### Phase 2 — Provision AWS infrastructure

```bash
cp infra/terraform/aws/terraform.tfvars.example infra/terraform/aws/terraform.tfvars
cp infra/terraform/aws/backend.hcl.example      infra/terraform/aws/backend.hcl
# Edit both files with your values
cd infra/terraform/aws
terraform init -backend-config=backend.hcl
terraform apply
```

Note all outputs — required in Phase 5.

### Phase 3 — Prepare secrets

```bash
cp infra/ansible/group_vars/all/vault.yml.example \
   infra/ansible/group_vars/all/vault.yml
# Edit vault.yml — Jenkins admin password, Grafana password,
# Slack webhook, SMTP credentials, SonarQube DB password
ansible-vault encrypt infra/ansible/group_vars/all/vault.yml
```

### Phase 4 — Configure all hosts

```bash
cd infra/ansible && ./run-playbook.sh
```

Configures Jenkins + Docker, Prometheus + Grafana + Jaeger + Alertmanager, and SonarQube
on the monitoring host. SonarQube first boot takes 2–3 minutes while Elasticsearch initialises.

### Phase 5 — Configure Jenkins

**Manage Jenkins → Configure System:**

| Setting | Value |
|---------|-------|
| SonarQube server name | `SonarQube` |
| SonarQube server URL | `http://<monitoring_public_ip>:9000` |

**Manage Jenkins → Credentials:**

| Credential ID | Type | Value |
|---------------|------|-------|
| `sonar-auth-token` | Secret Text | SonarQube UI → My Account → Security → Generate Token |
| `nvd-api-key` | Secret Text | [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) |
| `git_credentials` | Username / Password | Git SCM credentials |

**Manage Jenkins → Global properties (environment variables):**

| Variable | Source |
|----------|--------|
| `REGISTRY` | `<account_id>.dkr.ecr.<region>.amazonaws.com` |
| `AWS_REGION` | your region (e.g. `eu-west-1`) |
| `ALB_DNS_NAME` | Terraform output `alb_dns_name` |
| `ECS_CLUSTER_NAME` | Terraform output `ecs_cluster_name` |
| `ECS_SERVICE_NAME` | Terraform output `ecs_service_name` |
| `ECS_EXECUTION_ROLE_ARN` | Terraform output `ecs_execution_role_arn` |
| `ECS_TASK_ROLE_ARN` | Terraform output `ecs_task_role_arn` |
| `ECS_LOG_GROUP` | Terraform output `ecs_log_group_name` |
| `MONITORING_HOST_DNS` | Terraform output `monitoring_public_dns` (enables OTLP) |

**SonarQube UI → Administration → Webhooks → Create:**

- URL: `http://<jenkins_public_ip>:8080/sonarqube-webhook/`

### Phase 6 — Developer workstation (one-time per clone)

```bash
pip install pre-commit   # already in requirements-dev.txt
pre-commit install
```

---

## 8. Verification Checklist

**Infrastructure**
- [ ] `terraform show` reports no pending changes
- [ ] CloudTrail trail active (AWS Console → CloudTrail → Trails)
- [ ] GuardDuty detector enabled (AWS Console → GuardDuty → Summary)

**Services**
- [ ] Prometheus targets UP at `http://<monitoring_ip>:9090/targets`
  (python-app, node-exporter, alertmanager, jaeger, sonarqube)
- [ ] Grafana at `http://<monitoring_ip>:3000` — both dashboards in sidebar
- [ ] Jaeger UI at `http://<monitoring_ip>:16686` — `secure-flask-app` in service list after first request
- [ ] SonarQube at `http://<monitoring_ip>:9000` — project `secure-flask-app` visible after first scan
- [ ] Alertmanager at `http://<monitoring_ip>:9093`

**Pipeline**
- [ ] All 17 stages green on first successful build
- [ ] Security reports archived: `gitleaks-report.json`, `bandit-report.json`,
  `pip-audit-report.json`, `dependency-check-report.html`, `trivy-report.json`,
  `sbom.json`, `coverage.xml`
- [ ] OWASP DC trend graph visible on the Jenkins build page
- [ ] SonarQube Quality Gate status shows **Passed**

**Deployment**
- [ ] ECR contains an immutable tag in format `<build>-<short-sha>`
- [ ] ECS service shows desired count == running count
- [ ] App returns `HTTP 200` at `http://<ALB_DNS_NAME>/health`
- [ ] CloudWatch log group `/ecs/jenkins-pipeline/secure-flask-app` contains structured JSON
  with `trace_id` field

---

## 9. Rollback Procedure

### ECS task definition rollback

The ECS service uses `lifecycle { ignore_changes = [task_definition] }` — Terraform does not
manage the active task definition. Jenkins registers a new revision on every deploy.

To roll back to a previous revision:

```bash
# List recent active revisions (most recent last)
aws ecs list-task-definitions \
  --family-prefix secure-flask-app \
  --status ACTIVE --sort ASC \
  --region eu-west-1

# Point the service at a specific revision
aws ecs update-service \
  --cluster jenkins-pipeline-cluster \
  --service jenkins-pipeline-service \
  --task-definition secure-flask-app:<PREVIOUS_REVISION> \
  --region eu-west-1

# Wait for stability
aws ecs wait services-stable \
  --cluster jenkins-pipeline-cluster \
  --services jenkins-pipeline-service \
  --region eu-west-1
```

### Smoke test automatic abort

The **Smoke Test** stage polls `GET /health` up to 12 times (10 s apart — 2 min total). If the
new task never returns `200`, the stage fails and the ECS service retains the last stable task
definition revision. No manual intervention needed for deploy-time failures.

### ECR image tag rollback

Immutable image tags (`<build>-<commit>`) let you reference any prior image. Update the
task definition template to pin the desired tag and register a new revision, or use
`aws ecs update-service --task-definition` directly as above.

---

## 10. Reference Documentation

| Document | Contents |
|----------|----------|
| [`runbook.md`](runbook.md) | Ordered step-by-step operations guide |
| [`docs/devsecops-observability-security-stack.md`](docs/devsecops-observability-security-stack.md) | Original observability and monitoring stack design |
| [`docs/secure-cicd-ecs-pipeline.md`](docs/secure-cicd-ecs-pipeline.md) | ECS Fargate + SAST/SCA/SBOM pipeline design, rationale, and test procedures |
| [`infra/terraform/aws/terraform.tfvars.example`](infra/terraform/aws/terraform.tfvars.example) | All Terraform input variables with Terraform output → Jenkins env var mapping |
| [`infra/ansible/group_vars/all/vault.yml.example`](infra/ansible/group_vars/all/vault.yml.example) | Secret variable template |
| [`sonar-project.properties`](sonar-project.properties) | SonarQube project config and report import paths |
| [`.pre-commit-config.yaml`](.pre-commit-config.yaml) | Pre-commit hook definitions and rationale |

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
