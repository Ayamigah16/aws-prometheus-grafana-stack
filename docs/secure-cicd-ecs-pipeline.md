# Secure CI/CD Pipeline — ECS Fargate + SAST/SCA/SBOM

## 1. Overview

This document describes the hardened CI/CD pipeline extension built on top of the existing
DevSecOps stack. It replaces the EC2-direct Docker deployment model with an Amazon ECS Fargate
rolling-update deployment and integrates four mandatory security gates that block deployment
on any detected vulnerabilities, secrets, or misconfigurations.

### What changed at a glance

| Area | Before | After |
|---|---|---|
| Runtime | Docker on a single EC2 instance | ECS Fargate (managed, serverless containers) |
| Load balancing | Nginx/direct port 80 on EC2 | Application Load Balancer (multi-AZ) |
| Secret scanning | None | Gitleaks (blocks on any committed credential) |
| SAST | Bandit (no report, exit-only) | Bandit with JSON report archived per build |
| SCA | pip-audit (no report) | pip-audit with JSON report archived per build |
| Image scan | Disabled stub | Trivy (full JSON report, CRITICAL/HIGH gate) |
| SBOM | None | Syft CycloneDX JSON, archived per build |
| ECR lifecycle | Keep 30 (any tag) | Keep 10 tagged, expire untagged after 1 day |
| Task def versioning | N/A | Jenkins registers a new ECS revision each build |
| Old revision cleanup | N/A | Jenkins deregisters all but last 5 revisions |
| CloudWatch logs | Docker `awslogs` on EC2 | Native ECS `awslogs` log driver via task definition |

---

## 2. Architecture

```
             Developer pushes code
                      │
              ┌───────▼────────┐
              │  GitHub repo   │
              └───────┬────────┘
                      │  webhook
              ┌───────▼────────┐
              │  Jenkins EC2   │  (existing)
              │                │
              │ 1. Gitleaks    │◄─ blocks on any secret
              │ 2. Bandit      │◄─ blocks on HIGH+ SAST
              │ 3. pip-audit   │◄─ blocks on any CVE (SCA)
              │ 4. docker build│
              │ 5. Syft SBOM   │
              │ 6. Trivy scan  │◄─ blocks on CRIT/HIGH CVE
              │ 7. ECR push    │
              │ 8. ECS deploy  │
              │ 9. Smoke test  │
              └───────┬────────┘
                      │  aws ecr push
              ┌───────▼────────┐
              │  Amazon ECR    │  (existing, scan-on-push)
              └───────┬────────┘
                      │  aws ecs update-service
              ┌───────▼────────┐
              │  ECS Cluster   │  (new — Fargate, Container Insights)
              │  ┌───────────┐ │
              │  │  Task rev │ │  rendered task-definition.json
              │  │  (Fargate)│ │
              │  └─────┬─────┘ │
              └────────┼───────┘
                       │
              ┌────────▼───────┐
              │      ALB       │  (new — internet-facing, HTTP/80)
              └────────┬───────┘
                       │
                 ┌─────▼──────┐
                 │ Flask app  │  container port 3000
                 │ /health    │
                 │ /metrics   │
                 └─────┬──────┘
                       │ awslogs
              ┌────────▼───────┐
              │  CloudWatch    │  /ecs/<project>/<app>
              │  Logs          │
              └────────────────┘
                       │ OTLP gRPC (if MONITORING_HOST_DNS set)
              ┌────────▼───────┐
              │  Jaeger        │  (existing Monitoring EC2)
              └────────────────┘
```

---

## 3. Security Gates

There are four gates in the pipeline. **Any gate failure immediately aborts the run.**
No image is pushed. No ECS update happens. Reports are always archived even on failure.

### 3.1 Secret Scanning — Gitleaks

**Tool:** `zricethezav/gitleaks:v8.24.0`  
**Stage:** runs immediately after checkout, before any build work

**Why it's first:** The cheapest possible gate. A secret scan takes ~5 seconds and requires no
build artefacts. Running it first means a developer who accidentally commits an API key gets
blocked before the Jenkins node wastes minutes building and scanning.

**What it catches:**
- AWS access keys / secret keys
- Generic API tokens and OAuth secrets
- SSH private keys (PEM blocks)
- Database connection strings with embedded passwords
- Any pattern from the [Gitleaks default ruleset](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) (~100+ rules)

**Allowlisting:** `.gitleaks.toml` explicitly permits:
- `$ANSIBLE_VAULT;1.1;AES256` blobs — these are ciphertext, not raw secrets
- `infra/ansible/group_vars/all/vault.yml` — entire file is encrypted ciphertext

**Output:** `reports/gitleaks-report.json` — JSON array of any findings

---

### 3.2 SAST — Bandit

**Tool:** `bandit` (in `requirements-dev.txt`, runs inside existing Python docker container)  
**Stage:** after `pip install`, before docker build

**Why:** Static Application Security Testing analyses source code for common Python security
anti-patterns without executing it. It catches issues that unit tests don't cover:
- `subprocess` calls without `shell=False`
- Use of `eval()` or `exec()`
- Hardcoded passwords or cryptographic weaknesses
- Insecure use of `random` vs `secrets` for security-sensitive operations
- `flask.debug=True` in production

**Gate threshold:** `--severity-level high`  
Any finding with severity HIGH or CRITICAL fails the build. MEDIUM findings are reported
but do not block — this avoids excessive false-positive noise for a small-team project.

**Output:** `reports/bandit-report.json`

---

### 3.3 SCA — pip-audit

**Tool:** `pip-audit` (in `requirements-dev.txt`)  
**Stage:** runs alongside Bandit (same container, separate command)

**Why:** Software Composition Analysis checks the *third-party dependency tree* against the
[OSV (Open Source Vulnerabilities)](https://osv.dev) and PyPA advisory databases. This is
distinct from SAST (which analyses your own code) — a perfectly-written Flask app can still
ship a critical CVE in a pinned dependency like `requests` or `protobuf`.

**Gate threshold:** any CVE blocks the build. There is no severity filter — even a LOW CVE
in a direct dependency signals that the `requirements.txt` pinning needs updating.

**How to fix a blocking CVE:**
1. Read the `reports/pip-audit-report.json` finding
2. Check PyPI for the patched version
3. Update the pin in `app/requirements.txt`
4. Re-run the pipeline

**Evidence of gate effectiveness:**  
Pin `requests==2.6.0` in `app/requirements.txt` → pip-audit raises CVE-2014-1829,
CVE-2018-18074, blocking deployment. Restore `requests==2.32.5` → gate passes.

**Output:** `reports/pip-audit-report.json`

---

### 3.4 Container Image Scan — Trivy

**Tool:** `aquasec/trivy:0.60.0`  
**Stage:** runs after `docker build`, before ECR push

**Why it runs after build (not via ECR scan-on-push):** ECR scan-on-push runs asynchronously
**after** the image is uploaded. By the time Jenkins could query the results, the pipeline
might have already deployed. Running Trivy locally before the push means:
1. The gate is synchronous — the push itself is blocked, not just the deploy
2. No image ever lands in ECR with known critical CVEs
3. Faster feedback (seconds vs. waiting for ECR async scan)

ECR scan-on-push remains enabled as a second-layer safety net.

**Gate threshold:** `--severity CRITICAL,HIGH --exit-code 1`  
Any CRITICAL or HIGH CVE in the final image (including OS packages, Python packages, and
non-Python binaries in the Alpine base) fails the build.

**Why Alpine matters:** `python:3.12-alpine` has a smaller surface area than
`python:3.12-slim` (Debian-based). Fewer packages = fewer CVE candidates. Combined with
multi-stage build (dependencies only in the builder stage; runtime stage has no build tools),
the final image is as small as practically possible.

**Output:** `reports/trivy-report.json`

---

## 4. SBOM — Syft

**Tool:** `anchore/syft:v1.19.0`  
**Stage:** runs after `docker build`, before Trivy (no gate — informational)  
**Format:** CycloneDX JSON

**Why generate an SBOM:**  
A Software Bill of Materials is a machine-readable inventory of every component in the
container image: OS packages, Python packages, their versions, and their licences.

Benefits:
- **Incident response:** When a new CVE is disclosed (e.g. a new PyPI advisory for `flask`),
  you can audit your SBOM inventory rather than rebuilding and re-scanning every image
- **Licence compliance:** CycloneDX format includes licence identifiers (MIT, Apache-2.0,
  GPL) — legal/procurement teams can scan it automatically
- **Supply chain provenance:** Archived alongside each build, the SBOM is a point-in-time
  record of exactly what shipped
- **Regulatory requirements:** SOC 2, PCI DSS, and NIST SSDF all reference SBOM generation
  as a supply chain security control

**Output:** `reports/sbom.json` (CycloneDX)

---

## 5. ECS Fargate Deployment

### 5.1 Why ECS Fargate instead of continuing with EC2-direct Docker

| Concern | EC2-direct Docker | ECS Fargate |
|---|---|---|
| **Availability** | Single container, single host — one crash = outage | ECS restarts failed tasks automatically; service desired count maintained |
| **Scaling** | Manual — SSH in and change replica count | `aws ecs update-service --desired-count N` |
| **Deployment atomicity** | Custom blue/green script in `deploy_remote.sh` | Rolling update built into ECS; ECS waits for new task healthy before draining old |
| **Health checks** | Script polls `/health` in a loop | ALB target group health checks; task unhealthy = ECS replaces it |
| **Infrastructure blast radius** | Deploy EC2 failure takes down the app | ECS tasks isolated from the underlying Fargate compute |
| **Log aggregation** | Docker `awslogs` driver, manually configured | `logConfiguration.awslogs` in task definition — automatic, version-controlled |
| **IAM** | Single EC2 instance profile | Per-task IAM role — fine-grained, least-privilege, auditable |
| **Observability** | ECS Container Insights off | Container Insights enabled on cluster — CPU/memory per task, service event stream |

### 5.2 Task Definition Template (`infra/ecs/task-definition.json`)

The task definition is a JSON file with `${VAR}` tokens that Jenkins renders at deploy time
using a Python one-liner. This approach:

- **Keeps the single source of truth in git** — the template is version-controlled and
  diffable; no ad-hoc AWS Console edits
- **Avoids hardcoding account IDs** — `${EXECUTION_ROLE_ARN}`, `${TASK_ROLE_ARN}`, and
  `${LOG_GROUP}` are injected from Terraform outputs stored in Jenkins env vars
- **Parameterises the image URI** — `${IMAGE_URI}` = `<ECR_URL>/<repo>:<build>-<commit>`,
  ensuring the exact pinned image tag is deployed, not `latest`
- **Carries OTLP config forward** — `${OTLP_ENDPOINT}` is set when `MONITORING_HOST_DNS`
  is configured in Jenkins, enabling Jaeger traces from ECS tasks to the existing
  Monitoring EC2

Security hardening in the task definition:
```json
"readonlyRootFilesystem": true,
"linuxParameters": {
    "capabilities": { "drop": ["ALL"] },
    "initProcessEnabled": true,
    "tmpfs": [{ "containerPath": "/tmp", "size": 10,
                "mountOptions": ["noexec", "nosuid", "nodev"] }]
}
```
These four settings — read-only root, all capabilities dropped, no-exec `/tmp`, and
PID-1 init process — mirror the Docker hardening flags already in `deploy_remote.sh`,
ensuring the same security posture is preserved in ECS.

### 5.3 Rolling Deployment Flow

```
Jenkins registers new task definition revision
         │
         ▼
aws ecs update-service --task-definition <new ARN>
         │
         ▼
ECS scheduler starts new Fargate task with new image
         │
         ▼
ALB target group health check polls /health every 30s
         │
    ┌────▼─────────────────────┐
    │ New task healthy (200)?  │
    │    Yes ──────────────────┼──► ECS drains old task → deregisters from ALB
    │    No (after 3 retries)  │
    └────────────────┬─────────┘
                     ▼
             ECS marks task STOPPED
             Old revision continues serving traffic
             Jenkins `aws ecs wait services-stable` times out → pipeline FAILS
```

The `deployment_minimum_healthy_percent = 50` and `deployment_maximum_percent = 200`
settings allow ECS to run old and new tasks simultaneously during the rolling update,
ensuring zero downtime even on a `desired_count = 1` service.

### 5.4 ALB

**Why an ALB and not direct access:**
- Health-check-based traffic routing: ECS tasks only receive traffic after they pass the
  ALB target group health check
- Single stable DNS name (`ALB_DNS_NAME` Terraform output) — does not change when tasks
  are replaced or the ECS service is updated
- Future path: HTTPS termination, WAF attachment, and blue/green CodeDeploy are all
  ALB features; the foundation is already in place

### 5.5 IAM Roles — Least Privilege

Two separate IAM roles are created by the ECS module:

**Execution Role** (`ecs-execution-role`): trusted by `ecs-tasks.amazonaws.com`, permits:
- `AmazonECSTaskExecutionRolePolicy` (ECR image pull, CloudWatch log stream creation)
- `AmazonEC2ContainerRegistryReadOnly` (explicit ECR read access)

**Task Role** (`ecs-task-role`): trusted by `ecs-tasks.amazonaws.com`, permits only:
- `logs:CreateLogStream` and `logs:PutLogEvents` scoped to the specific log group ARN

The app container assumes the Task Role at runtime. It has **no** EC2, ECS, S3, or IAM
permissions. If the container is compromised, the blast radius is limited to writing logs
to one specific CloudWatch log group.

---

## 6. Terraform Changes

### 6.1 New module: `infra/terraform/aws/modules/ecs/`

| Resource | Why |
|---|---|
| `aws_ecs_cluster` | Cluster with Container Insights enabled — gives per-task CPU/memory metrics in CloudWatch |
| `aws_ecs_cluster_capacity_providers` | Registers FARGATE and FARGATE_SPOT; FARGATE is the default base |
| `aws_cloudwatch_log_group` | Dedicated log group `/ecs/<project>/<app>` with 30-day retention |
| `aws_iam_role.execution` | Minimal execution role — pulls image, creates log streams |
| `aws_iam_role.task` | Runtime role — logs only, scoped to this log group |
| `aws_lb` | Internet-facing ALB across both public subnets |
| `aws_lb_target_group` | `ip` target type (required for awsvpc/Fargate); `/health` health check |
| `aws_lb_listener` | HTTP/80 → forward to target group |
| `aws_ecs_task_definition` | Bootstrap revision — Jenkins replaces this on first deploy |
| `aws_ecs_service` | Rolling update; `lifecycle { ignore_changes = [task_definition, desired_count] }` |
| `aws_cloudwatch_metric_alarm` ×3 | CPU high, tasks low, ALB 5xx — feeds existing Grafana/Alertmanager setup |

**`lifecycle { ignore_changes = [task_definition, desired_count] }`**  
This is a critical Terraform design decision. Without it, every `terraform apply` would
reset the ECS service back to the bootstrap task definition, undoing every Jenkins deploy.
The `ignore_changes` annotation means Terraform provisions the initial service and then
deliberately yields control of `task_definition` and `desired_count` to Jenkins.

### 6.2 Network module — second public subnet

ALBs require a minimum of two subnets in two different Availability Zones. The network
module was extended with `aws_subnet.public_b` in `availability_zone_b` (always
`data.aws_availability_zones.available.names[1]`). A CIDR variable `public_subnet_cidr_b`
defaults to `10.20.2.0/24` (non-overlapping with the original `10.20.1.0/24`).

### 6.3 Security module — ALB and ECS task security groups

| Security Group | Inbound | Outbound | Why |
|---|---|---|---|
| `alb-sg` | 80/tcp from `0.0.0.0/0` | all | ALB receives public HTTP traffic |
| `ecs-tasks-sg` | 3000/tcp from `alb-sg` only | all | Tasks only accessible via ALB; direct internet access blocked |

The ECS tasks security group has no inbound rule from `0.0.0.0/0`. Even though Fargate
tasks have a public IP (`assign_public_ip = true` for ECR pull and OTLP export), they
cannot be directly reached from the internet — the security group enforces this.

### 6.4 ECR lifecycle policy tightened

| | Before | After | Why |
|---|---|---|---|
| Tagged images | Keep any 30 | Keep 10 | A 14-stage pipeline that ships ~10 builds/day would accumulate 300 images in a month; 10 gives enough rollback headroom |
| Untagged images | Not addressed | Expire after 1 day | Failed or test builds produce untagged layers; these have no rollback value and incur storage cost |

---

## 7. Post-`terraform apply` Setup

After running `terraform apply` in `infra/terraform/aws/`, capture the outputs and add them
as Jenkins Global Environment Variables (Manage Jenkins → Configure System → Global
Properties → Environment variables):

```
REGISTRY              = <ecr_repository_url>      # existing
AWS_REGION            = eu-west-1                 # existing
ALB_DNS_NAME          = <alb_dns_name>
ECS_CLUSTER_NAME      = <ecs_cluster_name>
ECS_SERVICE_NAME      = <ecs_service_name>
ECS_EXECUTION_ROLE_ARN = <ecs_execution_role_arn>
ECS_TASK_ROLE_ARN     = <ecs_task_role_arn>
ECS_LOG_GROUP         = <ecs_log_group_name>
MONITORING_HOST_DNS   = <monitoring_public_dns>   # existing; enables OTLP
```

The pipeline validates all required variables in the Initialize stage and fails fast
with an explicit error listing which ones are missing.

---

## 8. Pipeline Stage Reference

| # | Stage | Gate? | Blocks on | Output |
|---|---|---|---|---|
| 1 | Checkout | — | Branch policy | — |
| 2 | Initialize | ✓ | Missing required env vars | — |
| 3 | **Secret Scan** | ✓ | Any committed credential | `reports/gitleaks-report.json` |
| 4 | Install / Build | — | `pip check` conflicts | — |
| 5 | **Unit Tests** | ✓ | Coverage < 80% | `reports/coverage.xml` |
| 6 | **SAST — Bandit** | ✓ | HIGH+ finding | `reports/bandit-report.json` |
| 7 | **SCA — pip-audit** | ✓ | Any CVE | `reports/pip-audit-report.json` |
| 8 | Docker Build | — | Build failure | local image |
| 9 | SBOM — Syft | — | — (informational) | `reports/sbom.json` |
| 10 | **Image Scan — Trivy** | ✓ | CRITICAL/HIGH CVE | `reports/trivy-report.json` |
| 11 | Push Image | — | ECR auth failure | ECR image tag |
| 12 | ECS Deploy | ✓ | Service fails to stabilise | task-def ARN |
| 13 | Smoke Test | ✓ | `/health` not 200 after 12 retries | — |
| 14 | Cleanup | — | — | deregisters old revisions |

All `reports/` artifacts are archived by Jenkins `archiveArtifacts` in the `post { always }`
block — they are preserved and downloadable even when the build fails at a gate.

---

## 9. Inject-a-Vulnerability Test

This is the required evidence of the gate working correctly.

### Inject (pipeline should BLOCK)

In `app/requirements.txt`, change:
```
requests==2.32.5
```
to:
```
requests==2.6.0
```

Push the branch. The **SCA — pip-audit** stage will fail:
```
Found 2 known vulnerabilities in 1 package
requests 2.6.0
  PYSEC-2014-41  CVE-2014-1829  GHSA-652x-xj99-gmcc
  PYSEC-2018-32  CVE-2018-18074  GHSA-x84v-xcm2-53pg
```
Pipeline exits — no docker build, no image push, no ECS update.

### Fix (pipeline should PASS)

Restore:
```
requests==2.32.5
```

Push the branch. pip-audit finds no CVEs, build continues, image is pushed, ECS is
updated, smoke test confirms `/health` returns 200.

---

## 10. Observability Continuity

The ECS deployment **preserves the existing observability stack**:

| Signal | Path | Notes |
|---|---|---|
| **Traces** | ECS task → OTLP gRPC → Jaeger (Monitoring EC2) | Enabled when `MONITORING_HOST_DNS` is set; same `FlaskInstrumentor.instrument_app()` code path |
| **Logs** | ECS task → `awslogs` → CloudWatch Logs `/ecs/<project>/<app>` | Log lines retain `trace_id`/`span_id` JSON fields for Jaeger correlation |
| **Metrics** | Prometheus on Monitoring EC2 scrapes ECS task `/metrics` | ECS tasks SG allows inbound 3000/tcp from monitoring SG; Prometheus job config in `prometheus.yml` must include the ECS task IP or service discovery |
| **Alarms** | CloudWatch metric alarms (CPU, task count, 5xx) | Feed into existing Alertmanager → Slack/email routing |

> **Note on Prometheus service discovery for ECS:**  
> Fargate task IPs are ephemeral. To scrape ECS tasks, use the
> [prometheus-ecs-discovery](https://github.com/teralytics/prometheus-ecs-discovery) sidecar
> or AWS CloudMap service discovery. For a single-task deployment, a static target set to the
> ALB DNS name works when the Prometheus job uses `metrics_path: /metrics`.

---

## 11. Files Created / Modified

```
aws-prometheus-grafana-stack/
├── Jenkinsfile                                          MODIFIED
├── .gitleaks.toml                                       NEW — Gitleaks allowlist config
├── infra/
│   ├── ecs/
│   │   └── task-definition.json                        NEW — ECS task def template
│   └── terraform/aws/
│       ├── main.tf                                      MODIFIED — wires ecs module
│       ├── variables.tf                                 MODIFIED — ECS + subnet vars
│       ├── outputs.tf                                   MODIFIED — ECS outputs
│       ├── terraform.tfvars.example                     MODIFIED — ECS examples + Jenkins mapping
│       └── modules/
│           ├── ecs/
│           │   ├── main.tf                              NEW
│           │   ├── variables.tf                         NEW
│           │   └── outputs.tf                           NEW
│           ├── network/
│           │   ├── main.tf                              MODIFIED — adds second subnet
│           │   ├── variables.tf                         MODIFIED — adds subnet_cidr_b, az_b
│           │   └── outputs.tf                           MODIFIED — adds public_subnet_ids list
│           ├── security/
│           │   ├── main.tf                              MODIFIED — adds ALB + ECS task SGs
│           │   └── outputs.tf                           MODIFIED — exposes new SG IDs
│           └── ecr/
│               └── main.tf                              MODIFIED — tighter lifecycle policy
```
