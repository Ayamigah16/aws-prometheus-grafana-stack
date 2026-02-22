# Jenkins LTS CI/CD Pipeline (DevSecOps + IaC)

## Overview
This project implements a secure CI/CD pipeline for a containerized Flask app, with:
- Terraform for AWS infrastructure provisioning
- Ansible for server configuration
- Jenkins declarative pipeline for build, test, scan, push, deploy, verify, and cleanup
- S3 + DynamoDB backend for Terraform remote state and locking

## Repository Layout
- `app` Flask application (Prometheus metrics instrumented)
- `tests` unit tests
- `Jenkinsfile` Jenkins declarative pipeline
- `infra/terraform/bootstrap` Terraform state backend bootstrap (S3 + DynamoDB)
- `infra/terraform/aws` Terraform AWS stack (VPC, EC2 ×3, IAM, ECR, Security Groups, CloudTrail, GuardDuty)
  - `modules/compute` EC2 instances
  - `modules/network` VPC, subnets, routing
  - `modules/security` Security groups
  - `modules/iam` Instance profiles and roles
  - `modules/ecr` Container registry
  - `modules/key_pair` SSH key pair
  - `modules/security_services` CloudTrail trail + encrypted S3 bucket, GuardDuty detector
- `infra/ansible` Ansible playbooks and roles
  - `roles/common` OS baseline
  - `roles/jenkins` Jenkins LTS + plugins + Docker
  - `roles/deploy` Docker daemon (awslogs driver) + EC2 user setup
  - `roles/node_exporter` Prometheus Node Exporter (systemd)
  - `roles/monitoring` Prometheus + Alertmanager + Grafana (systemd)
- `infra/observability` Prometheus, Alertmanager, and Grafana config references
- `docs` architecture reference and technical report
- `scripts/cleanup_observability_security.sh` full teardown script
- `runbook.md` ordered setup and operations guide
- `screenshots` evidence placeholders

## Deployment Architecture
- **Jenkins EC2** (Amazon Linux 2) — runs CI/CD stages, pushes image to ECR.
- **ECR** — stores scanned image tags, scan-on-push enabled.
- **Deploy EC2** (Amazon Linux 2) — runs the application container on port `80` (mapped from container port `3000`); Docker daemon configured with the `awslogs` log driver, streaming all container stdout/stderr to CloudWatch Logs (`/docker/secure-flask-app`). Node Exporter on port `9100` exposes host metrics.
- **Monitoring EC2** (Amazon Linux 2) — runs Prometheus (`:9090`), Alertmanager (`:9093`), and Grafana (`:3000`). Prometheus scrapes the Flask app `/metrics` on port `80` and Node Exporter via the VPC-internal DNS name. Alertmanager routes `warning` alerts to Slack and `critical` alerts to Slack + email.
- **CloudTrail** — multi-region trail logging all API calls to an encrypted, versioned S3 bucket (`<project>-cloudtrail-<account_id>`); lifecycle transitions logs to Glacier at 90 days and expires at 365 days.
- **GuardDuty** — detector enabled with S3 protection and EBS malware scanning; findings published every 15 minutes.
- **CloudWatch Logs** — Docker awslogs driver configured on deploy host; IAM inline policy on deploy role grants `logs:CreateLogGroup/Stream/PutLogEvents`.
- Jenkins deploys over SSH with health-checked staging (`3001`) and automatic rollback.

## Setup Steps
See [`runbook.md`](runbook.md) for the full step-by-step guide. Summary:

1. **Bootstrap state backend** — `cd infra/terraform/bootstrap && terraform init && terraform apply`
2. **Provision AWS infrastructure** — fill in `terraform.tfvars` and `backend.hcl`, then `terraform apply` in `infra/terraform/aws` (creates Jenkins EC2, Deploy EC2, Monitoring EC2, VPC, IAM, ECR, CloudTrail trail + S3 bucket, GuardDuty detector, CloudWatch Logs IAM policy — all automated)
3. **Prepare secrets** — copy `group_vars/all/vault.yml.example` → `vault.yml`, fill in passwords/webhooks, encrypt with `ansible-vault encrypt`
4. **Configure all hosts** — `cd infra/ansible && ./run-playbook.sh` (configures Jenkins, Deploy host with Docker awslogs driver, Node Exporter, and Monitoring stack with Prometheus + Alertmanager + Grafana)
5. **Configure Jenkins** — create `git_credentials`, `ec2_ssh`, set `REGISTRY` and `EC2_HOST` from Terraform outputs
6. **Verify observability and security** — Prometheus targets UP at `:9090/targets`, Alertmanager ready at `:9093`, Grafana at `:3000` (dashboard auto-provisioned); CloudTrail trail active, GuardDuty detector enabled, CloudWatch log group `/docker/secure-flask-app` receiving logs after first deploy

## Security Controls
- **Vulnerability scanning**: `pip-audit` (dependencies), `trivy fs` (filesystem), `trivy image` (container image)
- **Static analysis**: `bandit`
- **Container hardening**: non-root user, read-only FS, dropped Linux capabilities
- **Remote state**: S3 encryption + public access block + DynamoDB locking
- **IAM**: separate instance roles — Jenkins (ECR push + SSM), deploy host (ECR pull + SSM + CloudWatch Logs write)
- **CloudTrail**: multi-region API audit trail, log file integrity validation, stored in AES-256-encrypted versioned S3 bucket
- **GuardDuty**: threat detection enabled with S3 protection and EBS malware scanning
- **CloudWatch Logs**: all container logs shipped via Docker `awslogs` driver to `/docker/secure-flask-app`

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
- Prometheus targets UP at `http://<monitoring_public_dns>:9090/targets`
- Grafana dashboard loads at `http://<monitoring_public_dns>:3000`
- CloudTrail trail status active in AWS Console (CloudTrail → Trails)
- GuardDuty detector enabled in AWS Console (GuardDuty → Summary)
- CloudWatch log group `/docker/secure-flask-app` receiving events after first pipeline run
