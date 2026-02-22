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
- `infra/terraform/aws` Terraform AWS stack (VPC, EC2 ×3, IAM, ECR, Security Groups)
- `infra/ansible` Ansible playbooks and roles (Jenkins, Deploy, Monitoring, Node Exporter)
- `infra/observability` Prometheus, Alertmanager, and Grafana config references
- `infra/security` CloudTrail S3 lifecycle policy
- `docs` architecture reference and technical report
- `scripts/cleanup_observability_security.sh` full teardown script
- `runbook.md` ordered setup and operations guide
- `screenshots` evidence placeholders

## Deployment Architecture
- **Jenkins EC2** (Amazon Linux 2) — runs CI/CD stages, pushes image to ECR.
- **ECR** — stores scanned image tags, scan-on-push enabled.
- **Deploy EC2** (Amazon Linux 2) — runs the application container on port `80`; Node Exporter on port `9100` exposes host metrics.
- **Monitoring EC2** (Amazon Linux 2) — runs Prometheus (`:9090`), Alertmanager (`:9093`), and Grafana (`:3000`). Prometheus scrapes the Flask app `/metrics` and Node Exporter over the VPC private network. Alertmanager routes `warning` alerts to Slack and `critical` alerts to Slack + email.
- Jenkins deploys over SSH with health-checked staging (`3001`) and automatic rollback.

## Setup Steps
See [`runbook.md`](runbook.md) for the full step-by-step guide. Summary:

1. **Bootstrap state backend** — `cd infra/terraform/bootstrap && terraform init && terraform apply`
2. **Provision AWS infrastructure** — fill in `terraform.tfvars` and `backend.hcl`, then `terraform apply` in `infra/terraform/aws` (creates Jenkins EC2, Deploy EC2, Monitoring EC2, VPC, IAM, ECR)
3. **Prepare secrets** — copy `group_vars/all/vault.yml.example` → `vault.yml`, fill in passwords/webhooks, encrypt with `ansible-vault encrypt`
4. **Configure all hosts** — `cd infra/ansible && ./run-playbook.sh --ask-vault-pass` (configures Jenkins, Deploy + Node Exporter, Monitoring stack)
5. **Configure Jenkins** — create `git_credentials`, `ec2_ssh`, set `REGISTRY` and `EC2_HOST` from Terraform outputs
6. **Enable security services** — CloudTrail (multi-region trail + encrypted S3), GuardDuty detector, CloudWatch Logs for containers
7. **Verify observability** — Prometheus targets UP at `:9090/targets`, Alertmanager ready at `:9093`, Grafana at `:3000`, import dashboard from `infra/observability/grafana/dashboards/`

## Security Controls
- Vulnerability and dependency scanning: `pip-audit`, `trivy fs`, `trivy image`
- Static analysis: `bandit`
- Container hardening: non-root user, read-only FS, dropped Linux capabilities
- Remote state security: S3 encryption + public access block + DynamoDB locking
- IAM: separate instance roles for Jenkins (ECR push) and deploy host (ECR pull)

## Rollback Process
- Deployment uses staging container on `3001` before cutover.
- If staging health check fails, production remains unchanged.
- If production post-switch check fails, pipeline restarts previous image automatically.

## Verification Checklist
- Terraform apply succeeds for backend and AWS stack
- Ansible playbook succeeds for both hosts
- Jenkins pipeline stages complete successfully
- ECR contains build tag and `latest`
- App responds at `http://<deploy_public_dns>/health`
