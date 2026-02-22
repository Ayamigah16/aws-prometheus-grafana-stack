# Runbook

## Purpose
Ordered setup and operations guide for the full DevSecOps stack:
Terraform (IaC) → Ansible (configuration) → Jenkins (CI/CD) → Observability (Prometheus + Alertmanager + Grafana + Node Exporter) → Security (CloudTrail, GuardDuty, CloudWatch Logs).

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
- Prometheus 2.50.1 — scrapes flask-app (`:3000/metrics`), Node Exporter (`:9100`), and Alertmanager (`:9093`)
- Alertmanager 0.27.0 — routes `warning` alerts to Slack `#alerts-warning`, `critical` alerts to Slack `#alerts-critical` **and** oncall email
- Grafana (latest from YUM repo) — pre-configured admin credentials; import dashboard from `infra/observability/grafana/dashboards/`
- Node Exporter 1.7.0 — installed on the Deploy EC2 host, scraped by Prometheus over the VPC private network

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
REGISTRY  = "<account_id>.dkr.ecr.<region>.amazonaws.com"
EC2_HOST  = "<DEPLOY_PUBLIC_DNS from terraform output>"
USE_ECR   = true
```

---

## Step 6 — Enable AWS Security Services

### CloudTrail

```bash
# Create the encrypted S3 bucket for trail logs
aws s3api create-bucket \
  --bucket <project>-cloudtrail-logs \
  --region us-east-1

aws s3api put-bucket-encryption \
  --bucket <project>-cloudtrail-logs \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-public-access-block \
  --bucket <project>-cloudtrail-logs \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Apply Glacier lifecycle (90-day transition, 365-day expiry)
aws s3api put-bucket-lifecycle-configuration \
  --bucket <project>-cloudtrail-logs \
  --lifecycle-configuration file://infra/security/cloudtrail-lifecycle-policy.json

# Create multi-region trail with log file validation
aws cloudtrail create-trail \
  --name <project>-trail \
  --s3-bucket-name <project>-cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation

aws cloudtrail start-logging --name <project>-trail
```

### GuardDuty

```bash
# Enable in each region where you operate
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

### CloudWatch Logs (container logs)

The Deploy EC2's Docker daemon ships container logs via the `awslogs` driver.
This is configured by Ansible in the `deploy` role.
Verify logs are appearing:

```bash
aws logs describe-log-groups --log-group-name-prefix /docker/secure-flask-app
aws logs get-log-events \
  --log-group-name /docker/secure-flask-app \
  --log-stream-name $(aws logs describe-log-streams \
    --log-group-name /docker/secure-flask-app \
    --order-by LastEventTime --descending \
    --query 'logStreams[0].logStreamName' --output text)
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
# Add datasource: Prometheus → http://localhost:9090
# Import dashboard: infra/observability/grafana/dashboards/devsecops-observability-dashboard.json
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
| Prometheus target DOWN | SG blocking port 3000 or 9100 from monitoring SG | Check deploy SG rules in `security/main.tf` |
| Alertmanager not receiving | `prometheus.yml` alertmanager target wrong | Confirm `localhost:9093` or monitoring-private-IP |
| Slack alerts not firing | Webhook URL wrong or secret not decrypted | Check `vault_alertmanager_slack_webhook_url` in vault; `amtool check-config` on monitoring host |
| ECR login failed | Instance role lacks ECR permissions | Confirm `iam/main.tf` jenkins role has ECR policy |
| Trivy not found on Jenkins | Ansible Jenkins role didn't complete | Re-run `./run-playbook.sh --tags trivy` |
| Container logs missing in CloudWatch | `awslogs` driver not configured | Re-run deploy Ansible role; check Docker daemon options |

---

## Incident Response

1. Rotate any compromised secret: vault password → edit `vault.yml` → `ansible-vault rekey` → redeploy with `./run-playbook.sh`
2. Revoke IAM sessions: `aws iam create-access-key` (new) → `aws iam delete-access-key` (old)
3. Audit events: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<principal>`
4. GuardDuty findings: `aws guardduty list-findings --detector-id <id>` → investigate → archive
5. Rebuild from clean commit after all security scans pass
