# Infrastructure as Code

This folder contains Terraform and Ansible assets for provisioning and configuring the CI/CD infrastructure.

## Components
- Terraform bootstrap stack: creates S3 backend bucket + DynamoDB lock table
- Terraform AWS stack (module-based): provisions VPC, Jenkins EC2, deploy EC2, security groups, IAM roles, and ECR repository
- Ansible: configures Jenkins LTS, Docker, Trivy, and deploy-host runtime dependencies

Terraform modules in `infra/terraform/aws/modules`:
- `network`
- `security`
- `iam`
- `key_pair`
- `compute`
- `ecr`

## Prerequisites
- Terraform >= 1.6
- Ansible >= 2.15
- AWS CLI configured (`aws configure`)

## 1. Create Terraform Remote State Backend
```bash
cd infra/terraform/bootstrap
terraform init
terraform apply \
  -var='state_bucket_name=<globally-unique-bucket-name>' \
  -var='lock_table_name=jenkins-pipeline-tf-locks' \
  -var='aws_region=us-east-1'
```

## 2. Provision AWS Infrastructure
```bash
cd ../aws
cp terraform.tfvars.example terraform.tfvars
cp backend.hcl.example backend.hcl
# edit both files

terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

Terraform automatically updates Ansible inventory at `infra/ansible/inventory/hosts.ini`.
Terraform also writes `infra/ansible/.env` with host IPs and SSH key path.
Verify generated files:
```bash
cat ../../ansible/.env
cat ../../ansible/inventory/hosts.ini
ls -l ../../keys/*.pem
```

## 3. Configure Servers with Ansible
```bash
cd ../../ansible
# optional: copy group_vars/all/vault.yml.example to group_vars/all/vault.yml and encrypt with ansible-vault
# optional fallback (instead of vault): export JENKINS_ADMIN_PASSWORD='<strong-password>'
./run-playbook.sh
```

If you run `ansible-playbook` directly, load `infra/ansible/.env` first.

## 4. Jenkins Pipeline Integration
Update `Jenkinsfile` values using Terraform outputs:
- `REGISTRY` = ECR registry host from `ecr_repository_url` (for example `123456789012.dkr.ecr.us-east-1.amazonaws.com`)
- `APP_NAME` = ECR repository name (for example `secure-flask-app`)
- `EC2_HOST` = Terraform output `deploy_public_dns`
- keep `USE_ECR=true`

## Security Notes
- Restrict `admin_cidrs` in Terraform to your real public IP/CIDR
- Move `jenkins_admin_password` into Ansible Vault
- Use Jenkins credentials store for GitHub tokens, SSH keys, and registry credentials when not using ECR IAM auth

## State Migration Note
If you already applied the pre-module version, this refactor includes Terraform `moved` blocks in `infra/terraform/aws/main.tf` so state addresses migrate to module paths without resource recreation.
