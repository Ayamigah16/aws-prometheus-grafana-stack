terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2", "amzn2-ami-hvm-*-x86_64-gp3"]
  }
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

module "network" {
  source             = "./modules/network"
  project_name       = var.project_name
  vpc_cidr           = var.vpc_cidr
  public_subnet_cidr = var.public_subnet_cidr
  availability_zone  = data.aws_availability_zones.available.names[0]
  tags               = local.common_tags
}

module "security" {
  source       = "./modules/security"
  project_name = var.project_name
  vpc_id       = module.network.vpc_id
  admin_cidrs  = var.admin_cidrs
  tags         = local.common_tags
}

module "iam" {
  source       = "./modules/iam"
  project_name = var.project_name
  tags         = local.common_tags
}

module "key_pair" {
  source          = "./modules/key_pair"
  key_pair_name   = var.key_pair_name
  keys_output_dir = "${abspath(path.root)}/../../keys"
  tags            = local.common_tags
}

module "compute" {
  source                          = "./modules/compute"
  project_name                    = var.project_name
  ami_id                          = data.aws_ami.amazon_linux_2.id
  subnet_id                       = module.network.public_subnet_id
  key_name                        = module.key_pair.key_name
  ssh_key_fingerprint             = module.key_pair.public_key_fingerprint_sha256
  jenkins_security_group_id       = module.security.jenkins_security_group_id
  deploy_security_group_id        = module.security.deploy_security_group_id
  monitoring_security_group_id    = module.security.monitoring_security_group_id
  jenkins_instance_profile_name   = module.iam.jenkins_instance_profile_name
  deploy_instance_profile_name    = module.iam.deploy_instance_profile_name
  monitoring_instance_profile_name = module.iam.monitoring_instance_profile_name
  jenkins_instance_type           = var.jenkins_instance_type
  deploy_instance_type            = var.deploy_instance_type
  monitoring_instance_type        = var.monitoring_instance_type
  tags                            = local.common_tags
}

module "ecr" {
  source          = "./modules/ecr"
  repository_name = var.ecr_repository_name
  tags            = local.common_tags
}

module "security_services" {
  source       = "./modules/security_services"
  project_name = var.project_name
  aws_region   = var.aws_region
  environment  = var.environment
  tags         = local.common_tags
}

resource "local_file" "ansible_inventory" {
  filename        = "${abspath(path.root)}/../../ansible/inventory/hosts.ini"
  content         = templatefile("${path.module}/templates/inventory.tftpl", {})
  file_permission = "0644"
}

resource "local_file" "ansible_env" {
  filename = "${abspath(path.root)}/../../ansible/.env"
  content = templatefile("${path.module}/templates/ansible_env.tftpl", {
    jenkins_host_ip        = module.compute.jenkins_public_ip
    jenkins_host_dns       = module.compute.jenkins_public_dns
    deploy_host_ip         = module.compute.deploy_public_ip
    deploy_host_dns        = module.compute.deploy_public_dns
    deploy_private_ip      = module.compute.deploy_private_ip
    monitoring_host_ip     = module.compute.monitoring_public_ip
    monitoring_host_dns    = module.compute.monitoring_public_dns
    monitoring_private_ip  = module.compute.monitoring_private_ip
    aws_region             = var.aws_region
    ssh_private_key_file   = abspath("${path.root}/../../keys/${var.key_pair_name}.pem")
  })
  file_permission = "0600"
}

moved {
  from = aws_vpc.main
  to   = module.network.aws_vpc.this
}

moved {
  from = aws_internet_gateway.main
  to   = module.network.aws_internet_gateway.this
}

moved {
  from = aws_subnet.public
  to   = module.network.aws_subnet.public
}

moved {
  from = aws_route_table.public
  to   = module.network.aws_route_table.public
}

moved {
  from = aws_route_table_association.public
  to   = module.network.aws_route_table_association.public
}

moved {
  from = aws_security_group.jenkins
  to   = module.security.aws_security_group.jenkins
}

moved {
  from = aws_security_group.deploy
  to   = module.security.aws_security_group.deploy
}

moved {
  from = aws_key_pair.deployer
  to   = module.key_pair.aws_key_pair.this
}

moved {
  from = aws_iam_role.jenkins
  to   = module.iam.aws_iam_role.jenkins
}

moved {
  from = aws_iam_role.deploy
  to   = module.iam.aws_iam_role.deploy
}

moved {
  from = aws_iam_role_policy_attachment.jenkins_ecr
  to   = module.iam.aws_iam_role_policy_attachment.jenkins_ecr
}

moved {
  from = aws_iam_role_policy_attachment.jenkins_ssm
  to   = module.iam.aws_iam_role_policy_attachment.jenkins_ssm
}

moved {
  from = aws_iam_role_policy_attachment.deploy_ecr_readonly
  to   = module.iam.aws_iam_role_policy_attachment.deploy_ecr_readonly
}

moved {
  from = aws_iam_role_policy_attachment.deploy_ssm
  to   = module.iam.aws_iam_role_policy_attachment.deploy_ssm
}

moved {
  from = aws_iam_instance_profile.jenkins
  to   = module.iam.aws_iam_instance_profile.jenkins
}

moved {
  from = aws_iam_instance_profile.deploy
  to   = module.iam.aws_iam_instance_profile.deploy
}

moved {
  from = aws_instance.jenkins
  to   = module.compute.aws_instance.jenkins
}

moved {
  from = aws_instance.deploy
  to   = module.compute.aws_instance.deploy
}

moved {
  from = aws_ecr_repository.app
  to   = module.ecr.aws_ecr_repository.this
}

moved {
  from = aws_ecr_lifecycle_policy.app
  to   = module.ecr.aws_ecr_lifecycle_policy.this
}
