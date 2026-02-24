variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "jenkins-pipeline"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR"
  type        = string
  default     = "10.20.1.0/24"
}

variable "admin_cidrs" {
  description = "Allowed CIDRs for SSH/Jenkins UI"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "key_pair_name" {
  description = "AWS key pair name"
  type        = string
  default     = "jenkins-pipeline-key"
}

variable "jenkins_instance_type" {
  description = "Instance type for Jenkins server"
  type        = string
  default     = "t3.medium"
}

variable "deploy_instance_type" {
  description = "Instance type for deployment host"
  type        = string
  default     = "t3.small"
}

variable "monitoring_instance_type" {
  description = "Instance type for monitoring host (Prometheus + Grafana + Alertmanager)"
  type        = string
  default     = "t3.small"
}

variable "sonarqube_instance_type" {
  description = "Instance type for dedicated SonarQube server"
  type        = string
  default     = "t3.medium"
}

variable "ecr_repository_name" {
  description = "ECR repository name for application image"
  type        = string
  default     = "secure-flask-app"
}

# ---------------------------------------------------------------------------
# Network — second public subnet (ALB requires >= 2 AZs)
# ---------------------------------------------------------------------------
variable "public_subnet_cidr_b" {
  description = "CIDR for the second public subnet (second AZ)"
  type        = string
  default     = "10.20.2.0/24"
}

# ---------------------------------------------------------------------------
# ECS Fargate
# ---------------------------------------------------------------------------
variable "ecs_bootstrap_image" {
  description = "Initial container image for the bootstrap ECS task definition (replaced by Jenkins)"
  type        = string
  default     = "public.ecr.aws/amazonlinux/amazonlinux:2023"
}

variable "ecs_task_cpu" {
  description = "ECS Fargate task CPU units"
  type        = string
  default     = "256"
}

variable "ecs_task_memory" {
  description = "ECS Fargate task memory in MiB"
  type        = string
  default     = "512"
}

variable "ecs_desired_count" {
  description = "Initial ECS service desired task count"
  type        = number
  default     = 1
}
