variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "app_name" {
  description = "Application container name and ECS family name"
  type        = string
  default     = "secure-flask-app"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where ALB and ECS tasks are placed"
  type        = string
}

variable "public_subnet_ids" {
  description = "At least 2 public subnets in different AZs for the ALB"
  type        = list(string)
}

variable "app_subnet_ids" {
  description = "Subnets where ECS Fargate tasks run (public with assign_public_ip=true)"
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group ID for the Application Load Balancer"
  type        = string
}

variable "ecs_security_group_id" {
  description = "Security group ID for ECS Fargate tasks"
  type        = string
}

variable "bootstrap_image" {
  description = "Container image for the bootstrap task definition revision (replaced by Jenkins)"
  type        = string
  default     = "public.ecr.aws/amazonlinux/amazonlinux:2023"
}

variable "task_cpu" {
  description = "Fargate task-level CPU units (256 = 0.25 vCPU)"
  type        = string
  default     = "256"
}

variable "task_memory" {
  description = "Fargate task-level memory in MiB"
  type        = string
  default     = "512"
}

variable "app_port" {
  description = "Container port the application listens on"
  type        = number
  default     = 3000
}

variable "service_desired_count" {
  description = "Initial desired task count (Jenkins manages this after first apply)"
  type        = number
  default     = 1
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
}
