variable "aws_region" {
  description = "AWS region for backend resources"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name prefix for resource naming"
  type        = string
  default     = "jenkins-pipeline"
}

variable "state_bucket_name" {
  description = "Unique S3 bucket name for Terraform state"
  type        = string
  default     = "jenkins-pipeline-state-bucket"
}

variable "lock_table_name" {
  description = "DynamoDB table for Terraform state locking"
  type        = string
  default     = "jenkins-pipeline-tf-locks"
}
