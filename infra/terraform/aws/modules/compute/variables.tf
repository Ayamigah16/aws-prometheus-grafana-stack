variable "project_name" {
  type = string
}

variable "ami_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "key_name" {
  type = string
}

variable "ssh_key_fingerprint" {
  type = string
}

variable "jenkins_security_group_id" {
  type = string
}

variable "deploy_security_group_id" {
  type = string
}

variable "jenkins_instance_profile_name" {
  type = string
}

variable "deploy_instance_profile_name" {
  type = string
}

variable "jenkins_instance_type" {
  type = string
}

variable "deploy_instance_type" {
  type = string
}

variable "monitoring_instance_type" {
  type = string
}

variable "monitoring_security_group_id" {
  type = string
}

variable "monitoring_instance_profile_name" {
  type = string
}

variable "tags" {
  type = map(string)
}
