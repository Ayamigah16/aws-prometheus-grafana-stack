variable "project_name" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "public_subnet_cidr" {
  type = string
}

variable "public_subnet_cidr_b" {
  description = "CIDR for the second public subnet (different AZ, required for ALB)"
  type        = string
  default     = "10.20.2.0/24"
}

variable "availability_zone" {
  type = string
}

variable "availability_zone_b" {
  description = "Second availability zone for the ALB subnet"
  type        = string
}

variable "tags" {
  type = map(string)
}
