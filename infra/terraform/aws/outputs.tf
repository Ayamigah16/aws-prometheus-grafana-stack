output "jenkins_public_ip" {
  value = module.compute.jenkins_public_ip
}

output "jenkins_public_dns" {
  value = module.compute.jenkins_public_dns
}

output "deploy_public_ip" {
  value = module.compute.deploy_public_ip
}

output "deploy_public_dns" {
  value = module.compute.deploy_public_dns
}

output "ecr_repository_url" {
  value = module.ecr.repository_url
}

output "monitoring_public_ip" {
  value = module.compute.monitoring_public_ip
}

output "monitoring_public_dns" {
  value = module.compute.monitoring_public_dns
}

output "cloudtrail_bucket" {
  value = module.security_services.cloudtrail_bucket_name
}

output "cloudtrail_trail_arn" {
  value = module.security_services.cloudtrail_trail_arn
}

output "guardduty_detector_id" {
  value = module.security_services.guardduty_detector_id
}

# ---------------------------------------------------------------------------
# ECS / ALB
# ---------------------------------------------------------------------------
output "alb_dns_name" {
  description = "ALB public DNS name — set as ALB_DNS_NAME in Jenkins"
  value       = module.ecs.alb_dns_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name — set as ECS_CLUSTER_NAME in Jenkins"
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name — set as ECS_SERVICE_NAME in Jenkins"
  value       = module.ecs.service_name
}

output "ecs_execution_role_arn" {
  description = "ECS task execution role ARN — set as ECS_EXECUTION_ROLE_ARN in Jenkins"
  value       = module.ecs.execution_role_arn
}

output "ecs_task_role_arn" {
  description = "ECS task role ARN — set as ECS_TASK_ROLE_ARN in Jenkins"
  value       = module.ecs.task_role_arn
}

output "ecs_log_group_name" {
  description = "CloudWatch log group for ECS container logs"
  value       = module.ecs.log_group_name
}
