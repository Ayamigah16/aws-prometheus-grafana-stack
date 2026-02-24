output "jenkins_security_group_id" {
  value = aws_security_group.jenkins.id
}

output "deploy_security_group_id" {
  value = aws_security_group.deploy.id
}

output "monitoring_security_group_id" {
  value = aws_security_group.monitoring.id
}

output "alb_security_group_id" {
  description = "Security group ID for the Application Load Balancer"
  value       = aws_security_group.alb.id
}

output "ecs_tasks_security_group_id" {
  description = "Security group ID for ECS Fargate tasks"
  value       = aws_security_group.ecs_tasks.id
}
