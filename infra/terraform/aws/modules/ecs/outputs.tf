output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.this.name
}

output "cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.this.arn
}

output "service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.this.name
}

output "task_definition_family" {
  description = "ECS task definition family"
  value       = aws_ecs_task_definition.app.family
}

output "execution_role_arn" {
  description = "ECS task execution role ARN"
  value       = aws_iam_role.execution.arn
}

output "task_role_arn" {
  description = "ECS task role ARN"
  value       = aws_iam_role.task.arn
}

output "alb_dns_name" {
  description = "ALB public DNS name"
  value       = aws_lb.this.dns_name
}

output "alb_arn_suffix" {
  description = "ALB ARN suffix (used in CloudWatch metric dimensions)"
  value       = aws_lb.this.arn_suffix
}

output "target_group_arn" {
  description = "ALB target group ARN"
  value       = aws_lb_target_group.this.arn
}

output "log_group_name" {
  description = "CloudWatch log group name for ECS container logs"
  value       = aws_cloudwatch_log_group.ecs_app.name
}
