output "jenkins_security_group_id" {
  value = aws_security_group.jenkins.id
}

output "deploy_security_group_id" {
  value = aws_security_group.deploy.id
}

output "monitoring_security_group_id" {
  value = aws_security_group.monitoring.id
}
