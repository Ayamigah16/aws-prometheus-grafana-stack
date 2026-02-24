output "jenkins_instance_profile_name" {
  value = aws_iam_instance_profile.jenkins.name
}

output "deploy_instance_profile_name" {
  value = aws_iam_instance_profile.deploy.name
}

output "monitoring_instance_profile_name" {
  value = aws_iam_instance_profile.monitoring.name
}
