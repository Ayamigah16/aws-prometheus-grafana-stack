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
