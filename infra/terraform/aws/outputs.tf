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
