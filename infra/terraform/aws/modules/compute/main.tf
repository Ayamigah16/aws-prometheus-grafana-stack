resource "aws_instance" "jenkins" {
  ami                         = var.ami_id
  instance_type               = var.jenkins_instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.jenkins_security_group_id]
  key_name                    = var.key_name
  associate_public_ip_address = true
  iam_instance_profile        = var.jenkins_instance_profile_name
  user_data                   = "ssh_key_fingerprint=${var.ssh_key_fingerprint}"
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-jenkins"
    Role = "jenkins"
  })
}

resource "aws_instance" "deploy" {
  ami                         = var.ami_id
  instance_type               = var.deploy_instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.deploy_security_group_id]
  key_name                    = var.key_name
  associate_public_ip_address = true
  iam_instance_profile        = var.deploy_instance_profile_name
  user_data                   = "ssh_key_fingerprint=${var.ssh_key_fingerprint}"
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-deploy"
    Role = "deploy"
  })
}

resource "aws_instance" "monitoring" {
  ami                         = var.ami_id
  instance_type               = var.monitoring_instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.monitoring_security_group_id]
  key_name                    = var.key_name
  associate_public_ip_address = true
  iam_instance_profile        = var.monitoring_instance_profile_name
  user_data                   = "ssh_key_fingerprint=${var.ssh_key_fingerprint}"
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    # Prometheus TSDB requires adequate local storage for metrics retention.
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-monitoring"
    Role = "monitoring"
  })
}
