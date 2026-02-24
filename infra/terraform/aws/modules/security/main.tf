resource "aws_security_group" "jenkins" {
  name        = "${var.project_name}-jenkins-sg"
  description = "Jenkins ingress rules"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from admin network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Jenkins UI from admin network"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-jenkins-sg"
  })
}

resource "aws_security_group" "deploy" {
  name        = "${var.project_name}-deploy-sg"
  description = "Deployment host ingress rules"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from admin network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description     = "SSH from Jenkins security group"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins.id]
  }

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-deploy-sg"
  })
}

resource "aws_security_group" "monitoring" {
  name        = "${var.project_name}-monitoring-sg"
  description = "Monitoring host: Prometheus, Grafana, Alertmanager"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from admin network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Prometheus UI from admin network"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Grafana UI from admin network"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Alertmanager UI from admin network"
    from_port   = 9093
    to_port     = 9093
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Jaeger UI from admin network"
    from_port   = 16686
    to_port     = 16686
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description     = "OTLP gRPC traces from deploy host"
    from_port       = 4317
    to_port         = 4317
    protocol        = "tcp"
    security_groups = [aws_security_group.deploy.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-monitoring-sg"
  })
}

# ---------------------------------------------------------------------------
# Cross-SG rules — must be declared outside the SG blocks to avoid cycles
# ---------------------------------------------------------------------------

# Allow Prometheus (monitoring host) to scrape app /metrics on deploy host
resource "aws_security_group_rule" "deploy_app_metrics_from_monitoring" {
  type                     = "ingress"
  description              = "Prometheus scrape app metrics"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  security_group_id        = aws_security_group.deploy.id
  source_security_group_id = aws_security_group.monitoring.id
}

# Allow Prometheus (monitoring host) to scrape Node Exporter on deploy host
resource "aws_security_group_rule" "deploy_node_exporter_from_monitoring" {
  type                     = "ingress"
  description              = "Prometheus scrape Node Exporter"
  from_port                = 9100
  to_port                  = 9100
  protocol                 = "tcp"
  security_group_id        = aws_security_group.deploy.id
  source_security_group_id = aws_security_group.monitoring.id
}

# Allow the deploy host to push OTLP traces (gRPC + HTTP) to Jaeger on monitoring host
resource "aws_security_group_rule" "monitoring_otlp_from_deploy" {
  type                     = "ingress"
  description              = "OTLP gRPC/HTTP traces from deploy host"
  from_port                = 4317
  to_port                  = 4318
  protocol                 = "tcp"
  security_group_id        = aws_security_group.monitoring.id
  source_security_group_id = aws_security_group.deploy.id
}

# Allow Jenkins pipeline to reach SonarQube API on the sonarqube host
# (sonar-scanner POST to /api/ce/submit and GET /api/qualitygates/project_status)
resource "aws_security_group_rule" "monitoring_sonarqube_from_jenkins" {
  type                     = "ingress"
  description              = "SonarQube API from Jenkins pipeline"
  from_port                = 9000
  to_port                  = 9000
  protocol                 = "tcp"
  security_group_id        = aws_security_group.sonarqube.id
  source_security_group_id = aws_security_group.jenkins.id
}

# ---------------------------------------------------------------------------
# SonarQube Security Group
# ---------------------------------------------------------------------------
resource "aws_security_group" "sonarqube" {
  name        = "${var.project_name}-sonarqube-sg"
  description = "SonarQube SAST server: port 9000 from admin and Jenkins"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from admin network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "SonarQube UI from admin network"
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-sonarqube-sg"
  })
}

# ---------------------------------------------------------------------------
# ALB Security Group
# ---------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "ALB: allow HTTP from internet"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.project_name}-alb-sg" })
}

# ---------------------------------------------------------------------------
# ECS Tasks Security Group
# ---------------------------------------------------------------------------
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.project_name}-ecs-tasks-sg"
  description = "ECS Fargate tasks: receive traffic from ALB only"
  vpc_id      = var.vpc_id

  egress {
    description = "All outbound (ECR pull, CW Logs, Jaeger OTLP)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.project_name}-ecs-tasks-sg" })
}

# Allow ALB to reach ECS tasks on the app port
resource "aws_security_group_rule" "ecs_from_alb" {
  type                     = "ingress"
  description              = "App port from ALB"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_tasks.id
  source_security_group_id = aws_security_group.alb.id
}

# Allow monitoring host to scrape ECS task metrics (Prometheus)
resource "aws_security_group_rule" "ecs_metrics_from_monitoring" {
  type                     = "ingress"
  description              = "Prometheus scrape from monitoring host"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_tasks.id
  source_security_group_id = aws_security_group.monitoring.id
}
