data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "jenkins" {
  name               = "${var.project_name}-jenkins-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = var.tags
}

resource "aws_iam_role" "deploy" {
  name               = "${var.project_name}-deploy-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "jenkins_ecr" {
  role       = aws_iam_role.jenkins.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

resource "aws_iam_role_policy_attachment" "jenkins_ssm" {
  role       = aws_iam_role.jenkins.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "deploy_ecr_readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "deploy_ssm" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "deploy_cloudwatch" {
  statement {
    sid    = "CloudWatchLogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["arn:aws:logs:*:*:log-group:/docker/*"]
  }
}

resource "aws_iam_role_policy" "deploy_cloudwatch" {
  name   = "${var.project_name}-deploy-cw-logs"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_cloudwatch.json
}

resource "aws_iam_instance_profile" "jenkins" {
  name = "${var.project_name}-jenkins-instance-profile"
  role = aws_iam_role.jenkins.name
}

resource "aws_iam_instance_profile" "deploy" {
  name = "${var.project_name}-deploy-instance-profile"
  role = aws_iam_role.deploy.name
}

# ---------------------------------------------------------------------------
# Monitoring role: Prometheus + Grafana + Alertmanager host
# Permissions: SSM (management) + CloudWatch Logs write (future log shipping)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "monitoring" {
  name               = "${var.project_name}-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = var.tags
}

data "aws_iam_policy_document" "monitoring_cloudwatch" {
  statement {
    sid    = "CloudWatchLogsWrite"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["arn:aws:logs:*:*:log-group:/aws/ec2/monitoring/*"]
  }
}

resource "aws_iam_role_policy" "monitoring_cloudwatch" {
  name   = "${var.project_name}-monitoring-cw-logs"
  role   = aws_iam_role.monitoring.id
  policy = data.aws_iam_policy_document.monitoring_cloudwatch.json
}

resource "aws_iam_role_policy_attachment" "monitoring_ssm" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "monitoring" {
  name = "${var.project_name}-monitoring-instance-profile"
  role = aws_iam_role.monitoring.name
}
