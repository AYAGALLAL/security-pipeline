# Get current account id (used in IAM policy if you want to restrict ARNs)
data "aws_caller_identity" "current" {}

# Get default VPC for the security group
data "aws_vpc" "default" {
  default = true
}


# -----------------------------
# IAM Role for EC2 (CloudWatch Agent)
# -----------------------------
resource "aws_iam_role" "cloudwatch_role" {
  name = "cloudwatch-prowler-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_and_s3_policy" {
  name = "cloudwatch-prowler-ec2-policy"
  role = aws_iam_role.cloudwatch_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },

      # S3 upload
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload",
          "s3:ListBucketMultipartUploads",
          "s3:ListMultipartUploadParts"
        ]
        Resource = "arn:aws:s3:::security-reports-pfs2025/prowler/*"
      },

      # S3 list bucket
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = "arn:aws:s3:::security-reports-pfs2025"
        Condition = {
          StringLike = {
            "s3:prefix" = ["prowler/*"]
          }
        }
      }
    ]
  })
}


resource "aws_iam_instance_profile" "prowler_cloudwatch_profile" {
  name = "prowler-cloudwatch-instance-profile"
  role = aws_iam_role.cloudwatch_role.name
}

# -----------------------------
# Security Group for the runner
# -----------------------------
resource "aws_security_group" "prowler_runner_sg" {
  name        = "prowler-runner-sg"
  description = "Security group for Prowler GitLab Runner EC2"
  vpc_id      = data.aws_vpc.default.id

  # SSH from your IP (change YOUR_IP/32)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ProwlerGitLabRunnerSG"
  }
}

resource "aws_iam_role_policy_attachment" "prowler_security_audit" {
  role       = aws_iam_role.cloudwatch_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# -----------------------------
# EC2 Instance for GitLab Runner + Prowler + CloudWatch Agent
# -----------------------------
resource "aws_instance" "prowler_runner" {
  ami                    = "ami-0a6793a25df710b06"
  instance_type          = "t3.micro"
  key_name               = "key_pair"          
  iam_instance_profile   = aws_iam_instance_profile.prowler_cloudwatch_profile.name
  vpc_security_group_ids = [aws_security_group.prowler_runner_sg.id]
  associate_public_ip_address = true

  tags = {
    Name = "ProwlerGitLabRunner"
  }

user_data = <<-EOF
  #!/bin/bash
  yum update -y

  # Install git if not already
  dnf install -y git

  # -------- Docker --------
  dnf install -y docker
  systemctl enable --now docker
  systemctl start docker
  usermod -aG docker ec2-user

  # -------- GitLab Runner --------
  curl -L --output gitlab-runner-linux-amd64 https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-amd64
  chmod +x gitlab-runner-linux-amd64
  mv gitlab-runner-linux-amd64 /usr/local/bin/gitlab-runner

  useradd --comment 'GitLab Runner' --create-home gitlab-runner --shell /bin/bash
  usermod -aG docker gitlab-runner

  # -------- Prowler base directory --------
  mkdir -p /var/lib/prowler/reports
  chown -R gitlab-runner:gitlab-runner /var/lib/prowler
  chmod -R 775 /var/lib/prowler

  # -------- NEW: Stable “event log” path (writable by runner) --------
  mkdir -p /var/lib/prowler/events
  chown -R gitlab-runner:gitlab-runner /var/lib/prowler/events
  chmod 775 /var/lib/prowler/events
  touch /var/lib/prowler/events/prowler_reports.log
  chown gitlab-runner:gitlab-runner /var/lib/prowler/events/prowler_reports.log
  chmod 664 /var/lib/prowler/events/prowler_reports.log

  gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
  gitlab-runner start

  # Register runner (glrt token workflow)
  gitlab-runner register --non-interactive \
  --config "/etc/gitlab-runner/config.toml" \
  --url "https://gitlab.com/" \
  --token "${var.authen_token}" \
  --name "Prowler Runner" \
  --executor "shell"


  # -------- CloudWatch Agent --------
  yum install -y amazon-cloudwatch-agent

  cat << 'CWCONFIG' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
  {
    "logs": {
      "logs_collected": {
        "files": {
          "collect_list": [
            {
              "file_path": "/var/log/prowler.log",
              "log_group_name": "security-reports-log-group",
              "log_stream_name": "{instance_id}-prowler",
              "timestamp_format": "%Y-%m-%d %H:%M:%S"
            },
            {
              "file_path": "/var/lib/prowler/events/prowler_reports.log",
              "log_group_name": "security-reports-log-group",
              "log_stream_name": "{instance_id}-prowler-reports"
            }
          ]
        }
      }
    }
  }
  CWCONFIG

  /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

  # Create log file for Prowler and make it writable (optional if you still write there)
  touch /var/log/prowler.log
  chmod 666 /var/log/prowler.log

  EOF
}

resource "aws_iam_role_policy" "runner_publish_sns" {
  name = "runner-publish-sns"
  role = aws_iam_role.cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowPublishToSecurityAlertsTopic"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = [
          aws_sns_topic.security_alerts_sns.arn,
          aws_sns_topic.security_alerts_sms.arn
        ]

      }
    ]
  })
}

variable "authen_token" {
  type        = string
  description = "gitlab runner authentication token"
}