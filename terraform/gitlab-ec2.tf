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

resource "aws_iam_role_policy" "cloudwatch_policy" {
  name = "cloudwatch-prowler-ec2-policy"
  role = aws_iam_role.cloudwatch_role.name

  # You can tighten this later; for now, allow CloudWatch Logs fully
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
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

    #Install git if not already
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

    gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
    gitlab-runner start

    # Register runner
    gitlab-runner register --non-interactive \
      --url "https://gitlab.com/" \
      --registration-token "glrt-zVRpm6jjHL0_nRZEkz2-YG86MQpwOjE5Y2x3Ygp0OjMKdTppd3czZhg.01.1j07h9yrg" \
      --executor "shell" \
      --description "Prowler Runner" \
      --tag-list "prowler,aws" \
      --run-untagged="false" \
      --locked="false"

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
              }
            ]
          }
        }
      }
    }
    CWCONFIG

    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

    # Create log file for Prowler and make it writable
    touch /var/log/prowler.log
    chmod 666 /var/log/prowler.log

  EOF
}
