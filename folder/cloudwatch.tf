resource "aws_cloudwatch_log_group" "aws_cloudwatch_log_group" {
  name = "security-reports-log-group"

  tags = {
    Name = "monitoring-infra"
  }
}