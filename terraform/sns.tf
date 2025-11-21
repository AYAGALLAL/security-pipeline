resource "aws_sns_topic" "security_alerts_sns" {
  name = "security-alerts"
  tags = {
    Name = "monitoring-infra"
  }
}

resource "aws_sns_topic_subscription" "queue_subscription" {
  topic_arn = aws_sns_topic.security_alerts_sns.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.security_queue.arn
}


