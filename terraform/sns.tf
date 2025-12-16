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
  raw_message_delivery = true
}

data "aws_iam_policy_document" "sqs_allow_sns" {
  statement {
    sid     = "AllowSNSPublish"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    resources = [aws_sqs_queue.security_queue.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.security_alerts_sns.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "security_queue_policy" {
  queue_url = aws_sqs_queue.security_queue.id
  policy    = data.aws_iam_policy_document.sqs_allow_sns.json
}


resource "aws_sns_topic" "security_alerts_sms" {
  name = "security-alerts-sms"
}

resource "aws_sns_topic_subscription" "sms_subscription" {
  topic_arn = aws_sns_topic.security_alerts_sms.arn
  protocol  = "sms"
  endpoint  = "+212*********"
}