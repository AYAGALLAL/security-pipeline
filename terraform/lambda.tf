data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "lambda_policy" {

  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # SQS consume
  statement {
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.security_queue.arn]
  }

  # EC2 remediation (optional)
  statement {
    effect = "Allow"
    actions = [
      "ec2:StopInstances",
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
  }

  # Read prowler reports (bucket + objects)
  statement {
    effect = "Allow"
    actions = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::security-reports-pfs2025"]
  }

  statement {
    effect = "Allow"
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::security-reports-pfs2025/prowler/*"]
  }

  # Remediation: set/get Public Access Block on ANY bucket
  statement {
    effect = "Allow"
    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock"
    ]
    resources = ["arn:aws:s3:::*"]
  }
}


resource "aws_iam_role_policy" "lambda_inline" {
  name   = "security-remediation-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_iam_role" "lambda_exec" {
  name               = "security-remediation-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

# Package the Lambda function code
data "archive_file" "lambda_code" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_function.py"
  output_path = "${path.module}/lambda/output.zip"
}

# Lambda function
resource "aws_lambda_function" "lambda_remediation" {
  filename         = data.archive_file.lambda_code.output_path
  function_name    = "lambda_remediation"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"  
  source_code_hash = data.archive_file.lambda_code.output_base64sha256

  runtime = "python3.12"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
      SECURITY_REPORTS_BUCKET = "security-reports-pfs2025"
      SECURITY_REPORTS_PREFIX = "prowler/"
    }
  }

  tags = {
    Environment = "production"
    Application = "example"
  }
}

resource "aws_lambda_event_source_mapping" "from_sqs" {
  event_source_arn = aws_sqs_queue.security_queue.arn
  function_name    = aws_lambda_function.lambda_remediation.arn
  batch_size       = 1

  scaling_config {
    maximum_concurrency = 10
  }
}
