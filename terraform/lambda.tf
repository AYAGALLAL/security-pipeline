// aws_lambda_function
// aws_iam_role_policy
// aws_iam_policy_document
// aws_lambda_event_source_mapping
// archive_file
// aws_iam_role

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
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.security_queue.arn]
  }

  # Remediation actions:
  statement {
    effect = "Allow"
    actions = [
      "ec2:StopInstances",
      "ec2:DescribeInstances",
    ]
    resources = ["*"]
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
  handler          = "lambda_function.handler"        # file: lambda_function.py, function: handler
  source_code_hash = data.archive_file.lambda_code.output_base64sha256

  runtime = "python3.12"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
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
