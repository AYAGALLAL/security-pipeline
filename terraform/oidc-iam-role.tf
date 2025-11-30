
# OIDC provider for GitLab
/*
resource "aws_iam_openid_connect_provider" "gitlab" {
  url = "https://gitlab.com"

  # Must match the "aud" claim in the GitLab OIDC token
  client_id_list = [
    "https://sts.amazonaws.com",
  ]

  thumbprint_list = [
    "A031C46782E6E6C662C2C87C76DA9AA62CCABD8E",
  ]
}

# IAM Role for GitLab CI/CD
resource "aws_iam_role" "gitlab_cicd_role" {
  name = "gitlab-cicd-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.gitlab.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            # Must match the "sub" claim from the decoded token
            "gitlab.com:sub" = "project_path:aaa4102647/pfs-final2025:ref_type:branch:ref:main",
            # Must match the "aud" claim
            "gitlab.com:aud" = "https://sts.amazonaws.com"
          }
        }
      }
    ]
  })
}
*/