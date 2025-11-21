resource "aws_s3_bucket" "security-reports-bucket" {
  bucket = "security-reports-pfs2025"

  tags = {
    Name        = "monitoring-infra"
  }
}