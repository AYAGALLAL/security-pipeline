variable "security_reports_bucket" {
  type        = string
  description = "S3 bucket where Prowler CSV reports are uploaded"
}

variable "security_reports_prefix" {
  type        = string
  description = "Prefix under the bucket where reports are stored (e.g., prowler/)"
  default     = "prowler/"
}
