variable "aws_region" {
  description = "AWS workload region. This is independent from the IAM Identity Center region."
  type        = string
  default     = "us-east-1"
}

variable "owner" {
  description = "Researcher or team label used for cost attribution."
  type        = string
}

variable "expiry" {
  description = "UTC project review/expiry timestamp recorded on persistent resources."
  type        = string
}

variable "evidence_retention_days" {
  description = "Days before smoke evidence transitions to expiration. Confirmatory evidence is copied before this limit."
  type        = number
  default     = 180

  validation {
    condition     = var.evidence_retention_days >= 90
    error_message = "E-B24 evidence retention must be at least 90 days."
  }
}
