variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "owner" {
  type = string
}

variable "expiry" {
  description = "Mandatory UTC shutdown/cleanup deadline recorded on every resource."
  type        = string
}

variable "enable_compute" {
  description = "Explicit gate. False creates no EC2 instances."
  type        = bool
  default     = false
}

variable "availability_zones" {
  description = "Three account-mapped AZ names selected during the read-only account audit."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  validation {
    condition     = length(var.availability_zones) == 3 && length(toset(var.availability_zones)) == 3
    error_message = "E-B24 smoke requires exactly three distinct Availability Zones."
  }
}

variable "instance_profile_name" {
  description = "Output of the bootstrap stack."
  type        = string
  default     = "paper-b-e-b24-node"
}

variable "runtime_image" {
  description = "E-B24 runtime image pinned by ECR digest; never pass a mutable tag."
  type        = string

  validation {
    condition     = can(regex("^[^[:space:]]+@sha256:[0-9a-f]{64}$", var.runtime_image))
    error_message = "runtime_image must be an ECR image reference pinned by sha256 digest."
  }
}

variable "root_volume_gib" {
  type    = number
  default = 30

  validation {
    condition     = var.root_volume_gib >= 20 && var.root_volume_gib <= 100
    error_message = "Smoke root volumes must remain between 20 and 100 GiB."
  }
}
