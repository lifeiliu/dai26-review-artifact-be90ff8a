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
  description = "Explicit gate. False creates no EC2 instances or EIP."
  type        = bool
  default     = false
}

variable "enable_push_front_door" {
  description = "Creates the public-address ALB needed for Keycloak's strict PUSH URL validator."
  type        = bool
  default     = false
}

variable "enable_push_listeners" {
  description = "Creates the two HTTPS listeners after a private-CA certificate has been imported into ACM."
  type        = bool
  default     = false
}

variable "push_certificate_arn" {
  description = "ARN of the short-lived private-CA ALB certificate imported into ACM; never certificate key material."
  type        = string
  default     = ""

  validation {
    condition = (
      var.push_certificate_arn == "" ||
      can(regex("^arn:[^:]+:acm:[^:]+:[0-9]{12}:certificate/[0-9a-f-]+$", var.push_certificate_arn))
    )
    error_message = "push_certificate_arn must be empty or an ACM certificate ARN."
  }
}

variable "availability_zones" {
  description = "Three account-mapped AZ names selected during the read-only account audit."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  validation {
    condition     = length(var.availability_zones) == 3 && length(toset(var.availability_zones)) == 3
    error_message = "E-B24 strict topology requires exactly three distinct Availability Zones."
  }
}

variable "instance_profile_name" {
  description = "General E-B24 node profile output by the bootstrap stack."
  type        = string
  default     = "paper-b-e-b24-node"
}

variable "fault_controller_instance_profile_name" {
  description = "Dedicated profile whose only additional authority is tagged E-B24 SSM fault control."
  type        = string
  default     = "paper-b-e-b24-fault-controller"
}

variable "runtime_image" {
  description = "E-B24 runtime image pinned by ECR digest; mutable tags are rejected."
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
    error_message = "Strict-topology root volumes must remain between 20 and 100 GiB."
  }
}
