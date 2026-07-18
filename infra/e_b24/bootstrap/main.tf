data "aws_caller_identity" "current" {}

locals {
  project = "paper-b-e-b24"
  common_tags = {
    Project = local.project
    Stage   = "bootstrap"
    Owner   = var.owner
    Expiry  = var.expiry
  }
  evidence_bucket_name = "paper-b-e-b24-evidence-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
}

resource "aws_s3_bucket" "evidence" {
  bucket        = local.evidence_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-smoke-only-prefix"
    status = "Enabled"
    filter {
      prefix = "smoke/"
    }
    expiration {
      days = var.evidence_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_ecr_repository" "runtime" {
  name                 = "paper-b-e-b24/runtime"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "paper-b-e-b24-node"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "artifact_access" {
  statement {
    sid       = "EvidenceBucketMetadata"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid    = "EvidenceObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListMultipartUploadParts",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid       = "EcrLogin"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "EcrRuntimePull"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.runtime.arn]
  }

  statement {
    sid     = "ExperimentParameterRead"
    effect  = "Allow"
    actions = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/paper-b/e-b24/smoke/*",
      "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/paper-b/e-b24/strict/*",
    ]
  }

  statement {
    sid       = "ExperimentMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["PaperB/EB24"]
    }
  }
}

resource "aws_iam_role_policy" "artifact_access" {
  name   = "paper-b-e-b24-artifact-access"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.artifact_access.json
}

resource "aws_iam_instance_profile" "node" {
  name = "paper-b-e-b24-node"
  role = aws_iam_role.node.name
}

# Keep fault injection authority off ordinary experiment nodes. The dedicated
# controller may run only the pinned AWS-RunShellScript document against EC2
# instances tagged for this project, and may read back command evidence.
resource "aws_iam_role" "fault_controller" {
  name               = "paper-b-e-b24-fault-controller"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "fault_controller_ssm_core" {
  role       = aws_iam_role.fault_controller.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "fault_controller_artifact_access" {
  name   = "paper-b-e-b24-artifact-access"
  role   = aws_iam_role.fault_controller.id
  policy = data.aws_iam_policy_document.artifact_access.json
}

data "aws_iam_policy_document" "fault_control" {
  statement {
    sid       = "PinnedFaultDocument"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"]
  }

  statement {
    sid       = "TaggedExperimentTargets"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/Project"
      values   = ["paper-b-e-b24"]
    }
  }

  statement {
    sid    = "FaultCommandEvidence"
    effect = "Allow"
    actions = [
      "ssm:CancelCommand",
      "ssm:DescribeInstanceInformation",
      "ssm:GetCommandInvocation",
      "ssm:ListCommandInvocations",
      "ssm:ListCommands",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "fault_control" {
  name   = "paper-b-e-b24-fault-control"
  role   = aws_iam_role.fault_controller.id
  policy = data.aws_iam_policy_document.fault_control.json
}

resource "aws_iam_instance_profile" "fault_controller" {
  name = "paper-b-e-b24-fault-controller"
  role = aws_iam_role.fault_controller.name
}
