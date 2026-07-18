output "evidence_bucket_name" {
  value = aws_s3_bucket.evidence.id
}

output "runtime_ecr_repository_url" {
  value = aws_ecr_repository.runtime.repository_url
}

output "runtime_ecr_repository_arn" {
  value = aws_ecr_repository.runtime.arn
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.node.name
}

output "fault_controller_instance_profile_name" {
  value = aws_iam_instance_profile.fault_controller.name
}
