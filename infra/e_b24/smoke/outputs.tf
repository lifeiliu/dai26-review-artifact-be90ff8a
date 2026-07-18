output "compute_enabled" {
  value = var.enable_compute
}

output "vpc_id" {
  value = aws_vpc.smoke.id
}

output "topology_manifest" {
  value = {
    protocol_stage = "three-host-infrastructure-smoke"
    region         = var.aws_region
    ami_id         = data.aws_ami.al2023_x86_64.id
    runtime_image  = var.runtime_image
    hosts = {
      for name, instance in aws_instance.smoke : name => {
        instance_id       = instance.id
        instance_type     = instance.instance_type
        private_ip        = instance.private_ip
        availability_zone = instance.availability_zone
        zone_id           = data.aws_availability_zone.selected[instance.availability_zone].zone_id
        role              = local.hosts[name].role
        cpu_credit_mode   = "standard"
      }
    }
  }
}

output "ssm_targets" {
  value = [for instance in aws_instance.smoke : instance.id]
}
