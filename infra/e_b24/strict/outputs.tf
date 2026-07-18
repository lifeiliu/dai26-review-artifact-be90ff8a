output "compute_enabled" {
  value = var.enable_compute
}

output "push_front_door_enabled" {
  value = var.enable_push_front_door
}

output "push_listeners_enabled" {
  value = var.enable_push_listeners
}

output "vpc_id" {
  value = aws_vpc.strict.id
}

output "push_alb_dns_name" {
  value = try(aws_lb.push[0].dns_name, null)
}

output "push_receiver_urls" {
  value = var.enable_push_front_door ? {
    receiver-a = "https://${aws_lb.push[0].dns_name}:443/events"
    receiver-b = "https://${aws_lb.push[0].dns_name}:8443/events"
  } : {}
}

output "topology_manifest" {
  value = {
    protocol_stage = "strict-confirmatory-candidate-pilot"
    region         = var.aws_region
    ami_id         = data.aws_ami.al2023_x86_64.id
    runtime_image  = var.runtime_image
    push_front_door = {
      enabled           = var.enable_push_front_door
      listeners_enabled = var.enable_push_listeners
      alb_dns_name      = try(aws_lb.push[0].dns_name, null)
      certificate_arn   = var.push_certificate_arn
      keycloak_eip      = try(aws_eip.keycloak[0].public_ip, null)
    }
    hosts = {
      for name, instance in aws_instance.strict : name => {
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
  value = [for instance in aws_instance.strict : instance.id]
}
