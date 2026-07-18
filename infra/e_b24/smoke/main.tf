data "aws_caller_identity" "current" {}

data "aws_ami" "al2023_x86_64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zone" "selected" {
  for_each = toset(var.availability_zones)
  name     = each.value
}

locals {
  project = "paper-b-e-b24"
  common_tags = {
    Project = local.project
    Stage   = "smoke"
    Owner   = var.owner
    Expiry  = var.expiry
  }
  azs = {
    a = var.availability_zones[0]
    b = var.availability_zones[1]
    c = var.availability_zones[2]
  }
  subnets = {
    a = { az = local.azs.a, cidr = "10.24.1.0/24" }
    b = { az = local.azs.b, cidr = "10.24.2.0/24" }
    c = { az = local.azs.c, cidr = "10.24.3.0/24" }
  }
  hosts = {
    smoke-1 = {
      az_key        = "a"
      instance_type = "t3.large"
      role          = "keycloak-keycloak-postgres"
      security      = "issuer"
    }
    smoke-2 = {
      az_key        = "b"
      instance_type = "t3.medium"
      role          = "durable-receiver-persistent-gateway"
      security      = "receiver_gateway"
    }
    smoke-3 = {
      az_key        = "c"
      instance_type = "t3.medium"
      role          = "real-effects-workload-fault-driver"
      security      = "effects_driver"
    }
  }
  active_hosts = var.enable_compute ? local.hosts : {}
  security_group_ids = {
    issuer           = aws_security_group.issuer.id
    receiver_gateway = aws_security_group.receiver_gateway.id
    effects_driver   = aws_security_group.effects_driver.id
  }
}

resource "aws_vpc" "smoke" {
  cidr_block           = "10.24.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "paper-b-e-b24-smoke" }
}

resource "aws_internet_gateway" "smoke" {
  vpc_id = aws_vpc.smoke.id
  tags   = { Name = "paper-b-e-b24-smoke" }
}

resource "aws_subnet" "smoke" {
  for_each                = local.subnets
  vpc_id                  = aws_vpc.smoke.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  tags = {
    Name   = "paper-b-e-b24-smoke-${each.key}"
    ZoneId = data.aws_availability_zone.selected[each.value.az].zone_id
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.smoke.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.smoke.id
  }
  tags = { Name = "paper-b-e-b24-smoke-public" }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.smoke
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "issuer" {
  name        = "paper-b-e-b24-smoke-issuer"
  description = "Keycloak and its co-located smoke PostgreSQL"
  vpc_id      = aws_vpc.smoke.id
}

resource "aws_security_group" "receiver_gateway" {
  name        = "paper-b-e-b24-smoke-receiver-gateway"
  description = "Durable receiver and persistent MCP gateway"
  vpc_id      = aws_vpc.smoke.id
}

resource "aws_security_group" "effects_driver" {
  name        = "paper-b-e-b24-smoke-effects-driver"
  description = "Real effects, workload driver, and independent fault driver"
  vpc_id      = aws_vpc.smoke.id
}

# Every host needs only outbound HTTPS for SSM, ECR/S3, package bootstrap, and
# public certificate/JWKS retrieval. There is deliberately no inbound SSH.
resource "aws_vpc_security_group_egress_rule" "https" {
  for_each          = local.security_group_ids
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Outbound HTTPS for managed-node bootstrap and AWS APIs"
}

resource "aws_vpc_security_group_egress_rule" "dns_udp" {
  for_each          = local.security_group_ids
  security_group_id = each.value
  cidr_ipv4         = aws_vpc.smoke.cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC DNS"
}

resource "aws_vpc_security_group_egress_rule" "dns_tcp" {
  for_each          = local.security_group_ids
  security_group_id = each.value
  cidr_ipv4         = aws_vpc.smoke.cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "VPC DNS fallback"
}

# Keycloak -> durable receiver HTTPS PUSH.
resource "aws_vpc_security_group_egress_rule" "issuer_to_receiver" {
  security_group_id            = aws_security_group.issuer.id
  referenced_security_group_id = aws_security_group.receiver_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "receiver_from_issuer" {
  security_group_id            = aws_security_group.receiver_gateway.id
  referenced_security_group_id = aws_security_group.issuer.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

# Durable receiver -> Keycloak JWKS over the same private HTTPS endpoint.
resource "aws_vpc_security_group_egress_rule" "receiver_to_issuer_jwks" {
  security_group_id            = aws_security_group.receiver_gateway.id
  referenced_security_group_id = aws_security_group.issuer.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "issuer_jwks_from_receiver" {
  security_group_id            = aws_security_group.issuer.id
  referenced_security_group_id = aws_security_group.receiver_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

# Gateway -> authoritative real-effect boundary.
resource "aws_vpc_security_group_egress_rule" "gateway_to_effects" {
  security_group_id            = aws_security_group.receiver_gateway.id
  referenced_security_group_id = aws_security_group.effects_driver.id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "effects_from_gateway" {
  security_group_id            = aws_security_group.effects_driver.id
  referenced_security_group_id = aws_security_group.receiver_gateway.id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

# Workload driver -> Keycloak HTTPS admin/login/logout path.
resource "aws_vpc_security_group_egress_rule" "driver_to_keycloak" {
  security_group_id            = aws_security_group.effects_driver.id
  referenced_security_group_id = aws_security_group.issuer.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_from_driver" {
  security_group_id            = aws_security_group.issuer.id
  referenced_security_group_id = aws_security_group.effects_driver.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

# Workload driver -> MCP gateway. Receiver -> gateway control is host-local in
# the three-host smoke; the strict topology will use a separate security edge.
resource "aws_vpc_security_group_egress_rule" "driver_to_gateway_mcp" {
  security_group_id            = aws_security_group.effects_driver.id
  referenced_security_group_id = aws_security_group.receiver_gateway.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "gateway_mcp_from_driver" {
  security_group_id            = aws_security_group.receiver_gateway.id
  referenced_security_group_id = aws_security_group.effects_driver.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "driver_to_receiver_health" {
  security_group_id            = aws_security_group.effects_driver.id
  referenced_security_group_id = aws_security_group.receiver_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "receiver_health_from_driver" {
  security_group_id            = aws_security_group.receiver_gateway.id
  referenced_security_group_id = aws_security_group.effects_driver.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_instance" "smoke" {
  for_each = local.active_hosts

  ami                                  = data.aws_ami.al2023_x86_64.id
  instance_type                        = each.value.instance_type
  subnet_id                            = aws_subnet.smoke[each.value.az_key].id
  vpc_security_group_ids               = [local.security_group_ids[each.value.security]]
  iam_instance_profile                 = var.instance_profile_name
  associate_public_ip_address          = true
  instance_initiated_shutdown_behavior = "stop"

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    host_name     = each.key
    role          = each.value.role
    zone_id       = data.aws_availability_zone.selected[local.subnets[each.value.az_key].az].zone_id
    runtime_image = var.runtime_image
  })
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gib
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "paper-b-e-b24-${each.key}"
    Host = each.key
    Role = each.value.role
  }
}
