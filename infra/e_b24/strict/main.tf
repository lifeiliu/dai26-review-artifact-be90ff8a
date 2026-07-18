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
    Stage   = "pilot"
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
    gateway-1          = { az_key = "a", private_ip = "10.24.1.11", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-2          = { az_key = "a", private_ip = "10.24.1.12", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-3          = { az_key = "a", private_ip = "10.24.1.13", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-4          = { az_key = "b", private_ip = "10.24.2.11", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-5          = { az_key = "b", private_ip = "10.24.2.12", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-6          = { az_key = "b", private_ip = "10.24.2.13", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-7          = { az_key = "c", private_ip = "10.24.3.11", instance_type = "t3.small", role = "gateway", security = "gateway" }
    gateway-8          = { az_key = "c", private_ip = "10.24.3.12", instance_type = "t3.small", role = "gateway", security = "gateway" }
    keycloak           = { az_key = "a", private_ip = "10.24.1.20", instance_type = "t3.medium", role = "keycloak", security = "keycloak" }
    keycloak-postgres  = { az_key = "b", private_ip = "10.24.2.20", instance_type = "t3.medium", role = "keycloak-postgres", security = "keycloak_db" }
    receiver-a         = { az_key = "a", private_ip = "10.24.1.21", instance_type = "t3.small", role = "durable-receiver-a", security = "receiver" }
    receiver-b         = { az_key = "c", private_ip = "10.24.3.20", instance_type = "t3.small", role = "durable-receiver-b", security = "receiver" }
    filesystem-effects = { az_key = "b", private_ip = "10.24.2.21", instance_type = "t3.small", role = "filesystem-effect-service", security = "filesystem_effect" }
    postgres-effects   = { az_key = "c", private_ip = "10.24.3.21", instance_type = "t3.medium", role = "postgres-effect-service-database", security = "postgres_effect" }
    workload-driver    = { az_key = "a", private_ip = "10.24.1.22", instance_type = "t3.small", role = "workload-driver", security = "driver" }
    fault-controller   = { az_key = "b", private_ip = "10.24.2.22", instance_type = "t3.small", role = "independent-fault-controller", security = "fault_controller" }
  }
  active_hosts = var.enable_compute ? local.hosts : {}
  gateway_hosts = {
    for name, host in local.hosts : name => host if host.role == "gateway"
  }
  active_gateway_hosts = var.enable_compute ? local.gateway_hosts : {}
  node_security_names = toset([
    "gateway",
    "keycloak",
    "keycloak_db",
    "receiver",
    "filesystem_effect",
    "postgres_effect",
    "driver",
    "fault_controller",
  ])
  host_lines = join("\n", [
    for name, host in local.hosts : "${host.private_ip} ${name} ${name}.e-b24.internal"
  ])
  push_listener_enabled = var.enable_push_front_door && var.enable_push_listeners
}

check "push_listener_contract" {
  assert {
    condition = (
      !var.enable_push_listeners ||
      (var.enable_push_front_door && var.push_certificate_arn != "")
    )
    error_message = "PUSH listeners require the front door and a non-empty imported ACM certificate ARN."
  }
}

resource "aws_vpc" "strict" {
  cidr_block           = "10.24.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "paper-b-e-b24-strict" }
}

resource "aws_internet_gateway" "strict" {
  vpc_id = aws_vpc.strict.id
  tags   = { Name = "paper-b-e-b24-strict" }
}

resource "aws_subnet" "strict" {
  for_each                = local.subnets
  vpc_id                  = aws_vpc.strict.id
  availability_zone       = each.value.az
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  tags = {
    Name   = "paper-b-e-b24-strict-${each.key}"
    ZoneId = data.aws_availability_zone.selected[each.value.az].zone_id
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.strict.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.strict.id
  }
  tags = { Name = "paper-b-e-b24-strict-public" }
}

resource "aws_route_table_association" "public" {
  for_each       = aws_subnet.strict
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "node" {
  for_each    = local.node_security_names
  name        = "paper-b-e-b24-strict-${replace(each.key, "_", "-")}"
  description = "E-B24 strict ${each.key} role"
  vpc_id      = aws_vpc.strict.id
}

resource "aws_security_group" "push_alb" {
  name        = "paper-b-e-b24-strict-push-alb"
  description = "Keycloak-only public-address HTTPS front door for strict SSF PUSH validation"
  vpc_id      = aws_vpc.strict.id
}

# Managed nodes need outbound HTTPS for SSM, ECR, S3, image pulls, and package
# bootstrap. No node security group has public ingress or SSH.
resource "aws_vpc_security_group_egress_rule" "node_https" {
  for_each          = aws_security_group.node
  security_group_id = each.value.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Managed-node HTTPS egress"
}

resource "aws_vpc_security_group_egress_rule" "node_dns_udp" {
  for_each          = aws_security_group.node
  security_group_id = each.value.id
  cidr_ipv4         = aws_vpc.strict.cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC DNS"
}

resource "aws_vpc_security_group_egress_rule" "node_dns_tcp" {
  for_each          = aws_security_group.node
  security_group_id = each.value.id
  cidr_ipv4         = aws_vpc.strict.cidr_block
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "VPC DNS fallback"
}

resource "aws_vpc_security_group_egress_rule" "node_time_sync" {
  for_each          = aws_security_group.node
  security_group_id = each.value.id
  cidr_ipv4         = "169.254.169.123/32"
  from_port         = 123
  to_port           = 123
  ip_protocol       = "udp"
  description       = "Amazon Time Sync Service"
}

# Keycloak -> separately hosted PostgreSQL.
resource "aws_vpc_security_group_egress_rule" "keycloak_to_db" {
  security_group_id            = aws_security_group.node["keycloak"].id
  referenced_security_group_id = aws_security_group.node["keycloak_db"].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_db_from_keycloak" {
  security_group_id            = aws_security_group.node["keycloak_db"].id
  referenced_security_group_id = aws_security_group.node["keycloak"].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# Receiver JWKS retrieval and workload control use Keycloak's private endpoint.
resource "aws_vpc_security_group_egress_rule" "receiver_to_keycloak" {
  security_group_id            = aws_security_group.node["receiver"].id
  referenced_security_group_id = aws_security_group.node["keycloak"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "driver_to_keycloak" {
  security_group_id            = aws_security_group.node["driver"].id
  referenced_security_group_id = aws_security_group.node["keycloak"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_from_receiver" {
  security_group_id            = aws_security_group.node["keycloak"].id
  referenced_security_group_id = aws_security_group.node["receiver"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_from_driver" {
  security_group_id            = aws_security_group.node["keycloak"].id
  referenced_security_group_id = aws_security_group.node["driver"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

# Receiver -> all eight gateway control endpoints.
resource "aws_vpc_security_group_egress_rule" "receiver_to_gateway" {
  security_group_id            = aws_security_group.node["receiver"].id
  referenced_security_group_id = aws_security_group.node["gateway"].id
  from_port                    = 9444
  to_port                      = 9444
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "gateway_control_from_receiver" {
  security_group_id            = aws_security_group.node["gateway"].id
  referenced_security_group_id = aws_security_group.node["receiver"].id
  from_port                    = 9444
  to_port                      = 9444
  ip_protocol                  = "tcp"
}

# Workload driver -> all gateway MCP endpoints and receiver health endpoints.
resource "aws_vpc_security_group_egress_rule" "driver_to_gateway" {
  security_group_id            = aws_security_group.node["driver"].id
  referenced_security_group_id = aws_security_group.node["gateway"].id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "gateway_mcp_from_driver" {
  security_group_id            = aws_security_group.node["gateway"].id
  referenced_security_group_id = aws_security_group.node["driver"].id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "driver_to_receiver" {
  security_group_id            = aws_security_group.node["driver"].id
  referenced_security_group_id = aws_security_group.node["receiver"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "receiver_from_driver" {
  security_group_id            = aws_security_group.node["receiver"].id
  referenced_security_group_id = aws_security_group.node["driver"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

# Gateways -> authoritative real-effect services.
resource "aws_vpc_security_group_egress_rule" "gateway_to_filesystem_effect" {
  security_group_id            = aws_security_group.node["gateway"].id
  referenced_security_group_id = aws_security_group.node["filesystem_effect"].id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "gateway_to_postgres_effect" {
  security_group_id            = aws_security_group.node["gateway"].id
  referenced_security_group_id = aws_security_group.node["postgres_effect"].id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "filesystem_effect_from_gateway" {
  security_group_id            = aws_security_group.node["filesystem_effect"].id
  referenced_security_group_id = aws_security_group.node["gateway"].id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "postgres_effect_from_gateway" {
  security_group_id            = aws_security_group.node["postgres_effect"].id
  referenced_security_group_id = aws_security_group.node["gateway"].id
  from_port                    = 9443
  to_port                      = 9443
  ip_protocol                  = "tcp"
}

resource "aws_instance" "strict" {
  for_each = local.active_hosts

  ami           = data.aws_ami.al2023_x86_64.id
  instance_type = each.value.instance_type
  subnet_id     = aws_subnet.strict[each.value.az_key].id
  private_ip    = each.value.private_ip
  vpc_security_group_ids = [
    aws_security_group.node[each.value.security].id,
  ]
  iam_instance_profile = (
    each.key == "fault-controller"
    ? var.fault_controller_instance_profile_name
    : var.instance_profile_name
  )
  associate_public_ip_address          = true
  instance_initiated_shutdown_behavior = "stop"

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    host_name     = each.key
    role          = each.value.role
    private_ip    = each.value.private_ip
    zone_id       = data.aws_availability_zone.selected[local.subnets[each.value.az_key].az].zone_id
    runtime_image = var.runtime_image
    host_lines    = local.host_lines
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

# A stable source address lets the public-address PUSH front door accept only
# Keycloak. No receiver, gateway, database, or SSH port is public.
resource "aws_eip" "keycloak" {
  count  = var.enable_compute && var.enable_push_front_door ? 1 : 0
  domain = "vpc"

  tags = { Name = "paper-b-e-b24-keycloak-push-source" }
}

resource "aws_eip_association" "keycloak" {
  count         = var.enable_compute && var.enable_push_front_door ? 1 : 0
  allocation_id = aws_eip.keycloak[0].id
  instance_id   = aws_instance.strict["keycloak"].id
}

resource "aws_vpc_security_group_ingress_rule" "push_alb_443_from_keycloak" {
  count             = var.enable_compute && var.enable_push_front_door ? 1 : 0
  security_group_id = aws_security_group.push_alb.id
  cidr_ipv4         = "${aws_eip.keycloak[0].public_ip}/32"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Receiver A PUSH from the Keycloak EIP only"
}

resource "aws_vpc_security_group_ingress_rule" "push_alb_8443_from_keycloak" {
  count             = var.enable_compute && var.enable_push_front_door ? 1 : 0
  security_group_id = aws_security_group.push_alb.id
  cidr_ipv4         = "${aws_eip.keycloak[0].public_ip}/32"
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
  description       = "Receiver B PUSH from the Keycloak EIP only"
}

resource "aws_vpc_security_group_egress_rule" "keycloak_to_push_8443" {
  security_group_id = aws_security_group.node["keycloak"].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
  description       = "Strict receiver B public-address PUSH endpoint"
}

resource "aws_vpc_security_group_egress_rule" "push_alb_to_receivers" {
  security_group_id            = aws_security_group.push_alb.id
  referenced_security_group_id = aws_security_group.node["receiver"].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "receiver_from_push_alb" {
  security_group_id            = aws_security_group.node["receiver"].id
  referenced_security_group_id = aws_security_group.push_alb.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_lb" "push" {
  count              = var.enable_push_front_door ? 1 : 0
  name               = "paper-b-eb24-push"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.push_alb.id]
  subnets            = [for subnet in aws_subnet.strict : subnet.id]

  enable_deletion_protection = false
  drop_invalid_header_fields = true
  idle_timeout               = 30

  tags = { Name = "paper-b-e-b24-strict-push" }
}

resource "aws_lb_target_group" "receiver" {
  for_each = var.enable_push_front_door ? { receiver-a = 443, receiver-b = 8443 } : {}

  name        = "paper-b-eb24-${replace(each.key, "receiver-", "recv-")}"
  port        = 8443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.strict.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    timeout             = 5
    path                = "/health"
    protocol            = "HTTPS"
    matcher             = "200"
  }

  deregistration_delay = 5
}

resource "aws_lb_target_group_attachment" "receiver" {
  for_each = var.enable_compute && var.enable_push_front_door ? {
    receiver-a = aws_instance.strict["receiver-a"].id
    receiver-b = aws_instance.strict["receiver-b"].id
  } : {}

  target_group_arn = aws_lb_target_group.receiver[each.key].arn
  target_id        = each.value
  port             = 8443
}

resource "aws_lb_listener" "receiver" {
  for_each = local.push_listener_enabled ? { receiver-a = 443, receiver-b = 8443 } : {}

  load_balancer_arn = aws_lb.push[0].arn
  port              = each.value
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.push_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.receiver[each.key].arn
  }
}
