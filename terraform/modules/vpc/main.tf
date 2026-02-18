# =============================================================================
# 🔒 VPC Module — Zero Trust Network
# =============================================================================

variable "vpc_cidr" { type = string }
variable "vpn_cidr" { type = string }
variable "environment" { type = string }

resource "aws_vpc" "bunker" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "bunker-vpc-${var.environment}" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.bunker.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = { Name = "bunker-public" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.bunker.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 2)
  availability_zone = "us-east-1a"

  tags = { Name = "bunker-private" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.bunker.id
  tags   = { Name = "bunker-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.bunker.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ── Security Groups (Zero Trust) ─────────────────────────────

# VPN Hub: Solo WireGuard entrante + SSH desde VPN
resource "aws_security_group" "vpn_hub" {
  name_prefix = "vpn-hub-"
  vpc_id      = aws_vpc.bunker.id
  description = "VPN Hub - Solo WireGuard + SSH via VPN"

  # WireGuard UDP
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard VPN"
  }

  # SSH SOLO desde la VPN (nunca desde Internet)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpn_cidr]
    description = "SSH via VPN only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "vpn-hub-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# Agent: CERO puertos abiertos al mundo — solo VPN
resource "aws_security_group" "agent" {
  name_prefix = "agent-"
  vpc_id      = aws_vpc.bunker.id
  description = "Agent - Solo accesible via VPN"

  # SSH solo desde VPN
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpn_cidr]
    description = "SSH via VPN only"
  }

  # WireGuard desde el Hub
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = [var.vpn_cidr]
    description = "WireGuard from Hub"
  }

  # mTLS desde la VPN
  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.vpn_cidr]
    description = "mTLS API via VPN"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "agent-sg" }
}

# ── Outputs ────────────────────────────────────────────────────
output "vpc_id" { value = aws_vpc.bunker.id }
output "public_subnet_id" { value = aws_subnet.public.id }
output "private_subnet_id" { value = aws_subnet.private.id }
output "vpn_hub_sg_id" { value = aws_security_group.vpn_hub.id }
output "agent_sg_id" { value = aws_security_group.agent.id }
