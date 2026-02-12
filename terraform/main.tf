# =============================================================================
# 🏗️ Terraform — Búnker DevSecOps Infrastructure
# Comunidad Claude Anthropic Colombia
# =============================================================================
# Provisiona la "Trinidad":
#   - VPC aislada con subredes privadas
#   - EC2 VPN Hub (WireGuard Gateway)
#   - EC2 Agent (OpenClaw Bot)
#   - Security Groups restrictivos (zero-trust)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # En producción, usar backend remoto
  # backend "s3" {
  #   bucket = "mantishield-terraform-state"
  #   key    = "bunker/terraform.tfstate"
  #   region = "us-east-1"
  #   encrypt = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "DevSecOps-Bunker"
      Workshop    = "Claude-Anthropic-Colombia"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

# ── Variables ──────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS Region para el Búnker"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "workshop"
}

variable "vpn_cidr" {
  description = "CIDR de la VPN WireGuard"
  type        = string
  default     = "10.13.13.0/24"
}

variable "allowed_ssh_cidr" {
  description = "CIDR permitido para SSH (solo VPN)"
  type        = string
  default     = "10.13.13.0/24"
}

# ── VPC Module ─────────────────────────────────────────────────
module "vpc" {
  source = "./modules/vpc"

  vpc_cidr     = "172.31.0.0/16"
  vpn_cidr     = var.vpn_cidr
  environment  = var.environment
}

# ── EC2 Instances ──────────────────────────────────────────────
module "vpn_hub" {
  source = "./modules/ec2"

  name              = "vpn-hub"
  instance_type     = "t3.micro"
  subnet_id         = module.vpc.public_subnet_id
  security_group_id = module.vpc.vpn_hub_sg_id
  key_name          = "bunker-key"

  user_data = templatefile("${path.module}/scripts/vpn-hub-init.sh", {
    vpn_cidr = var.vpn_cidr
  })
}

module "ec2_agent" {
  source = "./modules/ec2"

  name              = "ec2-agent-openclaw"
  instance_type     = "t3.small"  # Más recursos para AI/ML
  subnet_id         = module.vpc.private_subnet_id
  security_group_id = module.vpc.agent_sg_id
  key_name          = "bunker-key"
  root_volume_size  = 20  # Expandido para OpenClaw + modelos

  user_data = templatefile("${path.module}/scripts/agent-init.sh", {
    vpn_hub_endpoint = module.vpn_hub.private_ip
  })
}

# ── Outputs ────────────────────────────────────────────────────
output "vpn_hub_public_ip" {
  description = "IP pública del VPN Hub (único punto de entrada)"
  value       = module.vpn_hub.public_ip
}

output "agent_private_ip" {
  description = "IP privada del agente (sin acceso público)"
  value       = module.ec2_agent.private_ip
}

output "vpn_subnet" {
  description = "Subnet de la VPN"
  value       = var.vpn_cidr
}
