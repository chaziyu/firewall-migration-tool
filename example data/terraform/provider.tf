# ==============================================================================
# Terraform Provider Configuration for Palo Alto Networks (PAN-OS)
# ==============================================================================

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    panos = {
      source  = "PaloAltoNetworks/panos"
      version = "~> 1.11"
    }
  }
}

provider "panos" {
  hostname = var.panos_hostname
  username = var.panos_username != "" ? var.panos_username : null
  password = var.panos_password != "" ? var.panos_password : null
  api_key  = var.panos_api_key != "" ? var.panos_api_key : null
  vsys     = var.panos_vsys
}
