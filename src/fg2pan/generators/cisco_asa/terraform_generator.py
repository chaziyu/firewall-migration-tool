from typing import List
from fg2pan.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRPolicy
from fg2pan.ir.enums import AddressType, ServiceProtocol, PolicyAction

class CiscoASATerraformGenerator:
    """Generates Cisco ASA Terraform configurations targeting CiscoDevNet/asa or hashicorp/ciscoasa provider."""

    def generate_provider_tf(self) -> str:
        return """terraform {
  required_version = ">= 1.0"
  required_providers {
    ciscoasa = {
      source  = "CiscoDevNet/ciscoasa"
      version = "~> 1.3.0"
    }
  }
}

provider "ciscoasa" {
  api_url  = var.asa_api_url
  username = var.asa_username
  password = var.asa_password
  ssl_verify = var.asa_ssl_verify
}
"""

    def generate_variables_tf(self) -> str:
        return """variable "asa_api_url" {
  description = "Cisco ASA REST API endpoint (e.g. https://192.168.1.1)"
  type        = string
}

variable "asa_username" {
  description = "Cisco ASA administrator username"
  type        = string
}

variable "asa_password" {
  description = "Cisco ASA administrator password"
  type        = string
  sensitive   = true
}

variable "asa_ssl_verify" {
  description = "Verify SSL certificates"
  type        = bool
  default     = false
}
"""

    def generate_main_tf(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "# =============================================================================",
            f"# Cisco ASA Terraform Suite for {ir.metadata.hostname or 'cisco-asa'}",
            "# =============================================================================",
            ""
        ]

        for addr in ir.addresses:
            clean_id = self._safe_id(addr.name)
            ip_val = addr.value.split('/')[0]
            lines.append(f'resource "ciscoasa_network_object" "{clean_id}" {{')
            lines.append(f'  name  = "{addr.name}"')
            lines.append(f'  value = "{ip_val}"')
            lines.append('}\n')

        for grp in ir.address_groups:
            clean_id = self._safe_id(grp.name)
            lines.append(f'resource "ciscoasa_network_object_group" "{clean_id}" {{')
            lines.append(f'  name    = "{grp.name}"')
            members_str = ", ".join([f'"{m}"' for m in grp.members])
            lines.append(f'  members = [{members_str}]')
            lines.append('}\n')

        return "\n".join(lines)

    def _safe_id(self, name: str) -> str:
        return name.replace(".", "_").replace("-", "_").replace(" ", "_")
