from typing import List
from fwmigrate.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRPolicy
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

class CheckPointTerraformGenerator:
    """Generates Check Point Terraform configurations targeting CheckPointSW/checkpoint provider."""

    def generate_provider_tf(self) -> str:
        return """terraform {
  required_version = ">= 1.0"
  required_providers {
    checkpoint = {
      source  = "CheckPointSW/checkpoint"
      version = "~> 2.8.0"
    }
  }
}

provider "checkpoint" {
  server   = var.checkpoint_server
  api_key  = var.checkpoint_api_key
  context  = var.checkpoint_context
}
"""

    def generate_variables_tf(self) -> str:
        return """variable "checkpoint_server" {
  description = "Check Point Management Server IP or FQDN"
  type        = string
}

variable "checkpoint_api_key" {
  description = "Check Point API Key"
  type        = string
  sensitive   = true
}

variable "checkpoint_context" {
  description = "Check Point Context (web_api or gaia_api)"
  type        = string
  default     = "web_api"
}
"""

    def generate_main_tf(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "# =============================================================================",
            f"# Check Point Terraform Suite for {ir.metadata.hostname or 'cp-gateway'}",
            "# =============================================================================",
            ""
        ]

        for addr in ir.addresses:
            clean_id = self._safe_id(addr.name)
            if addr.type == AddressType.HOST:
                ip_val = addr.value.split('/')[0]
                lines.append(f'resource "checkpoint_management_host" "{clean_id}" {{')
                lines.append(f'  name       = "{addr.name}"')
                lines.append(f'  ipv4_address = "{ip_val}"')
                lines.append('}\n')
            elif addr.type == AddressType.NETWORK:
                if '/' in addr.value:
                    ip, prefix = addr.value.split('/')
                    lines.append(f'resource "checkpoint_management_network" "{clean_id}" {{')
                    lines.append(f'  name         = "{addr.name}"')
                    lines.append(f'  subnet4      = "{ip}"')
                    lines.append(f'  mask_length4 = {prefix}')
                    lines.append('}\n')

        for grp in ir.address_groups:
            clean_id = self._safe_id(grp.name)
            lines.append(f'resource "checkpoint_management_group" "{clean_id}" {{')
            lines.append(f'  name    = "{grp.name}"')
            members_str = ", ".join([f'"{m}"' for m in grp.members])
            lines.append(f'  members = [{members_str}]')
            lines.append('}\n')

        return "\n".join(lines)

    def _safe_id(self, name: str) -> str:
        return name.replace(".", "_").replace("-", "_").replace(" ", "_")
