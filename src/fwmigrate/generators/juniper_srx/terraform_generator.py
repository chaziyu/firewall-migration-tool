from typing import List
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType

class JuniperSRXTerraformGenerator:
    """Generates Juniper SRX Terraform configurations targeting juniper/junos provider."""

    def generate_provider_tf(self) -> str:
        return """terraform {
  required_version = ">= 1.0"
  required_providers {
    junos = {
      source  = "juniper/junos"
      version = "~> 2.1.0"
    }
  }
}

provider "junos" {
  ip         = var.junos_host
  port       = var.junos_port
  username   = var.junos_username
  password   = var.junos_password
  sshkeyfile = var.junos_ssh_key_file
}
"""

    def generate_variables_tf(self) -> str:
        return """variable "junos_host" {
  description = "JunOS device IP or hostname"
  type        = string
}

variable "junos_port" {
  description = "NETCONF port"
  type        = number
  default     = 830
}

variable "junos_username" {
  description = "JunOS username"
  type        = string
}

variable "junos_password" {
  description = "JunOS password"
  type        = string
  sensitive   = true
  default     = null
}

variable "junos_ssh_key_file" {
  description = "Path to SSH private key"
  type        = string
  default     = null
}
"""

    def generate_main_tf(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "# =============================================================================",
            f"# Juniper SRX JunOS Terraform Suite for {ir.metadata.hostname or 'srx-fw'}",
            "# Generated automatically by Universal Firewall Migration Platform",
            "# =============================================================================",
            ""
        ]

        for addr in ir.addresses:
            if (
                addr.requires_manual_review
                or addr.migration_status != "NORMALIZED"
                or addr.parse_error is not None
            ):
                continue

            clean_id = self._safe_id(addr.name)
            if addr.type == AddressType.HOST:
                ip = addr.value.split('/')[0]
                mask = "/128" if ":" in ip else "/32"
                lines.append(f'resource "junos_security_address_book" "{clean_id}" {{')
                lines.append(f'  name    = "{addr.name}"')
                lines.append(f'  network = "{ip}{mask}"')
                lines.append('}\n')
            elif addr.type == AddressType.NETWORK and addr.value:
                lines.append(f'resource "junos_security_address_book" "{clean_id}" {{')
                lines.append(f'  name    = "{addr.name}"')
                lines.append(f'  network = "{addr.value}"')
                lines.append('}\n')

        return "\n".join(lines)

    def _safe_id(self, name: str) -> str:
        return name.replace(".", "_").replace("-", "_").replace(" ", "_")
