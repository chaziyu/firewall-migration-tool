from typing import List
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction
from fwmigrate.ir.semantics import (
    AddressUniversalFamily,
    classify_universal_address_reference,
    unsafe_zone_names,
    policy_references_unsafe_zone,
)
from fwmigrate.core.base_generator import MigrationArtifact

class FortiGateTerraformGenerator:
    """Generates FortiOS Terraform HCL targeting provider `fortinetdev/fortios`."""

    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        artifacts = []

        # 1. provider.tf
        provider_tf = """terraform {
  required_providers {
    fortios = {
      source  = "fortinetdev/fortios"
      version = "~> 1.18.0"
    }
  }
}

provider "fortios" {
  hostname = var.fortios_hostname
  token    = var.fortios_token
  insecure = var.fortios_insecure
  vdom     = var.fortios_vdom
}
"""
        artifacts.append(MigrationArtifact(filename="provider.tf", content=provider_tf, format="terraform"))

        # 2. variables.tf
        vars_tf = """variable "fortios_hostname" {
  description = "FortiGate management IP or FQDN"
  type        = string
}

variable "fortios_token" {
  description = "FortiGate REST API Administrator Token"
  type        = string
  sensitive   = true
}

variable "fortios_insecure" {
  description = "Allow unverified SSL certificates"
  type        = bool
  default     = true
}

variable "fortios_vdom" {
  description = "Target VDOM name"
  type        = string
  default     = "root"
}
"""
        artifacts.append(MigrationArtifact(filename="variables.tf", content=vars_tf, format="terraform"))

        # 3. main.tf
        main_tf_lines = [
            f"# FortiOS Terraform Resources generated from {ir.metadata.source_vendor}",
            ""
        ]

        # Addresses
        for a in ir.addresses:
            if a.type == AddressType.STUB_UNSUPPORTED:
                main_tf_lines.append(
                    f"# Address {a.name} withheld: unsupported source address semantics require manual review\n"
                )
                continue
            clean_res_name = a.name.replace(".", "_").replace("-", "_").replace(" ", "_")
            if a.type == AddressType.FQDN:
                main_tf_lines.append(f"""resource "fortios_firewall_address" "{clean_res_name}" {{
  name = "{a.name}"
  type = "fqdn"
  fqdn = "{a.value}"
}}
""")
            elif a.type == AddressType.RANGE:
                parts = a.value.split('-')
                start_ip = parts[0] if len(parts) > 0 else "0.0.0.0"
                end_ip = parts[1] if len(parts) > 1 else "0.0.0.0"
                main_tf_lines.append(f"""resource "fortios_firewall_address" "{clean_res_name}" {{
  name     = "{a.name}"
  type     = "iprange"
  start_ip = "{start_ip}"
  end_ip   = "{end_ip}"
}}
""")
            else:
                subnet = a.value if '/' in a.value else f"{a.value}/32"
                main_tf_lines.append(f"""resource "fortios_firewall_address" "{clean_res_name}" {{
  name   = "{a.name}"
  type   = "ipmask"
  subnet = "{subnet}"
}}
""")

        # Address Groups
        for ag in ir.address_groups:
            if ag.requires_manual_review:
                continue
            clean_res_name = ag.name.replace(".", "_").replace("-", "_").replace(" ", "_")
            members_blocks = "\n".join([f'    name = "{m}"' for m in ag.members])
            main_tf_lines.append(f"""resource "fortios_firewall_addrgrp" "{clean_res_name}" {{
  name = "{ag.name}"
  dynamic "member" {{
    for_each = {ag.members}
    content {{
      name = member.value
    }}
  }}
}}
""")

        # Policies
        unsafe_zones = unsafe_zone_names(ir)
        for idx, p in enumerate(ir.policies, 1):
            if p.action == PolicyAction.IPSEC or not p.safe_for_target_generation:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: source semantics require manual review\n"
                )
                continue
            if policy_references_unsafe_zone(p, unsafe_zones):
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: referenced zone requires manual review\n"
                )
                continue
            if not p.from_zone or not p.to_zone:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: canonical zones require manual review\n"
                )
                continue
            clean_res_name = f"policy_{idx}_{p.name}".replace(".", "_").replace("-", "_").replace(" ", "_")
            act = "accept" if p.action == PolicyAction.ALLOW else "deny"

            ipv4_srcs = []
            ipv6_srcs = []
            for s in (p.source or ["all"]):
                fam = classify_universal_address_reference(s)
                if fam == AddressUniversalFamily.IPV6:
                    ipv6_srcs.append("all")
                elif fam == AddressUniversalFamily.IPV4:
                    ipv4_srcs.append("all")
                elif fam == AddressUniversalFamily.ANY:
                    ipv4_srcs.append("all")
                    ipv6_srcs.append("all")
                else:
                    ipv4_srcs.append(s)

            ipv4_dsts = []
            ipv6_dsts = []
            for d in (p.destination or ["all"]):
                fam = classify_universal_address_reference(d)
                if fam == AddressUniversalFamily.IPV6:
                    ipv6_dsts.append("all")
                elif fam == AddressUniversalFamily.IPV4:
                    ipv4_dsts.append("all")
                elif fam == AddressUniversalFamily.ANY:
                    ipv4_dsts.append("all")
                    ipv6_dsts.append("all")
                else:
                    ipv4_dsts.append(d)

            main_tf_lines.append(f"""resource "fortios_firewall_policy" "{clean_res_name}" {{
  name     = "{p.name}"
  action   = "{act}"
  schedule = "always"
  status   = "{"disable" if p.disabled else "enable"}"

  dynamic "srcintf" {{
    for_each = {p.from_zone}
    content {{
      name = srcintf.value
    }}
  }}

  dynamic "dstintf" {{
    for_each = {p.to_zone}
    content {{
      name = dstintf.value
    }}
  }}
""")

            if ipv4_srcs:
                main_tf_lines.append(f"""  dynamic "srcaddr" {{
    for_each = {ipv4_srcs}
    content {{
      name = srcaddr.value
    }}
  }}
""")
            elif ipv6_srcs:
                main_tf_lines.append(f"""  dynamic "srcaddr" {{
    for_each = ["none"]
    content {{
      name = srcaddr.value
    }}
  }}
""")

            if ipv6_srcs:
                main_tf_lines.append(f"""  dynamic "srcaddr6" {{
    for_each = {ipv6_srcs}
    content {{
      name = srcaddr6.value
    }}
  }}
""")

            if ipv4_dsts:
                main_tf_lines.append(f"""  dynamic "dstaddr" {{
    for_each = {ipv4_dsts}
    content {{
      name = dstaddr.value
    }}
  }}
""")
            elif ipv6_dsts:
                main_tf_lines.append(f"""  dynamic "dstaddr" {{
    for_each = ["none"]
    content {{
      name = dstaddr.value
    }}
  }}
""")

            if ipv6_dsts:
                main_tf_lines.append(f"""  dynamic "dstaddr6" {{
    for_each = {ipv6_dsts}
    content {{
      name = dstaddr6.value
    }}
  }}
""")

            main_tf_lines.append(f"""  dynamic "service" {{
    for_each = {p.service if p.service else ["ALL"]}
    content {{
      name = service.value
    }}
  }}
}}
""")

        artifacts.append(MigrationArtifact(filename="main.tf", content="\n".join(main_tf_lines), format="terraform"))
        return artifacts
