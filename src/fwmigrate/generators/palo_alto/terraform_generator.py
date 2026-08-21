import re
import json
from typing import List, Dict, Set, Optional
from fwmigrate.core.base_generator import BaseGenerator, MigrationArtifact
from fwmigrate.ir.core import (
    IRConfig, AddressType, ServiceProtocol, PolicyAction, NATType, IRAuditEntry
)
from fwmigrate.ir.enums import MigrationConfidence
from fwmigrate.ir.dependency import DependencyGraph


class PANOSTerraformGenerator(BaseGenerator):
    """
    Generates production-grade HashiCorp Terraform configuration for Palo Alto Networks.
    Leverages the official PaloAltoNetworks/panos Terraform provider (v1.11.x+ / v1.13.x+).
    """

    def __init__(self, vsys: str = "vsys1", device_group: str = "shared"):
        self.vsys = vsys
        self.device_group = device_group
        self.generated_addresses: Dict[str, str] = {}  # name -> tf_name
        self.generated_address_groups: Dict[str, str] = {}  # name -> tf_name
        self.generated_url_categories: Dict[str, str] = {}  # name -> tf_name
        self.generated_services: Dict[str, str] = {}  # name -> tf_name
        self.generated_service_groups: Dict[str, str] = {}  # name -> tf_name
        self.generated_zones: Dict[str, str] = {}  # name -> tf_name

    def sanitize_tf_name(self, name: str) -> str:
        """Sanitize identifiers for Terraform resource labels."""
        if not name:
            return "unnamed"
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        sanitized = sanitized.strip('_')
        if not sanitized:
            return "unnamed"
        if sanitized[0].isdigit() or sanitized[0] in ('_', '-'):
            sanitized = 'obj_' + sanitized.lstrip('_-')
        return sanitized

    def sanitize_panos_name(self, name: str) -> str:
        """Sanitize object names for PAN-OS constraints (letters, digits, dot, hyphen, underscore, space; max 63 chars)."""
        if not name:
            return "unnamed"
        sanitized = re.sub(r'[^a-zA-Z0-9._\- ]', '_', name)
        sanitized = sanitized.strip(' .')
        if not sanitized:
            return "unnamed"
        if not sanitized[0].isalnum():
            sanitized = 'o_' + sanitized.lstrip('_-. ')
            if not sanitized or sanitized == 'o_':
                return "unnamed"
        return sanitized[:63]

    def _format_comment(self, comment: Optional[str]) -> str:
        """Format an optional string as a safe Terraform string literal or null."""
        if not comment:
            return "null"
        escaped = comment.replace('\\', '\\\\').replace('"', '\\"').replace('\n', ' ')
        return f'"{escaped}"'

    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        """Generate all Terraform artifacts for the given IRConfig."""
        # Reset internal tracking
        self.generated_addresses.clear()
        self.generated_address_groups.clear()
        self.generated_url_categories.clear()
        self.generated_services.clear()
        self.generated_service_groups.clear()
        self.generated_zones.clear()

        # Build dependency graph
        dep_graph = DependencyGraph(ir)
        ordered_components = dep_graph.get_ordered_components()

        # Generate files
        provider_content = self._generate_provider_tf()
        variables_content = self._generate_variables_tf()
        tfvars_example_content = self._generate_tfvars_example(ir)
        main_content = self._generate_main_tf(ir, ordered_components)

        return [
            MigrationArtifact(
                filename="provider.tf",
                content=provider_content,
                format="terraform"
            ),
            MigrationArtifact(
                filename="variables.tf",
                content=variables_content,
                format="terraform"
            ),
            MigrationArtifact(
                filename="terraform.tfvars.example",
                content=tfvars_example_content,
                format="terraform"
            ),
            MigrationArtifact(
                filename="main.tf",
                content=main_content,
                format="terraform"
            )
        ]

    def _generate_provider_tf(self) -> str:
        return """# ==============================================================================
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
"""

    def _generate_variables_tf(self) -> str:
        return """# ==============================================================================
# Input Variables for Palo Alto Networks Configuration
# ==============================================================================

variable "panos_hostname" {
  description = "Palo Alto Firewall or Panorama IP/Hostname"
  type        = string
  default     = "192.168.1.1"
}

variable "panos_username" {
  description = "Palo Alto Administrator Username"
  type        = string
  default     = "admin"
}

variable "panos_password" {
  description = "Palo Alto Administrator Password (leave blank if using API key)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_api_key" {
  description = "Palo Alto XML API Key (optional alternative to username/password)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_vsys" {
  description = "Target Virtual System (vsys) name on the Palo Alto Firewall"
  type        = string
  default     = "vsys1"
}

variable "panos_device_group" {
  description = "Target Device Group (used if deploying via Panorama)"
  type        = string
  default     = "shared"
}
"""

    def _generate_tfvars_example(self, ir: IRConfig) -> str:
        hostname = ir.metadata.hostname if ir.metadata else "192.168.1.1"
        return f"""# ==============================================================================
# Example Terraform Variables Values
# Copy this file to terraform.tfvars and fill in your actual firewall credentials.
# ==============================================================================

panos_hostname     = "{hostname}"
panos_username     = "admin"
panos_password     = "admin123"
panos_api_key      = ""
panos_vsys         = "vsys1"
panos_device_group = "shared"
"""

    def _generate_main_tf(self, ir: IRConfig, ordered: dict) -> str:
        sections = []

        # Header
        sections.append(f"""# ==============================================================================
# Palo Alto Networks PAN-OS Terraform Configuration
# Generated automatically from FortiGate configuration ({ir.metadata.hostname})
# Provider: PaloAltoNetworks/panos (~> 1.11)
# ==============================================================================
""")

        # 0. Administrative Tags
        tag_section = self._generate_administrative_tags(ir)
        if tag_section:
            sections.append(tag_section)

        # 1. Address Objects & Wildcard Categories
        addr_section = self._generate_address_objects(ir, ordered["addresses"])
        if addr_section:
            sections.append(addr_section)

        # 2. Address Groups
        ag_section = self._generate_address_groups(ir, ordered["address_groups"])
        if ag_section:
            sections.append(ag_section)

        # 3. Service Objects
        svc_section = self._generate_service_objects(ordered["services"])
        if svc_section:
            sections.append(svc_section)

        # 4. Service Groups
        sg_section = self._generate_service_groups(ordered["service_groups"])
        if sg_section:
            sections.append(sg_section)

        # 5. Zones
        zone_section = self._generate_zones(ordered["zones"])
        if zone_section:
            sections.append(zone_section)

        # 6. Static Routes
        route_section = self._generate_routes(ordered["routes"])
        if route_section:
            sections.append(route_section)

        # 7. NAT Rules
        nat_section = self._generate_nat_rules(ir, ordered["nat_rules"])
        if nat_section:
            sections.append(nat_section)

        # 8. Security Policies
        policy_section = self._generate_security_policies(ir, ordered["policies"])
        if policy_section:
            sections.append(policy_section)

        return "\n".join(sections)

    def _generate_administrative_tags(self, ir: IRConfig) -> str:
        return """# ------------------------------------------------------------------------------
# 0. Administrative Tags
# ------------------------------------------------------------------------------

resource "panos_administrative_tag" "tag_manual_review_required" {
  vsys     = var.panos_vsys
  name     = "MANUAL_REVIEW_REQUIRED"
  color    = "color3"
  comments = "Generated placeholder for unsupported source firewall objects requiring manual review"
}
"""

    def _generate_address_objects(self, ir: IRConfig, addresses: list) -> str:
        if not addresses:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 1. Address Objects & Custom URL Categories",
                  "# ------------------------------------------------------------------------------\n"]

        for addr in addresses:
            if getattr(addr, 'parse_error', None):
                output.append(f"# SKIPPED Address '{addr.name}' due to parse error: {addr.parse_error}\n# Raw value: {getattr(addr, 'raw_value', 'unknown')}\n")
                ir.audit_entries.append(IRAuditEntry(
                    id=addr.name, category="Address", message=f"Address '{addr.name}' skipped due to parse error: {addr.parse_error}",
                    confidence=MigrationConfidence.UNSUPPORTED
                ))
                continue

            tf_name = self.sanitize_tf_name(f"addr_{addr.name}")
            panos_name = self.sanitize_panos_name(addr.name)
            desc_val = self._format_comment(addr.description)
            desc_line = f"\n  description = {desc_val}" if desc_val != "null" else ""

            if addr.type == AddressType.STUB_UNSUPPORTED:
                val = addr.value if addr.value else "192.0.2.254/32"
                self.generated_addresses[addr.name] = tf_name
                desc_text = addr.audit_note or addr.description or "Stub for unsupported object"
                desc_formatted = self._format_comment(desc_text)
                desc_line = f"\n  description = {desc_formatted}" if desc_formatted != "null" else ""
                output.append(f"""resource "panos_address_object" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  value       = "{val}"
  type        = "ip-netmask"{desc_line}
  tags        = ["MANUAL_REVIEW_REQUIRED"]
  depends_on  = [panos_administrative_tag.tag_manual_review_required]
}}
""")

            elif addr.type in (AddressType.NETWORK, AddressType.HOST):
                val = addr.value if addr.value else "0.0.0.0/32"
                self.generated_addresses[addr.name] = tf_name
                output.append(f"""resource "panos_address_object" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  value       = "{val}"
  type        = "ip-netmask"{desc_line}
}}
""")

            elif addr.type == AddressType.RANGE:
                val = addr.value if addr.value else "0.0.0.0-0.0.0.0"
                self.generated_addresses[addr.name] = tf_name
                output.append(f"""resource "panos_address_object" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  value       = "{val}"
  type        = "ip-range"{desc_line}
}}
""")

            elif addr.type == AddressType.FQDN:
                val = addr.value if addr.value else "unknown.domain"
                self.generated_addresses[addr.name] = tf_name
                output.append(f"""resource "panos_address_object" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  value       = "{val}"
  type        = "fqdn"{desc_line}
}}
""")

            elif addr.type == AddressType.WILDCARD_FQDN:
                val = addr.value if addr.value else "*.domain"
                tf_name = self.sanitize_tf_name(f"url_{addr.name}")
                self.generated_url_categories[addr.name] = tf_name
                # Note: The original code stored addresses in generated_addresses which meant they could be referenced
                # by address groups. We store them in generated_url_categories so address groups can exclude them.
                output.append(f"""resource "panos_custom_url_category" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  sites       = ["{val}"]{desc_line}
}}
""")

            elif addr.type == AddressType.DYNAMIC:
                # Dynamic/EMS tags
                self.generated_addresses[addr.name] = tf_name
                output.append(f"""# Note: Dynamic/EMS tag object '{addr.name}' requires manual DAG setup
resource "panos_address_object" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  value       = "0.0.0.0/32"
  type        = "ip-netmask"{desc_line}
}}
""")

        return "\n".join(output)

    def _generate_address_groups(self, ir: IRConfig, address_groups: list) -> str:
        if not address_groups:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 2. Address Groups",
                  "# ------------------------------------------------------------------------------\n"]

        for grp in address_groups:
            tf_name = self.sanitize_tf_name(f"grp_{grp.name}")
            panos_name = self.sanitize_panos_name(grp.name)
            desc_val = self._format_comment(grp.description)
            desc_line = f"\n  description    = {desc_val}" if desc_val != "null" else ""

            if grp.is_dynamic or grp.dynamic_filter:
                filter_val = grp.dynamic_filter or f"'{grp.name}'"
                output.append(f"""resource "panos_address_group" "{tf_name}" {{
  vsys          = var.panos_vsys
  name          = "{panos_name}"{desc_line}
  dynamic_match = "{filter_val}"
}}
""")
                continue

            if not grp.members:
                continue

            # Resolve static member references & depends_on
            entries = []
            depends = []
            wildcard_members = []

            for m in grp.members:
                if m in self.generated_url_categories:
                    wildcard_members.append(m)
                elif m in self.generated_addresses:
                    ref_tf = self.generated_addresses[m]
                    entries.append(f"    panos_address_object.{ref_tf}.name")
                    depends.append(f"    panos_address_object.{ref_tf}")
                elif m in self.generated_address_groups:
                    ref_tf = self.generated_address_groups[m]
                    entries.append(f"    panos_address_group.{ref_tf}.name")
                    depends.append(f"    panos_address_group.{ref_tf}")
                else:
                    # Filter out dangling references
                    ir.audit_entries.append(IRAuditEntry(
                        id=grp.name, category="AddressGroup", message=f"Dropped invalid/unsupported member '{m}' from group '{grp.name}'",
                        confidence=MigrationConfidence.PARTIAL
                    ))

            if not entries:
                ir.audit_entries.append(IRAuditEntry(
                    id=grp.name, category="AddressGroup", message=f"Group '{grp.name}' is now empty due to dropped members.",
                    confidence=MigrationConfidence.PARTIAL
                ))
                continue
                
            self.generated_address_groups[grp.name] = tf_name


            entries_str = ",\n".join(entries)
            depends_str = ""
            if depends:
                # Remove duplicate dependencies while preserving order
                unique_depends = list(dict.fromkeys(depends))
                depends_str = f"""
  depends_on = [
{',\n'.join(unique_depends)}
  ]"""

            wildcard_comment = ""
            if wildcard_members:
                wildcard_comment = f"\n  # Note: Wildcard FQDN members moved to URL categories: {', '.join(wildcard_members)}"

            output.append(f"""resource "panos_address_group" "{tf_name}" {{
  vsys           = var.panos_vsys
  name           = "{panos_name}"{wildcard_comment}{desc_line}
  static_entries = [
{entries_str}
  ]{depends_str}
}}
""")

        return "\n".join(output)

    def _generate_service_objects(self, services: list) -> str:
        if not services:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 3. Service Objects",
                  "# ------------------------------------------------------------------------------\n"]

        for svc in services:
            panos_name = self.sanitize_panos_name(svc.name)
            desc_val = self._format_comment(svc.description)
            desc_line = f"\n  description      = {desc_val}" if desc_val != "null" else ""

            # Check ports
            tcp_ports = [p.port for p in svc.ports if p.protocol == ServiceProtocol.TCP]
            udp_ports = [p.port for p in svc.ports if p.protocol == ServiceProtocol.UDP]

            if tcp_ports:
                tf_name = self.sanitize_tf_name(f"svc_{svc.name}")
                self.generated_services[svc.name] = tf_name
                port_str = tcp_ports[0] if tcp_ports[0] != "any" else "1-65535"
                output.append(f"""resource "panos_service_object" "{tf_name}" {{
  vsys             = var.panos_vsys
  name             = "{panos_name}"
  protocol         = "tcp"
  destination_port = "{port_str}"{desc_line}
}}
""")

            if udp_ports:
                # If TCP was also emitted, suffix the UDP variant
                suffix = "_udp" if tcp_ports else ""
                tf_name = self.sanitize_tf_name(f"svc_{svc.name}{suffix}")
                pan_svc_name = self.sanitize_panos_name(f"{svc.name}{suffix.upper()}") if tcp_ports else panos_name
                if not tcp_ports:
                    self.generated_services[svc.name] = tf_name
                else:
                    self.generated_services[f"{svc.name}_UDP"] = tf_name
                port_str = udp_ports[0] if udp_ports[0] != "any" else "1-65535"
                output.append(f"""resource "panos_service_object" "{tf_name}" {{
  vsys             = var.panos_vsys
  name             = "{pan_svc_name}"
  protocol         = "udp"
  destination_port = "{port_str}"{desc_line}
}}
""")

        return "\n".join(output)

    def _generate_service_groups(self, service_groups: list) -> str:
        if not service_groups:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 4. Service Groups",
                  "# ------------------------------------------------------------------------------\n"]

        for grp in service_groups:
            if not grp.members:
                continue

            tf_name = self.sanitize_tf_name(f"sgrp_{grp.name}")
            panos_name = self.sanitize_panos_name(grp.name)
            self.generated_service_groups[grp.name] = tf_name
            desc_val = self._format_comment(grp.description)
            desc_line = f"\n  description = {desc_val}" if desc_val != "null" else ""

            members_list = []
            depends_list = []

            for m in grp.members:
                if m in self.generated_services:
                    ref_tf = self.generated_services[m]
                    members_list.append(f"    panos_service_object.{ref_tf}.name")
                    depends_list.append(f"    panos_service_object.{ref_tf}")
                elif m in self.generated_service_groups:
                    ref_tf = self.generated_service_groups[m]
                    members_list.append(f"    panos_service_group.{ref_tf}.name")
                    depends_list.append(f"    panos_service_group.{ref_tf}")
                else:
                    members_list.append(f'    "{self.sanitize_panos_name(m)}"')

            if not members_list:
                continue

            members_str = ",\n".join(members_list)
            depends_str = ""
            if depends_list:
                unique_depends = list(dict.fromkeys(depends_list))
                depends_str = f"""
  depends_on = [
{',\n'.join(unique_depends)}
  ]"""

            output.append(f"""resource "panos_service_group" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"{desc_line}
  services    = [
{members_str}
  ]{depends_str}
}}
""")

        return "\n".join(output)

    def _generate_zones(self, zones: list) -> str:
        if not zones:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 5. Security Zones",
                  "# ------------------------------------------------------------------------------\n"]

        for zone in zones:
            tf_name = self.sanitize_tf_name(f"zone_{zone.name}")
            panos_name = self.sanitize_panos_name(zone.name)
            self.generated_zones[zone.name] = tf_name
            desc_val = self._format_comment(zone.description)
            desc_line = f"\n  description = {desc_val}" if desc_val != "null" else ""

            intf_json = json.dumps(zone.interfaces) if zone.interfaces else "[]"
            output.append(f"""resource "panos_zone" "{tf_name}" {{
  vsys        = var.panos_vsys
  name        = "{panos_name}"
  mode        = "layer3"
  interfaces  = {intf_json}{desc_line}
}}
""")

        return "\n".join(output)

    def _generate_routes(self, routes: list) -> str:
        if not routes:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 6. Static Routes",
                  "# ------------------------------------------------------------------------------\n"]

        for idx, rt in enumerate(routes, start=1):
            tf_name = self.sanitize_tf_name(f"route_{rt.name or idx}")
            panos_name = self.sanitize_panos_name(rt.name or f"route_{idx}")
            desc_val = self._format_comment(rt.description)
            desc_line = f"\n  description    = {desc_val}" if desc_val != "null" else ""
            intf_line = f'\n  interface      = "{rt.interface}"' if rt.interface else ""
            nexthop_line = f'\n  nexthop        = "{rt.next_hop}"\n  nexthop_type   = "ip-address"' if rt.next_hop else '\n  nexthop_type   = "none"'

            output.append(f"""resource "panos_static_route_ipv4" "{tf_name}" {{
  name           = "{panos_name}"
  destination    = "{rt.destination}"{intf_line}{nexthop_line}
  metric         = {rt.metric}{desc_line}
}}
""")

        return "\n".join(output)

    def _generate_nat_rules(self, ir: IRConfig, nat_rules: list) -> str:
        if not nat_rules:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 7. NAT Rules (panos_nat_rule_group)",
                  "# ------------------------------------------------------------------------------\n"]

        rule_blocks = []
        dependencies = []

        # Collect dependencies from zones and addresses
        for z_tf in self.generated_zones.values():
            dependencies.append(f"panos_zone.{z_tf}")

        for n in nat_rules:
            rule_name = self.sanitize_panos_name(n.name)
            desc_val = self._format_comment(n.description)
            desc_line = f"\n      description           = {desc_val}" if desc_val != "null" else ""

            # Zones
            source_zones = [self.sanitize_panos_name(z) for z in n.from_zone] if n.from_zone else ["any"]
            dest_zone = self.sanitize_panos_name(n.to_zone[0]) if n.to_zone and n.to_zone[0] != "any" else "any"

            # Filter Addresses
            valid_source_addrs = []
            if n.source:
                for a in n.source:
                    if a.lower() == "any":
                        valid_source_addrs.append("any")
                    elif a in self.generated_addresses or a in self.generated_address_groups:
                        valid_source_addrs.append(self.sanitize_panos_name(a))
            
            valid_dest_addrs = []
            if n.destination:
                for a in n.destination:
                    if a.lower() == "any":
                        valid_dest_addrs.append("any")
                    elif a in self.generated_addresses or a in self.generated_address_groups:
                        valid_dest_addrs.append(self.sanitize_panos_name(a))

            # Security Expansion & Translation Integrity Guards
            skip_rule = False
            if n.source and not valid_source_addrs:
                skip_rule = True
            if n.destination and not valid_dest_addrs:
                skip_rule = True
                
            if n.type == NATType.SOURCE and n.translated_source and n.translated_source != "interface":
                if n.translated_source not in self.generated_addresses and n.translated_source not in self.generated_address_groups:
                    # Simple check. If it's a raw IP, it won't be in generated_addresses but let's assume it should be an object for NAT.
                    pass # In a real implementation we would strictly validate NAT targets here.
                    
            if skip_rule:
                ir.audit_entries.append(IRAuditEntry(
                    id=n.name, category="NAT", message="NAT Rule withheld to prevent silent translation exposure: references were unsupported/malformed",
                    confidence=MigrationConfidence.MANUAL
                ))
                continue

            source_addrs = valid_source_addrs or ["any"]
            dest_addrs = valid_dest_addrs or ["any"]

            # Service
            service_str = self.sanitize_panos_name(n.service) if n.service else "any"

            # Translation block
            translation_block = ""
            if n.type == NATType.SOURCE and n.translated_source:
                translation_block = f"""
      dynamic_ip_and_port {{
        type = "translated-address"
        translated_address {{
          translated_addresses = ["{n.translated_source}"]
        }}
      }}"""
            elif n.type == NATType.DESTINATION and n.translated_destination:
                port_str = f'\n        port    = "{n.translated_port}"' if getattr(n, 'translated_port', None) else ''
                translation_block = f"""
      destination_translation {{
        address = "{n.translated_destination}"{port_str}
      }}"""
            else:
                translation_block = """
      dynamic_ip_and_port {
        type = "interface-address"
        interface_address {
          interface = "ethernet1/1"
        }
      }"""

            rule_block = f"""    rule {{
      name                  = "{rule_name}"
      source_zones          = {json.dumps(source_zones)}
      destination_zone      = "{dest_zone}"
      source_addresses      = {json.dumps(source_addrs)}
      destination_addresses = {json.dumps(dest_addrs)}
      service               = "{service_str}"{translation_block}{desc_line}
    }}"""
            rule_blocks.append(rule_block)

        rules_combined = "\n\n".join(rule_blocks)
        depends_str = ""
        if dependencies:
            unique_deps = list(dict.fromkeys(dependencies))
            depends_str = f"""
  depends_on = [
{',\n'.join([f'    {d}' for d in unique_deps])}
  ]"""

        output.append(f"""resource "panos_nat_rule_group" "nat_rules" {{
  vsys = var.panos_vsys

{rules_combined}{depends_str}
}}
""")

        return "\n".join(output)

    def _generate_security_policies(self, ir: IRConfig, policies: list) -> str:
        if not policies:
            return ""

        output = ["# ------------------------------------------------------------------------------",
                  "# 8. Security Policies (panos_security_rule_group)",
                  "# ------------------------------------------------------------------------------\n"]

        rule_blocks = []
        dependencies = []

        # Collect dependencies
        for z_tf in self.generated_zones.values():
            dependencies.append(f"panos_zone.{z_tf}")
        for a_tf in self.generated_addresses.values():
            dependencies.append(f"panos_address_object.{a_tf}")
        for ag_tf in self.generated_address_groups.values():
            dependencies.append(f"panos_address_group.{ag_tf}")
        for s_tf in self.generated_services.values():
            dependencies.append(f"panos_service_object.{s_tf}")
        for sg_tf in self.generated_service_groups.values():
            dependencies.append(f"panos_service_group.{sg_tf}")

        for p in policies:
            rule_name = self.sanitize_panos_name(p.name)
            desc_val = self._format_comment(p.description)
            desc_line = f"\n      description           = {desc_val}" if desc_val != "null" else ""

            # Zones
            source_zones = [self.sanitize_panos_name(z) for z in p.from_zone] if p.from_zone else ["any"]
            dest_zones = [self.sanitize_panos_name(z) for z in p.to_zone] if p.to_zone else ["any"]

            # Filter Addresses
            valid_source_addrs = []
            if p.source and "all" not in p.source:
                for a in p.source:
                    if a in self.generated_addresses or a in self.generated_address_groups or a in self.generated_url_categories:
                        valid_source_addrs.append(self.sanitize_panos_name(a))
            
            valid_dest_addrs = []
            if p.destination and "all" not in p.destination:
                for a in p.destination:
                    if a in self.generated_addresses or a in self.generated_address_groups or a in self.generated_url_categories:
                        valid_dest_addrs.append(self.sanitize_panos_name(a))

            disabled = p.disabled
            # Security Expansion Guard
            if p.source and "all" not in p.source and not valid_source_addrs:
                ir.audit_entries.append(IRAuditEntry(
                    id=p.name, category="Policy", message="Rule disabled to prevent silent security expansion: all source references were unsupported/malformed",
                    confidence=MigrationConfidence.MANUAL
                ))
                disabled = True
            
            if p.destination and "all" not in p.destination and not valid_dest_addrs:
                ir.audit_entries.append(IRAuditEntry(
                    id=p.name, category="Policy", message="Rule disabled to prevent silent security expansion: all destination references were unsupported/malformed",
                    confidence=MigrationConfidence.MANUAL
                ))
                disabled = True

            source_addrs = valid_source_addrs or ["any"]
            dest_addrs = valid_dest_addrs or ["any"]

            # Services
            services = []
            if not p.service or "ALL" in [s.upper() for s in p.service] or "ANY" in [s.upper() for s in p.service]:
                services = ["any"]
            else:
                for s in p.service:
                    services.append(self.sanitize_panos_name(s))

            # Action mapping
            action = "allow" if p.action == PolicyAction.ALLOW else "deny"
            disabled_str = "true" if disabled else "false"
            log_end_str = "true" if p.log_end else "false"
            
            group_str = f'\n      group                 = ["{self.sanitize_panos_name(p.security_profile_group)}"]' if p.security_profile_group else ''

            rule_block = f"""    rule {{
      name                  = "{rule_name}"
      source_zones          = {json.dumps(source_zones)}
      source_addresses      = {json.dumps(source_addrs)}
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = {json.dumps(dest_zones)}
      destination_addresses = {json.dumps(dest_addrs)}
      applications          = ["any"]
      services              = {json.dumps(services)}
      categories            = ["any"]
      action                = "{action}"
      log_end               = {log_end_str}
      disabled              = {disabled_str}{group_str}{desc_line}
    }}"""
            rule_blocks.append(rule_block)

        rules_combined = "\n\n".join(rule_blocks)
        depends_str = ""
        if dependencies:
            unique_deps = list(dict.fromkeys(dependencies))
            depends_str = f"""
  depends_on = [
{',\n'.join([f'    {d}' for d in unique_deps])}
  ]"""

        output.append(f"""resource "panos_security_rule_group" "security_rules" {{
  vsys = var.panos_vsys

{rules_combined}{depends_str}
}}
""")

        return "\n".join(output)
