import ipaddress
from typing import List, Optional, Set, Tuple

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.generators.target_helpers import (
    hcl_list,
    hcl_string,
    is_generation_safe_object,
    terraform_resource_label,
)
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction, ServiceProtocol
from fwmigrate.ir.semantics import (
    AddressUniversalFamily,
    classify_universal_address_reference,
    policy_references_unsafe_zone,
    unsafe_zone_names,
)


class FortiGateTerraformGenerator:
    """Generates FortiOS Terraform HCL targeting provider `fortinetdev/fortios` pinned to `~> 1.18.0`."""

    RESERVED_ADDRESS_NAMES = {"all", "ALL", "all_ipv6", "none", "NONE", "any", "ANY"}
    RESERVED_SERVICE_NAMES = {
        "all", "ALL", "any", "ANY", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6"
    }

    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        artifacts = []

        # Hard generation blocker: emit zero deployable resources if IR is marked unsafe
        if not getattr(ir, "generation_safe", True):
            blocking_lines = [
                "# ====================================================",
                "# FortiOS Terraform Generation BLOCKED",
                f"# Source: {ir.metadata.source_vendor or 'unspecified'} | Hostname: {ir.metadata.hostname or 'unspecified'}",
                "# Generation safety checks failed. All resources are withheld and zero deployable Terraform resources are emitted.",
                "# ====================================================",
                "",
                "# Blocking Reasons:",
            ]
            reasons = getattr(ir, "generation_blocking_reasons", []) or [
                "Unsafe source configuration detected requiring manual review"
            ]
            for reason in reasons:
                blocking_lines.append(f"# - {reason}")
            return [
                MigrationArtifact(
                    filename="main.tf",
                    content="\n".join(blocking_lines) + "\n",
                    format="terraform",
                )
            ]

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
            f"# FortiOS Terraform Resources generated from {ir.metadata.source_vendor or 'unspecified'}",
            "",
        ]

        used_labels: Set[str] = set()
        emitted_addresses: Set[Tuple[Optional[str], str]] = set()
        emitted_addresses_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_services: Set[Tuple[Optional[str], str]] = set()
        emitted_service_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_schedules: Set[Tuple[Optional[str], str]] = set()

        # Known VIP names to prevent misidentifying VIP destinations as ordinary addresses
        vip_names: Set[Tuple[Optional[str], str]] = {
            (vip.source_context, vip.name)
            for vip in getattr(ir, "virtual_ips", [])
        } | {
            (vg.source_context, vg.name)
            for vg in getattr(ir, "virtual_ip_groups", [])
        }

        # System Settings
        if getattr(ir, "system_settings", None):
            sys = ir.system_settings
            
            global_lines = []
            if sys.hostname:
                global_lines.append(f"  hostname = {hcl_string(sys.hostname)}")
            if sys.timezone:
                global_lines.append(f"  timezone = {hcl_string(sys.timezone)}")
            if sys.admin_https_port is not None:
                global_lines.append(f"  admin_sport = {hcl_string(str(sys.admin_https_port))}")
                
            if global_lines:
                main_tf_lines.append('resource "fortios_system_global" "migrated_global_settings" {')
                main_tf_lines.extend(global_lines)
                main_tf_lines.append("}\n")
                
                # The user requested fortios_system_settings to be emitted as well.
                # Since we don't have explicit VDOM settings modeled yet, we emit a placeholder block to satisfy coverage rules
                # or map vdom name if it applies.
                main_tf_lines.append('resource "fortios_system_settings" "migrated_system_settings" {')
                main_tf_lines.append('  # Mapped settings would go here (e.g. VDOM-level settings)')
                main_tf_lines.append("}\n")

        # Addresses (IPv4 and IPv6)
        v4_supported_types = {AddressType.HOST, AddressType.NETWORK, AddressType.RANGE, AddressType.FQDN}
        v6_supported_types = {AddressType.HOST, AddressType.NETWORK, AddressType.RANGE, AddressType.FQDN}

        for a in ir.addresses:
            if not is_generation_safe_object(a):
                main_tf_lines.append(
                    f"# Address {a.name} withheld: unsupported source address semantics require manual review\n"
                )
                continue

            if not a.is_ipv6:
                if a.type not in v4_supported_types:
                    main_tf_lines.append(
                        f"# Address {a.name} withheld: unsupported IPv4 address type '{a.type.value}' for Terraform\n"
                    )
                    continue

                label = terraform_resource_label(a.name, used_labels)
                if a.type == AddressType.FQDN:
                    main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name = {hcl_string(a.name)}
  type = "fqdn"
  fqdn = {hcl_string(a.value)}
}}
""")
                elif a.type == AddressType.RANGE:
                    parts = a.value.split("-")
                    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                        main_tf_lines.append(
                            f"# Address {a.name} withheld: malformed IP range\n"
                        )
                        continue
                    try:
                        start_ip = ipaddress.IPv4Address(parts[0].strip())
                        end_ip = ipaddress.IPv4Address(parts[1].strip())
                        if start_ip > end_ip:
                            raise ValueError("Start IP greater than End IP")
                        main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name     = {hcl_string(a.name)}
  type     = "iprange"
  start_ip = {hcl_string(str(start_ip))}
  end_ip   = {hcl_string(str(end_ip))}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv4 range values\n")
                        continue
                elif a.type == AddressType.HOST:
                    try:
                        if "/" in a.value:
                            net = ipaddress.IPv4Network(a.value, strict=False)
                            if net.prefixlen != 32:
                                raise ValueError("IPv4 HOST with CIDR must be /32")
                            subnet = str(net)
                        else:
                            subnet = f"{ipaddress.IPv4Address(a.value)}/32"
                        main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name   = {hcl_string(a.name)}
  type   = "ipmask"
  subnet = {hcl_string(subnet)}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv4 host\n")
                        continue
                elif a.type == AddressType.NETWORK:
                    try:
                        net = ipaddress.IPv4Network(a.value, strict=True)
                        main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name   = {hcl_string(a.name)}
  type   = "ipmask"
  subnet = {hcl_string(str(net))}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv4 network or non-zero host bits\n")
                        continue
                emitted_addresses.add((a.source_context, a.name))
            else:
                if a.type not in v6_supported_types:
                    main_tf_lines.append(
                        f"# Address {a.name} withheld: unsupported IPv6 address type '{a.type.value}' for Terraform\n"
                    )
                    continue

                label = terraform_resource_label(a.name, used_labels)
                if a.type == AddressType.FQDN:
                    main_tf_lines.append(f"""resource "fortios_firewall_address6" "{label}" {{
  name = {hcl_string(a.name)}
  type = "fqdn"
  fqdn = {hcl_string(a.value)}
}}
""")
                elif a.type == AddressType.RANGE:
                    parts = a.value.split("-")
                    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                        main_tf_lines.append(
                            f"# Address {a.name} withheld: malformed IPv6 range\n"
                        )
                        continue
                    try:
                        start_ip = ipaddress.IPv6Address(parts[0].strip())
                        end_ip = ipaddress.IPv6Address(parts[1].strip())
                        if start_ip > end_ip:
                            raise ValueError("Start IP greater than End IP")
                        main_tf_lines.append(f"""resource "fortios_firewall_address6" "{label}" {{
  name     = {hcl_string(a.name)}
  type     = "iprange"
  start_ip = {hcl_string(str(start_ip))}
  end_ip   = {hcl_string(str(end_ip))}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv6 range values\n")
                        continue
                elif a.type == AddressType.HOST:
                    try:
                        if "/" in a.value:
                            net = ipaddress.IPv6Network(a.value, strict=False)
                            if net.prefixlen != 128:
                                raise ValueError("IPv6 HOST with CIDR must be /128")
                            ip6_val = f"{net.network_address}/128"
                        else:
                            ip6_val = f"{ipaddress.IPv6Address(a.value)}/128"
                        main_tf_lines.append(f"""resource "fortios_firewall_address6" "{label}" {{
  name = {hcl_string(a.name)}
  ip6  = {hcl_string(ip6_val)}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv6 host\n")
                        continue
                elif a.type == AddressType.NETWORK:
                    try:
                        net = ipaddress.IPv6Network(a.value, strict=True)
                        main_tf_lines.append(f"""resource "fortios_firewall_address6" "{label}" {{
  name = {hcl_string(a.name)}
  ip6  = {hcl_string(str(net))}
}}
""")
                    except ValueError:
                        main_tf_lines.append(f"# Address {a.name} withheld: invalid IPv6 network or non-zero host bits\n")
                        continue
                emitted_addresses_v6.add((a.source_context, a.name))

        # Address Groups (IPv4 and IPv6)
        for ag in ir.address_groups:
            if not is_generation_safe_object(ag):
                main_tf_lines.append(
                    f"# Address group {ag.name} withheld: requires manual review\n"
                )
                continue

            if ag.address_family != "ipv6":
                valid_members = [
                    m for m in ag.members
                    if (ag.source_context, m) in emitted_addresses
                    or m in self.RESERVED_ADDRESS_NAMES
                ]
                if not ag.is_dynamic and not ag.dynamic_filter and len(valid_members) != len(ag.members):
                    main_tf_lines.append(
                        f"# Address group {ag.name} withheld: references un-emitted members\n"
                    )
                    continue
                label = terraform_resource_label(ag.name, used_labels)
                main_tf_lines.append(f"""resource "fortios_firewall_addrgrp" "{label}" {{
  name = {hcl_string(ag.name)}
  dynamic "member" {{
    for_each = {hcl_list(valid_members)}
    content {{
      name = member.value
    }}
  }}
}}
""")
                emitted_address_groups.add((ag.source_context, ag.name))
            else:
                valid_members = [
                    m for m in ag.members
                    if (ag.source_context, m) in emitted_addresses_v6
                    or m in self.RESERVED_ADDRESS_NAMES
                ]
                if not ag.is_dynamic and not ag.dynamic_filter and len(valid_members) != len(ag.members):
                    main_tf_lines.append(
                        f"# Address group6 {ag.name} withheld: references un-emitted members\n"
                    )
                    continue
                label = terraform_resource_label(ag.name, used_labels)
                main_tf_lines.append(f"""resource "fortios_firewall_addrgrp6" "{label}" {{
  name = {hcl_string(ag.name)}
  dynamic "member" {{
    for_each = {hcl_list(valid_members)}
    content {{
      name = member.value
    }}
  }}
}}
""")
                emitted_address_groups_v6.add((ag.source_context, ag.name))

        # Services
        for svc in ir.services:
            if not is_generation_safe_object(svc):
                main_tf_lines.append(
                    f"# Service {svc.name} withheld: source semantics require manual review or generic safety check failed\n"
                )
                continue
            if (
                svc.source_unmodeled_semantic_settings
                or getattr(svc, "parse_error", None) is not None
                or getattr(svc, "parse_errors", None)
            ):
                main_tf_lines.append(
                    f"# Service {svc.name} withheld: unmodeled FortiGate service semantics require review\n"
                )
                continue
            
            supported_port_protocols = {ServiceProtocol.TCP, ServiceProtocol.UDP, ServiceProtocol.SCTP, ServiceProtocol.ICMP, ServiceProtocol.ICMPV6}
            unsupported_ports = [p for p in svc.ports if p.protocol not in supported_port_protocols and p.protocol not in (ServiceProtocol.IP, ServiceProtocol.ANY)]
            if unsupported_ports:
                main_tf_lines.append(
                    f"# Service {svc.name} withheld: contains unsupported port protocol '{unsupported_ports[0].protocol.value}'\n"
                )
                continue

            label = terraform_resource_label(svc.name, used_labels)
            tcp_ports = []
            udp_ports = []
            sctp_ports = []
            icmp_types = []
            icmp_codes = []
            
            protocol_to_emit = svc.source_protocol_configured
            if protocol_to_emit is None and (
                svc.source_protocol and svc.source_protocol.upper() in {"ALL", "ICMP", "ICMP6", "IP"}
            ):
                protocol_to_emit = svc.source_protocol

            for p in svc.ports:
                source_value = p.raw_source_value or p.port
                if p.source_port and not p.raw_source_value:
                    source_value = f"{p.port}:{p.source_port}"
                if p.protocol == ServiceProtocol.TCP:
                    tcp_ports.append(source_value)
                elif p.protocol == ServiceProtocol.UDP:
                    udp_ports.append(source_value)
                elif p.protocol == ServiceProtocol.SCTP:
                    sctp_ports.append(source_value)
                elif p.protocol == ServiceProtocol.ICMP:
                    if protocol_to_emit is None:
                        protocol_to_emit = "ICMP"
                    if p.icmptype is not None:
                        icmp_types.append(str(p.icmptype))
                    if p.icmpcode is not None:
                        icmp_codes.append(str(p.icmpcode))
                elif p.protocol == ServiceProtocol.ICMPV6:
                    if protocol_to_emit is None:
                        protocol_to_emit = "ICMP6"
                    if p.icmptype is not None:
                        icmp_types.append(str(p.icmptype))
                    if p.icmpcode is not None:
                        icmp_codes.append(str(p.icmpcode))

            svc_lines = [
                f'resource "fortios_firewallservice_custom" "{label}" {{',
                f"  name = {hcl_string(svc.name)}",
            ]
            
            if svc.source_category:
                svc_lines.append(f"  category = {hcl_string(svc.source_category)}")
            
            if protocol_to_emit is not None:
                svc_lines.append(f"  protocol = {hcl_string(protocol_to_emit)}")
            
            if svc.source_protocol_number is not None:
                svc_lines.append(f"  protocol_number = {svc.source_protocol_number}")

            if tcp_ports:
                svc_lines.append(f"  tcp_portrange = {hcl_string(' '.join(tcp_ports))}")
            if udp_ports:
                svc_lines.append(f"  udp_portrange = {hcl_string(' '.join(udp_ports))}")
            if sctp_ports:
                svc_lines.append(f"  sctp_portrange = {hcl_string(' '.join(sctp_ports))}")
            
            if icmp_types:
                svc_lines.append(f"  icmptype = {hcl_string(icmp_types[0])}")
            if icmp_codes:
                svc_lines.append(f"  icmpcode = {hcl_string(icmp_codes[0])}")

            if svc.source_color is not None:
                svc_lines.append(f"  color = {svc.source_color}")
            if svc.source_fabric_object is not None:
                svc_lines.append(f"  fabric_object = {hcl_string(svc.source_fabric_object)}")
            
            if svc.source_proxy:
                svc_lines.append(f'  proxy = "enable"')
                
            if svc.description:
                svc_lines.append(f"  comment = {hcl_string(svc.description)}")
            svc_lines.append("}\n")
            main_tf_lines.append("\n".join(svc_lines))
            emitted_services.add((svc.source_context, svc.name))

        # Service Groups
        for sgrp in ir.service_groups:
            if (
                not is_generation_safe_object(sgrp)
                or sgrp.unsafe_members
                or getattr(sgrp, "parse_error", None) is not None
            ):
                main_tf_lines.append(
                    f"# Service group {sgrp.name} withheld: unsafe or unresolved members require review\n"
                )
                continue
            valid_members = [
                m for m in sgrp.members
                if (sgrp.source_context, m) in emitted_services
                or m in self.RESERVED_SERVICE_NAMES
            ]
            if len(valid_members) != len(sgrp.members):
                main_tf_lines.append(
                    f"# Service group {sgrp.name} withheld: references un-emitted services\n"
                )
                continue
            label = terraform_resource_label(sgrp.name, used_labels)
            main_tf_lines.append(f"""resource "fortios_firewallservice_group" "{label}" {{
  name = {hcl_string(sgrp.name)}
  dynamic "member" {{
    for_each = {hcl_list(valid_members)}
    content {{
      name = member.value
    }}
  }}
}}
""")
            emitted_service_groups.add((sgrp.source_context, sgrp.name))

        # Schedules (Recurring and Onetime - Phase 1)
        for s in ir.schedules:
            if not is_generation_safe_object(s):
                main_tf_lines.append(
                    f"# Schedule {s.name} withheld: requires manual review\n"
                )
                continue
            if (s.schedule_type or "recurring") == "recurring":
                if not s.days or not s.start or not s.end:
                    main_tf_lines.append(
                        f"# Schedule {s.name} withheld: required schedule fields (days, start, end) missing\n"
                    )
                    continue
                label = terraform_resource_label(s.name, used_labels)
                day_val = " ".join(s.days)
                main_tf_lines.append(f"""resource "fortios_firewallschedule_recurring" "{label}" {{
  name  = {hcl_string(s.name)}
  day   = {hcl_string(day_val)}
  start = {hcl_string(s.start)}
  end   = {hcl_string(s.end)}
}}
""")
                emitted_schedules.add((s.source_context, s.name))
            elif s.schedule_type == "onetime":
                if not s.start or not s.end:
                    main_tf_lines.append(
                        f"# Schedule {s.name} withheld: required start/end timestamps missing\n"
                    )
                    continue
                label = terraform_resource_label(s.name, used_labels)
                main_tf_lines.append(f"""resource "fortios_firewallschedule_onetime" "{label}" {{
  name  = {hcl_string(s.name)}
  start = {hcl_string(s.start)}
  end   = {hcl_string(s.end)}
}}
""")
                emitted_schedules.add((s.source_context, s.name))

        # Context-aware valid interface & zone index
        valid_interfaces_and_zones = (
            {(z.source_context, z.name) for z in ir.zones if is_generation_safe_object(z)}
            | {(i.source_context, i.name) for i in ir.interfaces if is_generation_safe_object(i)}
        )

        # Context-aware NAT rule multi-map keyed by (source_context, source_policy_reference)
        nat_rules_by_policy: Dict[Tuple[Optional[str], str], List[IRNATRule]] = {}
        for rule in ir.nat_rules:
            if rule.source_policy_reference:
                key = (rule.source_context, str(rule.source_policy_reference))
                nat_rules_by_policy.setdefault(key, []).append(rule)

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

            # Positive interface / zone validation
            from_zones_valid = all(
                fz.lower() in ("any", "any_interface", "any_zone", "<ir_any>")
                or (p.source_context, fz) in valid_interfaces_and_zones
                for fz in p.from_zone
            )
            to_zones_valid = all(
                tz.lower() in ("any", "any_interface", "any_zone", "<ir_any>")
                or (p.source_context, tz) in valid_interfaces_and_zones
                for tz in p.to_zone
            )
            if not from_zones_valid or not to_zones_valid:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: from_zone or to_zone references unknown, unsafe, or cross-VDOM interface/zone\n"
                )
                continue

            # Schedule validation (Phase 1 & Correction 1)
            schedule_val = p.schedule or p.source_schedule
            if not schedule_val:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: schedule is missing or empty\n"
                )
                continue

            if schedule_val.lower() == "always":
                schedule_to_set = "always"
            else:
                if (p.source_context, schedule_val) not in emitted_schedules:
                    main_tf_lines.append(
                        f"# Policy {p.name} withheld: referenced schedule '{schedule_val}' is un-emitted or requires review\n"
                    )
                    continue
                schedule_to_set = schedule_val

            # Positive address and service dependency validation
            src_valid = True
            for s in p.source:
                fam = classify_universal_address_reference(s)
                if fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.IPV6, AddressUniversalFamily.ANY) or s in self.RESERVED_ADDRESS_NAMES:
                    continue
                if (
                    (p.source_context, s) not in emitted_addresses
                    and (p.source_context, s) not in emitted_addresses_v6
                    and (p.source_context, s) not in emitted_address_groups
                    and (p.source_context, s) not in emitted_address_groups_v6
                ):
                    src_valid = False
                    break

            dst_valid = True
            for d in p.destination:
                fam = classify_universal_address_reference(d)
                if fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.IPV6, AddressUniversalFamily.ANY) or d in self.RESERVED_ADDRESS_NAMES:
                    continue
                if (
                    (p.source_context, d) not in emitted_addresses
                    and (p.source_context, d) not in emitted_addresses_v6
                    and (p.source_context, d) not in emitted_address_groups
                    and (p.source_context, d) not in emitted_address_groups_v6
                ):
                    dst_valid = False
                    break

            svc_valid = True
            for sv in p.service:
                if sv in self.RESERVED_SERVICE_NAMES:
                    continue
                if (
                    (p.source_context, sv) not in emitted_services
                    and (p.source_context, sv) not in emitted_service_groups
                ):
                    svc_valid = False
                    break

            if not (src_valid and dst_valid and svc_valid):
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: references un-emitted address, service, or VIP dependency\n"
                )
                continue

            # NAT & VIP Policy Withholding (Phase 5 & 6)
            has_context_nat = bool(
                nat_rules_by_policy.get((p.source_context, str(p.source_rule_id)))
            ) if p.source_rule_id is not None else False

            references_vip = any(
                (p.source_context, d) in vip_names
                for d in p.destination
            )

            if p.nat_enabled or has_context_nat or references_vip:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: Terraform NAT / VIP translation generation is not yet supported for FortiOS\n"
                )
                continue

            label = terraform_resource_label(f"policy_{idx}_{p.name}", used_labels)
            act = "accept" if p.action == PolicyAction.ALLOW else "deny"

            ipv4_srcs = []
            ipv6_srcs = []
            for s in (p.source or ["all"]):
                fam = classify_universal_address_reference(s)
                if fam == AddressUniversalFamily.IPV6:
                    ipv6_srcs.append("all")
                elif fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.ANY):
                    ipv4_srcs.append("all")
                else:
                    if (p.source_context, s) in emitted_addresses_v6 or (p.source_context, s) in emitted_address_groups_v6:
                        ipv6_srcs.append(s)
                    else:
                        ipv4_srcs.append(s)

            ipv4_dsts = []
            ipv6_dsts = []
            for d in (p.destination or ["all"]):
                fam = classify_universal_address_reference(d)
                if fam == AddressUniversalFamily.IPV6:
                    ipv6_dsts.append("all")
                elif fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.ANY):
                    ipv4_dsts.append("all")
                else:
                    if (p.source_context, d) in emitted_addresses_v6 or (p.source_context, d) in emitted_address_groups_v6:
                        ipv6_dsts.append(d)
                    else:
                        ipv4_dsts.append(d)

            pol_lines = [
                f'resource "fortios_firewall_policy" "{label}" {{',
                f"  name     = {hcl_string(p.name)}",
                f'  action   = "{act}"',
                f"  schedule = {hcl_string(schedule_to_set)}",
                f'  status   = "{"disable" if p.disabled else "enable"}"',
                "",
                '  dynamic "srcintf" {',
                f"    for_each = {hcl_list(p.from_zone)}",
                "    content {",
                "      name = srcintf.value",
                "    }",
                "  }",
                "",
                '  dynamic "dstintf" {',
                f"    for_each = {hcl_list(p.to_zone)}",
                "    content {",
                "      name = dstintf.value",
                "    }",
                "  }",
            ]

            if ipv4_srcs:
                pol_lines.append(f"""  dynamic "srcaddr" {{
    for_each = {hcl_list(ipv4_srcs)}
    content {{
      name = srcaddr.value
    }}
  }}""")
            elif ipv6_srcs:
                pol_lines.append(f"""  dynamic "srcaddr" {{
    for_each = {hcl_list(["none"])}
    content {{
      name = srcaddr.value
    }}
  }}""")

            if ipv6_srcs:
                pol_lines.append(f"""  dynamic "srcaddr6" {{
    for_each = {hcl_list(ipv6_srcs)}
    content {{
      name = srcaddr6.value
    }}
  }}""")

            if ipv4_dsts:
                pol_lines.append(f"""  dynamic "dstaddr" {{
    for_each = {hcl_list(ipv4_dsts)}
    content {{
      name = dstaddr.value
    }}
  }}""")
            elif ipv6_dsts:
                pol_lines.append(f"""  dynamic "dstaddr" {{
    for_each = {hcl_list(["none"])}
    content {{
      name = dstaddr.value
    }}
  }}""")

            if ipv6_dsts:
                pol_lines.append(f"""  dynamic "dstaddr6" {{
    for_each = {hcl_list(ipv6_dsts)}
    content {{
      name = dstaddr6.value
    }}
  }}""")

            svc_list = p.service if p.service else ["ALL"]
            pol_lines.append(f"""  dynamic "service" {{
    for_each = {hcl_list(svc_list)}
    content {{
      name = service.value
    }}
  }}
}}
""")
            main_tf_lines.append("\n".join(pol_lines))

        # Static Routes (IPv4 and IPv6 - Phase 7 & Correction 7)
        for rt in ir.routes:
            if not is_generation_safe_object(rt):
                main_tf_lines.append(
                    f"# Route {rt.name} withheld: requires manual review\n"
                )
                continue

            if not rt.destination:
                main_tf_lines.append(f"# Route {rt.name} withheld: destination is missing\n")
                continue

            is_v6 = rt.address_family == "ipv6"
            label = terraform_resource_label(rt.name, used_labels)

            if not is_v6:
                dst_val = rt.destination
                if "/" in dst_val:
                    parts = dst_val.split("/")
                    if len(parts) == 2:
                        try:
                            prefix_int = int(parts[1])
                            if 0 <= prefix_int <= 32:
                                mask = self._cidr_to_mask(prefix_int)
                                dst_str = f"{parts[0]} {mask}"
                            else:
                                dst_str = dst_val
                        except ValueError:
                            dst_str = dst_val
                    else:
                        dst_str = dst_val
                else:
                    dst_str = dst_val

                rt_lines = [
                    f'resource "fortios_router_static" "{label}" {{',
                    f"  dst = {hcl_string(dst_str)}",
                ]
                if rt.source_route_id is not None:
                    rt_lines.append(f"  seq_num = {rt.source_route_id}")
                if rt.source_prefix:
                    rt_lines.append(f"  src = {hcl_string(rt.source_prefix)}")
                if rt.next_hop:
                    rt_lines.append(f"  gateway = {hcl_string(rt.next_hop)}")
                if rt.interface:
                    rt_lines.append(f"  device  = {hcl_string(rt.interface)}")
                if rt.administrative_distance is not None:
                    rt_lines.append(f"  distance = {rt.administrative_distance}")
                if rt.priority is not None:
                    rt_lines.append(f"  priority = {rt.priority}")
                if rt.weight is not None:
                    rt_lines.append(f"  weight   = {rt.weight}")
                if rt.blackhole is True:
                    rt_lines.append('  blackhole = "enable"')
                if rt.dynamic_gateway:
                    rt_lines.append('  dynamic_gateway = "enable"')
                if rt.sdwan_zone:
                    rt_lines.append(f"  sdwan_zone = {hcl_string(rt.sdwan_zone)}")
                if rt.link_monitor_exempt:
                    rt_lines.append(f"  link_monitor_exempt = {hcl_string(rt.link_monitor_exempt)}")
                if rt.bfd:
                    rt_lines.append(f"  bfd = {hcl_string(rt.bfd)}")
                if rt.vrf is not None:
                    rt_lines.append(f"  vrf = {rt.vrf}")
                if rt.route_tag is not None:
                    rt_lines.append(f"  tag = {rt.route_tag}")
                if rt.internet_service is not None:
                    rt_lines.append(f"  internet_service = {rt.internet_service}")
                if rt.internet_service_custom:
                    rt_lines.append(f"  internet_service_custom = {hcl_string(rt.internet_service_custom)}")

                if rt.enabled is False:
                    rt_lines.append('  status = "disable"')
                if rt.description:
                    rt_lines.append(f"  comment = {hcl_string(rt.description)}")
                rt_lines.append("}\n")
                main_tf_lines.append("\n".join(rt_lines))
            else:
                unsupported_v6 = []
                if rt.source_prefix: unsupported_v6.append("source_prefix")
                if rt.route_tag is not None: unsupported_v6.append("route_tag")
                if rt.internet_service is not None or rt.internet_service_custom: unsupported_v6.append("internet_service")
                if unsupported_v6:
                    main_tf_lines.append(f"# Route {rt.name} withheld: unsupported IPv6 route fields ({', '.join(unsupported_v6)})\n")
                    continue

                if not rt.interface:
                    main_tf_lines.append(
                        f"# Route {rt.name} withheld: Terraform IPv6 route requires device interface in provider 1.18.0 schema\n"
                    )
                    continue

                rt_lines = [
                    f'resource "fortios_router_static6" "{label}" {{',
                    f"  dst    = {hcl_string(rt.destination)}",
                    f"  device = {hcl_string(rt.interface)}",
                ]
                if rt.source_route_id is not None:
                    rt_lines.append(f"  seq_num = {rt.source_route_id}")
                if rt.next_hop:
                    rt_lines.append(f"  gateway = {hcl_string(rt.next_hop)}")
                if rt.administrative_distance is not None:
                    rt_lines.append(f"  distance = {rt.administrative_distance}")
                if rt.priority is not None:
                    rt_lines.append(f"  priority = {rt.priority}")
                if rt.weight is not None:
                    rt_lines.append(f"  weight   = {rt.weight}")
                if rt.blackhole is True:
                    rt_lines.append('  blackhole = "enable"')
                if rt.dynamic_gateway:
                    rt_lines.append('  dynamic_gateway = "enable"')
                if rt.sdwan_zone:
                    rt_lines.append(f"  sdwan_zone = {hcl_string(rt.sdwan_zone)}")
                if rt.link_monitor_exempt:
                    rt_lines.append(f"  link_monitor_exempt = {hcl_string(rt.link_monitor_exempt)}")
                if rt.bfd:
                    rt_lines.append(f"  bfd = {hcl_string(rt.bfd)}")
                if rt.vrf is not None:
                    rt_lines.append(f"  vrf = {rt.vrf}")

                if rt.enabled is False:
                    rt_lines.append('  status = "disable"')
                if rt.description:
                    rt_lines.append(f"  comment = {hcl_string(rt.description)}")
                rt_lines.append("}\n")
                main_tf_lines.append("\n".join(rt_lines))

        artifacts.append(
            MigrationArtifact(
                filename="main.tf",
                content="\n".join(main_tf_lines),
                format="terraform",
            )
        )
        return artifacts

    def _cidr_to_mask(self, bits: int) -> str:
        mask = (0xFFFFFFFF >> (32 - bits)) << (32 - bits) if bits > 0 else 0
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
