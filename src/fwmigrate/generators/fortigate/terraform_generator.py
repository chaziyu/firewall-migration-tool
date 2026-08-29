from typing import List, Optional, Set, Tuple

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.generators.target_helpers import (
    hcl_list,
    hcl_string,
    is_generation_safe_object,
    terraform_resource_label,
)
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType, PolicyAction, ServiceProtocol
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
                f"# Source: {ir.metadata.source_vendor} | Hostname: {ir.metadata.hostname}",
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
            f"# FortiOS Terraform Resources generated from {ir.metadata.source_vendor}",
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

        # Addresses (IPv4 and IPv6)
        for a in ir.addresses:
            if not is_generation_safe_object(a) or a.type in (
                AddressType.STUB_UNSUPPORTED, AddressType.SPECIAL
            ):
                main_tf_lines.append(
                    f"# Address {a.name} withheld: unsupported source address semantics require manual review\n"
                )
                continue

            if not a.is_ipv6:
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
                    start_ip = parts[0] if len(parts) > 0 else "0.0.0.0"
                    end_ip = parts[1] if len(parts) > 1 else "0.0.0.0"
                    main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name     = {hcl_string(a.name)}
  type     = "iprange"
  start_ip = {hcl_string(start_ip)}
  end_ip   = {hcl_string(end_ip)}
}}
""")
                else:
                    subnet = a.value if "/" in a.value else f"{a.value}/32"
                    main_tf_lines.append(f"""resource "fortios_firewall_address" "{label}" {{
  name   = {hcl_string(a.name)}
  type   = "ipmask"
  subnet = {hcl_string(subnet)}
}}
""")
                emitted_addresses.add((a.source_context, a.name))
            else:
                label = terraform_resource_label(a.name, used_labels)
                main_tf_lines.append(f"""resource "fortios_firewall_address6" "{label}" {{
  name = {hcl_string(a.name)}
  ip6  = {hcl_string(a.value)}
}}
""")
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
            if not is_generation_safe_object(svc) or svc.source_unmodeled_semantic_settings:
                main_tf_lines.append(
                    f"# Service {svc.name} withheld: unmodeled FortiGate service semantics require review\n"
                )
                continue
            label = terraform_resource_label(svc.name, used_labels)
            tcp_ports = []
            udp_ports = []
            for p in svc.ports:
                source_value = p.raw_source_value or p.port
                if p.source_port and not p.raw_source_value:
                    source_value = f"{p.port}:{p.source_port}"
                if p.protocol == ServiceProtocol.TCP:
                    tcp_ports.append(source_value)
                elif p.protocol == ServiceProtocol.UDP:
                    udp_ports.append(source_value)

            svc_lines = [
                f'resource "fortios_firewallservice_custom" "{label}" {{',
                f"  name = {hcl_string(svc.name)}",
            ]
            if tcp_ports:
                svc_lines.append(f"  tcp_portrange = {hcl_string(' '.join(tcp_ports))}")
            if udp_ports:
                svc_lines.append(f"  udp_portrange = {hcl_string(' '.join(udp_ports))}")
            if svc.description:
                svc_lines.append(f"  comment = {hcl_string(svc.description)}")
            svc_lines.append("}\n")
            main_tf_lines.append("\n".join(svc_lines))
            emitted_services.add((svc.source_context, svc.name))

        # Service Groups
        for sgrp in ir.service_groups:
            if not is_generation_safe_object(sgrp) or sgrp.unsafe_members:
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

        # Schedules
        for s in ir.schedules:
            if not is_generation_safe_object(s):
                main_tf_lines.append(
                    f"# Schedule {s.name} withheld: requires manual review\n"
                )
                continue
            if (s.schedule_type or "recurring") == "recurring":
                label = terraform_resource_label(s.name, used_labels)
                day_val = " ".join(s.days) if s.days else "sunday monday tuesday wednesday thursday friday saturday"
                main_tf_lines.append(f"""resource "fortios_firewallschedule_recurring" "{label}" {{
  name  = {hcl_string(s.name)}
  day   = {hcl_string(day_val)}
  start = {hcl_string(s.start or "00:00")}
  end   = {hcl_string(s.end or "23:59")}
}}
""")
                emitted_schedules.add((s.source_context, s.name))
            elif s.schedule_type == "onetime":
                label = terraform_resource_label(s.name, used_labels)
                main_tf_lines.append(f"""resource "fortios_firewallschedule_onetime" "{label}" {{
  name  = {hcl_string(s.name)}
  start = {hcl_string(s.start or "00:00 2000/01/01")}
  end   = {hcl_string(s.end or "00:00 2030/01/01")}
}}
""")
                emitted_schedules.add((s.source_context, s.name))

        withheld_addresses: Set[Tuple[Optional[str], str]] = {
            (a.source_context, a.name)
            for a in ir.addresses
            if not is_generation_safe_object(a) or a.type in (AddressType.STUB_UNSUPPORTED, AddressType.SPECIAL)
        }
        withheld_address_groups: Set[Tuple[Optional[str], str]] = {
            (ag.source_context, ag.name)
            for ag in ir.address_groups
            if not is_generation_safe_object(ag)
        }
        withheld_services: Set[Tuple[Optional[str], str]] = {
            (s.source_context, s.name)
            for s in ir.services
            if s.source_unmodeled_semantic_settings or getattr(s, "parse_error", None) is not None
        }
        withheld_service_groups: Set[Tuple[Optional[str], str]] = {
            (sg.source_context, sg.name)
            for sg in ir.service_groups
            if sg.unsafe_members or getattr(sg, "parse_error", None) is not None
        }
        withheld_schedules: Set[Tuple[Optional[str], str]] = {
            (sch.source_context, sch.name)
            for sch in ir.schedules
            if not is_generation_safe_object(sch)
        }

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

            # Schedule validation
            schedule_val = p.schedule or p.source_schedule
            if schedule_val and schedule_val.lower() != "always":
                if (p.source_context, schedule_val) in withheld_schedules:
                    main_tf_lines.append(
                        f"# Policy {p.name} withheld: referenced schedule '{schedule_val}' requires review\n"
                    )
                    continue
                if ir.schedules and (p.source_context, schedule_val) not in emitted_schedules:
                    main_tf_lines.append(
                        f"# Policy {p.name} withheld: referenced schedule '{schedule_val}' is un-emitted or requires review\n"
                    )
                    continue

            # Address and service dependency validation against withheld objects
            src_valid = not any(
                (p.source_context, s) in withheld_addresses or (p.source_context, s) in withheld_address_groups
                for s in p.source
            )
            dst_valid = not any(
                (p.source_context, d) in withheld_addresses or (p.source_context, d) in withheld_address_groups
                for d in p.destination
            )
            svc_valid = not any(
                (p.source_context, sv) in withheld_services or (p.source_context, sv) in withheld_service_groups
                for sv in p.service
            )

            if not (src_valid and dst_valid and svc_valid):
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: references un-emitted address or service dependency\n"
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

            schedule_to_set = schedule_val or "always"

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

        artifacts.append(
            MigrationArtifact(
                filename="main.tf",
                content="\n".join(main_tf_lines),
                format="terraform",
            )
        )
        return artifacts
