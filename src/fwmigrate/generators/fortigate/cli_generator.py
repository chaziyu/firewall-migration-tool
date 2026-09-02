from datetime import datetime
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.generators.target_helpers import is_generation_safe_object
from fwmigrate.generators.nat_capabilities import nat_capabilities
from fwmigrate.ir.core import IRConfig, IRNATRule
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction, ServiceProtocol
from fwmigrate.ir.semantics import (
    AddressUniversalFamily,
    classify_universal_address_reference,
    policy_references_unsafe_zone,
    unsafe_zone_names,
)


class FortiGateCLIGenerator:
    """Generates FortiOS CLI configuration commands from IRConfig."""

    RESERVED_ADDRESS_NAMES = {"all", "ALL", "all_ipv6", "none", "NONE", "any", "ANY"}
    RESERVED_SERVICE_NAMES = {
        "all", "ALL", "any", "ANY", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6"
    }

    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        # Hard generation blocker: emit zero deployable config if IR is marked unsafe
        if not getattr(ir, "generation_safe", True):
            blocking_lines = [
                "# ====================================================",
                "# FortiOS Configuration Generation BLOCKED",
                f"# Source: {ir.metadata.source_vendor or 'unspecified'} | Hostname: {ir.metadata.hostname or 'unspecified'}",
                "# Generation safety checks failed. All configuration is withheld and zero deployable configuration is emitted.",
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
                    filename="fortigate_config.conf",
                    content="\n".join(blocking_lines) + "\n",
                    format="cli",
                )
            ]

        lines: List[str] = [
            "# ====================================================",
            "# FortiOS Configuration Generated from IR",
            f"# Source: {ir.metadata.source_vendor or 'unspecified'} | Hostname: {ir.metadata.hostname or 'unspecified'}",
            "# ====================================================",
            "",
        ]

        emitted_addresses: Set[Tuple[Optional[str], str]] = set()
        emitted_addresses_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_service_categories: Set[Tuple[Optional[str], str]] = set()
        emitted_services: Set[Tuple[Optional[str], str]] = set()
        emitted_service_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_schedules: Set[Tuple[Optional[str], str]] = set()
        emitted_ip_pools: Set[Tuple[Optional[str], str]] = set()
        emitted_vips: Set[Tuple[Optional[str], str]] = set()

        # 1. Addresses (IPv4 and IPv6)
        v4_supported_types = {AddressType.HOST, AddressType.NETWORK, AddressType.RANGE, AddressType.FQDN}
        v6_supported_types = {AddressType.HOST, AddressType.NETWORK, AddressType.RANGE, AddressType.FQDN}

        v4_addresses = []
        v6_addresses = []
        wildcard_fqdn_addresses = []

        for a in ir.addresses:
            if not is_generation_safe_object(a):
                lines.append(
                    f"# Address {a.name} withheld: unsupported source address semantics require manual review"
                )
                continue

            if a.type == AddressType.WILDCARD_FQDN and not a.is_ipv6:
                wildcard_fqdn_addresses.append(a)
            elif not a.is_ipv6:
                if a.type in v4_supported_types:
                    v4_addresses.append(a)
                else:
                    lines.append(
                        f"# Address {a.name} withheld: unsupported IPv4 address type '{a.type.value}'"
                    )
            else:
                if a.type in v6_supported_types:
                    v6_addresses.append(a)
                else:
                    lines.append(
                        f"# Address {a.name} withheld: unsupported IPv6 address type '{a.type.value}'"
                    )

        if v4_addresses:
            lines.append("config firewall address")
            for addr in v4_addresses:
                if addr.type == AddressType.FQDN:
                    lines.append(f'    edit "{addr.name}"')
                    lines.append("        set type fqdn")
                    lines.append(f'        set fqdn "{addr.value}"')
                elif addr.type == AddressType.RANGE:
                    parts = addr.value.split("-")
                    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                        lines.append(f'    # Address {addr.name} withheld: malformed IP range')
                        continue
                    try:
                        start_ip = ipaddress.IPv4Address(parts[0].strip())
                        end_ip = ipaddress.IPv4Address(parts[1].strip())
                        if start_ip > end_ip:
                            raise ValueError("Start IP greater than End IP")
                        lines.append(f'    edit "{addr.name}"')
                        lines.append("        set type iprange")
                        lines.append(f"        set start-ip {start_ip}")
                        lines.append(f"        set end-ip {end_ip}")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv4 range values')
                        continue
                elif addr.type == AddressType.HOST:
                    try:
                        if "/" in addr.value:
                            net = ipaddress.IPv4Network(addr.value, strict=False)
                            if net.prefixlen != 32:
                                raise ValueError("IPv4 HOST with CIDR must be /32")
                            ip_val = str(net.network_address)
                            lines.append(f'    edit "{addr.name}"')
                            lines.append(f"        set subnet {ip_val} 255.255.255.255")
                        else:
                            ip_val = str(ipaddress.IPv4Address(addr.value))
                            lines.append(f'    edit "{addr.name}"')
                            lines.append(f"        set subnet {ip_val} 255.255.255.255")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv4 host')
                        continue
                elif addr.type == AddressType.NETWORK:
                    try:
                        net = ipaddress.IPv4Network(addr.value, strict=True)
                        ip_val = str(net.network_address)
                        mask_val = str(net.netmask)
                        lines.append(f'    edit "{addr.name}"')
                        lines.append(f"        set subnet {ip_val} {mask_val}")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv4 network or non-zero host bits')
                        continue

                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
                emitted_addresses.add((addr.source_context, addr.name))
            lines.append("end\n")

        if wildcard_fqdn_addresses:
            lines.append("config firewall wildcard-fqdn custom")
            for addr in wildcard_fqdn_addresses:
                lines.append(f'    edit "{addr.name}"')
                lines.append(f'        set wildcard-fqdn "{addr.value}"')
                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
                emitted_addresses.add((addr.source_context, addr.name))
            lines.append("end\n")

        if v6_addresses:
            lines.append("config firewall address6")
            for addr in v6_addresses:
                if addr.type == AddressType.FQDN:
                    lines.append(f'    edit "{addr.name}"')
                    lines.append("        set type fqdn")
                    lines.append(f'        set fqdn "{addr.value}"')
                elif addr.type == AddressType.RANGE:
                    parts = addr.value.split("-")
                    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
                        lines.append(f'    # Address {addr.name} withheld: malformed IPv6 range')
                        continue
                    try:
                        start_ip = ipaddress.IPv6Address(parts[0].strip())
                        end_ip = ipaddress.IPv6Address(parts[1].strip())
                        if start_ip > end_ip:
                            raise ValueError("Start IP greater than End IP")
                        lines.append(f'    edit "{addr.name}"')
                        lines.append("        set type iprange")
                        lines.append(f"        set start-ip {start_ip}")
                        lines.append(f"        set end-ip {end_ip}")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv6 range values')
                        continue
                elif addr.type == AddressType.HOST:
                    try:
                        if "/" in addr.value:
                            net = ipaddress.IPv6Network(addr.value, strict=False)
                            if net.prefixlen != 128:
                                raise ValueError("IPv6 HOST with CIDR must be /128")
                            ip_val = f"{net.network_address}/128"
                            lines.append(f'    edit "{addr.name}"')
                            lines.append(f"        set ip6 {ip_val}")
                        else:
                            ip_val = str(ipaddress.IPv6Address(addr.value))
                            lines.append(f'    edit "{addr.name}"')
                            lines.append(f"        set ip6 {ip_val}/128")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv6 host')
                        continue
                elif addr.type == AddressType.NETWORK:
                    try:
                        net = ipaddress.IPv6Network(addr.value, strict=True)
                        lines.append(f'    edit "{addr.name}"')
                        lines.append(f"        set ip6 {net}")
                    except ValueError:
                        lines.append(f'    # Address {addr.name} withheld: invalid IPv6 network or non-zero host bits')
                        continue
                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
                emitted_addresses_v6.add((addr.source_context, addr.name))
            lines.append("end\n")

        # 2. Address Groups
        if ir.address_groups:
            v4_groups = [g for g in ir.address_groups if g.address_family != "ipv6" and is_generation_safe_object(g)]
            v6_groups = [g for g in ir.address_groups if g.address_family == "ipv6" and is_generation_safe_object(g)]

            for g in ir.address_groups:
                if not is_generation_safe_object(g):
                    lines.append(f"# Address group {g.name} withheld: requires manual review")

            if v4_groups:
                lines.append("config firewall addrgrp")
                for grp in v4_groups:
                    valid_members = [
                        m for m in grp.members
                        if (grp.source_context, m) in emitted_addresses
                        or m in self.RESERVED_ADDRESS_NAMES
                    ]
                    if not grp.is_dynamic and not grp.dynamic_filter and len(valid_members) != len(grp.members):
                        lines.append(
                            f"    # Address group {grp.name} withheld: references un-emitted members"
                        )
                        continue
                    lines.append(f'    edit "{grp.name}"')
                    if grp.is_dynamic or grp.dynamic_filter:
                        tag_clean = (grp.dynamic_filter or grp.name).replace("'", "").replace('"', "")
                        lines.append("        set type dynamic")
                        lines.append("        set sub-type ems-tag")
                        lines.append(f'        set ems-tag-name "{tag_clean}"')
                    elif valid_members:
                        members_str = " ".join(f'"{m}"' for m in valid_members)
                        lines.append(f"        set member {members_str}")
                    if grp.description:
                        lines.append(f'        set comment "{grp.description}"')
                    lines.append("    next")
                    emitted_address_groups.add((grp.source_context, grp.name))
                lines.append("end\n")

            if v6_groups:
                lines.append("config firewall addrgrp6")
                for grp in v6_groups:
                    valid_members = [
                        m for m in grp.members
                        if (grp.source_context, m) in emitted_addresses_v6
                        or m in self.RESERVED_ADDRESS_NAMES
                    ]
                    if not grp.is_dynamic and not grp.dynamic_filter and len(valid_members) != len(grp.members):
                        lines.append(
                            f"    # Address group6 {grp.name} withheld: references un-emitted members"
                        )
                        continue
                    lines.append(f'    edit "{grp.name}"')
                    if valid_members:
                        members_str = " ".join(f'"{m}"' for m in valid_members)
                        lines.append(f"        set member {members_str}")
                    if grp.description:
                        lines.append(f'        set comment "{grp.description}"')
                    lines.append("    next")
                    emitted_address_groups_v6.add((grp.source_context, grp.name))
                lines.append("end\n")

        # 3. Service Categories
        if ir.service_categories:
            cat_lines = []
            for cat in ir.service_categories:
                if not is_generation_safe_object(cat):
                    lines.append(f"# Service category {cat.name} withheld: requires manual review")
                    continue
                if not cat.name or len(cat.name) > 63:
                    lines.append(f"# Service category {cat.name} withheld: invalid name length")
                    continue
                if cat.description is not None and len(cat.description) > 255:
                    lines.append(f"# Service category {cat.name} withheld: description exceeds 255 characters")
                    continue
                if cat.source_fabric_object is not None and cat.source_fabric_object not in {"enable", "disable"}:
                    lines.append(f"# Service category {cat.name} withheld: invalid fabric-object setting")
                    continue

                cat_lines.append(f'    edit "{cat.name}"')
                if cat.description:
                    cat_lines.append(f'        set comment "{cat.description}"')
                if cat.source_fabric_object is not None:
                    cat_lines.append(f"        set fabric-object {cat.source_fabric_object}")
                cat_lines.append("    next")
                emitted_service_categories.add((cat.source_context, cat.name))

            if cat_lines:
                lines.append("config firewall service category")
                lines.extend(cat_lines)
                lines.append("end\n")

        # 4. Services
        if ir.services:
            lines.append("config firewall service custom")
            for svc in ir.services:
                if not is_generation_safe_object(svc):
                    lines.append(
                        f"    # Service {svc.name} withheld: source semantics require manual review or generic safety check failed"
                    )
                    continue
                if (
                    svc.source_unmodeled_semantic_settings
                    or getattr(svc, "parse_error", None) is not None
                    or getattr(svc, "parse_errors", None)
                ):
                    lines.append(
                        f"    # Service {svc.name} withheld: unmodeled FortiGate service semantics require manual review"
                    )
                    continue

                if svc.source_category:
                    if (svc.source_context, svc.source_category) not in emitted_service_categories:
                        lines.append(
                            f"    # Service {svc.name} withheld: references un-emitted service category '{svc.source_category}'"
                        )
                        continue

                if svc.source_protocol_number is not None and not (0 <= svc.source_protocol_number <= 254):
                    lines.append(
                        f"    # Service {svc.name} withheld: protocol-number {svc.source_protocol_number} outside valid range 0-254"
                    )
                    continue

                if svc.source_color is not None and not (0 <= svc.source_color <= 32):
                    lines.append(
                        f"    # Service {svc.name} withheld: color {svc.source_color} outside valid range 0-32"
                    )
                    continue

                supported_port_protocols = {ServiceProtocol.TCP, ServiceProtocol.UDP, ServiceProtocol.SCTP, ServiceProtocol.ICMP, ServiceProtocol.ICMPV6}
                unsupported_ports = [p for p in svc.ports if p.protocol not in supported_port_protocols and p.protocol not in (ServiceProtocol.IP, ServiceProtocol.ANY)]
                if unsupported_ports:
                    lines.append(
                        f"    # Service {svc.name} withheld: contains unsupported port protocol '{unsupported_ports[0].protocol.value}'"
                    )
                    continue

                icmp_ports = [p for p in svc.ports if p.protocol in (ServiceProtocol.ICMP, ServiceProtocol.ICMPV6)]
                distinct_icmp_types = {p.icmptype for p in icmp_ports if p.icmptype is not None}
                distinct_icmp_codes = {p.icmpcode for p in icmp_ports if p.icmpcode is not None}
                if len(distinct_icmp_types) > 1 or len(distinct_icmp_codes) > 1:
                    lines.append(
                        f"    # Service {svc.name} withheld: multiple conflicting ICMP types or codes cannot be represented in a single service"
                    )
                    continue

                port_range_invalid = False
                for p in icmp_ports:
                    if p.icmptype is not None and not (0 <= p.icmptype <= 4294967295):
                        lines.append(
                            f"    # Service {svc.name} withheld: icmptype {p.icmptype} outside valid range 0-4294967295"
                        )
                        port_range_invalid = True
                        break
                    if p.icmpcode is not None and not (0 <= p.icmpcode <= 255):
                        lines.append(
                            f"    # Service {svc.name} withheld: icmpcode {p.icmpcode} outside valid range 0-255"
                        )
                        port_range_invalid = True
                        break
                if port_range_invalid:
                    continue

                lines.append(f'    edit "{svc.name}"')
                if svc.source_category:
                    lines.append(f'        set category "{svc.source_category}"')
                if svc.source_proxy:
                    lines.append("        set proxy enable")
                protocol_to_emit = svc.source_protocol_configured
                if protocol_to_emit is None and (
                    svc.source_protocol and svc.source_protocol.upper() in {"ALL", "ICMP", "ICMP6", "IP"}
                ):
                    protocol_to_emit = svc.source_protocol
                if protocol_to_emit is not None:
                    lines.append(f"        set protocol {protocol_to_emit}")
                if svc.source_protocol_number is not None:
                    lines.append(f"        set protocol-number {svc.source_protocol_number}")
                for p in svc.ports:
                    source_value = p.raw_source_value or p.port
                    if p.source_port and ":" not in (p.raw_source_value or ""):
                        source_value = f"{p.port}:{p.source_port}"
                    if p.protocol == ServiceProtocol.TCP:
                        lines.append(f"        set tcp-portrange {source_value}")
                    elif p.protocol == ServiceProtocol.UDP:
                        lines.append(f"        set udp-portrange {source_value}")
                    elif p.protocol == ServiceProtocol.SCTP:
                        lines.append(f"        set sctp-portrange {source_value}")
                    elif p.protocol == ServiceProtocol.ICMP:
                        if protocol_to_emit is None:
                            lines.append("        set protocol ICMP")
                        if p.icmptype is not None:
                            lines.append(f"        set icmptype {p.icmptype}")
                        if p.icmpcode is not None:
                            lines.append(f"        set icmpcode {p.icmpcode}")
                    elif p.protocol == ServiceProtocol.ICMPV6:
                        if protocol_to_emit is None:
                            lines.append("        set protocol ICMP6")
                        if p.icmptype is not None:
                            lines.append(f"        set icmptype {p.icmptype}")
                        if p.icmpcode is not None:
                            lines.append(f"        set icmpcode {p.icmpcode}")
                if svc.source_color is not None:
                    lines.append(f"        set color {svc.source_color}")
                if svc.source_fabric_object is not None:
                    lines.append(f"        set fabric-object {svc.source_fabric_object}")
                if svc.description:
                    lines.append(f'        set comment "{svc.description}"')
                lines.append("    next")
                emitted_services.add((svc.source_context, svc.name))
            lines.append("end\n")

        # 5. Service Groups
        if ir.service_groups:
            lines.append("config firewall service group")
            for sgrp in ir.service_groups:
                if (
                    not is_generation_safe_object(sgrp)
                    or sgrp.unsafe_members
                    or getattr(sgrp, "parse_error", None) is not None
                ):
                    lines.append(
                        f"    # Service group {sgrp.name} withheld: unsafe or unresolved members require manual review"
                    )
                    continue
                valid_members = [
                    m for m in sgrp.members
                    if (sgrp.source_context, m) in emitted_services
                    or m in self.RESERVED_SERVICE_NAMES
                ]
                if len(valid_members) != len(sgrp.members):
                    lines.append(
                        f"    # Service group {sgrp.name} withheld: references un-emitted services"
                    )
                    continue
                lines.append(f'    edit "{sgrp.name}"')
                if valid_members:
                    members_str = " ".join(f'"{m}"' for m in valid_members)
                    lines.append(f"        set member {members_str}")
                if sgrp.source_proxy is True:
                    lines.append("        set proxy enable")
                if sgrp.source_color is not None:
                    lines.append(f"        set color {sgrp.source_color}")
                if sgrp.source_fabric_object is not None:
                    lines.append(f"        set fabric-object {sgrp.source_fabric_object}")
                if sgrp.description:
                    lines.append(f'        set comment "{sgrp.description}"')
                lines.append("    next")
                emitted_service_groups.add((sgrp.source_context, sgrp.name))
            lines.append("end\n")

        # 6. Schedules (Recurring and Onetime)
        if ir.schedules:
            recurring = [s for s in ir.schedules if (s.schedule_type or "recurring") == "recurring"]
            onetime = [s for s in ir.schedules if s.schedule_type == "onetime"]

            if recurring:
                lines.append("config firewall schedule recurring")
                valid_weekdays = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}
                for s in recurring:
                    if not is_generation_safe_object(s):
                        lines.append(f"    # Schedule {s.name} withheld: requires manual review")
                        continue
                    if s.source_attributes:
                        lines.append(f"    # Schedule {s.name} withheld: contains unmodeled source attributes")
                        continue
                    if not s.name or len(s.name) > 31:
                        lines.append(f"    # Schedule {s.name} withheld: invalid name length (1-31 characters)")
                        continue
                    if not s.start or not s.end:
                        lines.append(f"    # Schedule {s.name} withheld: start and end are required")
                        continue
                    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", s.start) or not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", s.end):
                        lines.append(f"    # Schedule {s.name} withheld: invalid HH:MM start or end time format")
                        continue
                    if s.expiration_days is not None:
                        lines.append(f"    # Schedule {s.name} withheld: expiration_days is not supported on recurring schedules")
                        continue
                    if s.source_color is not None and not (0 <= s.source_color <= 32):
                        lines.append(f"    # Schedule {s.name} withheld: color outside valid range 0-32")
                        continue
                    if s.source_fabric_object is not None and s.source_fabric_object not in {"enable", "disable"}:
                        lines.append(f"    # Schedule {s.name} withheld: invalid fabric-object setting")
                        continue

                    # Day handling
                    day_clause = None
                    if s.days == []:
                        day_clause = None
                    elif s.days == ["none"]:
                        day_clause = "none"
                    elif "none" in s.days:
                        lines.append(f"    # Schedule {s.name} withheld: 'none' cannot be combined with weekday names")
                        continue
                    else:
                        if not all(d.lower() in valid_weekdays for d in s.days):
                            lines.append(f"    # Schedule {s.name} withheld: contains invalid day name")
                            continue
                        day_clause = " ".join(d.lower() for d in s.days)

                    lines.append(f'    edit "{s.name}"')
                    if day_clause is not None:
                        lines.append(f"        set day {day_clause}")
                    lines.append(f'        set start "{s.start}"')
                    lines.append(f'        set end "{s.end}"')
                    if s.source_color is not None:
                        lines.append(f"        set color {s.source_color}")
                    if s.source_fabric_object is not None:
                        lines.append(f"        set fabric-object {s.source_fabric_object}")
                    lines.append("    next")
                    emitted_schedules.add((s.source_context, s.name))
                lines.append("end\n")

            if onetime:
                lines.append("config firewall schedule onetime")
                for s in onetime:
                    if not is_generation_safe_object(s):
                        lines.append(f"    # Schedule {s.name} withheld: requires manual review")
                        continue
                    if s.source_attributes:
                        lines.append(f"    # Schedule {s.name} withheld: contains unmodeled source attributes")
                        continue
                    if not s.name or len(s.name) > 31:
                        lines.append(f"    # Schedule {s.name} withheld: invalid name length (1-31 characters)")
                        continue
                    if not s.start or not s.end:
                        lines.append(f"    # Schedule {s.name} withheld: start and end are required")
                        continue

                    # Parse HH:MM YYYY/MM/DD
                    try:
                        start_dt = datetime.strptime(s.start, "%H:%M %Y/%m/%d")
                        end_dt = datetime.strptime(s.end, "%H:%M %Y/%m/%d")
                        if end_dt <= start_dt:
                            lines.append(f"    # Schedule {s.name} withheld: end date/time must be after start date/time")
                            continue
                    except ValueError:
                        lines.append(f"    # Schedule {s.name} withheld: invalid HH:MM YYYY/MM/DD start or end format")
                        continue

                    # Validate start_utc and end_utc if present
                    if s.start_utc is not None:
                        if not str(s.start_utc).isdigit():
                            lines.append(f"    # Schedule {s.name} withheld: invalid start_utc epoch")
                            continue
                    if s.end_utc is not None:
                        if not str(s.end_utc).isdigit():
                            lines.append(f"    # Schedule {s.name} withheld: invalid end_utc epoch")
                            continue
                    if s.start_utc is not None and s.end_utc is not None:
                        if int(s.end_utc) <= int(s.start_utc):
                            lines.append(f"    # Schedule {s.name} withheld: end_utc must be greater than start_utc")
                            continue

                    if s.source_color is not None and not (0 <= s.source_color <= 32):
                        lines.append(f"    # Schedule {s.name} withheld: color outside valid range 0-32")
                        continue
                    if s.expiration_days is not None and not (0 <= s.expiration_days <= 100):
                        lines.append(f"    # Schedule {s.name} withheld: expiration_days outside valid range 0-100")
                        continue
                    if s.source_fabric_object is not None and s.source_fabric_object not in {"enable", "disable"}:
                        lines.append(f"    # Schedule {s.name} withheld: invalid fabric-object setting")
                        continue

                    lines.append(f'    edit "{s.name}"')
                    lines.append(f'        set start "{s.start}"')
                    if s.start_utc is not None:
                        lines.append(f'        set start-utc "{s.start_utc}"')
                    lines.append(f'        set end "{s.end}"')
                    if s.end_utc is not None:
                        lines.append(f'        set end-utc "{s.end_utc}"')
                    if s.source_color is not None:
                        lines.append(f"        set color {s.source_color}")
                    if s.expiration_days is not None:
                        lines.append(f"        set expiration-days {s.expiration_days}")
                    if s.source_fabric_object is not None:
                        lines.append(f"        set fabric-object {s.source_fabric_object}")
                    lines.append("    next")
                    emitted_schedules.add((s.source_context, s.name))
                lines.append("end\n")

        # 6. Capability-Gated IP Pools (Simple Normalized Pools only)
        if ir.ip_pools:
            lines.append("config firewall ippool")
            for pool in ir.ip_pools:
                if pool.address_family != "ipv4" or not is_generation_safe_object(pool):
                    lines.append(
                        f"    # IP pool {pool.name} withheld: unsupported address family or requires review"
                    )
                    continue
                if pool.pool_type not in (None, "overload", "one-to-one"):
                    lines.append(
                        f"    # IP pool {pool.name} withheld: advanced pool type '{pool.pool_type}'"
                    )
                    continue
                if pool.excluded_ips or pool.permit_any_host:
                    lines.append(
                        f"    # IP pool {pool.name} withheld: exclusion or permit-any-host semantics"
                    )
                    continue
                if (
                    pool.pba_timeout
                    or pool.block_size
                    or pool.cgn_block_size
                    or pool.nat64
                    or pool.nat46
                ):
                    lines.append(
                        f"    # IP pool {pool.name} withheld: advanced PBA/CGN/NAT64 semantics"
                    )
                    continue

                lines.append(f'    edit "{pool.name}"')
                if pool.pool_type:
                    lines.append(f"        set type {pool.pool_type}")
                if pool.start_ip:
                    lines.append(f"        set startip {pool.start_ip}")
                if pool.end_ip:
                    lines.append(f"        set endip {pool.end_ip}")
                if pool.associated_interface:
                    lines.append(f'        set associated-interface "{pool.associated_interface}"')
                if pool.arp_reply is not None:
                    lines.append(f"        set arp-reply {'enable' if pool.arp_reply else 'disable'}")
                if pool.description:
                    lines.append(f'        set comments "{pool.description}"')
                lines.append("    next")
                emitted_ip_pools.add((pool.source_context, pool.name))
            lines.append("end\n")

        # 7. Capability-Gated VIPs (Simple Normalized Static VIPs only)
        if ir.virtual_ips:
            lines.append("config firewall vip")
            for vip in ir.virtual_ips:
                if vip.address_family != "ipv4" or not is_generation_safe_object(vip):
                    lines.append(
                        f"    # VIP {vip.name} withheld: unsupported address family or requires review"
                    )
                    continue
                if vip.vip_type not in (None, "static-nat"):
                    lines.append(
                        f"    # VIP {vip.name} withheld: advanced VIP type '{vip.vip_type}'"
                    )
                    continue
                if vip.real_servers or vip.load_balance_method or vip.source_filters or vip.nat46 or vip.nat64:
                    lines.append(
                        f"    # VIP {vip.name} withheld: real-server or load-balancing semantics"
                    )
                    continue

                lines.append(f'    edit "{vip.name}"')
                if vip.external_ip:
                    lines.append(f"        set extip {vip.external_ip}")
                if vip.mapped_ips:
                    lines.append(f"        set mappedip {' '.join(vip.mapped_ips)}")
                if vip.external_interface:
                    lines.append(f'        set extintf "{vip.external_interface}"')
                if vip.port_forward:
                    lines.append("        set portforward enable")
                    if vip.protocol:
                        lines.append(f"        set protocol {vip.protocol}")
                    if vip.external_port:
                        lines.append(f"        set extport {vip.external_port}")
                    if vip.mapped_port:
                        lines.append(f"        set mappedport {vip.mapped_port}")
                if vip.description:
                    lines.append(f'        set comment "{vip.description}"')
                lines.append("    next")
                emitted_vips.add((vip.source_context, vip.name))
            lines.append("end\n")



        # Build context-aware NAT rule multi-map keyed by (source_context, source_policy_reference)
        nat_rules_by_policy: Dict[Tuple[Optional[str], str], List[IRNATRule]] = {}
        for rule in ir.nat_rules:
            if rule.source_policy_reference:
                key = (rule.source_context, str(rule.source_policy_reference))
                nat_rules_by_policy.setdefault(key, []).append(rule)

        # Context-aware valid interface & zone index
        valid_interfaces_and_zones = (
            {(z.source_context, z.name) for z in ir.zones if is_generation_safe_object(z)}
            | {(i.source_context, i.name) for i in ir.interfaces if is_generation_safe_object(i)}
        )

        # 8. Profile Groups
        emitted_profile_groups: Set[Tuple[Optional[str], str]] = set()
        if ir.security_profile_groups:
            pg_lines = []
            for pg in ir.security_profile_groups:
                if not is_generation_safe_object(pg):
                    lines.append(
                        f"    # Security profile group {pg.name} withheld: source profile semantics require manual review"
                    )
                    continue
                if pg.anti_spyware or pg.file_blocking or pg.wildfire:
                    lines.append(
                        f"    # Security profile group {pg.name} withheld: unsupported profile semantics (anti-spyware/file-blocking/wildfire)"
                    )
                    continue
                if pg.antivirus or pg.vulnerability or pg.url_filtering or pg.ssl_decryption:
                    lines.append(
                        f"    # Security profile group {pg.name} withheld: referenced child security profiles are not generated by this backend"
                    )
                    continue

                pg_lines.append(f'    edit "{pg.name}"')
                if pg.description:
                    pg_lines.append(f'        set comment "{pg.description}"')
                pg_lines.append("    next")
                emitted_profile_groups.add((pg.source_context, pg.name))

            if pg_lines:
                lines.append("config firewall profile-group")
                lines.extend(pg_lines)
                lines.append("end\n")

        # 9. Policies
        if ir.policies:
            lines.append("config firewall policy")
            unsafe_zones = unsafe_zone_names(ir)
            for idx, pol in enumerate(ir.policies, 1):
                if pol.action == PolicyAction.IPSEC or not pol.safe_for_target_generation:
                    lines.append(
                        f"    # Policy {pol.name} withheld: source semantics require manual review"
                    )
                    continue
                if policy_references_unsafe_zone(pol, unsafe_zones):
                    lines.append(
                        f"    # Policy {pol.name} withheld: referenced zone requires manual review"
                    )
                    continue
                if not pol.from_zone or not pol.to_zone:
                    lines.append(
                        f"    # Policy {pol.name} withheld: canonical zones require manual review"
                    )
                    continue

                # Positive interface / zone validation
                from_zones_valid = all(
                    fz.lower() in ("any", "any_interface", "any_zone", "<ir_any>")
                    or (pol.source_context, fz) in valid_interfaces_and_zones
                    for fz in pol.from_zone
                )
                to_zones_valid = all(
                    tz.lower() in ("any", "any_interface", "any_zone", "<ir_any>")
                    or (pol.source_context, tz) in valid_interfaces_and_zones
                    for tz in pol.to_zone
                )
                if not from_zones_valid or not to_zones_valid:
                    lines.append(
                        f"    # Policy {pol.name} withheld: from_zone or to_zone references unknown, unsafe, or cross-VDOM interface/zone"
                    )
                    continue

                # Schedule validation
                schedule_val = pol.schedule or pol.source_schedule
                if not schedule_val:
                    lines.append(
                        f"    # Policy {pol.name} withheld: schedule is missing or empty"
                    )
                    continue

                if schedule_val.lower() == "always":
                    schedule_to_set = "always"
                else:
                    if (pol.source_context, schedule_val) not in emitted_schedules:
                        lines.append(
                            f"    # Policy {pol.name} withheld: referenced schedule '{schedule_val}' is un-emitted or requires review"
                        )
                        continue
                    schedule_to_set = schedule_val

                # Positive address, service, and VIP dependency validation
                src_valid = True
                for s in pol.source:
                    fam = classify_universal_address_reference(s)
                    if fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.IPV6, AddressUniversalFamily.ANY) or s in self.RESERVED_ADDRESS_NAMES:
                        continue
                    if (
                        (pol.source_context, s) not in emitted_addresses
                        and (pol.source_context, s) not in emitted_addresses_v6
                        and (pol.source_context, s) not in emitted_address_groups
                        and (pol.source_context, s) not in emitted_address_groups_v6
                    ):
                        src_valid = False
                        break

                dst_valid = True
                for d in pol.destination:
                    fam = classify_universal_address_reference(d)
                    if fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.IPV6, AddressUniversalFamily.ANY) or d in self.RESERVED_ADDRESS_NAMES:
                        continue
                    if (
                        (pol.source_context, d) not in emitted_addresses
                        and (pol.source_context, d) not in emitted_addresses_v6
                        and (pol.source_context, d) not in emitted_address_groups
                        and (pol.source_context, d) not in emitted_address_groups_v6
                        and (pol.source_context, d) not in emitted_vips
                    ):
                        dst_valid = False
                        break

                svc_valid = True
                for sv in pol.service:
                    if sv in self.RESERVED_SERVICE_NAMES:
                        continue
                    if (
                        (pol.source_context, sv) not in emitted_services
                        and (pol.source_context, sv) not in emitted_service_groups
                    ):
                        svc_valid = False
                        break

                if not (src_valid and dst_valid and svc_valid):
                    lines.append(
                        f"    # Policy {pol.name} withheld: references un-emitted address, service, or VIP dependency"
                    )
                    continue

                # NAT Completeness & validation
                p_nat_rules = nat_rules_by_policy.get(
                    (pol.source_context, str(pol.source_rule_id)), []
                ) if pol.source_rule_id is not None else []

                source_nat_rules = [r for r in p_nat_rules if r.type == NATType.SOURCE]
                dest_nat_rules = [r for r in p_nat_rules if r.type == NATType.DESTINATION]
                twice_nat_rules = [r for r in p_nat_rules if r.type == NATType.TWICE]

                if twice_nat_rules:
                    lines.append(
                        f"    # Policy {pol.name} withheld: TWICE NAT is not supported as a single semantic entity in this CLI generator"
                    )
                    continue

                if dest_nat_rules:
                    dnat_invalid = False
                    for dnat in dest_nat_rules:
                        if not is_generation_safe_object(dnat) or not dnat.safe_for_target_generation:
                            lines.append(
                                f"    # Policy {pol.name} withheld: associated DNAT rule requires manual review"
                            )
                            dnat_invalid = True
                            break
                        if dnat.source_vip_group_reference:
                            lines.append(
                                f"    # Policy {pol.name} withheld: associated DNAT rule references un-emitted VIP group '{dnat.source_vip_group_reference}'"
                            )
                            dnat_invalid = True
                            break
                        if dnat.source_vip_reference:
                            if (pol.source_context, dnat.source_vip_reference) not in emitted_vips:
                                lines.append(
                                    f"    # Policy {pol.name} withheld: associated DNAT rule references un-emitted VIP '{dnat.source_vip_reference}'"
                                )
                                dnat_invalid = True
                                break
                    if dnat_invalid:
                        continue

                policy_nat_enabled = bool(pol.nat_enabled) or bool(source_nat_rules)
                nat_rule_to_use: Optional[IRNATRule] = None

                if policy_nat_enabled:
                    if len(source_nat_rules) > 1:
                        lines.append(
                            f"    # Policy {pol.name} withheld: multiple ambiguous source NAT rules exist for policy"
                        )
                        continue
                    if source_nat_rules:
                        nat_rule_to_use = source_nat_rules[0]
                        if not is_generation_safe_object(nat_rule_to_use) or not nat_rule_to_use.safe_for_target_generation:
                            lines.append(
                                f"    # Policy {pol.name} withheld: associated NAT rule requires manual review or lacks required semantics"
                            )
                            continue

                    pool_names = (
                        pol.nat_pool_names
                        or (nat_rule_to_use.source_pool_references if nat_rule_to_use else [])
                    )
                    if bool(pol.nat_pool_enabled) or pool_names or (nat_rule_to_use and nat_rule_to_use.source_translation_mode == "pool"):
                        pools_valid = pool_names and all(
                            (pol.source_context, p) in emitted_ip_pools
                            for p in pool_names
                        )
                        if not pools_valid:
                            lines.append(
                                f"    # Policy {pol.name} withheld: required IP pool is un-emitted or requires review"
                            )
                            continue

                if pol.security_profile_group:
                    if (pol.source_context, pol.security_profile_group) not in emitted_profile_groups:
                        lines.append(
                            f"    # Policy {pol.name} withheld: referenced security_profile_group '{pol.security_profile_group}' is un-emitted"
                        )
                        continue
                elif pol.antivirus or pol.ips_sensor or pol.webfilter or pol.application_list or pol.ssl_ssh_profile:
                    lines.append(
                        f"    # Policy {pol.name} withheld: referenced security profiles are not emitted by this generator"
                    )
                    continue

                lines.append(f"    edit {idx}")
                lines.append(f'        set name "{pol.name}"')
                srcintf_str = " ".join(f'"{z}"' for z in pol.from_zone) if pol.from_zone else '"any"'
                dstintf_str = " ".join(f'"{z}"' for z in pol.to_zone) if pol.to_zone else '"any"'

                ipv4_srcs = []
                ipv6_srcs = []
                for s in (pol.source or ["all"]):
                    fam = classify_universal_address_reference(s)
                    if fam == AddressUniversalFamily.IPV6:
                        ipv6_srcs.append("all")
                    elif fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.ANY):
                        ipv4_srcs.append("all")
                    else:
                        if (pol.source_context, s) in emitted_addresses_v6 or (pol.source_context, s) in emitted_address_groups_v6:
                            ipv6_srcs.append(s)
                        else:
                            ipv4_srcs.append(s)

                ipv4_dsts = []
                ipv6_dsts = []
                for d in (pol.destination or ["all"]):
                    fam = classify_universal_address_reference(d)
                    if fam == AddressUniversalFamily.IPV6:
                        ipv6_dsts.append("all")
                    elif fam in (AddressUniversalFamily.IPV4, AddressUniversalFamily.ANY):
                        ipv4_dsts.append("all")
                    else:
                        if (pol.source_context, d) in emitted_addresses_v6 or (pol.source_context, d) in emitted_address_groups_v6:
                            ipv6_dsts.append(d)
                        else:
                            ipv4_dsts.append(d)

                svc_str = " ".join(f'"{sv}"' for sv in pol.service) if pol.service else '"ALL"'

                lines.append(f"        set srcintf {srcintf_str}")
                lines.append(f"        set dstintf {dstintf_str}")

                if ipv4_srcs:
                    lines.append(f'        set srcaddr {" ".join(chr(34) + s + chr(34) for s in ipv4_srcs)}')
                elif ipv6_srcs:
                    lines.append('        set srcaddr "none"')

                if ipv6_srcs:
                    lines.append(f'        set srcaddr6 {" ".join(chr(34) + s + chr(34) for s in ipv6_srcs)}')

                if ipv4_dsts:
                    lines.append(f'        set dstaddr {" ".join(chr(34) + d + chr(34) for d in ipv4_dsts)}')
                elif ipv6_dsts:
                    lines.append('        set dstaddr "none"')

                if ipv6_dsts:
                    lines.append(f'        set dstaddr6 {" ".join(chr(34) + d + chr(34) for d in ipv6_dsts)}')

                lines.append(f'        set action {"accept" if pol.action == PolicyAction.ALLOW else "deny"}')
                lines.append(f'        set schedule "{schedule_to_set}"')
                lines.append(f"        set service {svc_str}")

                # NAT generation derived from canonical NAT / IRNATRule
                if policy_nat_enabled:
                    lines.append("        set nat enable")
                    pool_names = (
                        pol.nat_pool_names
                        or (nat_rule_to_use.source_pool_references if nat_rule_to_use else [])
                    )
                    if bool(pol.nat_pool_enabled) or pool_names:
                        lines.append("        set ippool enable")
                        pool_str = " ".join(f'"{p}"' for p in pool_names)
                        lines.append(f"        set poolname {pool_str}")
                    else:
                        lines.append("        set ippool disable")
                    if nat_rule_to_use and nat_rule_to_use.source_policy_fixed_port == "enable":
                        lines.append("        set fixedport enable")
                else:
                    lines.append("        set nat disable")

                if pol.security_profile_group or pol.antivirus or pol.ips_sensor or pol.webfilter:
                    lines.append("        set utm-status enable")
                    if pol.security_profile_group:
                        lines.append(f'        set profile-group "{pol.security_profile_group}"')
                    else:
                        if pol.antivirus:
                            lines.append(f'        set av-profile "{pol.antivirus}"')
                        if pol.ips_sensor:
                            lines.append(f'        set ips-sensor "{pol.ips_sensor}"')
                        if pol.webfilter:
                            lines.append(f'        set webfilter-profile "{pol.webfilter}"')
                        if pol.ssl_ssh_profile:
                            lines.append(f'        set ssl-ssh-profile "{pol.ssl_ssh_profile}"')

                if pol.disabled:
                    lines.append("        set status disable")
                if pol.description:
                    lines.append(f'        set comments "{pol.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 10. Static Routes (Separate IPv4 and IPv6)
        v4_routes = [r for r in ir.routes if (r.address_family or "ipv4") == "ipv4"]
        v6_routes = [r for r in ir.routes if r.address_family == "ipv6"]

        for rt in ir.routes:
            if not is_generation_safe_object(rt):
                lines.append(f"# Route {rt.name} withheld: requires manual review")

        if v4_routes:
            v4_route_lines = []
            for idx, rt in enumerate(v4_routes, 1):
                if not is_generation_safe_object(rt):
                    continue
                if rt.destination is None:
                    lines.append(f"    # Route {rt.name} withheld: destination is missing")
                    continue

                # Strict destination validation
                try:
                    dest_net = ipaddress.IPv4Network(rt.destination, strict=True)
                except ValueError:
                    lines.append(f"    # Route {rt.name} withheld: invalid or non-canonical IPv4 destination '{rt.destination}'")
                    continue

                # Strict source_prefix validation
                if rt.source_prefix:
                    try:
                        ipaddress.IPv4Network(rt.source_prefix, strict=True)
                    except ValueError:
                        lines.append(f"    # Route {rt.name} withheld: invalid IPv4 source prefix '{rt.source_prefix}'")
                        continue

                # Strict next_hop validation
                if rt.next_hop:
                    try:
                        ipaddress.IPv4Address(rt.next_hop)
                    except ValueError:
                        lines.append(f"    # Route {rt.name} withheld: invalid or cross-family IPv4 gateway '{rt.next_hop}'")
                        continue

                # String enable/disable validation
                if rt.dynamic_gateway is not None and rt.dynamic_gateway not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid dynamic_gateway setting '{rt.dynamic_gateway}'")
                    continue
                if rt.link_monitor_exempt is not None and rt.link_monitor_exempt not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid link_monitor_exempt setting '{rt.link_monitor_exempt}'")
                    continue
                if rt.bfd is not None and rt.bfd not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid bfd setting '{rt.bfd}'")
                    continue

                # Numeric range validation
                if rt.administrative_distance is not None and not (1 <= rt.administrative_distance <= 255):
                    lines.append(f"    # Route {rt.name} withheld: distance {rt.administrative_distance} outside range 1-255")
                    continue
                if rt.priority is not None and not (1 <= rt.priority <= 65535):
                    lines.append(f"    # Route {rt.name} withheld: priority {rt.priority} outside range 1-65535")
                    continue
                if rt.weight is not None and not (0 <= rt.weight <= 255):
                    lines.append(f"    # Route {rt.name} withheld: weight {rt.weight} outside range 0-255")
                    continue
                if rt.vrf is not None and not (0 <= rt.vrf <= 251):
                    lines.append(f"    # Route {rt.name} withheld: vrf {rt.vrf} outside range 0-251")
                    continue
                if rt.route_tag is not None and not (0 <= rt.route_tag <= 4294967295):
                    lines.append(f"    # Route {rt.name} withheld: tag {rt.route_tag} outside range 0-4294967295")
                    continue
                if rt.internet_service is not None and not (0 <= rt.internet_service <= 4294967295):
                    lines.append(f"    # Route {rt.name} withheld: internet_service {rt.internet_service} outside range 0-4294967295")
                    continue
                if rt.source_route_id is not None and not (0 <= rt.source_route_id <= 4294967295):
                    lines.append(f"    # Route {rt.name} withheld: source_route_id {rt.source_route_id} outside range 0-4294967295")
                    continue

                if rt.metric is not None:
                    lines.append(f"    # Route {rt.name} withheld: generic metric is not supported in FortiOS static routes")
                    continue

                # SD-WAN zones IR consistency and dependency check
                if rt.sdwan_zones:
                    if rt.sdwan_zone is not None:
                        if len(rt.sdwan_zones) != 1 or rt.sdwan_zone != rt.sdwan_zones[0]:
                            lines.append(f"    # Route {rt.name} withheld: inconsistent singular/list SD-WAN zone configuration")
                            continue
                    canonical_sdwan_zones = rt.sdwan_zones
                elif rt.sdwan_zone:
                    canonical_sdwan_zones = [rt.sdwan_zone]
                else:
                    canonical_sdwan_zones = []

                if canonical_sdwan_zones:
                    lines.append(f"    # Route {rt.name} withheld: referenced SD-WAN zone(s) are not generated by this backend")
                    continue

                if rt.internet_service_custom:
                    lines.append(f"    # Route {rt.name} withheld: custom Internet Service dependency is not generated by this backend")
                    continue

                # All preflight checks passed -> append edit block
                edit_id = rt.source_route_id if rt.source_route_id is not None else idx
                v4_route_lines.append(f"    edit {edit_id}")
                v4_route_lines.append(f"        set dst {dest_net.network_address} {dest_net.netmask}")
                if rt.source_prefix:
                    v4_route_lines.append(f"        set src {rt.source_prefix}")
                if rt.next_hop:
                    v4_route_lines.append(f"        set gateway {rt.next_hop}")
                if rt.interface:
                    v4_route_lines.append(f'        set device "{rt.interface}"')
                if rt.administrative_distance is not None:
                    v4_route_lines.append(f"        set distance {rt.administrative_distance}")
                if rt.priority is not None:
                    v4_route_lines.append(f"        set priority {rt.priority}")
                if rt.weight is not None:
                    v4_route_lines.append(f"        set weight {rt.weight}")
                if rt.blackhole is True:
                    v4_route_lines.append("        set blackhole enable")
                if rt.dynamic_gateway is not None:
                    v4_route_lines.append(f"        set dynamic-gateway {rt.dynamic_gateway}")
                if rt.link_monitor_exempt is not None:
                    v4_route_lines.append(f"        set link-monitor-exempt {rt.link_monitor_exempt}")
                if rt.bfd is not None:
                    v4_route_lines.append(f"        set bfd {rt.bfd}")
                if rt.vrf is not None:
                    v4_route_lines.append(f"        set vrf {rt.vrf}")
                if rt.route_tag is not None:
                    v4_route_lines.append(f"        set tag {rt.route_tag}")
                if rt.internet_service is not None:
                    v4_route_lines.append(f"        set internet-service {rt.internet_service}")
                if rt.enabled is False:
                    v4_route_lines.append("        set status disable")
                if rt.description:
                    v4_route_lines.append(f'        set comment "{rt.description}"')
                v4_route_lines.append("    next")

            if v4_route_lines:
                lines.append("config router static")
                lines.extend(v4_route_lines)
                lines.append("end\n")

        if v6_routes:
            v6_route_lines = []
            for idx, rt in enumerate(v6_routes, 1):
                if not is_generation_safe_object(rt):
                    continue
                if rt.destination is None:
                    lines.append(f"    # Route {rt.name} withheld: destination is missing")
                    continue

                # Strict destination validation
                try:
                    dest_net6 = ipaddress.IPv6Network(rt.destination, strict=True)
                except ValueError:
                    lines.append(f"    # Route {rt.name} withheld: invalid or non-canonical IPv6 destination '{rt.destination}'")
                    continue

                unsupported_v6 = []
                if rt.source_prefix: unsupported_v6.append("source_prefix")
                if rt.route_tag is not None: unsupported_v6.append("route_tag")
                if rt.internet_service is not None or rt.internet_service_custom: unsupported_v6.append("internet_service")
                if unsupported_v6:
                    lines.append(f"    # Route {rt.name} withheld: unsupported IPv6 route fields ({', '.join(unsupported_v6)})")
                    continue

                # Strict next_hop validation
                if rt.next_hop:
                    try:
                        ipaddress.IPv6Address(rt.next_hop)
                    except ValueError:
                        lines.append(f"    # Route {rt.name} withheld: invalid or cross-family IPv6 gateway '{rt.next_hop}'")
                        continue

                # String enable/disable validation
                if rt.dynamic_gateway is not None and rt.dynamic_gateway not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid dynamic_gateway setting '{rt.dynamic_gateway}'")
                    continue
                if rt.link_monitor_exempt is not None and rt.link_monitor_exempt not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid link_monitor_exempt setting '{rt.link_monitor_exempt}'")
                    continue
                if rt.bfd is not None and rt.bfd not in {"enable", "disable"}:
                    lines.append(f"    # Route {rt.name} withheld: invalid bfd setting '{rt.bfd}'")
                    continue

                # Numeric range validation
                if rt.administrative_distance is not None and not (1 <= rt.administrative_distance <= 255):
                    lines.append(f"    # Route {rt.name} withheld: distance {rt.administrative_distance} outside range 1-255")
                    continue
                if rt.priority is not None and not (1 <= rt.priority <= 65535):
                    lines.append(f"    # Route {rt.name} withheld: priority {rt.priority} outside range 1-65535")
                    continue
                if rt.weight is not None and not (0 <= rt.weight <= 255):
                    lines.append(f"    # Route {rt.name} withheld: weight {rt.weight} outside range 0-255")
                    continue
                if rt.vrf is not None and not (0 <= rt.vrf <= 251):
                    lines.append(f"    # Route {rt.name} withheld: vrf {rt.vrf} outside range 0-251")
                    continue
                if rt.source_route_id is not None and not (0 <= rt.source_route_id <= 4294967295):
                    lines.append(f"    # Route {rt.name} withheld: source_route_id {rt.source_route_id} outside range 0-4294967295")
                    continue

                if rt.metric is not None:
                    lines.append(f"    # Route {rt.name} withheld: generic metric is not supported in FortiOS static routes")
                    continue

                # SD-WAN zones IR consistency and dependency check
                if rt.sdwan_zones:
                    if rt.sdwan_zone is not None:
                        if len(rt.sdwan_zones) != 1 or rt.sdwan_zone != rt.sdwan_zones[0]:
                            lines.append(f"    # Route {rt.name} withheld: inconsistent singular/list SD-WAN zone configuration")
                            continue
                    canonical_sdwan_zones = rt.sdwan_zones
                elif rt.sdwan_zone:
                    canonical_sdwan_zones = [rt.sdwan_zone]
                else:
                    canonical_sdwan_zones = []

                if canonical_sdwan_zones:
                    lines.append(f"    # Route {rt.name} withheld: referenced SD-WAN zone(s) are not generated by this backend")
                    continue

                edit_id = rt.source_route_id if rt.source_route_id is not None else idx
                v6_route_lines.append(f"    edit {edit_id}")
                v6_route_lines.append(f"        set dst {dest_net6}")
                if rt.next_hop:
                    v6_route_lines.append(f"        set gateway {rt.next_hop}")
                if rt.interface:
                    v6_route_lines.append(f'        set device "{rt.interface}"')
                if rt.administrative_distance is not None:
                    v6_route_lines.append(f"        set distance {rt.administrative_distance}")
                if rt.priority is not None:
                    v6_route_lines.append(f"        set priority {rt.priority}")
                if rt.weight is not None:
                    v6_route_lines.append(f"        set weight {rt.weight}")
                if rt.blackhole is True:
                    v6_route_lines.append("        set blackhole enable")
                if rt.dynamic_gateway is not None:
                    v6_route_lines.append(f"        set dynamic-gateway {rt.dynamic_gateway}")
                if rt.link_monitor_exempt is not None:
                    v6_route_lines.append(f"        set link-monitor-exempt {rt.link_monitor_exempt}")
                if rt.bfd is not None:
                    v6_route_lines.append(f"        set bfd {rt.bfd}")
                if rt.vrf is not None:
                    v6_route_lines.append(f"        set vrf {rt.vrf}")
                if rt.enabled is False:
                    v6_route_lines.append("        set status disable")
                if rt.description:
                    v6_route_lines.append(f'        set comment "{rt.description}"')
                v6_route_lines.append("    next")

            if v6_route_lines:
                lines.append("config router static6")
                lines.extend(v6_route_lines)
                lines.append("end\n")

        central_rules = [
            rule for rule in ir.nat_rules
            if rule.type == NATType.CENTRAL
        ]
        if central_rules:
            lines.append("config firewall central-snat-map")
            for index, rule in enumerate(central_rules, 1):
                reason = nat_capabilities("fortigate").unsupported_reason(rule)
                if reason or not is_generation_safe_object(rule):
                    lines.append(f"    # NAT rule {rule.name} withheld: {reason or 'requires manual review'}")
                    continue
                edit_id = rule.source_rule_id or rule.sequence or index
                lines.append(f"    edit {edit_id}")
                if rule.source_from_interfaces:
                    lines.append(f'        set srcintf {" ".join(chr(34) + v + chr(34) for v in rule.source_from_interfaces)}')
                if rule.source_to_interfaces:
                    lines.append(f'        set dstintf {" ".join(chr(34) + v + chr(34) for v in rule.source_to_interfaces)}')
                family = rule.original_address_family or "ipv4"
                source_key = "orig-addr6" if family == "ipv6" else "orig-addr"
                destination_key = "dst-addr6" if family == "ipv6" else "dst-addr"
                if rule.source:
                    lines.append(f'        set {source_key} {" ".join(chr(34) + v + chr(34) for v in rule.source)}')
                if rule.destination:
                    lines.append(f'        set {destination_key} {" ".join(chr(34) + v + chr(34) for v in rule.destination)}')
                if rule.protocol_number is not None or rule.protocol_name:
                    lines.append(f'        set protocol {rule.protocol_number if rule.protocol_number is not None else rule.protocol_name}')
                if rule.source_translation_mode == NATTranslationMode.NONE:
                    lines.append("        set nat disable")
                elif rule.source_pool_references:
                    lines.append(f'        set nat-ippool {" ".join(chr(34) + v + chr(34) for v in rule.source_pool_references)}')
                if rule.source_port_behavior == "dynamic":
                    lines.append("        set port-preserve disable")
                if not rule.enabled:
                    lines.append("        set status disable")
                if rule.description:
                    lines.append(f'        set comments "{rule.description}"')
                lines.append("    next")
            lines.append("end\n")

        translation_rules = [
            rule for rule in ir.nat_rules
            if rule.type == NATType.ADDRESS_TRANSLATION
        ]
        if translation_rules:
            lines.append("config firewall ip-translation")
            for index, rule in enumerate(translation_rules, 1):
                reason = nat_capabilities("fortigate").unsupported_reason(rule)
                mapping = rule.address_range_mappings[0] if rule.address_range_mappings else None
                if reason or not is_generation_safe_object(rule) or mapping is None:
                    lines.append(f"    # NAT rule {rule.name} withheld: {reason or 'requires manual review'}")
                    continue
                lines.extend([
                    f"    edit {rule.source_rule_id or rule.sequence or index}",
                    "        set type SCTP",
                    f"        set startip {mapping.original_start}",
                    f"        set endip {mapping.original_end}",
                    f"        set map-startip {mapping.translated_start}",
                    "    next",
                ])
            lines.append("end\n")

        return [
            MigrationArtifact(
                filename="fortigate_config.conf",
                content="\n".join(lines),
                format="cli",
            )
        ]

    def _cidr_to_mask(self, bits: int) -> str:
        mask = (0xFFFFFFFF >> (32 - bits)) << (32 - bits) if bits > 0 else 0
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
