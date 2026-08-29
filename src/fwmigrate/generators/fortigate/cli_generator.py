import re
from typing import Dict, List, Optional, Set, Tuple

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.generators.target_helpers import is_generation_safe_object
from fwmigrate.ir.core import IRConfig, IRNATRule
from fwmigrate.ir.enums import AddressType, PolicyAction, ServiceProtocol
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
                f"# Source: {ir.metadata.source_vendor} | Hostname: {ir.metadata.hostname}",
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
            f"# Source: {ir.metadata.source_vendor} | Hostname: {ir.metadata.hostname}",
            "# ====================================================",
            "",
        ]

        emitted_addresses: Set[Tuple[Optional[str], str]] = set()
        emitted_addresses_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_address_groups_v6: Set[Tuple[Optional[str], str]] = set()
        emitted_services: Set[Tuple[Optional[str], str]] = set()
        emitted_service_groups: Set[Tuple[Optional[str], str]] = set()
        emitted_schedules: Set[Tuple[Optional[str], str]] = set()
        emitted_ip_pools: Set[Tuple[Optional[str], str]] = set()
        emitted_vips: Set[Tuple[Optional[str], str]] = set()

        # 1. Addresses (IPv4 and IPv6)
        v4_addresses = [
            a for a in ir.addresses
            if not a.is_ipv6 and is_generation_safe_object(a)
            and a.type not in (AddressType.STUB_UNSUPPORTED, AddressType.SPECIAL)
        ]
        v6_addresses = [
            a for a in ir.addresses
            if a.is_ipv6 and is_generation_safe_object(a)
            and a.type not in (AddressType.STUB_UNSUPPORTED, AddressType.SPECIAL)
        ]

        for a in ir.addresses:
            if not is_generation_safe_object(a) or a.type in (
                AddressType.STUB_UNSUPPORTED, AddressType.SPECIAL
            ):
                lines.append(
                    f"# Address {a.name} withheld: unsupported source address semantics require manual review"
                )

        if v4_addresses:
            lines.append("config firewall address")
            for addr in v4_addresses:
                lines.append(f'    edit "{addr.name}"')
                if addr.type == AddressType.FQDN:
                    lines.append("        set type fqdn")
                    lines.append(f'        set fqdn "{addr.value}"')
                elif addr.type == AddressType.RANGE:
                    lines.append("        set type iprange")
                    parts = addr.value.split("-")
                    if len(parts) == 2:
                        lines.append(f"        set start-ip {parts[0]}")
                        lines.append(f"        set end-ip {parts[1]}")
                elif addr.type == AddressType.DYNAMIC:
                    lines.append("        set type dynamic")
                    lines.append("        set sub-type ems-tag")
                    tag_clean = addr.value.replace("'", "").replace('"', "")
                    lines.append(f'        set ems-tag-name "{tag_clean}"')
                else:
                    if "/" in addr.value:
                        ip, prefix = addr.value.split("/")
                        try:
                            mask = self._cidr_to_mask(int(prefix))
                            lines.append(f"        set subnet {ip} {mask}")
                        except Exception:
                            lines.append(f"        set subnet {addr.value} 255.255.255.255")
                    else:
                        lines.append(f"        set subnet {addr.value} 255.255.255.255")
                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
                emitted_addresses.add((addr.source_context, addr.name))
            lines.append("end\n")

        if v6_addresses:
            lines.append("config firewall address6")
            for addr in v6_addresses:
                lines.append(f'    edit "{addr.name}"')
                if addr.type == AddressType.FQDN:
                    lines.append("        set type fqdn")
                    lines.append(f'        set fqdn "{addr.value}"')
                elif addr.type == AddressType.RANGE:
                    lines.append("        set type iprange")
                    parts = addr.value.split("-")
                    if len(parts) == 2:
                        lines.append(f"        set start-ip {parts[0]}")
                        lines.append(f"        set end-ip {parts[1]}")
                else:
                    lines.append(f"        set ip6 {addr.value}")
                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
                emitted_addresses_v6.add((addr.source_context, addr.name))
            lines.append("end\n")

        # 2. Address Groups
        if ir.address_groups:
            v4_groups = [g for g in ir.address_groups if g.address_family != "ipv6" and is_generation_safe_object(g)]
            v6_groups = [g for g in ir.address_groups if g.address_family == "ipv6" and is_generation_safe_object(g)]

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

        # 3. Services
        if ir.services:
            lines.append("config firewall service custom")
            for svc in ir.services:
                if svc.source_unmodeled_semantic_settings or getattr(svc, "parse_error", None) is not None:
                    lines.append(
                        f"    # Service {svc.name} withheld: unmodeled FortiGate service semantics require manual review"
                    )
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
                    if p.source_port and not p.raw_source_value:
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

        # 4. Service Groups
        if ir.service_groups:
            lines.append("config firewall service group")
            for sgrp in ir.service_groups:
                if sgrp.unsafe_members or getattr(sgrp, "parse_error", None) is not None:
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

        # 5. Schedules (Recurring and Onetime)
        if ir.schedules:
            recurring = [s for s in ir.schedules if (s.schedule_type or "recurring") == "recurring"]
            onetime = [s for s in ir.schedules if s.schedule_type == "onetime"]

            if recurring:
                lines.append("config firewall schedule recurring")
                for s in recurring:
                    lines.append(f'    edit "{s.name}"')
                    if s.days:
                        days_str = " ".join(s.days)
                        lines.append(f"        set day {days_str}")
                    if s.start:
                        lines.append(f'        set start "{s.start}"')
                    if s.end:
                        lines.append(f'        set end "{s.end}"')
                    if s.source_color is not None:
                        lines.append(f"        set color {s.source_color}")
                    lines.append("    next")
                    emitted_schedules.add((s.source_context, s.name))
                lines.append("end\n")

            if onetime:
                lines.append("config firewall schedule onetime")
                for s in onetime:
                    lines.append(f'    edit "{s.name}"')
                    if s.start:
                        lines.append(f'        set start "{s.start}"')
                    if s.end:
                        lines.append(f'        set end "{s.end}"')
                    if s.source_color is not None:
                        lines.append(f"        set color {s.source_color}")
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

        # 7. Capability-Gated VIPs (Simple Normalized VIPs only)
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

        # 8. Security Profile Groups
        if ir.security_profile_groups:
            lines.append("config firewall profile-group")
            for pg in ir.security_profile_groups:
                if not is_generation_safe_object(pg):
                    lines.append(
                        f"    # Security profile group {pg.name} withheld: source profile semantics require manual review"
                    )
                    continue
                lines.append(f'    edit "{pg.name}"')
                if pg.antivirus:
                    lines.append(f'        set av-profile "{pg.antivirus}"')
                if pg.vulnerability:
                    lines.append(f'        set ips-sensor "{pg.vulnerability}"')
                if pg.url_filtering:
                    lines.append(f'        set webfilter-profile "{pg.url_filtering}"')
                if pg.ssl_decryption:
                    lines.append(f'        set ssl-ssh-profile "{pg.ssl_decryption}"')
                lines.append("    next")
            lines.append("end\n")

        # Build NAT rule map keyed by (source_context, source_policy_reference)
        nat_rules_by_policy: Dict[Tuple[Optional[str], Optional[str]], IRNATRule] = {}
        for rule in ir.nat_rules:
            if rule.source_policy_reference:
                nat_rules_by_policy[(rule.source_context, str(rule.source_policy_reference))] = rule

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
        withheld_vips: Set[Tuple[Optional[str], str]] = {
            (vip.source_context, vip.name)
            for vip in getattr(ir, "virtual_ips", [])
            if not is_generation_safe_object(vip)
        }

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

                # Schedule validation (Correction 10)
                schedule_val = pol.schedule or pol.source_schedule
                if schedule_val and schedule_val.lower() != "always":
                    if (pol.source_context, schedule_val) in withheld_schedules:
                        lines.append(
                            f"    # Policy {pol.name} withheld: referenced schedule '{schedule_val}' requires review"
                        )
                        continue
                    if ir.schedules and (pol.source_context, schedule_val) not in emitted_schedules:
                        lines.append(
                            f"    # Policy {pol.name} withheld: referenced schedule '{schedule_val}' is un-emitted or requires review"
                        )
                        continue

                # Address and service dependency validation against withheld objects
                src_valid = not any(
                    (pol.source_context, s) in withheld_addresses or (pol.source_context, s) in withheld_address_groups
                    for s in pol.source
                )
                dst_valid = not any(
                    (pol.source_context, d) in withheld_addresses
                    or (pol.source_context, d) in withheld_address_groups
                    or (pol.source_context, d) in withheld_vips
                    for d in pol.destination
                )
                svc_valid = not any(
                    (pol.source_context, sv) in withheld_services or (pol.source_context, sv) in withheld_service_groups
                    for sv in pol.service
                )

                if not (src_valid and dst_valid and svc_valid):
                    lines.append(
                        f"    # Policy {pol.name} withheld: references un-emitted address, service, or VIP dependency"
                    )
                    continue

                # NAT Completeness & validation (Corrections 1, 11)
                nat_rule = nat_rules_by_policy.get(
                    (pol.source_context, str(pol.source_rule_id))
                ) if pol.source_rule_id is not None else None

                policy_nat_enabled = bool(pol.nat_enabled) or (
                    nat_rule is not None and nat_rule.type.value in ("source", "twice")
                )

                if policy_nat_enabled:
                    if nat_rule is not None and not is_generation_safe_object(nat_rule):
                        lines.append(
                            f"    # Policy {pol.name} withheld: associated NAT rule requires manual review"
                        )
                        continue
                    # Check IP pool dependencies
                    pool_names = (
                        pol.nat_pool_names
                        or (nat_rule.source_pool_references if nat_rule else [])
                    )
                    if bool(pol.nat_pool_enabled) or pool_names:
                        pools_valid = all(
                            (pol.source_context, p) in emitted_ip_pools
                            for p in pool_names
                        )
                        if not pools_valid or not pool_names:
                            lines.append(
                                f"    # Policy {pol.name} withheld: required IP pool is un-emitted or requires review"
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

                # Exact schedule preservation (Correction 10)
                schedule_to_set = schedule_val or "always"
                lines.append(f'        set schedule "{schedule_to_set}"')
                lines.append(f"        set service {svc_str}")

                # NAT generation derived from canonical NAT / IRNATRule (Correction 1)
                if policy_nat_enabled:
                    lines.append("        set nat enable")
                    pool_names = (
                        pol.nat_pool_names
                        or (nat_rule.source_pool_references if nat_rule else [])
                    )
                    if bool(pol.nat_pool_enabled) or pool_names:
                        lines.append("        set ippool enable")
                        pool_str = " ".join(f'"{p}"' for p in pool_names)
                        lines.append(f"        set poolname {pool_str}")
                    else:
                        lines.append("        set ippool disable")
                    if nat_rule and nat_rule.source_policy_fixed_port == "enable":
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

        # 10. Static Routes
        if ir.routes:
            lines.append("config router static")
            for idx, rt in enumerate(ir.routes, 1):
                if not is_generation_safe_object(rt):
                    lines.append(
                        f"    # Route {rt.name} withheld: source semantics require manual review"
                    )
                    continue
                lines.append(f"    edit {idx}")
                if rt.destination:
                    if "/" in rt.destination:
                        ip, prefix = rt.destination.split("/")
                        mask = self._cidr_to_mask(int(prefix))
                        lines.append(f"        set dst {ip} {mask}")
                    else:
                        lines.append(f"        set dst {rt.destination}")
                if rt.next_hop:
                    lines.append(f"        set gateway {rt.next_hop}")
                if rt.interface:
                    lines.append(f'        set device "{rt.interface}"')
                lines.append("    next")
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
