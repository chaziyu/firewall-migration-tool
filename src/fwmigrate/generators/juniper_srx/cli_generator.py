from typing import List
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

class JuniperSRXCLIGenerator:
    """Generates JunOS SRX set syntax configuration commands from Canonical IR."""

    def generate(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "# =============================================================================",
            f"# Juniper SRX JunOS Set Syntax Migration for {ir.metadata.hostname or 'srx-fw'}",
            "# Generated automatically by Universal Firewall Migration Platform",
            "# =============================================================================",
            ""
        ]

        if ir.metadata.hostname:
            lines.append(f"set system host-name {ir.metadata.hostname}")

        # 1. Zones & Interfaces
        if ir.zones:
            lines.append("# --- Security Zones ---")
            for zone in ir.zones:
                for intf in zone.interfaces:
                    lines.append(f"set security zones security-zone {zone.name} interfaces {intf}")
            lines.append("")

        # 2. Address Objects
        if ir.addresses:
            lines.append("# --- Address Book ---")
            for addr in ir.addresses:
                if addr.type == AddressType.STUB_UNSUPPORTED and addr.value:
                    lines.append(f"set security address-book global address {addr.name} {addr.value}")
                    continue

                if (
                    addr.requires_manual_review
                    or addr.migration_status != "NORMALIZED"
                    or addr.parse_error is not None
                    or addr.type == AddressType.STUB_UNSUPPORTED
                ):
                    lines.append(
                        f"# Address {addr.name} withheld: source semantics require manual review"
                    )
                    continue

                if addr.type == AddressType.HOST:
                    ip = addr.value.split('/')[0]
                    mask = "/128" if ":" in ip else "/32"
                    lines.append(f"set security address-book global address {addr.name} {ip}{mask}")
                elif addr.type == AddressType.NETWORK:
                    if '/' in addr.value:
                        lines.append(f"set security address-book global address {addr.name} {addr.value}")
                    elif ' ' in addr.value:
                        ip, mask_str = addr.value.split(' ')
                        cidr = sum([bin(int(x)).count('1') for x in mask_str.split('.')])
                        lines.append(f"set security address-book global address {addr.name} {ip}/{cidr}")
                elif addr.type == AddressType.RANGE:
                    lines.append(f"set security address-book global address {addr.name} range-address {addr.value.replace('-', ' to ')}")
                elif addr.type == AddressType.FQDN:
                    lines.append(f"set security address-book global address {addr.name} dns-name {addr.value}")
                elif addr.type == AddressType.WILDCARD_MASK:
                    lines.append(f"set security address-book global address {addr.name} wildcard-address {addr.value}")
                elif addr.type == AddressType.DYNAMIC:
                    lines.append(f"set security address-book global dynamic-address {addr.name}")
                else:
                    lines.append(
                        f"# Address {addr.name} ({addr.type}) withheld: unrepresentable target address type"
                    )
            lines.append("")

        # 3. Address Groups (address-set)
        if ir.address_groups:
            lines.append("# --- Address Sets ---")
            for grp in ir.address_groups:
                if grp.requires_manual_review or grp.migration_status != "NORMALIZED":
                    lines.append(
                        f"# Address set {grp.name} withheld: member semantics require manual review"
                    )
                    continue
                if grp.is_dynamic:
                    lines.append(f"set security address-book global dynamic-address {grp.name}")
                else:
                    for mem in grp.members:
                        lines.append(f"set security address-book global address-set {grp.name} address {mem}")
            lines.append("")

        # 4. Applications (Services)
        if ir.services or ir.service_groups:
            lines.append("# --- Applications & Application Sets ---")
            for svc in ir.services:
                if (
                    svc.requires_manual_review
                    or svc.migration_status != "NORMALIZED"
                    or any(port.source_port for port in svc.ports)
                ):
                    lines.append(
                        f"# Service {svc.name} withheld: source/proxy port semantics require manual review"
                    )
                    continue
                for port_entry in svc.ports:
                    proto = port_entry.protocol.value.lower()
                    if port_entry.protocol in (ServiceProtocol.ICMP, ServiceProtocol.ICMPV6):
                        lines.append(f"set applications application {svc.name} protocol {proto}")
                        if port_entry.icmptype is not None:
                            lines.append(f"set applications application {svc.name} icmp-type {port_entry.icmptype}")
                            if port_entry.icmpcode is not None:
                                lines.append(f"set applications application {svc.name} icmp-code {port_entry.icmpcode}")
                    else:
                        dest_p = port_entry.port if port_entry.port != "any" else "0-65535"
                        lines.append(f"set applications application {svc.name} protocol {proto} destination-port {dest_p}")
            for sgrp in ir.service_groups:
                if sgrp.requires_manual_review or sgrp.migration_status != "NORMALIZED":
                    lines.append(
                        f"# Service group {sgrp.name} withheld: member semantics require manual review"
                    )
                    continue
                for mem in sgrp.members:
                    lines.append(f"set applications application-set {sgrp.name} application {mem}")
            lines.append("")

        # 4.5 UTM & IDP Policies
        if ir.security_profile_groups:
            lines.append("# --- UTM Policies ---")
            for pg in ir.security_profile_groups:
                if pg.requires_manual_review:
                    lines.append(
                        f"# Security profile group {pg.name} withheld: source profile semantics require manual review"
                    )
                    continue
                lines.append(f"set security utm utm-policy {pg.name} anti-virus http-profile {pg.antivirus or 'default'}")
                lines.append(f"set security utm utm-policy {pg.name} web-filtering http-profile {pg.url_filtering or 'default'}")
            lines.append("")

        # 5. Security Policies
        if ir.policies:
            lines.append("# --- Security Policies ---")
            for pol in ir.policies:
                if (
                    pol.action == PolicyAction.IPSEC
                    or not pol.safe_for_target_generation
                    or pol.requires_manual_review
                    or pol.migration_status != "NORMALIZED"
                    or pol.source_user_groups
                    or pol.source_users
                ):
                    lines.append(
                        f"# Policy {pol.name} withheld: source semantics require manual review"
                    )
                    continue
                if not pol.from_zone or not pol.to_zone or not pol.source or not pol.destination or not pol.service or pol.action is None:
                    lines.append(
                        f"# Policy {pol.name} withheld: incomplete policy match/action"
                    )
                    continue
                from_z = pol.from_zone[0]
                to_z = pol.to_zone[0]
                pol_name = pol.name

                for s in pol.source:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match source-address {s}")
                for d in pol.destination:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match destination-address {d}")
                for a in pol.service:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match application {a}")

                action_str = "permit" if pol.action == PolicyAction.ALLOW else "deny" if pol.action == PolicyAction.DENY else None
                if not action_str:
                    lines.append(f"# Policy {pol_name} withheld: unsupported action {pol.action}")
                    continue

                lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} then {action_str}")
                if pol.security_profile_group and pol.action == PolicyAction.ALLOW:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} then application-services utm-policy {pol.security_profile_group}")
                if pol.log_end:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} then log session-close")
            lines.append("")

        # 6. Static Routes
        if ir.routes:
            lines.append("# --- Routing Options ---")
            for rt in ir.routes:
                if not rt.safe_for_target_generation or rt.requires_manual_review or rt.migration_status != "NORMALIZED":
                    lines.append(
                        f"# Route {rt.name} withheld: source semantics require manual review"
                    )
                    continue
                if not rt.next_hop and not rt.blackhole:
                    lines.append(
                        f"# Route {rt.name} withheld: missing next hop"
                    )
                    continue

                if rt.blackhole:
                    lines.append(f"set routing-options static route {rt.destination} discard")
                else:
                    lines.append(f"set routing-options static route {rt.destination} next-hop {rt.next_hop}")
            lines.append("")

        return "\n".join(lines)
