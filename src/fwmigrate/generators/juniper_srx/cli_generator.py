from typing import List
from fwmigrate.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRServiceGroup, IRPolicy, IRRoute
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
                if addr.type == AddressType.HOST:
                    ip = addr.value.split('/')[0]
                    lines.append(f"set security address-book global address {addr.name} {ip}/32")
                elif addr.type == AddressType.NETWORK:
                    if '/' in addr.value:
                        lines.append(f"set security address-book global address {addr.name} {addr.value}")
                    elif ' ' in addr.value:
                        ip, mask = addr.value.split(' ')
                        cidr = sum([bin(int(x)).count('1') for x in mask.split('.')])
                        lines.append(f"set security address-book global address {addr.name} {ip}/{cidr}")
                elif addr.type == AddressType.RANGE:
                    lines.append(f"set security address-book global address {addr.name} range-address {addr.value.replace('-', ' to ')}")
                elif addr.type == AddressType.FQDN:
                    lines.append(f"set security address-book global address {addr.name} dns-name {addr.value}")
                elif addr.type == AddressType.STUB_UNSUPPORTED:
                    stub_cidr = addr.value if "/" in addr.value else f"{addr.value}/32" if addr.value else "198.19.255.254/32"
                    lines.append(f"set security address-book global address {addr.name} {stub_cidr}")
                elif addr.type == AddressType.DYNAMIC:
                    lines.append(f"set security address-book global dynamic-address {addr.name}")
            lines.append("")

        # 3. Address Groups (address-set)
        if ir.address_groups:
            lines.append("# --- Address Sets ---")
            for grp in ir.address_groups:
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
                    or any(port.source_port for port in svc.ports)
                ):
                    lines.append(
                        f"# Service {svc.name} withheld: source/proxy port semantics require manual review"
                    )
                    continue
                for port_entry in svc.ports:
                    proto = port_entry.protocol.value.lower()
                    lines.append(f"set applications application {svc.name} protocol {proto} destination-port {port_entry.port}")
            for sgrp in ir.service_groups:
                for mem in sgrp.members:
                    lines.append(f"set applications application-set {sgrp.name} application {mem}")
            lines.append("")

        # 4.5 UTM & IDP Policies
        if ir.security_profile_groups:
            lines.append("# --- UTM Policies ---")
            for pg in ir.security_profile_groups:
                lines.append(f"set security utm utm-policy {pg.name} anti-virus http-profile {pg.antivirus or 'default'}")
                lines.append(f"set security utm utm-policy {pg.name} web-filtering http-profile {pg.url_filtering or 'default'}")
            lines.append("")

        # 5. Security Policies
        if ir.policies:
            lines.append("# --- Security Policies ---")
            for pol in ir.policies:
                if not pol.from_zone or not pol.to_zone:
                    lines.append(
                        f"# Policy {pol.name} withheld: canonical zones require manual review"
                    )
                    continue
                from_z = pol.from_zone[0]
                to_z = pol.to_zone[0]
                pol_name = pol.name

                for s in (pol.source or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match source-address {s}")
                for d in (pol.destination or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match destination-address {d}")
                for a in (pol.service or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match application {a}")

                action_str = "permit" if pol.action == PolicyAction.ALLOW else "deny"
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
                if not rt.destination:
                    lines.append(
                        f"# Route {rt.name} withheld: destination requires manual review"
                    )
                    continue
                lines.append(f"set routing-options static route {rt.destination} next-hop {rt.next_hop or '192.168.1.1'}")
            lines.append("")

        return "\n".join(lines)
