from typing import List
from fg2pan.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRServiceGroup, IRPolicy, IRRoute
from fg2pan.ir.enums import AddressType, ServiceProtocol, PolicyAction

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
            lines.append("")

        # 3. Address Groups (address-set)
        if ir.address_groups:
            lines.append("# --- Address Sets ---")
            for grp in ir.address_groups:
                for mem in grp.members:
                    lines.append(f"set security address-book global address-set {grp.name} address {mem}")
            lines.append("")

        # 4. Applications (Services)
        if ir.services or ir.service_groups:
            lines.append("# --- Applications & Application Sets ---")
            for svc in ir.services:
                for port_entry in svc.ports:
                    proto = port_entry.protocol.value.lower()
                    lines.append(f"set applications application {svc.name} protocol {proto} destination-port {port_entry.port}")
            for sgrp in ir.service_groups:
                for mem in sgrp.members:
                    lines.append(f"set applications application-set {sgrp.name} application {mem}")
            lines.append("")

        # 5. Security Policies
        if ir.policies:
            lines.append("# --- Security Policies ---")
            for pol in ir.policies:
                from_z = pol.from_zone[0] if pol.from_zone else "any"
                to_z = pol.to_zone[0] if pol.to_zone else "any"
                pol_name = pol.name

                for s in (pol.source or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match source-address {s}")
                for d in (pol.destination or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match destination-address {d}")
                for a in (pol.service or ["any"]):
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} match application {a}")

                action_str = "permit" if pol.action == PolicyAction.ALLOW else "deny"
                lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} then {action_str}")
                if pol.log_end:
                    lines.append(f"set security policies from-zone {from_z} to-zone {to_z} policy {pol_name} then log session-close")
            lines.append("")

        # 6. Static Routes
        if ir.routes:
            lines.append("# --- Routing Options ---")
            for rt in ir.routes:
                lines.append(f"set routing-options static route {rt.destination} next-hop {rt.next_hop or '192.168.1.1'}")
            lines.append("")

        return "\n".join(lines)
