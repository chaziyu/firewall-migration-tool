from typing import List
from fwmigrate.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRServiceGroup, IRPolicy, IRNATRule, IRRoute
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

class CiscoASACLIGenerator:
    """Generates Cisco ASA native CLI commands from Canonical IR."""

    def generate(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "! =============================================================================",
            f"! Cisco ASA Configuration Migration from {ir.metadata.source_vendor or 'Generic'} -> Cisco ASA",
            f"! Hostname: {ir.metadata.hostname or 'cisco-asa'}",
            "! Generated automatically by Universal Firewall Migration Platform",
            "! =============================================================================",
            ""
        ]

        if ir.metadata.hostname:
            lines.append(f"hostname {ir.metadata.hostname}")
            lines.append("!")

        # 1. Address Objects
        if ir.addresses:
            lines.append("! --- Network Objects ---")
            for addr in ir.addresses:
                lines.append(f"object network {addr.name}")
                if addr.type == AddressType.HOST:
                    ip = addr.value.split('/')[0]
                    lines.append(f" host {ip}")
                elif addr.type == AddressType.NETWORK:
                    if '/' in addr.value:
                        ip, prefix = addr.value.split('/')
                        mask = self._cidr_to_netmask(int(prefix))
                        lines.append(f" subnet {ip} {mask}")
                    elif ' ' in addr.value:
                        lines.append(f" subnet {addr.value}")
                elif addr.type == AddressType.RANGE:
                    parts = addr.value.replace(' ', '-').split('-')
                    if len(parts) == 2:
                        lines.append(f" range {parts[0]} {parts[1]}")
                elif addr.type == AddressType.FQDN:
                    lines.append(f" fqdn {addr.value}")
                elif addr.type == AddressType.STUB_UNSUPPORTED:
                    stub_ip = addr.value.split('/')[0] if addr.value else "198.19.255.254"
                    lines.append(f" host {stub_ip}")
                elif addr.type == AddressType.DYNAMIC:
                    tag_clean = addr.value.replace("'", "").replace('"', '')
                    lines.append(f" fqdn dynamic-{tag_clean}.local")
                
                if addr.description:
                    lines.append(f" description {addr.description}")
                lines.append("!")
            lines.append("")

        # 2. Address Groups
        if ir.address_groups:
            lines.append("! --- Network Object Groups ---")
            for grp in ir.address_groups:
                if grp.requires_manual_review:
                    lines.append(f"! Address group {grp.name} withheld: manual review required")
                    continue
                lines.append(f"object-group network {grp.name}")
                if grp.is_dynamic:
                    tag_clean = (grp.dynamic_filter or grp.name).replace("'", "").replace('"', '')
                    lines.append(f" description Dynamic Tag: {tag_clean}")
                elif grp.description:
                    lines.append(f" description {grp.description}")
                for mem in grp.members:
                    lines.append(f" network-object object {mem}")
                lines.append("!")
            lines.append("")

        # 3. Services & Service Groups
        if ir.services or ir.service_groups:
            lines.append("! --- Service Objects & Groups ---")
            for svc in ir.services:
                if (
                    svc.requires_manual_review
                    or any(port.source_port for port in svc.ports)
                ):
                    lines.append(
                        f"! Service {svc.name} withheld: source/proxy port semantics require manual review"
                    )
                    continue
                for port_entry in svc.ports:
                    proto = port_entry.protocol.value.lower()
                    if proto in ['tcp', 'udp']:
                        lines.append(f"object service {svc.name}")
                        lines.append(f" service {proto} destination eq {port_entry.port}")
                        lines.append("!")
            
            for sgrp in ir.service_groups:
                if sgrp.requires_manual_review:
                    lines.append(
                        f"! Service group {sgrp.name} withheld: member semantics require manual review"
                    )
                    continue
                lines.append(f"object-group service {sgrp.name}")
                if sgrp.description:
                    lines.append(f" description {sgrp.description}")
                for mem in sgrp.members:
                    lines.append(f" service-object object {mem}")
                lines.append("!")
            lines.append("")

        # 4. Security Access-Lists
        if ir.policies:
            lines.append("! --- Access Control Lists ---")
            for pol in ir.policies:
                if (
                    pol.action == PolicyAction.IPSEC
                    or not pol.safe_for_target_generation
                    or pol.source_user_groups
                    or pol.source_users
                ):
                    lines.append(
                        f"! Policy {pol.name} withheld: source semantics require manual review"
                    )
                    continue
                if not pol.from_zone or not pol.to_zone:
                    lines.append(
                        f"! Policy {pol.name} withheld: canonical zones require manual review"
                    )
                    continue
                acl_name = f"{pol.from_zone[0]}_access_in"
                action_str = "permit" if pol.action == PolicyAction.ALLOW else "deny"
                
                # Source representation
                src_str = "any"
                if pol.source and pol.source != ["all"] and pol.source != ["any"]:
                    src_str = f"object {pol.source[0]}" if len(pol.source) == 1 else f"object-group {pol.source[0]}"

                # Destination representation
                dst_str = "any"
                if pol.destination and pol.destination != ["all"] and pol.destination != ["any"]:
                    dst_str = f"object {pol.destination[0]}" if len(pol.destination) == 1 else f"object-group {pol.destination[0]}"

                svc_str = "ip"
                if pol.service and pol.service != ["ALL"] and pol.service != ["any"]:
                    svc_str = f"object-group {pol.service[0]}"

                line = f"access-list {acl_name} extended {action_str} {svc_str} {src_str} {dst_str}"
                if pol.disabled:
                    line += " inactive"
                lines.append(line)
            lines.append("!")
            lines.append("")

        # 5. NAT Rules
        if ir.nat_rules:
            lines.append("! --- NAT Rules ---")
            for nat in ir.nat_rules:
                if not nat.safe_for_target_generation or not nat.from_zone or not nat.to_zone:
                    lines.append(
                        f"! NAT rule {nat.name} withheld: canonical zones require manual review"
                    )
                    continue
                from_z = nat.from_zone[0]
                to_z = nat.to_zone[0]
                if nat.type == NATType.SOURCE:
                    if nat.translated_source and nat.translated_source != "interface":
                        lines.append(f"nat ({from_z},{to_z}) source dynamic any {nat.translated_source}")
                    else:
                        lines.append(f"nat ({from_z},{to_z}) source dynamic any interface")
                elif nat.type == NATType.DESTINATION:
                    lines.append(f"nat ({to_z},{from_z}) source static any any destination static {nat.destination[0] if nat.destination else 'any'} {nat.translated_destination}")
            lines.append("!")
            lines.append("")

        # 6. Static Routes
        if ir.routes:
            lines.append("! --- Static Routing ---")
            for rt in ir.routes:
                if not rt.safe_for_target_generation:
                    lines.append(
                        f"! Route {rt.name} withheld: source semantics require manual review"
                    )
                    continue
                intf = rt.interface or "outside"
                dest_ip = "0.0.0.0"
                dest_mask = "0.0.0.0"
                if rt.destination != "0.0.0.0/0":
                    if '/' in rt.destination:
                        dip, pre = rt.destination.split('/')
                        dest_ip = dip
                        dest_mask = self._cidr_to_netmask(int(pre))
                    elif ' ' in rt.destination:
                        dest_ip, dest_mask = rt.destination.split(' ')
                nh = rt.next_hop or "192.168.1.1"
                distance = (
                    rt.administrative_distance
                    if rt.administrative_distance is not None
                    else 1
                )
                lines.append(f"route {intf} {dest_ip} {dest_mask} {nh} {distance}")
            lines.append("")

        return "\n".join(lines)

    def _cidr_to_netmask(self, cidr: int) -> str:
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
