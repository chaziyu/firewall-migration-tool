from typing import List
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction
from fwmigrate.core.base_generator import MigrationArtifact

class FortiGateCLIGenerator:
    """Generates FortiOS CLI configuration commands from IRConfig."""

    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        lines: List[str] = [
            f"# ====================================================",
            f"# FortiOS Configuration Generated from IR",
            f"# Source: {ir.metadata.source_vendor} | Hostname: {ir.metadata.hostname}",
            f"# ====================================================",
            ""
        ]

        # 1. Addresses
        if ir.addresses:
            lines.append("config firewall address")
            for addr in ir.addresses:
                lines.append(f'    edit "{addr.name}"')
                if addr.type == AddressType.FQDN:
                    lines.append(f'        set type fqdn')
                    lines.append(f'        set fqdn "{addr.value}"')
                elif addr.type == AddressType.RANGE:
                    lines.append(f'        set type iprange')
                    parts = addr.value.split('-')
                    if len(parts) == 2:
                        lines.append(f'        set start-ip {parts[0]}')
                        lines.append(f'        set end-ip {parts[1]}')
                else:
                    # CIDR to subnet
                    if '/' in addr.value:
                        ip, prefix = addr.value.split('/')
                        mask = self._cidr_to_mask(int(prefix))
                        lines.append(f'        set subnet {ip} {mask}')
                    else:
                        lines.append(f'        set subnet {addr.value} 255.255.255.255')
                if addr.description:
                    lines.append(f'        set comment "{addr.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 2. Address Groups
        if ir.address_groups:
            lines.append("config firewall addrgrp")
            for grp in ir.address_groups:
                lines.append(f'    edit "{grp.name}"')
                if grp.members:
                    members_str = ' '.join(f'"{m}"' for m in grp.members)
                    lines.append(f'        set member {members_str}')
                if grp.description:
                    lines.append(f'        set comment "{grp.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 3. Services
        if ir.services:
            lines.append("config firewall service custom")
            for svc in ir.services:
                lines.append(f'    edit "{svc.name}"')
                for p in svc.ports:
                    if p.protocol == ServiceProtocol.TCP:
                        lines.append(f'        set tcp-portrange {p.port}')
                    elif p.protocol == ServiceProtocol.UDP:
                        lines.append(f'        set udp-portrange {p.port}')
                    elif p.protocol == ServiceProtocol.ICMP:
                        lines.append(f'        set protocol ICMP')
                if svc.description:
                    lines.append(f'        set comment "{svc.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 4. Service Groups
        if ir.service_groups:
            lines.append("config firewall service group")
            for sgrp in ir.service_groups:
                lines.append(f'    edit "{sgrp.name}"')
                if sgrp.members:
                    members_str = ' '.join(f'"{m}"' for m in sgrp.members)
                    lines.append(f'        set member {members_str}')
                if sgrp.description:
                    lines.append(f'        set comment "{sgrp.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 5. Policies
        if ir.policies:
            lines.append("config firewall policy")
            for idx, pol in enumerate(ir.policies, 1):
                lines.append(f'    edit {idx}')
                lines.append(f'        set name "{pol.name}"')
                srcintf_str = ' '.join(f'"{z}"' for z in pol.from_zone) if pol.from_zone else '"any"'
                dstintf_str = ' '.join(f'"{z}"' for z in pol.to_zone) if pol.to_zone else '"any"'
                srcaddr_str = ' '.join(f'"{s}"' for s in pol.source) if pol.source else '"all"'
                dstaddr_str = ' '.join(f'"{d}"' for d in pol.destination) if pol.destination else '"all"'
                svc_str = ' '.join(f'"{sv}"' for sv in pol.service) if pol.service else '"ALL"'

                lines.append(f'        set srcintf {srcintf_str}')
                lines.append(f'        set dstintf {dstintf_str}')
                lines.append(f'        set srcaddr {srcaddr_str}')
                lines.append(f'        set dstaddr {dstaddr_str}')
                lines.append(f'        set action {"accept" if pol.action == PolicyAction.ALLOW else "deny"}')
                lines.append(f'        set schedule "always"')
                lines.append(f'        set service {svc_str}')
                if pol.disabled:
                    lines.append(f'        set status disable')
                if pol.description:
                    lines.append(f'        set comments "{pol.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 6. Static Routes
        if ir.routes:
            lines.append("config router static")
            for idx, rt in enumerate(ir.routes, 1):
                lines.append(f'    edit {idx}')
                if '/' in rt.destination:
                    ip, prefix = rt.destination.split('/')
                    mask = self._cidr_to_mask(int(prefix))
                    lines.append(f'        set dst {ip} {mask}')
                if rt.next_hop:
                    lines.append(f'        set gateway {rt.next_hop}')
                if rt.interface:
                    lines.append(f'        set device "{rt.interface}"')
                lines.append("    next")
            lines.append("end\n")

        return [MigrationArtifact(
            filename="fortigate_config.conf",
            content="\n".join(lines),
            format="cli"
        )]

    def _cidr_to_mask(self, bits: int) -> str:
        mask = (0xffffffff >> (32 - bits)) << (32 - bits) if bits > 0 else 0
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
