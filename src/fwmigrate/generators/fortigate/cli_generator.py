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
                elif addr.type == AddressType.DYNAMIC:
                    lines.append(f'        set type dynamic')
                    lines.append(f'        set sub-type ems-tag')
                    tag_clean = addr.value.replace("'", "").replace('"', '')
                    lines.append(f'        set ems-tag-name "{tag_clean}"')
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
                if grp.requires_manual_review:
                    continue
                lines.append(f'    edit "{grp.name}"')
                if grp.is_dynamic or grp.dynamic_filter:
                    tag_clean = (grp.dynamic_filter or grp.name).replace("'", "").replace('"', '')
                    lines.append(f'        set type dynamic')
                    lines.append(f'        set sub-type ems-tag')
                    lines.append(f'        set ems-tag-name "{tag_clean}"')
                elif grp.members:
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
                if svc.source_unmodeled_semantic_settings:
                    lines.append(
                        f"    # Service {svc.name} withheld: unmodeled FortiGate "
                        "service semantics require manual review"
                    )
                    continue
                lines.append(f'    edit "{svc.name}"')
                if svc.source_category:
                    lines.append(
                        f'        set category "{svc.source_category}"'
                    )
                if svc.source_proxy:
                    lines.append("        set proxy enable")
                protocol_to_emit = svc.source_protocol_configured
                if protocol_to_emit is None and (
                    svc.source_protocol
                    and svc.source_protocol.upper() in {
                        "ALL", "ICMP", "ICMP6", "IP"
                    }
                ):
                    protocol_to_emit = svc.source_protocol
                if protocol_to_emit is not None:
                    lines.append(
                        f"        set protocol {protocol_to_emit}"
                    )
                if svc.source_protocol_number is not None:
                    lines.append(
                        "        set protocol-number "
                        f"{svc.source_protocol_number}"
                    )
                for p in svc.ports:
                    source_value = p.raw_source_value or p.port
                    if p.source_port and not p.raw_source_value:
                        source_value = f"{p.port}:{p.source_port}"
                    if p.protocol == ServiceProtocol.TCP:
                        lines.append(f'        set tcp-portrange {source_value}')
                    elif p.protocol == ServiceProtocol.UDP:
                        lines.append(f'        set udp-portrange {source_value}')
                    elif p.protocol == ServiceProtocol.SCTP:
                        lines.append(f'        set sctp-portrange {source_value}')
                    elif p.protocol == ServiceProtocol.ICMP:
                        if protocol_to_emit is None:
                            lines.append('        set protocol ICMP')
                        if p.icmptype is not None:
                            lines.append(f'        set icmptype {p.icmptype}')
                        if p.icmpcode is not None:
                            lines.append(f'        set icmpcode {p.icmpcode}')
                    elif p.protocol == ServiceProtocol.ICMPV6:
                        if protocol_to_emit is None:
                            lines.append('        set protocol ICMP6')
                        if p.icmptype is not None:
                            lines.append(f'        set icmptype {p.icmptype}')
                        if p.icmpcode is not None:
                            lines.append(f'        set icmpcode {p.icmpcode}')
                if svc.source_color is not None:
                    lines.append(f'        set color {svc.source_color}')
                if svc.source_fabric_object is not None:
                    lines.append(
                        f'        set fabric-object {svc.source_fabric_object}'
                    )
                if svc.description:
                    lines.append(f'        set comment "{svc.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 4. Service Groups
        if ir.service_groups:
            lines.append("config firewall service group")
            for sgrp in ir.service_groups:
                if sgrp.unsafe_members:
                    lines.append(
                        f"    # Service group {sgrp.name} withheld: unsafe or "
                        "unresolved members require manual review"
                    )
                    continue
                lines.append(f'    edit "{sgrp.name}"')
                if sgrp.members:
                    members_str = ' '.join(f'"{m}"' for m in sgrp.members)
                    lines.append(f'        set member {members_str}')
                if sgrp.source_proxy is True:
                    lines.append("        set proxy enable")
                if sgrp.source_color is not None:
                    lines.append(f"        set color {sgrp.source_color}")
                if sgrp.source_fabric_object is not None:
                    lines.append(f"        set fabric-object {sgrp.source_fabric_object}")
                if sgrp.description:
                    lines.append(f'        set comment "{sgrp.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 4.5 Security Profile Groups
        if ir.security_profile_groups:
            lines.append("config firewall profile-group")
            for pg in ir.security_profile_groups:
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

        # 5. Policies
        if ir.policies:
            lines.append("config firewall policy")
            for idx, pol in enumerate(ir.policies, 1):
                if pol.action == PolicyAction.IPSEC or pol.requires_manual_review:
                    lines.append(
                        f"    # Policy {pol.name} withheld: source semantics require manual review"
                    )
                    continue
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

                if pol.security_profile_group or pol.antivirus or pol.ips_sensor or pol.webfilter:
                    lines.append(f'        set utm-status enable')
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
                    lines.append(f'        set status disable')
                if pol.description:
                    lines.append(f'        set comments "{pol.description}"')
                lines.append("    next")
            lines.append("end\n")

        # 6. Static Routes
        if ir.routes:
            lines.append("config router static")
            for idx, rt in enumerate(ir.routes, 1):
                if not rt.safe_for_target_generation:
                    lines.append(
                        f"    # Route {rt.name} withheld: source semantics require manual review"
                    )
                    continue
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
