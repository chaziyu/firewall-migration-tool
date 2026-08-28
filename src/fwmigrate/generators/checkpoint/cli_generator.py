from typing import List
from fwmigrate.ir.core import IRConfig, IRAddress, IRAddressGroup, IRService, IRPolicy
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

class CheckPointCLIGenerator:
    """Generates Check Point mgmt_cli automation batch scripts from Canonical IR."""

    def generate(self, ir: IRConfig) -> str:
        lines: List[str] = [
            "#!/bin/bash",
            "# =============================================================================",
            f"# Check Point mgmt_cli Provisioning Script for {ir.metadata.hostname or 'cp-gateway'}",
            "# Generated automatically by Universal Firewall Migration Platform",
            "# =============================================================================",
            "",
            "# Log in to Check Point Management Server",
            'SESSION_ID=$(mgmt_cli -r true login --format json | jq -r .sid)',
            'export MGMT_CLI_SESSION_ID=$SESSION_ID',
            ""
        ]

        # 1. Address Objects
        if ir.addresses:
            lines.append("# --- Network Objects ---")
            for addr in ir.addresses:
                comments_arg = f' comments "{addr.description}"' if addr.description else ""
                if addr.type == AddressType.HOST:
                    ip = addr.value.split('/')[0]
                    lines.append(f'mgmt_cli add host name "{addr.name}" ip-address "{ip}"{comments_arg} --session-id $SESSION_ID -s id.txt')
                elif addr.type == AddressType.NETWORK:
                    if '/' in addr.value:
                        ip, prefix = addr.value.split('/')
                        lines.append(f'mgmt_cli add network name "{addr.name}" subnet "{ip}" mask-length {prefix}{comments_arg} --session-id $SESSION_ID -s id.txt')
                    elif ' ' in addr.value:
                        ip, mask = addr.value.split(' ')
                        lines.append(f'mgmt_cli add network name "{addr.name}" subnet "{ip}" subnet-mask "{mask}"{comments_arg} --session-id $SESSION_ID -s id.txt')
                elif addr.type == AddressType.RANGE:
                    parts = addr.value.replace(' ', '-').split('-')
                    if len(parts) == 2:
                        lines.append(f'mgmt_cli add address-range name "{addr.name}" ip-address-first "{parts[0]}" ip-address-last "{parts[1]}"{comments_arg} --session-id $SESSION_ID -s id.txt')
                elif addr.type == AddressType.STUB_UNSUPPORTED:
                    stub_ip = addr.value.split('/')[0] if addr.value else "198.19.255.254"
                    lines.append(f'mgmt_cli add host name "{addr.name}" ip-address "{stub_ip}"{comments_arg} --session-id $SESSION_ID -s id.txt')
                elif addr.type == AddressType.DYNAMIC:
                    lines.append(f'mgmt_cli add dynamic-object name "{addr.name}"{comments_arg} --session-id $SESSION_ID -s id.txt')
            lines.append("")

        # 2. Address Groups
        if ir.address_groups:
            lines.append("# --- Group Objects ---")
            for grp in ir.address_groups:
                if grp.requires_manual_review:
                    continue
                if grp.is_dynamic:
                    lines.append(f'mgmt_cli add dynamic-object name "{grp.name}" --session-id $SESSION_ID -s id.txt')
                else:
                    members_args = " ".join([f'members.{i+1} "{m}"' for i, m in enumerate(grp.members)])
                    lines.append(f'mgmt_cli add group name "{grp.name}" {members_args} --session-id $SESSION_ID -s id.txt')
            lines.append("")

        # 3. Services
        if ir.services:
            lines.append("# --- Service Objects ---")
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
                    if proto == 'tcp':
                        lines.append(f'mgmt_cli add service-tcp name "{svc.name}" port "{port_entry.port}" --session-id $SESSION_ID -s id.txt')
                    elif proto == 'udp':
                        lines.append(f'mgmt_cli add service-udp name "{svc.name}" port "{port_entry.port}" --session-id $SESSION_ID -s id.txt')
            lines.append("")

        # 4. Security Rules
        if ir.policies:
            lines.append("# --- Access Rulebase ---")
            for idx, pol in enumerate(ir.policies):
                if (
                    pol.action == PolicyAction.IPSEC
                    or pol.requires_manual_review
                    or pol.source_user_groups
                    or pol.source_users
                ):
                    lines.append(
                        f"# Policy {pol.name} withheld: source semantics require manual review"
                    )
                    continue
                act = "Accept" if pol.action == PolicyAction.ALLOW else "Drop"
                src_val = pol.source[0] if pol.source and pol.source != ["all"] and pol.source != ["any"] else "Any"
                dst_val = pol.destination[0] if pol.destination and pol.destination != ["all"] and pol.destination != ["any"] else "Any"
                svc_val = pol.service[0] if pol.service and pol.service != ["ALL"] and pol.service != ["any"] else "Any"

                lines.append(f'mgmt_cli add access-rule layer "Network" position {idx+1} name "{pol.name}" source "{src_val}" destination "{dst_val}" service "{svc_val}" action "{act}" --session-id $SESSION_ID -s id.txt')

            # 4.5 Threat Prevention Rules
            threat_policies = [
                p for p in ir.policies
                if not p.requires_manual_review
                and not p.source_user_groups
                and not p.source_users
                and p.action != PolicyAction.IPSEC
                and (p.security_profile_group or p.antivirus or p.ips_sensor)
            ]
            if threat_policies:
                lines.append("")
                lines.append("# --- Threat Prevention Layer ---")
                for idx, pol in enumerate(threat_policies):
                    profile_name = pol.security_profile_group or "Optimized"
                    lines.append(f'mgmt_cli add threat-rule layer "Standard Threat Prevention" position {idx+1} name "Threat_{pol.name}" action "Apply" profile "{profile_name}" --session-id $SESSION_ID -s id.txt')
            lines.append("")

        lines.append("# Publish changes and logout")
        lines.append("mgmt_cli publish --session-id $SESSION_ID -s id.txt")
        lines.append("mgmt_cli logout --session-id $SESSION_ID -s id.txt")
        lines.append("")

        return "\n".join(lines)
