from typing import List, Dict
from collections import defaultdict
from fg2pan.ir.core import IRConfig, IRAuditEntry, MigrationConfidence, PolicyAction, NATType

class MigrationReporter:
    """Generates a unified, comprehensive Markdown migration report and configuration inventory."""
    
    def __init__(self, ir: IRConfig):
        self.ir = ir
        
    def generate_report(self) -> str:
        sections = [
            self._render_header(),
            self._render_executive_summary(),
            self._render_audit_trail(),
            self._render_network_topology(),
            self._render_object_inventory(),
            self._render_rulebase(),
        ]
        return "\n\n".join(sections) + "\n"

    def _render_header(self) -> str:
        timestamp_str = self.ir.metadata.migration_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"# 🛡️ Firewall Migration & Configuration Report\n\n"
            f"- **Hostname:** `{self.ir.metadata.hostname}`\n"
            f"- **Source Vendor:** {self.ir.metadata.source_vendor.title()}\n"
            f"- **Target Platform:** Palo Alto Networks (PAN-OS XML / REST)\n"
            f"- **Generated At:** {timestamp_str}"
        )

    def _render_executive_summary(self) -> str:
        total_objects = (
            len(self.ir.interfaces) + len(self.ir.addresses) + len(self.ir.address_groups) +
            len(self.ir.services) + len(self.ir.service_groups) + len(self.ir.policies) +
            len(self.ir.nat_rules) + len(self.ir.vpn_tunnels) + len(self.ir.routes)
        )
        
        confidence_counts = defaultdict(int)
        for entry in self.ir.audit_entries:
            confidence_counts[entry.confidence] += 1
            
        confidence_counts[MigrationConfidence.FULL] += max(0, total_objects - len(self.ir.audit_entries))

        lines = [
            "## 1. Executive Summary & Migration Health",
            "",
            "| Metric | Count | Status / Notes |",
            "| :--- | :--- | :--- |",
            f"| **Total Processed Objects** | **{total_objects}** | Combined network, object, and policy entities |",
            f"| 🟢 **Full Confidence** | {confidence_counts[MigrationConfidence.FULL]} | Translated directly with high fidelity |",
            f"| 🟡 **Partial Confidence** | {confidence_counts[MigrationConfidence.PARTIAL]} | Semantic translation completed; profile/crypto review suggested |",
            f"| 🟠 **Manual Review Required** | {confidence_counts[MigrationConfidence.MANUAL]} | Vendor-proprietary features requiring manual mapping |",
            f"| 🔴 **Unsupported** | {confidence_counts[MigrationConfidence.UNSUPPORTED]} | Feature not supported in target PAN-OS architecture |",
        ]
        return "\n".join(lines)

    def _render_audit_trail(self) -> str:
        lines = [
            "## 2. ⚠️ Audit Trail & Action Items",
            "",
        ]
        if not self.ir.audit_entries:
            lines.append("✅ **No migration warnings or manual action items flagged.** All objects converted automatically.")
            return "\n".join(lines)

        lines.extend([
            "> [!IMPORTANT]",
            "> Review the following items before deploying the generated configuration to production.",
            "",
            "| Category | Object ID | Confidence | Message / Remediation |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for entry in self.ir.audit_entries:
            conf_badge = entry.confidence.value.upper()
            if entry.confidence == MigrationConfidence.MANUAL:
                conf_badge = f"🟠 `{conf_badge}`"
            elif entry.confidence == MigrationConfidence.PARTIAL:
                conf_badge = f"🟡 `{conf_badge}`"
            elif entry.confidence == MigrationConfidence.UNSUPPORTED:
                conf_badge = f"🔴 `{conf_badge}`"
            else:
                conf_badge = f"🟢 `{conf_badge}`"

            lines.append(f"| {entry.category} | `{entry.id}` | {conf_badge} | {entry.message} |")

        return "\n".join(lines)

    def _render_network_topology(self) -> str:
        lines = [
            "## 3. 🌐 Network Architecture & Zones",
            "",
            "### Interfaces & Zone Assignments",
            "",
        ]

        if not self.ir.interfaces:
            lines.append("*No interfaces configured.*")
        else:
            lines.extend([
                "| Interface | Assigned Zone | IP / Subnet | Description |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for intf in self.ir.interfaces:
                zone = f"`{intf.zone}`" if intf.zone else "*None*"
                ip = f"`{intf.ip}`" if intf.ip else "-"
                desc = intf.description or "-"
                lines.append(f"| `{intf.name}` | {zone} | {ip} | {desc} |")

        # Static Routes
        if self.ir.routes:
            lines.extend([
                "",
                "### Static Routes",
                "",
                "| Route Name | Destination | Next Hop | Outgoing Interface | Metric | Description |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for rt in self.ir.routes:
                dest = f"`{rt.destination}`"
                gw = f"`{rt.next_hop}`" if rt.next_hop else "-"
                intf = f"`{rt.interface}`" if rt.interface else "-"
                desc = rt.description or "-"
                lines.append(f"| `{rt.name}` | {dest} | {gw} | {intf} | {rt.metric} | {desc} |")

        # VPN Tunnels
        if self.ir.vpn_tunnels:
            lines.extend([
                "",
                "### IPsec VPN Tunnels",
                "",
                "| Tunnel Name | Peer Gateway | Local Interface | IKE Version | PSK Configured | Description |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for vpn in self.ir.vpn_tunnels:
                peer = f"`{vpn.peer_address}`"
                intf = f"`{vpn.local_interface}`"
                psk_status = "✅ Configured" if vpn.psk else "⚠️ Not Set"
                desc = vpn.description or "-"
                lines.append(f"| `{vpn.name}` | {peer} | {intf} | {vpn.ike_version.upper()} | {psk_status} | {desc} |")

        return "\n".join(lines)

    def _render_object_inventory(self) -> str:
        lines = [
            "## 4. 📦 Object Inventory",
            "",
        ]

        # Address Objects
        addr_count = len(self.ir.addresses)
        lines.append(f"<details><summary><b>Address Objects ({addr_count})</b> - Click to expand</summary>\n")
        if not self.ir.addresses:
            lines.append("*No address objects configured.*\n")
        else:
            lines.extend([
                "| Address Name | Type | Value | Description |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for addr in self.ir.addresses:
                val = f"`{addr.value}`" if addr.value else "-"
                desc = addr.description or "-"
                lines.append(f"| `{addr.name}` | `{addr.type.value}` | {val} | {desc} |")
            lines.append("")
        lines.append("</details>\n")

        # Address Groups
        grp_count = len(self.ir.address_groups)
        lines.append(f"<details><summary><b>Address Groups ({grp_count})</b> - Click to expand</summary>\n")
        if not self.ir.address_groups:
            lines.append("*No address groups configured.*\n")
        else:
            lines.extend([
                "| Group Name | Members | Description |",
                "| :--- | :--- | :--- |",
            ])
            for ag in self.ir.address_groups:
                members = ", ".join([f"`{m}`" for m in ag.members]) if ag.members else "*Empty*"
                desc = ag.description or "-"
                lines.append(f"| `{ag.name}` | {members} | {desc} |")
            lines.append("")
        lines.append("</details>\n")

        # Service Objects
        svc_count = len(self.ir.services)
        lines.append(f"<details><summary><b>Service Objects ({svc_count})</b> - Click to expand</summary>\n")
        if not self.ir.services:
            lines.append("*No custom service objects configured.*\n")
        else:
            lines.extend([
                "| Service Name | Protocol | Port(s) | Description |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for svc in self.ir.services:
                proto_list = ", ".join([p.protocol.value.upper() for p in svc.ports]) if svc.ports else "TCP"
                ports_list = ", ".join([p.port for p in svc.ports]) if svc.ports else "any"
                desc = svc.description or "-"
                lines.append(f"| `{svc.name}` | `{proto_list}` | `{ports_list}` | {desc} |")
            lines.append("")
        lines.append("</details>\n")

        # Service Groups
        sgrp_count = len(self.ir.service_groups)
        lines.append(f"<details><summary><b>Service Groups ({sgrp_count})</b> - Click to expand</summary>\n")
        if not self.ir.service_groups:
            lines.append("*No service groups configured.*\n")
        else:
            lines.extend([
                "| Group Name | Members | Description |",
                "| :--- | :--- | :--- |",
            ])
            for sg in self.ir.service_groups:
                members = ", ".join([f"`{m}`" for m in sg.members]) if sg.members else "*Empty*"
                desc = sg.description or "-"
                lines.append(f"| `{sg.name}` | {members} | {desc} |")
            lines.append("")
        lines.append("</details>")

        return "\n".join(lines)

    def _render_rulebase(self) -> str:
        lines = [
            "## 5. 📋 Rulebase & Policies",
            "",
            "### Security Policies",
            "",
        ]

        if not self.ir.policies:
            lines.append("*No security policies configured.*")
        else:
            lines.extend([
                "| # | Policy Name | From Zone | To Zone | Source | Destination | Service | Action | Status | Profiles | Description |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for idx, pol in enumerate(self.ir.policies, start=1):
                from_z = ", ".join(pol.from_zone) or "any"
                to_z = ", ".join(pol.to_zone) or "any"
                src = ", ".join(pol.source) or "any"
                dst = ", ".join(pol.destination) or "any"
                svc = ", ".join(pol.service) or "any"
                
                action_str = f"**`{pol.action.value.upper()}`**"
                if pol.action == PolicyAction.ALLOW:
                    action_str = f"🟢 `{pol.action.value.upper()}`"
                elif pol.action in [PolicyAction.DENY, PolicyAction.DROP]:
                    action_str = f"🔴 `{pol.action.value.upper()}`"
                    
                status_str = "⚠️ *Disabled*" if pol.disabled else "Active"
                profiles = f"`{pol.security_profile_group}`" if pol.security_profile_group else "-"
                desc = pol.description or "-"
                
                lines.append(
                    f"| {idx} | `{pol.name}` | `{from_z}` | `{to_z}` | `{src}` | `{dst}` | `{svc}` | {action_str} | {status_str} | {profiles} | {desc} |"
                )

        # NAT Rules
        if self.ir.nat_rules:
            lines.extend([
                "",
                "### NAT Rules",
                "",
                "| Rule Name | Type | From Zone | To Zone | Source | Destination | Translated Source | Translated Dest | Service | Description |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for nat in self.ir.nat_rules:
                nat_type = f"`{nat.type.value.upper()}`"
                from_z = ", ".join(nat.from_zone) if nat.from_zone else "any"
                to_z = ", ".join(nat.to_zone) if nat.to_zone else "any"
                src = ", ".join(nat.source) if nat.source else "any"
                dst = ", ".join(nat.destination) if nat.destination else "any"
                tr_src = f"`{nat.translated_source}`" if nat.translated_source else "-"
                tr_dst = f"`{nat.translated_destination}`" if nat.translated_destination else "-"
                svc = f"`{nat.service}`"
                desc = nat.description or "-"
                lines.append(
                    f"| `{nat.name}` | {nat_type} | `{from_z}` | `{to_z}` | `{src}` | `{dst}` | {tr_src} | {tr_dst} | {svc} | {desc} |"
                )

        return "\n".join(lines)

