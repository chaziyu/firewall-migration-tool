import json
import html
from typing import List, Dict
from collections import defaultdict
from fwmigrate.ir.core import IRConfig, IRAuditEntry, MigrationConfidence, PolicyAction, NATType

class MigrationReporter:
    """Generates a unified, comprehensive Markdown and interactive HTML migration report and configuration inventory."""
    
    def __init__(self, ir: IRConfig, target_vendor: str = "Palo Alto Networks"):
        self.ir = ir
        self.target_vendor = target_vendor
        self.ir.metadata.target_vendor = target_vendor
        
    def generate_report(self) -> str:
        sections = [
            self._render_header(),
            self._render_executive_summary(),
            self._render_audit_trail(),
            self._render_network_topology(),
            self._render_object_inventory(),
            self._render_rulebase(),
            self._render_canonical_json(),
        ]
        return "\n\n".join(sections) + "\n"

    def generate_json_summary(self) -> Dict:
        """Return structured machine-readable summary."""
        return {
            "hostname": self.ir.metadata.hostname,
            "source_vendor": self.ir.metadata.source_vendor,
            "target_vendor": self.target_vendor,
            "timestamp": self.ir.metadata.migration_timestamp.isoformat(),
            "counts": {
                "zones": len(self.ir.zones),
                "interfaces": len(self.ir.interfaces),
                "addresses": len(self.ir.addresses),
                "address_groups": len(self.ir.address_groups),
                "services": len(self.ir.services),
                "service_groups": len(self.ir.service_groups),
                "security_profile_groups": len(self.ir.security_profile_groups),
                "policies": len(self.ir.policies),
                "nat_rules": len(self.ir.nat_rules),
                "vpn_tunnels": len(self.ir.vpn_tunnels),
                "routes": len(self.ir.routes)
            }
        }

    def _render_header(self) -> str:
        timestamp_str = self.ir.metadata.migration_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"# 🛡️ Firewall Migration & Configuration Report\n\n"
            f"- **Hostname:** `{self.ir.metadata.hostname}`\n"
            f"- **Source Vendor:** {self.ir.metadata.source_vendor.title()}\n"
            f"- **Target Platform:** {self.target_vendor}\n"
            f"- **Generated At:** {timestamp_str}"
        )

    def _render_executive_summary(self) -> str:
        total_objects = (
            len(self.ir.interfaces) + len(self.ir.addresses) + len(self.ir.address_groups) +
            len(self.ir.services) + len(self.ir.service_groups) + len(self.ir.security_profile_groups) +
            len(self.ir.policies) + len(self.ir.nat_rules) + len(self.ir.vpn_tunnels) + len(self.ir.routes)
        )
        
        confidence_counts = defaultdict(int)
        for entry in self.ir.audit_entries:
            confidence_counts[entry.confidence] += 1
            
        confidence_counts[MigrationConfidence.FULL] += max(0, total_objects - len(self.ir.audit_entries))

        lines = [
            "## 1. Executive Summary & Migration Health",
            "",
            "### Migration Health & Confidence",
            "",
            "| Metric | Count | Status / Notes |",
            "| :--- | :--- | :--- |",
            f"| **Total Processed Objects** | **{total_objects}** | Combined network, object, security, and policy entities |",
            f"| 🟢 **Full Confidence** | {confidence_counts[MigrationConfidence.FULL]} | Translated directly with high fidelity |",
            f"| 🟡 **Partial Confidence** | {confidence_counts[MigrationConfidence.PARTIAL]} | Semantic translation completed; review suggested |",
            f"| 🟠 **Manual Review Required** | {confidence_counts[MigrationConfidence.MANUAL]} | Vendor-proprietary features requiring manual mapping |",
            f"| 🔴 **Unsupported** | {confidence_counts[MigrationConfidence.UNSUPPORTED]} | Feature not supported in target architecture |",
            "",
            "### Configuration Inventory Summary",
            "",
            "| Inventory Category | Count | Description |",
            "| :--- | :--- | :--- |",
            f"| **Security Zones** | {len(self.ir.zones)} | Logical zone boundaries and interface mappings |",
            f"| **Network Interfaces** | {len(self.ir.interfaces)} | Physical/VLAN interfaces and assigned IP subnets |",
            f"| **Address Objects** | {len(self.ir.addresses)} | Host, subnet, range, and FQDN definitions |",
            f"| **Address Groups** | {len(self.ir.address_groups)} | Grouped address collections |",
            f"| **Service Objects** | {len(self.ir.services)} | Custom TCP/UDP/ICMP protocol definitions |",
            f"| **Service Groups** | {len(self.ir.service_groups)} | Grouped port and service collections |",
            f"| **Threat Profile Groups** | {len(self.ir.security_profile_groups)} | Unified threat inspection bundles (AV, IPS, URL, etc.) |",
            f"| **Security Policies** | {len(self.ir.policies)} | Firewall access control rules |",
            f"| **NAT Rules** | {len(self.ir.nat_rules)} | Source, destination, and static NAT translations |",
            f"| **IPsec VPN Tunnels** | {len(self.ir.vpn_tunnels)} | Site-to-site IPsec tunnel endpoints |",
            f"| **Static Routes** | {len(self.ir.routes)} | Routing table next-hop definitions |",
            "",
            "### Out of Scope / Manually Required",
            "The following features are intentionally out of scope for automated conversion and require manual design:",
            "- SSL VPN and Portals",
            "- FortiClient EMS Dynamic Endpoint Tagging",
            "- Automation Stitches and Event Handlers",
            "- FortiAnalyzer and Syslog integrations",
            "- Admin Users and Profiles",
            "- Certificates and Private Keys",
            "- SAML / User Group mappings"
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
                "| Interface | Type / VLAN Tag | Assigned Zone | IP / Subnet | Description |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            for intf in self.ir.interfaces:
                if intf.tag is not None:
                    parent_str = f" (Parent: `{intf.parent}`)" if intf.parent else ""
                    type_str = f"VLAN {intf.tag}{parent_str}"
                elif intf.parent:
                    type_str = f"Sub-interface (Parent: `{intf.parent}`)"
                else:
                    type_str = "Physical"
                zone = f"`{intf.zone}`" if intf.zone else "*None*"
                ip = f"`{intf.ip}`" if intf.ip else "-"
                desc = intf.description or "-"
                lines.append(f"| `{intf.name}` | {type_str} | {zone} | {ip} | {desc} |")

        # Security Zones
        if self.ir.zones:
            lines.extend([
                "",
                "### Security Zones",
                "",
                "| Zone Name | Bound Interfaces | Description |",
                "| :--- | :--- | :--- |",
            ])
            for z in self.ir.zones:
                intfs = ", ".join([f"`{i}`" for i in z.interfaces]) if z.interfaces else "*None*"
                desc = z.description or "-"
                lines.append(f"| `{z.name}` | {intfs} | {desc} |")

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
                psk_status = "✅ Configured" if vpn.psk else "⚠️ Encrypted/Not Set"
                desc = vpn.description or "-"
                lines.append(f"| `{vpn.name}` | {peer} | {intf} | {vpn.ike_version.upper()} | {psk_status} | {desc} |")

        return "\n".join(lines)

    def _render_object_inventory(self) -> str:
        lines = [
            "## 4. 📦 Object Inventory",
            "",
            "### Address Objects",
            "",
        ]

        # Address Objects
        if not self.ir.addresses:
            lines.append("*No address objects configured.*")
        else:
            lines.extend([
                "| Address Name | Type | Value | Description |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for addr in self.ir.addresses:
                val = f"`{addr.value}`" if addr.value else "-"
                desc = addr.description or "-"
                lines.append(f"| `{addr.name}` | `{addr.type.value}` | {val} | {desc} |")

        # Address Groups
        lines.extend([
            "",
            "### Address Groups",
            "",
        ])
        if not self.ir.address_groups:
            lines.append("*No address groups configured.*")
        else:
            lines.extend([
                "| Group Name | Members | Description |",
                "| :--- | :--- | :--- |",
            ])
            for ag in self.ir.address_groups:
                if ag.is_dynamic or ag.dynamic_filter:
                    members = f"*(Dynamic DAG: `{ag.dynamic_filter or ag.name}`)*"
                else:
                    members = ", ".join([f"`{m}`" for m in ag.members]) if ag.members else "*Empty*"
                desc = ag.description or "-"
                lines.append(f"| `{ag.name}` | {members} | {desc} |")

        # Service Objects
        lines.extend([
            "",
            "### Service Objects",
            "",
        ])
        if not self.ir.services:
            lines.append("*No custom service objects configured.*")
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

        # Service Groups
        lines.extend([
            "",
            "### Service Groups",
            "",
        ])
        if not self.ir.service_groups:
            lines.append("*No service groups configured.*")
        else:
            lines.extend([
                "| Group Name | Members | Description |",
                "| :--- | :--- | :--- |",
            ])
            for sg in self.ir.service_groups:
                members = ", ".join([f"`{m}`" for m in sg.members]) if sg.members else "*Empty*"
                desc = sg.description or "-"
                lines.append(f"| `{sg.name}` | {members} | {desc} |")

        # Schedules
        if self.ir.schedules:
            lines.extend([
                "",
                "### Schedules",
                "",
                "| Schedule Name | Start Time | End Time | Recurring Days |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for sch in self.ir.schedules:
                start = sch.start or "Always"
                end = sch.end or "Always"
                days = ", ".join(sch.days) if sch.days else "All"
                lines.append(f"| `{sch.name}` | `{start}` | `{end}` | `{days}` |")

        # Universal Threat Profiles
        if self.ir.security_profile_groups:
            lines.extend([
                "",
                "### Universal Threat Prevention & Profile Groups",
                "",
                "| Profile Group Name | Antivirus | Vulnerability (IPS) | Anti-Spyware | URL Filtering | File Blocking | Sandbox | Decryption | Description |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for spg in self.ir.security_profile_groups:
                av = f"`{spg.antivirus}`" if spg.antivirus else "-"
                vuln = f"`{spg.vulnerability}`" if spg.vulnerability else "-"
                spy = f"`{spg.anti_spyware}`" if spg.anti_spyware else "-"
                url = f"`{spg.url_filtering}`" if spg.url_filtering else "-"
                fb = f"`{spg.file_blocking}`" if spg.file_blocking else "-"
                wf = f"`{spg.wildfire}`" if spg.wildfire else "-"
                dec = f"`{spg.ssl_decryption}`" if spg.ssl_decryption else "-"
                desc = spg.description or "-"
                lines.append(f"| `{spg.name}` | {av} | {vuln} | {spy} | {url} | {fb} | {wf} | {dec} | {desc} |")

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
                
                action_str = "🟢 `ALLOW`" if pol.action == PolicyAction.ALLOW else "🔴 `DENY`"
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

    def _render_canonical_json(self) -> str:
        lines = [
            "## 6. 📄 Raw Canonical Intermediate Representation (JSON)",
            "",
            "This section provides the full, machine-readable Intermediate Representation (`IRConfig`) JSON export for pipeline automation and external audit validation.",
            "",
            "<details><summary><b>View Full Normalized JSON Data</b> - Click to expand</summary>",
            "",
            "```json",
            json.dumps(self.ir.model_dump(mode='json'), indent=2),
            "```",
            "",
            "</details>"
        ]
        return "\n".join(lines)

    def generate_html_report(self) -> str:
        """Generates a standalone, interactive, styled single-page HTML migration report."""
        timestamp_str = self.ir.metadata.migration_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        hostname = html.escape(self.ir.metadata.hostname or "Firewall")
        source_vendor = html.escape(self.ir.metadata.source_vendor.title() if self.ir.metadata.source_vendor else "Generic")
        target_vendor = html.escape(self.target_vendor or "Target Platform")

        total_objects = (
            len(self.ir.interfaces) + len(self.ir.addresses) + len(self.ir.address_groups) +
            len(self.ir.services) + len(self.ir.service_groups) + len(self.ir.security_profile_groups) +
            len(self.ir.policies) + len(self.ir.nat_rules) + len(self.ir.vpn_tunnels) + len(self.ir.routes)
        )
        
        confidence_counts = defaultdict(int)
        for entry in self.ir.audit_entries:
            confidence_counts[entry.confidence] += 1
        confidence_counts[MigrationConfidence.FULL] += max(0, total_objects - len(self.ir.audit_entries))

        json_dump = html.escape(json.dumps(self.ir.model_dump(mode='json'), indent=2))

        # Build HTML Tables
        # 1. Audit Entries
        audit_rows = []
        for entry in self.ir.audit_entries:
            c_class = {
                MigrationConfidence.FULL: "badge-full",
                MigrationConfidence.PARTIAL: "badge-partial",
                MigrationConfidence.MANUAL: "badge-manual",
                MigrationConfidence.UNSUPPORTED: "badge-unsupported"
            }.get(entry.confidence, "badge-partial")
            audit_rows.append(
                f"<tr><td>{html.escape(entry.category)}</td>"
                f"<td><code>{html.escape(entry.id)}</code></td>"
                f"<td><span class='badge {c_class}'>{html.escape(entry.confidence.value.upper())}</span></td>"
                f"<td>{html.escape(entry.message)}</td></tr>"
            )
        audit_html = "".join(audit_rows) if audit_rows else "<tr><td colspan='4' class='text-muted'>✅ No migration warnings or manual action items flagged.</td></tr>"

        # 2. Interfaces
        intf_rows = []
        for i in self.ir.interfaces:
            if i.tag is not None:
                parent_info = f" (Parent: <code>{html.escape(i.parent)}</code>)" if i.parent else ""
                type_badge = f"<span class='type-tag'>VLAN {i.tag}</span>{parent_info}"
            elif i.parent:
                type_badge = f"<span class='type-tag'>Sub-interface</span> (Parent: <code>{html.escape(i.parent)}</code>)"
            else:
                type_badge = "<span class='badge' style='background:#f1f5f9; color:#334155;'>Physical</span>"
            intf_rows.append(
                f"<tr><td><code>{html.escape(i.name)}</code></td>"
                f"<td>{type_badge}</td>"
                f"<td><span class='zone-tag'>{html.escape(i.zone or 'None')}</span></td>"
                f"<td>{html.escape(i.ip or '-')}</td>"
                f"<td>{html.escape(i.description or '-')}</td></tr>"
            )
        intf_html = "".join(intf_rows) if intf_rows else "<tr><td colspan='5' class='text-muted'>No interfaces configured.</td></tr>"

        # 3. Zones
        zone_rows = []
        for z in self.ir.zones:
            intfs = ", ".join([f"<code>{html.escape(x)}</code>" for x in z.interfaces]) if z.interfaces else "None"
            zone_rows.append(f"<tr><td><b>{html.escape(z.name)}</b></td><td>{intfs}</td><td>{html.escape(z.description or '-')}</td></tr>")
        zone_html = "".join(zone_rows) if zone_rows else "<tr><td colspan='3' class='text-muted'>No security zones configured.</td></tr>"

        # 4. Routes
        route_rows = []
        for r in self.ir.routes:
            route_rows.append(
                f"<tr><td><code>{html.escape(r.name)}</code></td>"
                f"<td>{html.escape(r.destination)}</td>"
                f"<td>{html.escape(r.next_hop or '-')}</td>"
                f"<td>{html.escape(r.interface or '-')}</td>"
                f"<td>{r.metric}</td>"
                f"<td>{html.escape(r.description or '-')}</td></tr>"
            )
        route_html = "".join(route_rows) if route_rows else "<tr><td colspan='6' class='text-muted'>No static routes configured.</td></tr>"

        # 5. VPN
        vpn_rows = []
        for v in self.ir.vpn_tunnels:
            psk_badge = "<span class='badge badge-full'>Configured</span>" if v.psk else "<span class='badge badge-partial'>Encrypted / Not Set</span>"
            vpn_rows.append(
                f"<tr><td><code>{html.escape(v.name)}</code></td>"
                f"<td>{html.escape(v.peer_address)}</td>"
                f"<td>{html.escape(v.local_interface or '-')}</td>"
                f"<td>{html.escape(v.ike_version.upper())}</td>"
                f"<td>{psk_badge}</td>"
                f"<td>{html.escape(v.description or '-')}</td></tr>"
            )
        vpn_html = "".join(vpn_rows) if vpn_rows else "<tr><td colspan='6' class='text-muted'>No IPsec VPN tunnels configured.</td></tr>"

        # 6. Addresses
        addr_rows = []
        for a in self.ir.addresses:
            addr_rows.append(
                f"<tr><td><code>{html.escape(a.name)}</code></td>"
                f"<td><span class='type-tag'>{html.escape(a.type.value.upper())}</span></td>"
                f"<td>{html.escape(a.value or '-')}</td>"
                f"<td>{html.escape(a.description or '-')}</td></tr>"
            )
        addr_html = "".join(addr_rows) if addr_rows else "<tr><td colspan='4' class='text-muted'>No address objects configured.</td></tr>"

        # 7. Address Groups
        ag_rows = []
        for ag in self.ir.address_groups:
            if ag.is_dynamic or ag.dynamic_filter:
                members = f"<span class='type-tag'>Dynamic DAG: {html.escape(ag.dynamic_filter or ag.name)}</span>"
            else:
                members = ", ".join([f"<code>{html.escape(m)}</code>" for m in ag.members]) if ag.members else "Empty"
            ag_rows.append(f"<tr><td><code>{html.escape(ag.name)}</code></td><td>{members}</td><td>{html.escape(ag.description or '-')}</td></tr>")
        ag_html = "".join(ag_rows) if ag_rows else "<tr><td colspan='3' class='text-muted'>No address groups configured.</td></tr>"

        # 8. Services
        svc_rows = []
        for s in self.ir.services:
            protos = ", ".join([p.protocol.value.upper() for p in s.ports]) if s.ports else "TCP"
            ports = ", ".join([p.port for p in s.ports]) if s.ports else "any"
            svc_rows.append(f"<tr><td><code>{html.escape(s.name)}</code></td><td>{protos}</td><td>{ports}</td><td>{html.escape(s.description or '-')}</td></tr>")
        svc_html = "".join(svc_rows) if svc_rows else "<tr><td colspan='4' class='text-muted'>No service objects configured.</td></tr>"

        # 9. Threat Profiles
        spg_rows = []
        for spg in self.ir.security_profile_groups:
            spg_rows.append(
                f"<tr><td><b><code>{html.escape(spg.name)}</code></b></td>"
                f"<td>{html.escape(spg.antivirus or '-')}</td>"
                f"<td>{html.escape(spg.vulnerability or '-')}</td>"
                f"<td>{html.escape(spg.anti_spyware or '-')}</td>"
                f"<td>{html.escape(spg.url_filtering or '-')}</td>"
                f"<td>{html.escape(spg.file_blocking or '-')}</td>"
                f"<td>{html.escape(spg.wildfire or '-')}</td>"
                f"<td>{html.escape(spg.ssl_decryption or '-')}</td>"
                f"<td>{html.escape(spg.description or '-')}</td></tr>"
            )
        spg_html = "".join(spg_rows) if spg_rows else "<tr><td colspan='9' class='text-muted'>No threat profile groups configured.</td></tr>"

        # 10. Policies
        pol_rows = []
        for idx, p in enumerate(self.ir.policies, start=1):
            act_class = "badge-allow" if p.action == PolicyAction.ALLOW else "badge-deny"
            spg_text = f"<code>{html.escape(p.security_profile_group)}</code>" if p.security_profile_group else "-"
            from_z = ", ".join([html.escape(z) for z in p.from_zone]) or "any"
            to_z = ", ".join([html.escape(z) for z in p.to_zone]) or "any"
            src = ", ".join([f"<code>{html.escape(s)}</code>" for s in p.source]) or "any"
            dst = ", ".join([f"<code>{html.escape(d)}</code>" for d in p.destination]) or "any"
            svc = ", ".join([f"<code>{html.escape(sv)}</code>" for sv in p.service]) or "any"
            status_text = "<span class='badge badge-unsupported'>Disabled</span>" if p.disabled else "Active"
            pol_rows.append(
                f"<tr><td>{idx}</td>"
                f"<td><b><code>{html.escape(p.name)}</code></b></td>"
                f"<td>{from_z}</td><td>{to_z}</td>"
                f"<td>{src}</td><td>{dst}</td><td>{svc}</td>"
                f"<td><span class='badge {act_class}'>{html.escape(p.action.value.upper())}</span></td>"
                f"<td>{status_text}</td>"
                f"<td>{spg_text}</td>"
                f"<td>{html.escape(p.description or '-')}</td></tr>"
            )
        pol_html = "".join(pol_rows) if pol_rows else "<tr><td colspan='11' class='text-muted'>No security policies configured.</td></tr>"

        # 11. NAT Rules
        nat_rows = []
        for n in self.ir.nat_rules:
            from_z = ", ".join([html.escape(z) for z in n.from_zone]) or "any"
            to_z = ", ".join([html.escape(z) for z in n.to_zone]) or "any"
            src = ", ".join([f"<code>{html.escape(s)}</code>" for s in n.source]) or "any"
            dst = ", ".join([f"<code>{html.escape(d)}</code>" for d in n.destination]) or "any"
            tr_src = f"<code>{html.escape(n.translated_source)}</code>" if n.translated_source else "-"
            tr_dst = f"<code>{html.escape(n.translated_destination)}</code>" if n.translated_destination else "-"
            nat_rows.append(
                f"<tr><td><b><code>{html.escape(n.name)}</code></b></td>"
                f"<td><span class='type-tag'>{html.escape(n.type.value.upper())}</span></td>"
                f"<td>{from_z}</td><td>{to_z}</td>"
                f"<td>{src}</td><td>{dst}</td>"
                f"<td>{tr_src}</td><td>{tr_dst}</td>"
                f"<td><code>{html.escape(n.service or 'any')}</code></td>"
                f"<td>{html.escape(n.description or '-')}</td></tr>"
            )
        nat_html = "".join(nat_rows) if nat_rows else "<tr><td colspan='10' class='text-muted'>No NAT rules configured.</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Firewall Migration Report — {hostname}</title>
<!-- Google Fonts: Poppins (Display), Roboto & Inter (UI), JetBrains Mono (Code) -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Poppins:wght@400;500;600;700;800&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --color-primary: #0087cc;
    --color-primary-hover: #0284c7;
    --color-primary-active: #0369a1;
    --color-primary-subtle: rgba(0, 135, 204, 0.12);
    --color-primary-glow: rgba(0, 135, 204, 0.22);
    --color-secondary: #0e4e95;
    --color-secondary-dark: #082f49;
    --color-cyber: #581c87;
    --color-teal: #065f46;
    --color-pink: #9f1239;
    
    --success: #15803d;
    --warning: #b45309;
    --danger: #b91c1c;
    --info: #0284c7;
    
    --bg-main: #ffffff;
    --bg-surface: #f8fafc;
    --bg-card: #ffffff;
    --bg-card-hover: #f0f9ff;
    --bg-input: #ffffff;
    
    --border-glass: #cbd5e1;
    --border-subtle: rgba(0, 135, 204, 0.30);
    --border-hover: rgba(0, 135, 204, 0.60);
    --border-focus: #0087cc;
    
    --text-main: #090d16;
    --text-heading: #020617;
    --text-muted: #1e293b;
    --text-dim: #334155;
    
    --font-display: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-ui: 'Roboto', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --font-mono: 'JetBrains Mono', 'Roboto Mono', ui-monospace, monospace;
    
    --radius-xs: 4px;
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 18px;
    --radius-full: 9999px;
    
    --shadow-card: 0 4px 24px -4px rgba(0, 0, 0, 0.10), 0 0 0 1px var(--border-subtle);
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  
  body {{
    font-family: var(--font-ui);
    background-color: var(--bg-main);
    color: var(--text-main);
    min-height: 100vh;
    padding: 2.5rem 1.25rem;
    position: relative;
    overflow-x: hidden;
    line-height: 1.5;
  }}

  /* Ambient Background Glow */
  .bg-shape {{
    position: fixed;
    border-radius: 50%;
    filter: blur(140px);
    z-index: -1;
    pointer-events: none;
  }}
  .shape-primary {{
    top: -10%;
    left: -5%;
    width: 650px;
    height: 650px;
    background: radial-gradient(circle, rgba(0, 135, 204, 0.06) 0%, rgba(0, 135, 204, 0) 70%);
  }}
  .shape-secondary {{
    bottom: -15%;
    right: -10%;
    width: 750px;
    height: 750px;
    background: radial-gradient(circle, rgba(14, 78, 149, 0.06) 0%, rgba(14, 78, 149, 0) 70%);
  }}

  .container {{
    width: 100%;
    max-width: 1100px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    gap: 1.75rem;
    z-index: 1;
  }}
  
  /* Enterprise Header */
  .app-header {{
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg);
    padding: 1.75rem 2rem;
    box-shadow: var(--shadow-card);
  }}
  
  .header-content {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.25rem;
  }}

  .brand {{
    display: flex;
    align-items: center;
    gap: 1rem;
  }}

  .brand-icon {{
    width: 52px;
    height: 52px;
    border-radius: var(--radius-md);
    background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    box-shadow: 0 6px 16px -4px var(--color-primary-glow);
    flex-shrink: 0;
  }}

  .brand-title {{
    font-family: var(--font-display);
    font-size: 1.55rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: var(--text-heading);
    line-height: 1.2;
  }}

  .text-gradient {{
    background: linear-gradient(135deg, #0087cc 0%, #0e4e95 50%, #581c87 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}

  .meta-chips {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 6px;
  }}

  .meta-chip {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #f1f5f9;
    border: 1px solid var(--border-glass);
    padding: 4px 12px;
    border-radius: var(--radius-full);
    font-family: var(--font-display);
    font-size: 0.82rem;
    font-weight: 600;
    color: var(--text-muted);
  }}
  .meta-chip b {{ color: var(--text-heading); font-weight: 800; }}

  /* Action Buttons */
  .toolbar {{ display: flex; gap: 10px; align-items: center; }}
  
  .btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px 18px;
    border-radius: var(--radius-sm);
    font-family: var(--font-display);
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    border: 1px solid transparent;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  }}
  
  .btn-primary {{
    background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
    color: white;
    box-shadow: 0 4px 14px -2px var(--color-primary-glow);
  }}
  .btn-primary:hover {{
    background: linear-gradient(135deg, #0284c7, #0c4a6e);
    transform: translateY(-1px);
    box-shadow: 0 8px 20px -2px rgba(0, 135, 204, 0.4);
  }}
  
  .btn-secondary {{
    background: #f1f5f9;
    border-color: #cbd5e1;
    color: var(--text-heading);
    font-weight: 700;
  }}
  .btn-secondary:hover {{
    background: #e2e8f0;
    border-color: #94a3b8;
  }}

  /* Metric Cards */
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 1.25rem;
  }}
  
  .metric-card {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 4px;
    box-shadow: var(--shadow-card);
    transition: transform 0.2s ease, border-color 0.2s ease;
  }}
  .metric-card:hover {{
    border-color: var(--border-hover);
    background: var(--bg-card-hover);
    transform: translateY(-2px);
  }}
  .metric-title {{
    font-family: var(--font-display);
    font-size: 0.8rem;
    color: var(--text-muted);
    text-transform: uppercase;
    font-weight: 800;
    letter-spacing: 0.05em;
  }}
  .metric-val {{
    font-family: var(--font-display);
    font-size: 1.95rem;
    font-weight: 800;
    color: var(--text-heading);
    line-height: 1.2;
  }}

  /* Search Input */
  .search-box {{ width: 100%; }}
  .search-input {{
    width: 100%;
    background: var(--bg-input);
    border: 2px solid var(--border-glass);
    color: var(--text-heading);
    padding: 14px 18px;
    border-radius: var(--radius-sm);
    font-family: var(--font-display);
    font-size: 0.94rem;
    font-weight: 600;
    outline: none;
    transition: all 0.25s ease;
  }}
  .search-input:focus {{
    border-color: var(--color-primary);
    background: #ffffff;
    box-shadow: 0 0 0 3px var(--color-primary-subtle);
  }}

  /* Card Containers */
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg);
    padding: 2rem;
    box-shadow: var(--shadow-card);
    transition: border-color 0.3s ease;
  }}
  .card:hover {{ border-color: var(--border-hover); }}
  
  .card-header {{
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    border-bottom: 2px solid var(--border-glass);
    padding-bottom: 1rem;
  }}

  .card h2 {{
    font-family: var(--font-display);
    font-size: 1.3rem;
    font-weight: 800;
    color: var(--text-heading);
    display: flex;
    align-items: center;
    gap: 10px;
  }}

  .step-num {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    background: #e0f2fe;
    border: 2px solid var(--color-primary);
    color: var(--color-primary);
    font-size: 0.9rem;
    font-weight: 800;
    flex-shrink: 0;
  }}

  .sub-title {{
    font-family: var(--font-display);
    font-size: 1rem;
    font-weight: 800;
    color: var(--color-secondary);
    margin: 1.5rem 0 0.6rem 0;
    letter-spacing: -0.01em;
  }}

  /* Tables */
  .table-responsive {{
    overflow-x: auto;
    border: 1px solid var(--border-glass);
    border-radius: var(--radius-sm);
    background: #ffffff;
    margin-bottom: 1.25rem;
  }}
  
  table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    font-size: 0.9rem;
  }}
  
  th {{
    background: #f1f5f9;
    color: var(--text-heading);
    font-family: var(--font-display);
    font-weight: 800;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 12px 14px;
    border-bottom: 2px solid var(--border-glass);
    white-space: nowrap;
  }}
  
  td {{
    padding: 11px 14px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: middle;
    color: var(--text-main);
    font-weight: 500;
  }}
  
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f0f9ff; }}
  
  /* Badges & Tags */
  code {{
    background: #f1f5f9;
    color: #0369a1;
    border: 1px solid #cbd5e1;
    padding: 2px 7px;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.88em;
    font-weight: 700;
  }}

  .badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: var(--radius-full);
    font-family: var(--font-display);
    font-size: 0.76rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }}

  .badge-full {{
    background: #dcfce7;
    color: #14532d;
    border: 1px solid #86efac;
  }}
  .badge-partial {{
    background: #fef3c7;
    color: #78350f;
    border: 1px solid #fde68a;
  }}
  .badge-manual {{
    background: #ffe4e6;
    color: #881337;
    border: 1px solid #fecdd3;
  }}
  .badge-unsupported {{
    background: #ffe4e6;
    color: #881337;
    border: 1px solid #fecdd3;
  }}
  .badge-allow {{
    background: #dcfce7;
    color: #14532d;
    font-weight: 800;
    border: 1px solid #86efac;
  }}
  .badge-deny {{
    background: #ffe4e6;
    color: #881337;
    font-weight: 800;
    border: 1px solid #fecdd3;
  }}
  .zone-tag {{
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--text-heading);
  }}
  .type-tag {{
    background: #ede9fe;
    color: #4c1d95;
    border: 1px solid #ddd6fe;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 800;
    font-family: var(--font-display);
  }}
  .text-muted {{ color: var(--text-muted); font-style: italic; font-weight: 600; }}

  /* JSON Viewer */
  pre {{
    background: #030712;
    border: 1px solid rgba(0, 135, 204, 0.4);
    border-radius: var(--radius-md);
    padding: 1.25rem;
    max-height: 420px;
    overflow-y: auto;
    font-family: var(--font-mono);
    font-size: 0.85rem;
    color: #e0f2fe;
    line-height: 1.6;
  }}

  /* Print Optimization */
  @media print {{
    body {{ background: #fff; color: #000; padding: 0; }}
    .bg-shape, .toolbar, .search-box {{ display: none !important; }}
    .app-header, .card, .metric-card {{ box-shadow: none; border: 1px solid #000; background: #fff; }}
    th {{ background: #f1f5f9 !important; color: #000 !important; font-weight: 800 !important; }}
    td {{ color: #000 !important; border-bottom: 1px solid #000 !important; }}
    code {{ background: #f1f5f9 !important; color: #000 !important; border: 1px solid #000 !important; }}
    .brand-title {{ color: #000 !important; }}
  }}
</style>
</head>
<body>
  <!-- Ambient Background Accents -->
  <div class="bg-shape shape-primary"></div>
  <div class="bg-shape shape-secondary"></div>

  <div class="container">
    <!-- Enterprise Header -->
    <header class="app-header">
      <div class="header-content">
        <div class="brand">
          <div class="brand-icon">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div>
            <h1 class="brand-title">Firewall Migration <span class="text-gradient">& Audit Report</span></h1>
            <div class="meta-chips">
              <span class="meta-chip">Device Hostname: <b>{hostname}</b></span>
              <span class="meta-chip">Source Platform: <b>{source_vendor}</b></span>
              <span class="meta-chip">Target Destination: <b>{target_vendor}</b></span>
              <span class="meta-chip">Generated: <b>{timestamp_str}</b></span>
            </div>
          </div>
        </div>
        <div class="toolbar">
          <button class="btn btn-primary" onclick="window.print()">🖨️ Print / Save as PDF</button>
          <button class="btn btn-secondary" onclick="copyJson()">📋 Copy JSON</button>
        </div>
      </div>
    </header>

    <!-- Metric Overview Cards -->
    <div class="metrics-grid">
      <div class="metric-card">
        <span class="metric-title">Total Entities</span>
        <span class="metric-val">{total_objects}</span>
      </div>
      <div class="metric-card">
        <span class="metric-title">Full Confidence</span>
        <span class="metric-val" style="color: var(--success);">{confidence_counts[MigrationConfidence.FULL]}</span>
      </div>
      <div class="metric-card">
        <span class="metric-title">Review Required</span>
        <span class="metric-val" style="color: var(--warning);">{confidence_counts[MigrationConfidence.PARTIAL] + confidence_counts[MigrationConfidence.MANUAL]}</span>
      </div>
      <div class="metric-card">
        <span class="metric-title">Security Policies</span>
        <span class="metric-val" style="color: var(--color-primary);">{len(self.ir.policies)}</span>
      </div>
      <div class="metric-card">
        <span class="metric-title">Objects & Services</span>
        <span class="metric-val" style="color: var(--color-cyber);">{len(self.ir.addresses) + len(self.ir.services)}</span>
      </div>
    </div>

    <!-- Search Box -->
    <div class="search-box">
      <input type="text" id="reportSearch" class="search-input" placeholder="🔍 Search across all rules, addresses, interfaces, and profiles..." onkeyup="filterTables()">
    </div>

    <!-- 1. Audit Trail -->
    <div class="card">
      <div class="card-header">
        <h2><span class="step-num">1</span> Audit Trail & Action Items</h2>
      </div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Category</th><th>Object ID</th><th>Confidence</th><th>Message / Remediation</th></tr></thead>
          <tbody>{audit_html}</tbody>
        </table>
      </div>
    </div>

    <!-- 2. Network Architecture & Zones -->
    <div class="card">
      <div class="card-header">
        <h2><span class="step-num">2</span> Network Architecture & Zones</h2>
      </div>
      
      <div class="sub-title">Interfaces & Zone Assignments</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Interface</th><th>Type / VLAN Tag</th><th>Assigned Zone</th><th>IP / Subnet</th><th>Description</th></tr></thead>
          <tbody>{intf_html}</tbody>
        </table>
      </div>

      <div class="sub-title">Security Zones</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Zone Name</th><th>Bound Interfaces</th><th>Description</th></tr></thead>
          <tbody>{zone_html}</tbody>
        </table>
      </div>

      <div class="sub-title">Static Routing Table</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Route Name</th><th>Destination</th><th>Next Hop</th><th>Interface</th><th>Metric</th><th>Description</th></tr></thead>
          <tbody>{route_html}</tbody>
        </table>
      </div>

      <div class="sub-title">IPsec VPN Tunnels</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Tunnel Name</th><th>Peer Gateway</th><th>Interface</th><th>IKE Ver</th><th>PSK Status</th><th>Description</th></tr></thead>
          <tbody>{vpn_html}</tbody>
        </table>
      </div>
    </div>

    <!-- 3. Object Inventory -->
    <div class="card">
      <div class="card-header">
        <h2><span class="step-num">3</span> Object Inventory</h2>
      </div>
      
      <div class="sub-title">Address Objects</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Address Name</th><th>Type</th><th>Value / Subnet</th><th>Description</th></tr></thead>
          <tbody>{addr_html}</tbody>
        </table>
      </div>

      <div class="sub-title">Address Groups</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Group Name</th><th>Members</th><th>Description</th></tr></thead>
          <tbody>{ag_html}</tbody>
        </table>
      </div>

      <div class="sub-title">Custom Services & Protocols</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Service Name</th><th>Protocol</th><th>Port(s)</th><th>Description</th></tr></thead>
          <tbody>{svc_html}</tbody>
        </table>
      </div>

      <div class="sub-title">Universal Threat Prevention & Profile Groups</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Profile Group</th><th>Antivirus</th><th>IPS</th><th>Spyware</th><th>URL</th><th>File Block</th><th>Sandbox</th><th>Decryption</th><th>Description</th></tr></thead>
          <tbody>{spg_html}</tbody>
        </table>
      </div>
    </div>

    <!-- 4. Security Policies & NAT -->
    <div class="card">
      <div class="card-header">
        <h2><span class="step-num">4</span> Security Policies & NAT Rulebase</h2>
      </div>
      
      <div class="sub-title">Security Policies</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>#</th><th>Policy Name</th><th>From</th><th>To</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Status</th><th>Threat Profiles</th><th>Description</th></tr></thead>
          <tbody>{pol_html}</tbody>
        </table>
      </div>

      <div class="sub-title">NAT Translations</div>
      <div class="table-responsive">
        <table class="filterable-table">
          <thead><tr><th>Rule Name</th><th>Type</th><th>From</th><th>To</th><th>Source Match</th><th>Dest Match</th><th>Translated Source</th><th>Translated Dest</th><th>Service</th><th>Description</th></tr></thead>
          <tbody>{nat_html}</tbody>
        </table>
      </div>
    </div>

    <!-- 5. Raw Canonical JSON -->
    <div class="card">
      <div class="card-header">
        <h2><span class="step-num">5</span> Raw Canonical Intermediate Representation (JSON)</h2>
      </div>
      <pre id="jsonPayload">{json_dump}</pre>
    </div>
  </div>

  <script>
  function filterTables() {{
    const query = document.getElementById('reportSearch').value.toLowerCase();
    const tables = document.querySelectorAll('.filterable-table');
    tables.forEach(table => {{
      const rows = table.querySelectorAll('tbody tr');
      rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
      }});
    }});
  }}

  function copyJson() {{
    const jsonText = document.getElementById('jsonPayload').textContent;
    navigator.clipboard.writeText(jsonText).then(() => {{
      alert('Canonical IR JSON copied to clipboard!');
    }}).catch(err => {{
      console.error('Failed to copy JSON: ', err);
    }});
  }}
  </script>
</body>
</html>
"""




