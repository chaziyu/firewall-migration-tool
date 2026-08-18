from typing import List
from fg2pan.generator.base import BaseGenerator, MigrationArtifact
from fg2pan.ir.core import IRConfig

class TXTReportGenerator(BaseGenerator):
    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append(f"FIREWALL CONFIGURATION SUMMARY")
        lines.append(f"Source: {ir.metadata.hostname} ({ir.metadata.source_vendor})")
        lines.append(f"Timestamp: {ir.metadata.migration_timestamp.isoformat()}")
        lines.append("=" * 80)
        lines.append("")
        
        # 1. Interfaces & Zones
        lines.append("1. INTERFACES & ZONES")
        lines.append("-" * 80)
        if not ir.zones:
            lines.append("No zones configured.")
        else:
            for zone in ir.zones:
                lines.append(f"Zone: {zone.name}")
                if zone.description:
                    lines.append(f"  Description: {zone.description}")
                if zone.interfaces:
                    lines.append(f"  Interfaces: {', '.join(zone.interfaces)}")
                else:
                    lines.append("  Interfaces: None")
                lines.append("")
                
        # 2. Addresses
        lines.append("2. ADDRESS OBJECTS")
        lines.append("-" * 80)
        if not ir.addresses:
            lines.append("No address objects configured.")
        else:
            for addr in ir.addresses:
                lines.append(f"Address: {addr.name}")
                lines.append(f"  Type:  {addr.type.value}")
                lines.append(f"  Value: {addr.value}")
                if addr.description:
                    lines.append(f"  Desc:  {addr.description}")
                lines.append("")
                
        # 3. Address Groups
        lines.append("3. ADDRESS GROUPS")
        lines.append("-" * 80)
        if not ir.address_groups:
            lines.append("No address groups configured.")
        else:
            for ag in ir.address_groups:
                lines.append(f"Group: {ag.name}")
                lines.append(f"  Members: {', '.join(ag.members)}")
                if ag.description:
                    lines.append(f"  Desc:    {ag.description}")
                lines.append("")

        # 4. Services
        lines.append("4. SERVICE OBJECTS")
        lines.append("-" * 80)
        if not ir.services:
            lines.append("No custom service objects configured.")
        else:
            for svc in ir.services:
                lines.append(f"Service: {svc.name}")
                for port in svc.ports:
                    lines.append(f"  Protocol: {port.protocol.value} | Port(s): {port.port}")
                if svc.description:
                    lines.append(f"  Desc:     {svc.description}")
                lines.append("")

        # 5. Policies
        lines.append("5. SECURITY POLICIES")
        lines.append("-" * 80)
        if not ir.policies:
            lines.append("No security policies configured.")
        else:
            for idx, pol in enumerate(ir.policies, 1):
                disabled_marker = " [DISABLED]" if pol.disabled else ""
                lines.append(f"Policy {idx}: {pol.name}{disabled_marker}")
                lines.append(f"  Action:      {pol.action.value.upper()}")
                lines.append(f"  From Zone:   {', '.join(pol.from_zone)}")
                lines.append(f"  To Zone:     {', '.join(pol.to_zone)}")
                lines.append(f"  Source:      {', '.join(pol.source)}")
                lines.append(f"  Destination: {', '.join(pol.destination)}")
                lines.append(f"  Service:     {', '.join(pol.service)}")
                if pol.security_profile_group:
                    lines.append(f"  Profiles:    {pol.security_profile_group}")
                if pol.description:
                    lines.append(f"  Desc:        {pol.description}")
                lines.append("")

        # 6. NAT Rules
        lines.append("6. NAT RULES")
        lines.append("-" * 80)
        if not ir.nat_rules:
            lines.append("No NAT rules configured.")
        else:
            for nat in ir.nat_rules:
                lines.append(f"NAT Rule: {nat.name} ({nat.type.value.upper()})")
                lines.append(f"  From Zone: {', '.join(nat.from_zone)}")
                lines.append(f"  To Zone:   {', '.join(nat.to_zone)}")
                lines.append(f"  Source:    {', '.join(nat.source)}")
                lines.append(f"  Dest:      {', '.join(nat.destination)}")
                lines.append(f"  Service:   {nat.service}")
                if nat.translated_source:
                    lines.append(f"  Translated Source: {nat.translated_source}")
                if nat.translated_destination:
                    lines.append(f"  Translated Dest:   {nat.translated_destination}")
                lines.append("")

        content = "\n".join(lines)
        
        return [
            MigrationArtifact(
                filename="config_summary.txt",
                content=content,
                format="txt"
            )
        ]
