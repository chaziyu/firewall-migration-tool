import re

from fwmigrate.ir.core import (
    IRConfig, AddressType, ServiceProtocol, PolicyAction, NATType,
    NATTranslationMode, IRAuditEntry, MigrationConfidence,
)
from fwmigrate.generators.palo_alto.model import (
    PANConfig, PANDeviceConfig, PANVsysEntry, PANZoneEntry, PANZoneNetwork,
    PANAddressEntry, PANAddressGroupEntry, PANServiceEntry, PANServiceProtocol,
    PANTcpService, PANUdpService, PANServiceGroupEntry, PANRuleEntry, PANNATRuleEntry,
    PANProfileGroupEntry, PANTagEntry
)

class IRToPANOSTransformer:
    def __init__(self, ir: IRConfig):
        self.ir = ir
        
    def transform(self) -> PANConfig:
        valid_routes = []
        for route in self.ir.routes:
            if route.destination:
                valid_routes.append(route)
                continue
            self.ir.audit_entries.append(IRAuditEntry(
                id=f"panos-route:{route.name}",
                category="PAN-OS Route",
                message=(
                    f"Route '{route.name}' has no valid canonical destination "
                    "and was withheld from PAN-OS generation."
                ),
                confidence=MigrationConfidence.MANUAL,
            ))

        pan = PANConfig(
            device_config=PANDeviceConfig(hostname=self.ir.metadata.hostname),
            vsys=PANVsysEntry(),
            interfaces=self.ir.interfaces,
            routes=valid_routes,
            vpn_tunnels=self.ir.vpn_tunnels
        )
        
        # 0. Global Tag Inventory (MANUAL_REVIEW_REQUIRED: color3 / Red)
        pan.vsys.tags.append(PANTagEntry(
            name="MANUAL_REVIEW_REQUIRED",
            color="color3",
            comments="Generated placeholder for unsupported source firewall objects requiring manual review"
        ))
        
        # 1. Transform Zones
        for z in self.ir.zones:
            pan.vsys.zones.append(PANZoneEntry(
                name=z.name,
                network=PANZoneNetwork(layer3=z.interfaces)
            ))
            
        # 2. Transform Addresses
        for a in self.ir.addresses:
            pan_addr = PANAddressEntry(name=a.name, description=a.description)
            if a.type == AddressType.STUB_UNSUPPORTED:
                # Risk 1 fix: Map stub to RFC 2544 dummy IP to prevent DNS polling and commit delays
                pan_addr.ip_netmask = a.value if a.value and "/" in a.value else "198.19.255.254/32"
                pan_addr.description = a.audit_note or a.description or f"Stub for unsupported {a.original_type or 'object'}"
                pan_addr.tag = ["MANUAL_REVIEW_REQUIRED"]
            elif a.type in (AddressType.NETWORK, AddressType.HOST):
                pan_addr.ip_netmask = a.value
                if a.tags:
                    pan_addr.tag = list(a.tags)
            elif a.type in (AddressType.FQDN, AddressType.WILDCARD_FQDN):
                pan_addr.fqdn = a.value
                if (
                    a.type == AddressType.WILDCARD_FQDN
                    and pan_addr.fqdn.startswith("*")
                    and not pan_addr.fqdn.startswith("*.")
                ):
                    pan_addr.fqdn = "*." + pan_addr.fqdn[1:]
                if a.tags:
                    pan_addr.tag = list(a.tags)
            elif a.type == AddressType.RANGE:
                pan_addr.ip_range = a.value
                if a.tags:
                    pan_addr.tag = list(a.tags)
            else:
                # Fallback for dynamic/group
                pan_addr.ip_netmask = "0.0.0.0/32"
                if a.tags:
                    pan_addr.tag = list(a.tags)
                
            pan.vsys.addresses.append(pan_addr)
            
        # 3. Transform Address Groups
        for ag in self.ir.address_groups:
            if ag.is_dynamic or ag.dynamic_filter:
                pan.vsys.address_groups.append(PANAddressGroupEntry(
                    name=ag.name, dynamic=ag.dynamic_filter or f"'{ag.name}'", description=ag.description
                ))
            else:
                pan.vsys.address_groups.append(PANAddressGroupEntry(
                    name=ag.name, static=ag.members, description=ag.description
                ))
            
        # 4. Transform Services (Only TCP and UDP are valid PAN-OS custom service objects)
        valid_custom_services = set()
        for s in self.ir.services:
            if (
                s.requires_manual_review
                or any(port.source_port for port in s.ports)
            ):
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=s.name,
                        category="PAN-OS Service",
                        message=(
                            f"Service '{s.name}' was withheld from PAN-OS "
                            "generation because proxy or source-port "
                            "semantics require manual review."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )
                continue
            pan_proto = PANServiceProtocol()
            
            # Use the first valid TCP/UDP port for PAN-OS service object
            if s.ports:
                for port in s.ports:
                    if port.protocol == ServiceProtocol.TCP:
                        pan_proto.tcp = PANTcpService(port=port.port)
                        break
                    elif port.protocol == ServiceProtocol.UDP:
                        pan_proto.udp = PANUdpService(port=port.port)
                        break
            
            if pan_proto.tcp or pan_proto.udp:
                valid_custom_services.add(s.name)
                pan_service = PANServiceEntry(
                    name=s.name, protocol=pan_proto, description=s.description
                )
                pan.vsys.services.append(pan_service)
            
        # 5. Transform Service Groups
        service_group_names = {sg.name for sg in self.ir.service_groups}
        source_service_names = {s.name for s in self.ir.services}
        for sg in self.ir.service_groups:
            # Bug 9 fix: Allow custom services, nested service groups, and built-in PAN-OS services
            filtered_members = []
            for m in sg.members:
                if m in valid_custom_services or m in service_group_names:
                    # Known custom service or nested group
                    filtered_members.append(m)
                elif m in source_service_names:
                    # Service was dropped during mapping (e.g. ICMP), do not pass through
                    continue
                else:
                    # Assume it's a valid PAN-OS built-in or pre-existing service, pass through
                    filtered_members.append(m)
            if filtered_members:
                pan.vsys.service_groups.append(PANServiceGroupEntry(
                    name=sg.name, members=filtered_members
                ))

        # 5.5 Transform Security Profile Groups
        existing_groups = set()
        for pg in self.ir.security_profile_groups:
            existing_groups.add(pg.name)
            pan.vsys.profile_groups.append(PANProfileGroupEntry(
                name=pg.name,
                virus=[pg.antivirus] if pg.antivirus else ["default"],
                vulnerability=[pg.vulnerability] if pg.vulnerability else ["default"],
                spyware=[pg.anti_spyware] if pg.anti_spyware else ["default"],
                url_filtering=[pg.url_filtering] if pg.url_filtering else ["default"],
                file_blocking=[pg.file_blocking] if pg.file_blocking else ["basic-file-blocking"],
                wildfire_analysis=[pg.wildfire] if pg.wildfire else ["default"]
            ))

        # 6. Transform Policies
        APP_MAPPING = {
            "ALL_ICMP": "icmp",
            "ALL_ICMP6": "ipv6-icmp",
            "ICMP": "icmp",
            "ICMP6": "ipv6-icmp",
            "PING": "ping",
            "GRE": "gre",
            "AH": "ipsec-ah",
            "ESP": "ipsec-esp"
        }

        for p in self.ir.policies:
            if p.action == PolicyAction.IPSEC or p.requires_manual_review:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-policy-review:{p.source_rule_id or p.name}",
                    category="PAN-OS Policy",
                    message=(
                        f"Policy '{p.name}' has source semantics requiring "
                        "manual review and was withheld from PAN-OS generation."
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue
            if not p.from_zone or not p.to_zone:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-policy-zone:{p.source_rule_id or p.name}",
                    category="PAN-OS Policy",
                    message=(
                        f"Policy '{p.name}' has unresolved canonical zones "
                        "and was withheld from PAN-OS generation."
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue

            rule_name = p.name
            action = "allow" if p.action == PolicyAction.ALLOW else "deny"
            disabled = "yes" if p.disabled else "no"

            # If policy references a profile group not yet in profile_groups, create a default entry
            if p.security_profile_group and p.security_profile_group not in existing_groups:
                existing_groups.add(p.security_profile_group)
                pan.vsys.profile_groups.append(PANProfileGroupEntry(name=p.security_profile_group))
            
            # Map non-TCP/UDP services (e.g. ALL_ICMP) to PAN-OS applications
            rule_apps = list(p.applications) if p.applications else []
            rule_services = []
            for svc in p.service:
                svc_clean = svc.strip()
                if svc_clean.upper() in APP_MAPPING:
                    mapped_app = APP_MAPPING[svc_clean.upper()]
                    if mapped_app not in rule_apps:
                        rule_apps.append(mapped_app)
                elif svc_clean in ["ALL", "all", "ANY", "any"]:
                    rule_services.append("any")
                else:
                    rule_services.append(svc_clean)

            if not rule_apps:
                rule_apps = ["any"]
            if not rule_services:
                rule_services = ["application-default"] if rule_apps != ["any"] else ["any"]

            pan.vsys.security_rules.append(PANRuleEntry(
                name=rule_name,
                from_zones=p.from_zone,
                to_zones=p.to_zone,
                source=p.source,
                destination=p.destination,
                application=rule_apps,
                service=rule_services,
                action=action,
                log_start="yes" if getattr(p, 'log_start', False) else "no",
                disabled=disabled,
                description=p.description,
                profile_setting_group=p.security_profile_group
            ))
            
        # 7. Transform NAT Rules
        for n in self.ir.nat_rules:
            if not n.safe_for_target_generation:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=n.name,
                    category="PAN-OS NAT",
                    message=f"NAT rule '{n.name}' was preserved in IR but withheld from PAN-OS XML pending manual review.",
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue

            services = list(n.services) or ([n.service] if n.service else [])
            services = ["any" if service.lower() in ("all", "any", "<ir_any>") else service for service in services]
            if "any" in services:
                services = ["any"]
            if not services:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=n.name,
                    category="PAN-OS NAT",
                    message=f"NAT rule '{n.name}' has no representable service match and was withheld.",
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue

            if n.original_destination_port:
                protocol = (n.destination_protocol or "tcp").lower()
                if protocol not in ("tcp", "udp"):
                    self.ir.audit_entries.append(IRAuditEntry(
                        id=n.name,
                        category="PAN-OS NAT",
                        message=f"NAT rule '{n.name}' port-forward protocol '{protocol}' requires manual review.",
                        confidence=MigrationConfidence.MANUAL,
                    ))
                    continue
                service_name = re.sub(r"[^a-zA-Z0-9._ -]", "_", f"svc_nat_{protocol}_{n.original_destination_port}")[:63]
                if not any(service.name == service_name for service in pan.vsys.services):
                    pan_protocol = PANServiceProtocol()
                    if protocol == "udp":
                        pan_protocol.udp = PANUdpService(port=n.original_destination_port)
                    else:
                        pan_protocol.tcp = PANTcpService(port=n.original_destination_port)
                    pan.vsys.services.append(PANServiceEntry(
                        name=service_name,
                        protocol=pan_protocol,
                        description=f"Generated from canonical NAT rule {n.name}",
                    ))
                services = [service_name]

            for service in services:
                suffix = f"-{service}" if len(services) > 1 else ""
                entry_name = re.sub(r"[^a-zA-Z0-9._ -]", "_", f"{n.name}{suffix}")[:63]
                nat_entry = PANNATRuleEntry(
                    name=entry_name,
                    from_zones=n.from_zone,
                    to_zones=n.to_zone,
                    source=n.source,
                    destination=n.destination,
                    service=service,
                    disabled="no" if n.enabled else "yes",
                    description=n.description,
                )

                if n.type in (NATType.SOURCE, NATType.TWICE):
                    source_mode = n.source_translation_mode
                    if source_mode is None and n.translated_sources:
                        source_mode = NATTranslationMode.POOL
                    if source_mode == NATTranslationMode.INTERFACE_ADDRESS:
                        if len(n.source_to_interfaces) != 1:
                            continue
                        nat_entry.source_translation_mode = NATTranslationMode.INTERFACE_ADDRESS.value
                        nat_entry.source_translation_interface = n.source_to_interfaces[0]
                    elif source_mode == NATTranslationMode.POOL:
                        nat_entry.source_translation_mode = (
                            NATTranslationMode.STATIC.value
                            if n.source_pool_type == "one-to-one"
                            else NATTranslationMode.DYNAMIC_IP_AND_PORT.value
                        )
                        nat_entry.source_translations = list(n.translated_sources)

                if n.type in (NATType.DESTINATION, NATType.TWICE):
                    if len(n.translated_destinations) != 1:
                        continue
                    nat_entry.destination_translation = n.translated_destinations[0]
                    nat_entry.destination_translated_port = n.translated_port

                pan.vsys.nat_rules.append(nat_entry)
            
        return pan
