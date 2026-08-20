from fwmigrate.ir.core import IRConfig, AddressType, ServiceProtocol, PolicyAction, NATType
from fwmigrate.generators.palo_alto.model import (
    PANConfig, PANDeviceConfig, PANVsysEntry, PANZoneEntry, PANZoneNetwork,
    PANAddressEntry, PANAddressGroupEntry, PANServiceEntry, PANServiceProtocol,
    PANTcpService, PANUdpService, PANServiceGroupEntry, PANRuleEntry, PANNATRuleEntry,
    PANProfileGroupEntry
)

class IRToPANOSTransformer:
    def __init__(self, ir: IRConfig):
        self.ir = ir
        
    def transform(self) -> PANConfig:
        pan = PANConfig(
            device_config=PANDeviceConfig(hostname=self.ir.metadata.hostname),
            vsys=PANVsysEntry()
        )
        
        # 1. Transform Zones
        for z in self.ir.zones:
            pan.vsys.zones.append(PANZoneEntry(
                name=z.name,
                network=PANZoneNetwork(layer3=z.interfaces)
            ))
            
        # 2. Transform Addresses
        for a in self.ir.addresses:
            pan_addr = PANAddressEntry(name=a.name, description=a.description)
            if a.type == AddressType.NETWORK or a.type == AddressType.HOST:
                pan_addr.ip_netmask = a.value
            elif a.type == AddressType.FQDN or a.type == AddressType.WILDCARD_FQDN:
                pan_addr.fqdn = a.value
            elif a.type == AddressType.RANGE:
                pan_addr.ip_range = a.value
            else:
                # Fallback for dynamic/group
                pan_addr.ip_netmask = "0.0.0.0/32" 
                
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
            
        # 4. Transform Services
        for s in self.ir.services:
            pan_proto = PANServiceProtocol()
            
            # Use the first port for simple PAN-OS service object
            if s.ports:
                port = s.ports[0]
                if port.protocol == ServiceProtocol.TCP:
                    pan_proto.tcp = PANTcpService(port=port.port)
                elif port.protocol == ServiceProtocol.UDP:
                    pan_proto.udp = PANUdpService(port=port.port)
            
            pan_service = PANServiceEntry(
                name=s.name, protocol=pan_proto, description=s.description
            )
            pan.vsys.services.append(pan_service)
            
        # 5. Transform Service Groups
        for sg in self.ir.service_groups:
            pan.vsys.service_groups.append(PANServiceGroupEntry(
                name=sg.name, members=sg.members
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
        for p in self.ir.policies:
            rule_name = p.name
            action = "allow" if p.action == PolicyAction.ALLOW else "deny"
            disabled = "yes" if p.disabled else "no"

            # If policy references a profile group not yet in profile_groups, create a default entry
            if p.security_profile_group and p.security_profile_group not in existing_groups:
                existing_groups.add(p.security_profile_group)
                pan.vsys.profile_groups.append(PANProfileGroupEntry(name=p.security_profile_group))
            
            pan.vsys.security_rules.append(PANRuleEntry(
                name=rule_name,
                from_zones=p.from_zone,
                to_zones=p.to_zone,
                source=p.source,
                destination=p.destination,
                application=p.applications if p.applications else ["any"],
                service=p.service,
                action=action,
                disabled=disabled,
                description=p.description,
                profile_setting_group=p.security_profile_group
            ))
            
        # 7. Transform NAT Rules
        for n in self.ir.nat_rules:
            nat_entry = PANNATRuleEntry(
                name=n.name,
                from_zones=n.from_zone,
                to_zones=n.to_zone,
                source=n.source,
                destination=n.destination,
                service=n.service
            )
            if n.type == NATType.SOURCE:
                nat_entry.source_translation = n.translated_source
            elif n.type == NATType.DESTINATION:
                nat_entry.destination_translation = n.translated_destination
                
            pan.vsys.nat_rules.append(nat_entry)
            
        return pan
