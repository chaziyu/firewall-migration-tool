from fwmigrate.ir.v2.models import IRConfigV2
from fwmigrate.ir.core import IRConfig, Zone, Address, AddressGroup, Service, ServiceGroup, SecurityRule
from fwmigrate.ir.core import Metadata

class IRv2ToV1Adapter:
    """
    Down-converts an IRConfigV2 to the legacy IRConfig format
    so that existing generators (Terraform generators for PAN-OS, etc.)
    continue to work without modification while the core is being hardened.
    """
    
    @staticmethod
    def adapt(config_v2: IRConfigV2, hostname: str = "migrated-firewall", vendor: str = "unknown") -> IRConfig:
        v1 = IRConfig(metadata=Metadata(hostname=hostname, source_vendor=vendor))
        
        for z in config_v2.zones:
            v1.zones.append(Zone(name=z.name, interfaces=z.interfaces, description=z.description))
            
        for a in config_v2.addresses:
            v1.addresses.append(Address(name=a.name, type=a.type, value=a.value, description=a.description))
            
        for ag in config_v2.address_groups:
            v1.address_groups.append(AddressGroup(name=ag.name, members=ag.members, description=ag.description))
            
        for s in config_v2.services:
            v1.services.append(Service(name=s.name, protocol=s.protocol, port_range=s.port_range, description=s.description))
            
        for sg in config_v2.service_groups:
            v1.service_groups.append(ServiceGroup(name=sg.name, members=sg.members, description=sg.description))
            
        for p in config_v2.policies:
            v1.policies.append(SecurityRule(
                name=p.name,
                from_zone=p.from_zone,
                to_zone=p.to_zone,
                source=p.source,
                destination=p.destination,
                service=p.service,
                action=p.action,
                disabled=p.disabled,
                description=p.description,
                log_end=p.log_end
            ))
            
        return v1
