import xml.etree.ElementTree as ET
from typing import Optional, Dict, List
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRNATRule, IRRoute,
    IRSecurityProfileGroup, IRAuditEntry
)
from pydantic import ValidationError
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

from fwmigrate.extraction.models import ExtractionResult, SourceInventoryItem, ExtractionStatus
from .resolver import PANResolver
from .source_model import PANScope, PANSourceObject
from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation
from .routing import PANRouteExtractor
from .extraction import record_partial, record_extract_only, record_normalized
from .residual import PANResidualExtractor


class PANOSSourceParser(BaseSourceParser):
    """Parses Palo Alto Networks PAN-OS XML configuration exports into canonical IRConfig."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver = PANResolver()

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".xml", ".txt", ".conf"]

    def _create_ir_address(self, ir: IRConfig, name: str, addr_type: AddressType, val: str, description: Optional[str] = None, scope: Optional[PANScope] = None):
        kwargs = {
            "name": name,
            "type": addr_type,
            "description": description
        }
        
        if addr_type in (AddressType.NETWORK, AddressType.HOST):
            kwargs["subnet"] = val
        elif addr_type == AddressType.RANGE:
            if "-" in val:
                kwargs["ip_range_start"] = val.split("-")[0]
                kwargs["ip_range_end"] = val.split("-")[1]
        elif addr_type in (AddressType.FQDN, AddressType.WILDCARD_FQDN):
            kwargs["fqdn"] = val

        try:
            ir.addresses.append(IRAddress(**kwargs))
        except ValidationError as e:
            safe_kwargs = {
                "name": name,
                "type": addr_type,
                "description": description,
                "parse_error": str(e),
                "raw_value": val
            }
            from fwmigrate.ir.enums import MigrationConfidence
            ir.audit_entries.append(IRAuditEntry(
                id=name, category="Address", message=f"Address '{name}' failed strict validation: {str(e)}",
                confidence=MigrationConfidence.UNSUPPORTED
            ))
            ir.addresses.append(IRAddress(**safe_kwargs))

        self.resolver.register_object(PANSourceObject(name=name, kind='address', original_value=val, domain='address', source_path=f"address/entry[@name='{name}']", scope=scope), "address")

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            # Handle possible surrounding whitespace or partial tags
            try:
                cleaned = content.strip()
                if not cleaned:
                    raise ValueError("Empty configuration input.")
                root = ET.fromstring(cleaned)
            except ET.ParseError:
                # Check for PAN-OS CLI
                if cleaned.startswith("set "):
                    raise ValueError("PAN-OS CLI 'set' format is not supported. Please provide XML configuration.")
                raise ValueError(f"Malformed XML input: {str(e)}")

        if root.tag != "config":
            raise ValueError(f"Unsupported XML format: expected root element '<config>', found '<{root.tag}>'.")

        # 1. Metadata
        hostname = None
        host_elem = root.find(".//system/hostname")
        if host_elem is None:
            host_elem = root.find(".//deviceconfig/system/hostname")
        if host_elem is not None and host_elem.text:
            hostname = host_elem.text.strip()

        ir = IRConfig(
            metadata=IRMetadata(
                hostname=hostname,
                source_vendor="palo_alto",
                source_version=root.get("version")
            )
        )
        extraction = ExtractionResult(canonical_ir=ir)

        # Find all scopes: shared, vsys, device-group
        
        shared_root = root.find(".//shared")
        if shared_root is not None:
            self._parse_scope(PANScope(kind="shared", name="shared"), shared_root, extraction)
        elif root.find(".//vsys/entry") is None and root.find(".//device-group/entry") is None:
            # Standalone PAN-OS without vsys or shared
            self._parse_scope(PANScope(kind="vsys", name="vsys1"), root, extraction)

        for vsys_entry in root.findall(".//vsys/entry"):
            vsys_name = vsys_entry.get("name") or "vsys1"
            self._parse_scope(PANScope(kind="vsys", name=vsys_name), vsys_entry, extraction)
            
        for dg_entry in root.findall(".//device-group/entry"):
            dg_name = dg_entry.get("name") or "dg1"
            self._parse_scope(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)

        extraction.canonical_ir = ir
        return extraction

    def _parse_scope(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        
        # 2. Zones
        zones_dict: Dict[str, List[str]] = {}
        for z_entry in search_root.findall(".//zone/entry"):
            z_name = z_entry.get("name")
            if z_name:
                intfs = [m.text for m in z_entry.findall(".//network/layer3/member") if m.text]
                zones_dict[z_name] = intfs
                ir.zones.append(IRZone(name=z_name, interfaces=intfs))
                for intf in intfs:
                    ir.interfaces.append(IRInterface(name=intf, zone=z_name))

        # 3. Addresses
        for a_entry in search_root.findall(".//address/entry"):
            a_name = a_entry.get("name")
            if not a_name:
                continue

            desc_elem = a_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            ip_netmask = a_entry.find("ip-netmask")
            ip_range = a_entry.find("ip-range")
            fqdn = a_entry.find("fqdn")

            if ip_netmask is not None and ip_netmask.text:
                val = ip_netmask.text.strip()
                if val.endswith("/32") or "/128" in val:
                    a_type = AddressType.HOST
                else:
                    a_type = AddressType.NETWORK if "/" in val else AddressType.HOST
                self._create_ir_address(ir, a_name, a_type, val, desc, scope)
            elif ip_range is not None and ip_range.text:
                self._create_ir_address(ir, a_name, AddressType.RANGE, ip_range.text.strip(), desc, scope)
            elif fqdn is not None and fqdn.text:
                self._create_ir_address(ir, a_name, AddressType.FQDN, fqdn.text.strip(), desc, scope)

        # 4. Address Groups
        for g_entry in search_root.findall(".//address-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            desc_elem = g_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            members = [m.text for m in g_entry.findall(".//static/member") if m.text]
            dyn_filter_elem = g_entry.find(".//dynamic/filter")
            is_dynamic = dyn_filter_elem is not None
            dynamic_filter = dyn_filter_elem.text.strip() if is_dynamic and dyn_filter_elem.text else None
            ir.address_groups.append(IRAddressGroup(
                name=g_name,
                members=members,
                description=desc,
                is_dynamic=is_dynamic,
                dynamic_filter=dynamic_filter
            ))
            self.resolver.register_object(PANSourceObject(name=g_name, kind='address-group', domain='address', source_path=f"address-group/entry[@name='{g_name}']", scope=scope), "address")

        # 5. Services
        for s_entry in search_root.findall(".//service/entry"):
            s_name = s_entry.get("name")
            if not s_name:
                continue
            desc_elem = s_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            ports: List[IRServicePort] = []
            tcp_port = s_entry.find(".//protocol/tcp/port")
            if tcp_port is not None and tcp_port.text:
                ports.append(IRServicePort(protocol=ServiceProtocol.TCP, port=tcp_port.text.strip()))

            udp_port = s_entry.find(".//protocol/udp/port")
            if udp_port is not None and udp_port.text:
                ports.append(IRServicePort(protocol=ServiceProtocol.UDP, port=udp_port.text.strip()))

            if ports:
                ir.services.append(IRService(name=s_name, ports=ports, description=desc))
                self.resolver.register_object(PANSourceObject(name=s_name, kind='service', domain='service', source_path=f"service/entry[@name='{s_name}']", scope=scope), "service")

        # 6. Service Groups
        for g_entry in search_root.findall(".//service-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            members = [m.text for m in g_entry.findall(".//members/member") if m.text]
            ir.service_groups.append(IRServiceGroup(name=g_name, members=members))
            self.resolver.register_object(PANSourceObject(name=g_name, kind='service-group', domain='service', source_path=f"service-group/entry[@name='{g_name}']", scope=scope), "service")

        # 7. Security Policies
        rules_paths = [".//rulebase/security/rules/entry", ".//pre-rulebase/security/rules/entry", ".//post-rulebase/security/rules/entry"]
        for path in rules_paths:
            for p_entry in search_root.findall(path):
                p_name = p_entry.get("name")
                if not p_name:
                    continue

                from_zones = [m.text for m in p_entry.findall(".//from/member") if m.text]
                to_zones = [m.text for m in p_entry.findall(".//to/member") if m.text]
                sources = [m.text for m in p_entry.findall(".//source/member") if m.text]
                destinations = [m.text for m in p_entry.findall(".//destination/member") if m.text]
                applications = [m.text for m in p_entry.findall(".//application/member") if m.text]
                services = [m.text for m in p_entry.findall(".//service/member") if m.text]

                act_elem = p_entry.find("action")
                act_text = act_elem.text.strip().lower() if act_elem is not None and act_elem.text else None
                action = PolicyAction.DENY if act_text in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else (PolicyAction.ALLOW if act_text else None)

                # Safety check
                if not action:
                    record_partial(
                        extraction, domain="policies", 
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']", 
                        scope=scope, name=p_name, notes=["Missing required action"]
                    )
                    continue

                if not from_zones or not to_zones or not sources or not destinations:
                    record_partial(
                        extraction, domain="policies", 
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']", 
                        scope=scope, name=p_name, notes=["Missing required fields"]
                    )
                    continue

                desc_elem = p_entry.find("description")
                desc = desc_elem.text if desc_elem is not None else None

                disabled_elem = p_entry.find("disabled")
                disabled = (disabled_elem is not None and disabled_elem.text and disabled_elem.text.strip().lower() == "yes")

                log_end_elem = p_entry.find(".//log-end")
                log_end = (log_end_elem is None or (log_end_elem.text and log_end_elem.text.strip().lower() == "yes"))

                log_start_elem = p_entry.find(".//log-start")
                log_start = (log_start_elem is not None and log_start_elem.text and log_start_elem.text.strip().lower() == "yes")

                spg_elem = p_entry.find(".//profile-setting/group/member")
                spg_name = spg_elem.text.strip() if spg_elem is not None and spg_elem.text else None

                sched_elem = p_entry.find(".//schedule")
                sched = sched_elem.text.strip() if sched_elem is not None and sched_elem.text else None
                
                missing_refs = []
                for s in sources:
                    if s not in ("any",) and not self.resolver.resolve(s, "address", scope):
                        missing_refs.append(s)
                for d in destinations:
                    if d not in ("any",) and not self.resolver.resolve(d, "address", scope):
                        missing_refs.append(d)
                for svc in services:
                    if svc not in ("any", "application-default") and not self.resolver.resolve(svc, "service", scope):
                        missing_refs.append(svc)
                        
                pol = IRPolicy(
                    name=p_name, from_zone=from_zones, to_zone=to_zones, source=sources, destination=destinations,
                    applications=applications, service=services, action=action, description=desc, disabled=disabled,
                    schedule=sched, log_end=log_end, log_start=log_start, security_profile_group=spg_name
                )
                
                if missing_refs:
                    pol.migration_status = "PARTIALLY_NORMALIZED"
                    pol.requires_manual_review = True
                    pol.review_reasons.append(f"Unresolved references: {', '.join(missing_refs)}")
                    record_partial(
                        extraction, domain="policies",
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                        scope=scope, name=p_name, notes=[f"Unresolved references: {', '.join(missing_refs)}"]
                    )
                else:
                    record_normalized(
                        extraction, domain="policies",
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                        scope=scope, name=p_name
                    )
                    
                ir.policies.append(pol)

        # 8. NAT Rules
        paths = [".//rulebase/nat/rules/entry", ".//pre-rulebase/nat/rules/entry", ".//post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in search_root.findall(path):
                n_name = n_entry.get("name")
                if not n_name: continue
                
                from_z = [m.text for m in n_entry.findall(".//from/member") if m.text]
                to_z = [m.text for m in n_entry.findall(".//to/member") if m.text]
                src = [m.text for m in n_entry.findall(".//source/member") if m.text]
                dst = [m.text for m in n_entry.findall(".//destination/member") if m.text]
                srv = [m.text for m in n_entry.findall(".//service/member") if m.text]
                
                snat_elem = n_entry.find(".//source-translation")
                dnat_elem = n_entry.find(".//destination-translation")
                dyn_dnat_elem = n_entry.find(".//dynamic-destination-translation")
                
                s_trans = PANNatRuleExtractor.extract_source_translation(snat_elem)
                d_trans = PANNatRuleExtractor.extract_destination_translation(dnat_elem)
                dyn_d_trans = PANNatRuleExtractor.extract_dynamic_destination_translation(dyn_dnat_elem)
                
                if not s_trans and not d_trans and not dyn_d_trans:
                    record_extract_only(
                        extraction, domain="nat",
                        source_path=f"nat/rules/entry[@name='{n_name}']",
                        scope=scope, name=n_name,
                        notes=["NAT rule has no translation"]
                    )
                    continue
                
                # Determine NAT type
                nat_type = NATType.SOURCE
                if s_trans and (d_trans or dyn_d_trans):
                    nat_type = NATType.TWICE
                elif d_trans or dyn_d_trans:
                    nat_type = NATType.DESTINATION
                    
                nat_rule = IRNATRule(
                    name=n_name, type=nat_type, from_zone=from_z, to_zone=to_z, 
                    source=src, destination=dst, services=srv
                )
                
                if s_trans and s_trans.translated_address:
                    nat_rule.translated_sources = s_trans.translated_address
                if d_trans and d_trans.translated_address:
                    nat_rule.translated_destinations = [d_trans.translated_address]
                    
                ir.nat_rules.append(nat_rule)
                record_normalized(
                    extraction, domain="nat",
                    source_path=f"nat/rules/entry[@name='{n_name}']",
                    scope=scope, name=n_name
                )

        # 9. Static Routes
        PANRouteExtractor.extract_static_routes(scope, search_root, extraction)
        
        # 10. Residual accounting
        PANResidualExtractor.extract_residual_scope(scope, search_root, extraction)

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping).canonical_ir
