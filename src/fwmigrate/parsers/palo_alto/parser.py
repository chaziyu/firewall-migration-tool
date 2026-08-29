import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Optional, Dict, List
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRNATRule, IRRoute,
    IRSecurityProfileGroup
)
from pydantic import ValidationError
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

from fwmigrate.extraction.models import ExtractionResult, SourceInventoryItem, ExtractionStatus
from .resolver import PANResolver
from .source_model import PANScope, PANSourceObject
from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation
from .routing import PANRouteExtractor
from .extraction import record_partial, record_extract_only, record_normalized, record_parse_error
from .residual import PANResidualExtractor
from .xml_utils import collect_unknown_children, member_texts, text_or_none


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

    @staticmethod
    def _parse_address_value(source_type: str, source_value: str) -> Dict[str, Any]:
        if source_type == "ip-netmask":
            parsed = ipaddress.ip_interface(source_value)
            family = f"ipv{parsed.version}"
            return {
                "type": AddressType.HOST if parsed.network.prefixlen == parsed.max_prefixlen else AddressType.NETWORK,
                "subnet": source_value,
                "address_family": family,
                "is_ipv6": parsed.version == 6,
            }

        if source_type == "ip-range":
            if source_value.count("-") != 1:
                raise ValueError("IP range must contain exactly one hyphen separator.")
            start_text, end_text = (part.strip() for part in source_value.split("-", 1))
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
            if start.version != end.version:
                raise ValueError("IP range endpoints must use the same address family.")
            if int(start) > int(end):
                raise ValueError("IP range start must not be greater than its end.")
            return {
                "type": AddressType.RANGE,
                "ip_range_start": start_text,
                "ip_range_end": end_text,
                "address_family": f"ipv{start.version}",
                "is_ipv6": start.version == 6,
            }

        if source_type == "ip-wildcard":
            if source_value.count("/") != 1:
                raise ValueError("IP wildcard must contain exactly one slash separator.")
            address_text, mask_text = (part.strip() for part in source_value.split("/", 1))
            ipaddress.IPv4Address(address_text)
            ipaddress.IPv4Address(mask_text)
            return {
                "type": AddressType.WILDCARD_MASK,
                "wildcard_mask": source_value,
                "address_family": "ipv4",
                "is_ipv6": False,
            }

        if source_type == "fqdn":
            return {"type": AddressType.FQDN, "fqdn": source_value}

        raise ValueError(f"Unsupported PAN-OS address type: {source_type}")

    def _parse_addresses(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        for entry in search_root.findall("./address/entry"):
            self._parse_address_object(scope, entry, extraction)

    def _parse_address_object(self, scope: PANScope, entry: ET.Element, extraction: ExtractionResult) -> Optional[IRAddress]:
        source_name = entry.get("name")
        source_path = f"address/entry[@name='{source_name}']" if source_name else "address/entry"
        description = text_or_none(entry, "./description")
        tags = member_texts(entry, "./tag/member")
        tag_element = entry.find("./tag")
        unknown_tag_fields = (
            collect_unknown_children(tag_element, known_children=["member"])
            if tag_element is not None else {}
        )
        unknown_fields = collect_unknown_children(
            entry,
            known_children=["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description", "tag"],
        )
        type_candidates = {
            source_type: text_or_none(entry, f"./{source_type}")
            for source_type in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn")
        }
        configured_types = [source_type for source_type, value in type_candidates.items() if value]
        evidence: Dict[str, Any] = {}
        present_types = [
            source_type for source_type in type_candidates
            if entry.find(f"./{source_type}") is not None
        ]
        empty_types = [source_type for source_type in present_types if not type_candidates[source_type]]
        if description is not None:
            evidence["pan_description"] = description
        if tags:
            evidence["pan_tags"] = tags
        if unknown_fields:
            evidence["pan_unknown_fields"] = unknown_fields
        if unknown_tag_fields:
            evidence["pan_unknown_tag_fields"] = unknown_tag_fields
        if empty_types:
            evidence["pan_empty_address_type_fields"] = empty_types

        if not source_name:
            evidence["pan_configured_address_values"] = {
                key: value for key, value in type_candidates.items() if value
            }
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                attributes=evidence, notes=["PAN-OS address entry is missing its required name."],
            )
            return None

        if len(configured_types) != 1:
            evidence["pan_configured_address_values"] = {
                key: value for key, value in type_candidates.items() if value
            }
            reason = (
                "PAN-OS address entry has no supported non-empty address type."
                if not configured_types
                else f"PAN-OS address entry has multiple configured address types: {', '.join(configured_types)}."
            )
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence, notes=[reason],
            )
            return None

        source_type = configured_types[0]
        source_value = type_candidates[source_type]
        evidence.update({"pan_source_type": source_type, "pan_source_value": source_value})

        if self.resolver.resolve_exact(source_name, "address", scope):
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=["Duplicate PAN-OS address name in the same scope."],
            )
            return None

        try:
            value_kwargs = self._parse_address_value(source_type, source_value)
            if value_kwargs.get("address_family") == "ipv6":
                evidence["pan_address_family"] = "ipv6"
            ir_address = IRAddress(
                name=source_name,
                description=description,
                tags=tags,
                source_type=source_type,
                source_attributes=evidence,
                **value_kwargs,
            )
        except (ValueError, ValidationError) as error:
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=[f"Invalid PAN-OS {source_type} value: {error}"],
            )
            return None

        extraction.canonical_ir.addresses.append(ir_address)
        source_object = PANSourceObject(
            name=source_name,
            kind="address",
            domain="address",
            source_path=source_path,
            scope=scope,
            attributes=evidence,
            ir_object=ir_address,
        )
        if not self.resolver.register_object(source_object, "address"):
            extraction.canonical_ir.addresses.remove(ir_address)
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=["Duplicate PAN-OS address name in the same scope."],
            )
            return None

        residual_fields = list(unknown_fields)
        if unknown_tag_fields:
            residual_fields.append("tag")
        residual_fields.extend(empty_types)
        if residual_fields:
            record_partial(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=[f"Unrepresented PAN-OS address fields retained: {', '.join(residual_fields)}."],
            )
        else:
            record_normalized(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
            )
        return ir_address

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        # A parser instance may be reused; definitions from an earlier source
        # must never participate in current-scope reference resolution.
        self.resolver = PANResolver()
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
        
        # Pass 1: Objects
        devices = root.findall(".//devices/entry")
        for dev in devices:
            dev_name = dev.get("name") or "localhost.localdomain"
            dev_scope = PANScope(kind="device", name=dev_name)
            
            network_elem = dev.find("./network")
            if network_elem is not None:
                self._parse_network(extraction, ir, dev_scope, network_elem)

        shared_root = root.find(".//shared")
        if shared_root is not None:
            self._parse_objects(PANScope(kind="shared", name="shared"), shared_root, extraction)
            
        for vsys_entry in root.findall(".//vsys/entry"):
            vsys_name = vsys_entry.get("name") or "vsys1"
            self._parse_objects(PANScope(kind="vsys", name=vsys_name), vsys_entry, extraction)
            
        for dg_entry in root.findall(".//device-group/entry"):
            dg_name = dg_entry.get("name") or "dg1"
            self._parse_objects(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)

        if root.find(".//vsys/entry") is None and root.find(".//device-group/entry") is None and shared_root is None:
            self._parse_objects(PANScope(kind="vsys", name="vsys1"), root, extraction)
            
        # Build canonical names
        self.resolver.build_canonical_names()
        
        # Fix group members with canonical names
        for sk, types_dict in self.resolver._objects.items():
            scope = PANScope(kind=sk[0], name=sk[1])
            if "address-group" in types_dict:
                for obj in types_dict["address-group"].values():
                    if obj.ir_object:
                        obj.ir_object.members = [self.resolver.canonical_name_for(m, "address-reference", scope) or m for m in obj.ir_object.members]
            if "service" in types_dict:
                for obj in types_dict["service"].values():
                    if obj.kind == "service-group" and obj.ir_object:
                        obj.ir_object.members = [self.resolver.canonical_name_for(m, "service", scope) or m for m in obj.ir_object.members]

        # Pass 2: Rules
        if shared_root is not None:
            self._parse_rules(PANScope(kind="shared", name="shared"), shared_root, extraction)
            
        for vsys_entry in root.findall(".//vsys/entry"):
            vsys_name = vsys_entry.get("name") or "vsys1"
            self._parse_rules(PANScope(kind="vsys", name=vsys_name), vsys_entry, extraction)
            
        for dg_entry in root.findall(".//device-group/entry"):
            dg_name = dg_entry.get("name") or "dg1"
            self._parse_rules(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)

        if root.find(".//vsys/entry") is None and root.find(".//device-group/entry") is None and shared_root is None:
            self._parse_rules(PANScope(kind="vsys", name="vsys1"), root, extraction)

        # Interface Accounting
        for intf in ir.interfaces:
            # Interfaces are stored under "device" scopes
            source_obj = None
            for sk, types_dict in self.resolver._objects.items():
                if "interface" in types_dict and intf.name in types_dict["interface"]:
                    source_obj = types_dict["interface"][intf.name]
                    break
            
            if source_obj:
                # If there are unresolved PAN semantics, it would be marked PARTIALLY_NORMALIZED
                if "pan_ipv4_addresses" in source_obj.attributes and len(source_obj.attributes["pan_ipv4_addresses"]) > 1:
                    record_partial(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, notes=["Multiple IPv4 addresses on interface not canonicalized."])
                elif "pan_ipv6_addresses" in source_obj.attributes:
                    record_partial(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, notes=["IPv6 addresses on interface not canonicalized."])
                else:
                    record_normalized(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name)
        extraction.canonical_ir = ir
        return extraction

    def _parse_l3_interface_node(self, config_node: ET.Element, interface_name: str, interface_type: str, parent: Optional[str], scope: PANScope) -> tuple[IRInterface, dict]:
        """Parses a specific logical interface node and returns the IRInterface and source_attributes dict."""
        source_attrs = {}
        ip = None
        secondary_ips = []
        
        # IPv4
        all_ipv4 = []
        for ip_elem in config_node.findall("./ip/entry"):
            addr = ip_elem.get("name")
            if addr:
                all_ipv4.append(addr)
        if all_ipv4:
            source_attrs["pan_ipv4_addresses"] = all_ipv4
            ip = all_ipv4[0]
            # We don't populate secondary_ips to avoid fake semantics
        
        # IPv6
        all_ipv6 = []
        for ipv6_elem in config_node.findall("./ipv6/address/entry"):
            addr = ipv6_elem.get("name")
            if addr:
                # Can collect more attributes inside if present
                v6_attrs = {"address": addr}
                enable_elem = ipv6_elem.find("enable")
                if enable_elem is not None and enable_elem.text:
                    v6_attrs["enable"] = enable_elem.text.strip()
                all_ipv6.append(v6_attrs)
        if all_ipv6:
            source_attrs["pan_ipv6_addresses"] = all_ipv6

        # Description
        desc_elem = config_node.find("./comment")
        desc = desc_elem.text if desc_elem is not None else None
        
        # Management profile
        mgmt_elem = config_node.find("./interface-management-profile")
        mgmt_prof = mgmt_elem.text if mgmt_elem is not None else None
        
        # Explicit status
        status_kwargs = {}
        state_elem = config_node.find("./link-state")
        if state_elem is not None and state_elem.text:
            source_attrs["status_explicit"] = True
            status_kwargs["status"] = (state_elem.text.strip().lower() != "down")
        else:
            source_attrs["status_explicit"] = False
            
        # Addressing mode
        addr_mode = None
        if config_node.find("./dhcp-client") is not None:
            addr_mode = "dhcp-client"
        elif config_node.find("./pppoe") is not None:
            addr_mode = "pppoe"
        elif all_ipv4:
            addr_mode = "static"
            
        # VLAN tag
        vlanid = None
        tag_elem = config_node.find("./tag")
        if tag_elem is not None and tag_elem.text and tag_elem.text.isdigit():
            vlanid = int(tag_elem.text.strip())
            
        ir_intf = IRInterface(
            name=interface_name,
            ip=ip,
            description=desc,
            interface_type=interface_type,
            parent=parent,
            management_profile=mgmt_prof,
            addressing_mode=addr_mode,
            vlanid=vlanid,
            **status_kwargs
        )
        return ir_intf, source_attrs

    def _parse_network(self, extraction: ExtractionResult, ir: IRConfig, scope: PANScope, network_root: ET.Element):
        intfs_root = network_root.find("./interface")
        if intfs_root is None:
            return

        # Explicitly support physical and subinterfaces
        families = [
            ("ethernet", "./ethernet/entry", True),
            ("aggregate-ethernet", "./aggregate-ethernet/entry", True),
            ("loopback", "./loopback/units/entry", False),
            ("tunnel", "./tunnel/units/entry", False),
            ("vlan", "./vlan/units/entry", False)
        ]
        
        for family_type, path, has_layer3 in families:
            for i_entry in intfs_root.findall(path):
                i_name = i_entry.get("name")
                if not i_name: continue
                
                # For physical interfaces, we look at layer3
                # For logical interfaces, the entry itself is the node
                
                if has_layer3:
                    l3_node = i_entry.find("./layer3")
                    if l3_node is not None:
                        ir_intf, source_attrs = self._parse_l3_interface_node(l3_node, i_name, family_type, None, scope)
                        ir.interfaces.append(ir_intf)
                        self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']/layer3", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
                    
                    # Subinterfaces
                    for unit_entry in i_entry.findall("./layer3/units/entry"):
                        u_name = unit_entry.get("name")
                        if not u_name: continue
                        ir_intf, source_attrs = self._parse_l3_interface_node(unit_entry, u_name, f"{family_type}-subinterface", i_name, scope)
                        ir.interfaces.append(ir_intf)
                        self.resolver.register_object(PANSourceObject(name=u_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']/layer3/units/entry[@name='{u_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
                else:
                    ir_intf, source_attrs = self._parse_l3_interface_node(i_entry, i_name, family_type, None, scope)
                    ir.interfaces.append(ir_intf)
                    self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/units/entry[@name='{i_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
        
        # Additional parsing for loopback/tunnel/vlan directly under their types if some PAN-OS versions don't use 'units'
        for family_type in ["loopback", "tunnel", "vlan"]:
            for i_entry in intfs_root.findall(f"./{family_type}/entry"):
                i_name = i_entry.get("name")
                if not i_name: continue
                # if already parsed via units/entry, skip
                if any(i.name == i_name for i in ir.interfaces): continue
                
                ir_intf, source_attrs = self._parse_l3_interface_node(i_entry, i_name, family_type, None, scope)
                ir.interfaces.append(ir_intf)
                self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")

    def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        
        # 2. Zones
        for z_entry in search_root.findall("./zone/entry"):
            z_name = z_entry.get("name")
            if not z_name: continue
            
            intfs = []
            zone_type = None
            
            for n_type in ["layer3", "layer2", "virtual-wire", "tap", "tunnel"]:
                type_members = [m.text for m in z_entry.findall(f".//network/{n_type}/member") if m.text]
                if type_members:
                    zone_type = n_type
                    intfs.extend(type_members)
                    
            source_attrs = {}
            if zone_type:
                source_attrs["pan_zone_type"] = zone_type
                
            ir_zone = IRZone(name=z_name, interfaces=intfs)
            ir.zones.append(ir_zone)
            
            zone_issues = []
            
            for intf in intfs:
                existing = next((i for i in ir.interfaces if i.name == intf), None)
                if not existing:
                    zone_issues.append(f"Unresolved interface reference: {intf}")
                else:
                    if existing.zone is None:
                        existing.zone = z_name
                    elif existing.zone != z_name:
                        # Conflict: interface in multiple zones
                        zone_issues.append(f"Interface {intf} conflict: belongs to multiple zones ({existing.zone} and {z_name})")
                        
            if zone_issues:
                record_partial(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name, notes=zone_issues
                )
            else:
                record_normalized(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name
                )

        # 3. Addresses
        self._parse_addresses(scope, search_root, extraction)

        # 4. Address Groups
        for g_entry in search_root.findall("./address-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            existing_address = self.resolver.resolve_exact(g_name, "address", scope)
            existing_group = self.resolver.resolve_exact(g_name, "address-group", scope)
            if existing_address or existing_group:
                reason = (
                    "Address object and address group use the same name in the same scope."
                    if existing_address
                    else "Duplicate PAN-OS address-group name in the same scope."
                )
                record_parse_error(
                    extraction, domain="address_groups",
                    source_path=f"address-group/entry[@name='{g_name}']",
                    scope=scope, name=g_name,
                    notes=[reason],
                )
                continue
            desc_elem = g_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            members = [m.text for m in g_entry.findall(".//static/member") if m.text]
            dyn_filter_elem = g_entry.find(".//dynamic/filter")
            is_dynamic = dyn_filter_elem is not None
            dynamic_filter = dyn_filter_elem.text.strip() if is_dynamic and dyn_filter_elem.text else None
            ir_group = IRAddressGroup(
                name=g_name,
                members=members,
                description=desc,
                is_dynamic=is_dynamic,
                dynamic_filter=dynamic_filter
            )
            ir.address_groups.append(ir_group)
            self.resolver.register_object(PANSourceObject(name=g_name, kind='address-group', domain='address', source_path=f"address-group/entry[@name='{g_name}']", scope=scope, ir_object=ir_group), "address-group")

        # 5. Services
        for s_entry in search_root.findall("./service/entry"):
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
                ir_svc = IRService(name=s_name, ports=ports, description=desc)
                ir.services.append(ir_svc)
                self.resolver.register_object(PANSourceObject(name=s_name, kind='service', domain='service', source_path=f"service/entry[@name='{s_name}']", scope=scope, ir_object=ir_svc), "service")

        # 6. Service Groups
        for g_entry in search_root.findall("./service-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            members = [m.text for m in g_entry.findall(".//members/member") if m.text]
            ir_sgroup = IRServiceGroup(name=g_name, members=members)
            ir.service_groups.append(ir_sgroup)
            self.resolver.register_object(PANSourceObject(name=g_name, kind='service-group', domain='service', source_path=f"service-group/entry[@name='{g_name}']", scope=scope, ir_object=ir_sgroup), "service")

        # 6.5 Security Profile Groups
        for pg_entry in search_root.findall("./profile-group/entry"):
            pg_name = pg_entry.get("name")
            if not pg_name:
                continue
            v_members = [m.text for m in pg_entry.findall(".//virus/member") if m.text]
            vuln_members = [m.text for m in pg_entry.findall(".//vulnerability/member") if m.text]
            spy_members = [m.text for m in pg_entry.findall(".//spyware/member") if m.text]
            url_members = [m.text for m in pg_entry.findall(".//url-filtering/member") if m.text]
            fb_members = [m.text for m in pg_entry.findall(".//file-blocking/member") if m.text]
            wf_members = [m.text for m in pg_entry.findall(".//wildfire-analysis/member") if m.text]

            ir.security_profile_groups.append(IRSecurityProfileGroup(
                name=pg_name,
                antivirus=v_members[0] if v_members else None,
                vulnerability=vuln_members[0] if vuln_members else None,
                anti_spyware=spy_members[0] if spy_members else None,
                url_filtering=url_members[0] if url_members else None,
                file_blocking=fb_members[0] if fb_members else None,
                wildfire=wf_members[0] if wf_members else None
            ))

    def _parse_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir

        # 7. Security Policies
        rules_paths = ["./rulebase/security/rules/entry", "./pre-rulebase/security/rules/entry", "./post-rulebase/security/rules/entry"]
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
                    if s not in ("any",) and not self.resolver.resolve(s, "address-reference", scope):
                        missing_refs.append(s)
                for d in destinations:
                    if d not in ("any",) and not self.resolver.resolve(d, "address-reference", scope):
                        missing_refs.append(d)
                for svc in services:
                    if svc not in ("any", "application-default") and not self.resolver.resolve(svc, "service", scope):
                        missing_refs.append(svc)
                        
                sources = [self.resolver.canonical_name_for(s, "address-reference", scope) or s for s in sources]
                destinations = [self.resolver.canonical_name_for(d, "address-reference", scope) or d for d in destinations]
                services = [self.resolver.canonical_name_for(svc, "service", scope) or svc for svc in services]
                
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
        paths = ["./rulebase/nat/rules/entry", "./pre-rulebase/nat/rules/entry", "./post-rulebase/nat/rules/entry"]
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
                    nat_rule.translated_sources = [self.resolver.canonical_name_for(a, "address-reference", scope) or a for a in s_trans.translated_address]
                if d_trans and d_trans.translated_address:
                    nat_rule.translated_destinations = [self.resolver.canonical_name_for(d_trans.translated_address, "address-reference", scope) or d_trans.translated_address]
                    
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
