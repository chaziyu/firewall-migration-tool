import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# We want to fix the `extract` method and `_parse_scope` method.

start_idx = content.find("        # Find all scopes: shared, vsys, device-group")
end_idx = content.find("    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:")

if start_idx == -1 or end_idx == -1:
    print("Could not find start or end index")
    exit(1)

new_code = """        # Find all scopes: shared, vsys, device-group
        
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
                self._create_ir_address(ir, a_name, a_type, val, desc)
            elif ip_range is not None and ip_range.text:
                self._create_ir_address(ir, a_name, AddressType.RANGE, ip_range.text.strip(), desc)
            elif fqdn is not None and fqdn.text:
                self._create_ir_address(ir, a_name, AddressType.FQDN, fqdn.text.strip(), desc)

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

        # 6. Service Groups
        for g_entry in search_root.findall(".//service-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            members = [m.text for m in g_entry.findall(".//members/member") if m.text]
            ir.service_groups.append(IRServiceGroup(name=g_name, members=members))

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
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="policies", source_path=f"rulebase/security/rules/entry[@name='{p_name}']", name=p_name,
                        status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True, notes=["Missing required action"]
                    ))
                    continue

                if not from_zones or not to_zones or not sources or not destinations:
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="policies", source_path=f"rulebase/security/rules/entry[@name='{p_name}']", name=p_name,
                        status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True, notes=["Missing required fields"]
                    ))
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

                ir.policies.append(IRPolicy(
                    name=p_name, from_zone=from_zones, to_zone=to_zones, source=sources, destination=destinations,
                    applications=applications, service=services, action=action, description=desc, disabled=disabled,
                    schedule=sched, log_end=log_end, log_start=log_start, security_profile_group=spg_name
                ))

        # 8. NAT Rules
        paths = ["./rulebase/nat/rules/entry", "./pre-rulebase/nat/rules/entry", "./post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in search_root.findall(path):
                n_name = n_entry.get("name")
                if not n_name: continue
                # Basic mapping for now
                from_z = [m.text for m in n_entry.findall("./from/member") if m.text]
                to_z = [m.text for m in n_entry.findall("./to/member") if m.text]
                src = [m.text for m in n_entry.findall("./source/member") if m.text]
                dst = [m.text for m in n_entry.findall("./destination/member") if m.text]
                srv = [m.text for m in n_entry.findall("./service/member") if m.text]
                ir.nat_rules.append(IRNATRule(name=n_name, type=NATType.SOURCE, from_zone=from_z, to_zone=to_z, source=src, destination=dst, services=srv))

        # 9. Static Routes
        PANRouteExtractor.extract_static_routes(scope, search_root, extraction)

"""

content = content[:start_idx] + new_code + content[end_idx:]

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Updated parser to use _parse_scope")
