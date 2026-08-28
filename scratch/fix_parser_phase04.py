import re

def fix_parser():
    with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Update _create_ir_address signature and register_object
    content = content.replace(
        'def _create_ir_address(self, ir: IRConfig, name: str, addr_type: AddressType, val: str, description: Optional[str] = None):',
        'def _create_ir_address(self, ir: IRConfig, name: str, addr_type: AddressType, val: str, description: Optional[str] = None, scope: Optional[PANScope] = None):'
    )
    content = content.replace(
        'self.resolver.register_object(PANSourceObject(name=name, kind=\'address\', original_value=val, domain=\'address\', source_path=f"address/entry[@name=\'{name}\']", scope=PANScope(kind=\'shared\', name=\'shared\')), "address")',
        'self.resolver.register_object(PANSourceObject(name=name, kind=\'address\', original_value=val, domain=\'address\', source_path=f"address/entry[@name=\'{name}\']", scope=scope), "address")'
    )
    
    # 2. Update address calls in _parse_objects (currently _parse_scope)
    content = content.replace(
        'self._create_ir_address(ir, a_name, a_type, val, desc)',
        'self._create_ir_address(ir, a_name, a_type, val, desc, scope)'
    )
    content = content.replace(
        'self._create_ir_address(ir, a_name, AddressType.RANGE, ip_range.text.strip(), desc)',
        'self._create_ir_address(ir, a_name, AddressType.RANGE, ip_range.text.strip(), desc, scope)'
    )
    content = content.replace(
        'self._create_ir_address(ir, a_name, AddressType.FQDN, fqdn.text.strip(), desc)',
        'self._create_ir_address(ir, a_name, AddressType.FQDN, fqdn.text.strip(), desc, scope)'
    )
    
    # 3. Add ir_object to register_object for groups and services
    content = content.replace(
        'ir.address_groups.append(IRAddressGroup(',
        'ir_group = IRAddressGroup('
    )
    content = content.replace(
        '        ))\\n        self.resolver.register_object(PANSourceObject(name=g_name, kind=\'address-group\', domain=\'address\', source_path=f"address-group/entry[@name=\'{g_name}\']", scope=scope), "address")',
        '        )\\n        ir.address_groups.append(ir_group)\\n        self.resolver.register_object(PANSourceObject(name=g_name, kind=\'address-group\', domain=\'address\', source_path=f"address-group/entry[@name=\'{g_name}\']", scope=scope, ir_object=ir_group), "address")'
    )
    
    content = content.replace(
        'ir.services.append(IRService(name=s_name, ports=ports, description=desc))',
        'ir_svc = IRService(name=s_name, ports=ports, description=desc)\\n                ir.services.append(ir_svc)'
    )
    content = content.replace(
        'self.resolver.register_object(PANSourceObject(name=s_name, kind=\'service\', domain=\'service\', source_path=f"service/entry[@name=\'{s_name}\']", scope=scope), "service")',
        'self.resolver.register_object(PANSourceObject(name=s_name, kind=\'service\', domain=\'service\', source_path=f"service/entry[@name=\'{s_name}\']", scope=scope, ir_object=ir_svc), "service")'
    )
    
    content = content.replace(
        'ir.service_groups.append(IRServiceGroup(name=g_name, members=members))',
        'ir_sgroup = IRServiceGroup(name=g_name, members=members)\\n            ir.service_groups.append(ir_sgroup)'
    )
    content = content.replace(
        'self.resolver.register_object(PANSourceObject(name=g_name, kind=\'service-group\', domain=\'service\', source_path=f"service-group/entry[@name=\'{g_name}\']", scope=scope), "service")',
        'self.resolver.register_object(PANSourceObject(name=g_name, kind=\'service-group\', domain=\'service\', source_path=f"service-group/entry[@name=\'{g_name}\']", scope=scope, ir_object=ir_sgroup), "service")'
    )
    
    # 4. Split _parse_scope into _parse_objects and _parse_rules
    content = content.replace(
        'def _parse_scope(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):',
        'def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):'
    )
    content = content.replace(
        '        # 7. Security Policies',
        '    def _parse_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):\\n        ir = extraction.canonical_ir\\n\\n        # 7. Security Policies'
    )
    
    # 5. Fix extract() two-pass logic
    extract_logic = """
        # Pass 1: Objects
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
            if "address" in types_dict:
                for obj in types_dict["address"].values():
                    if obj.kind == "address-group" and obj.ir_object:
                        obj.ir_object.members = [self.resolver.canonical_name_for(m, "address", scope) or m for m in obj.ir_object.members]
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
"""
    old_extract = """        shared_root = root.find(".//shared")
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
            self._parse_scope(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)"""
    
    content = content.replace(old_extract, extract_logic)
    
    # 6. Apply canonical naming to Policy and NAT rules
    
    old_pol = """                pol = IRPolicy(
                    name=p_name, from_zone=from_zones, to_zone=to_zones, source=sources, destination=destinations,"""
    new_pol = """                sources = [self.resolver.canonical_name_for(s, "address", scope) or s for s in sources]
                destinations = [self.resolver.canonical_name_for(d, "address", scope) or d for d in destinations]
                services = [self.resolver.canonical_name_for(svc, "service", scope) or svc for svc in services]
                
                pol = IRPolicy(
                    name=p_name, from_zone=from_zones, to_zone=to_zones, source=sources, destination=destinations,"""
    content = content.replace(old_pol, new_pol)
    
    old_nat_src = "nat_rule.translated_sources = s_trans.translated_address"
    new_nat_src = 'nat_rule.translated_sources = [self.resolver.canonical_name_for(a, "address", scope) or a for a in s_trans.translated_address]'
    content = content.replace(old_nat_src, new_nat_src)
    
    old_nat_dst = "nat_rule.translated_destinations = [d_trans.translated_address]"
    new_nat_dst = 'nat_rule.translated_destinations = [self.resolver.canonical_name_for(d_trans.translated_address, "address", scope) or d_trans.translated_address]'
    content = content.replace(old_nat_dst, new_nat_dst)
    
    with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
        f.write(content)
        
if __name__ == "__main__":
    fix_parser()
