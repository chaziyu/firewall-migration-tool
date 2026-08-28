import re
with open("src/fwmigrate/parsers/palo_alto/parser.py", "r") as f:
    content = f.read()

# 1. Register Addresses
addr_repl = '''                if ip_netmask is not None and ip_netmask.text:
                    val = ip_netmask.text.strip()
                    if val.endswith("/32") or "/128" in val:
                        a_type = AddressType.HOST
                    else:
                        a_type = AddressType.NETWORK if "/" in val else AddressType.HOST
                    self._create_ir_address(ir, a_name, a_type, val, desc)
                    self.resolver.register_object(PANSourceObject(name=a_name, scope=scope), "address")
                elif ip_range is not None and ip_range.text:
                    self._create_ir_address(ir, a_name, AddressType.RANGE, ip_range.text.strip(), desc)
                    self.resolver.register_object(PANSourceObject(name=a_name, scope=scope), "address")
                elif fqdn is not None and fqdn.text:
                    self._create_ir_address(ir, a_name, AddressType.FQDN, fqdn.text.strip(), desc)
                    self.resolver.register_object(PANSourceObject(name=a_name, scope=scope), "address")'''

content = re.sub(r'                if ip_netmask is not None.*?(?=                elif fqdn is not None and fqdn\.text:\n                    self\._create_ir_address.*?desc\))                elif fqdn is not None and fqdn\.text:\n                    self\._create_ir_address.*?desc\)', addr_repl, content, flags=re.DOTALL)

# 2. Register Address Groups
ag_repl = '''                ir.address_groups.append(IRAddressGroup(
                    name=g_name,
                    members=members,
                    description=desc
                ))
                self.resolver.register_object(PANSourceObject(name=g_name, scope=scope), "address")'''
content = content.replace('''                ir.address_groups.append(IRAddressGroup(
                    name=g_name,
                    members=members,
                    description=desc
                ))''', ag_repl)

# 3. Register Services
svc_repl = '''                if ports:
                    ir.services.append(IRService(name=s_name, ports=ports, description=desc))
                    self.resolver.register_object(PANSourceObject(name=s_name, scope=scope), "service")'''
content = content.replace('''                if ports:
                    ir.services.append(IRService(name=s_name, ports=ports, description=desc))''', svc_repl)

# 4. Register Service Groups
sg_repl = '''                ir.service_groups.append(IRServiceGroup(name=sg_name, members=members))
                self.resolver.register_object(PANSourceObject(name=sg_name, scope=scope), "service")'''
content = content.replace('''                ir.service_groups.append(IRServiceGroup(name=sg_name, members=members))''', sg_repl)

# 5. Resolve references in policies
pol_repl = '''
                # Resolve references
                resolved_sources = []
                for s in sources:
                    if s.lower() == "any" or s.lower() == "all":
                        resolved_sources.append(s)
                    elif self.resolver.resolve(s, "address", scope):
                        resolved_sources.append(s)
                    else:
                        extraction.inventory_items.append(SourceInventoryItem(
                            domain="policies",
                            source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                            name=p_name,
                            status=ExtractionStatus.EXTRACT_ONLY,
                            requires_manual_review=True,
                            notes=[f"Dropped unresolvable source address: {s}"]
                        ))

                resolved_destinations = []
                for d in destinations:
                    if d.lower() == "any" or d.lower() == "all":
                        resolved_destinations.append(d)
                    elif self.resolver.resolve(d, "address", scope):
                        resolved_destinations.append(d)
                    else:
                        extraction.inventory_items.append(SourceInventoryItem(
                            domain="policies",
                            source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                            name=p_name,
                            status=ExtractionStatus.EXTRACT_ONLY,
                            requires_manual_review=True,
                            notes=[f"Dropped unresolvable destination address: {d}"]
                        ))

                resolved_services = []
                for s in services:
                    if s.lower() in ["any", "all", "application-default"]:
                        resolved_services.append(s)
                    elif self.resolver.resolve(s, "service", scope):
                        resolved_services.append(s)
                    else:
                        extraction.inventory_items.append(SourceInventoryItem(
                            domain="policies",
                            source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                            name=p_name,
                            status=ExtractionStatus.EXTRACT_ONLY,
                            requires_manual_review=True,
                            notes=[f"Dropped unresolvable service: {s}"]
                        ))

                # Safety check
                if action is None or not resolved_sources or not resolved_destinations or not resolved_services:
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="policies",
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                        name=p_name,
                        status=ExtractionStatus.PARTIALLY_NORMALIZED,
                        requires_manual_review=True,
                        notes=["Policy missing required action or all sources/destinations/services were dropped."]
                    ))
                    continue

                ir.policies.append(IRPolicy(
                    name=p_name,
                    from_zone=from_zones or [],
                    to_zone=to_zones or [],
                    source=resolved_sources,
                    destination=resolved_destinations,
                    applications=applications or [],
                    service=resolved_services,
'''
content = re.sub(r'\n\s*# Safety check\n\s*if action is None or not sources or not destinations or not services:.*?\n\s*service=services or \[\],\n', pol_repl, content, flags=re.DOTALL)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w") as f:
    f.write(content)

print("Patched parser.py")
