import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# Add import
import_stmt = "from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation\n"
if "PANNatRuleExtractor" not in content:
    content = content.replace("from .source_model import PANScope, PANSourceObject", "from .source_model import PANScope, PANSourceObject\n" + import_stmt)

# New _parse_nat_rules
new_nat_rules = '''    def _parse_nat_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        paths = ["./rulebase/nat/rules/entry"] if scope.kind == "vsys" else ["./shared/pre-rulebase/nat/rules/entry", "./shared/post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in search_root.findall(path):
                n_name = n_entry.get("name")
                if not n_name:
                    continue

                from_z = [m.text for m in n_entry.findall("./from/member") if m.text]
                to_z = [m.text for m in n_entry.findall("./to/member") if m.text]
                src = [m.text for m in n_entry.findall("./source/member") if m.text]
                dst = [m.text for m in n_entry.findall("./destination/member") if m.text]
                srv = [m.text for m in n_entry.findall("./service/member") if m.text]

                snat_elem = n_entry.find("./source-translation")
                dnat_elem = n_entry.find("./destination-translation")
                dyn_dnat_elem = n_entry.find("./dynamic-destination-translation")
                
                s_trans = PANNatRuleExtractor.extract_source_translation(snat_elem)
                d_trans = PANNatRuleExtractor.extract_destination_translation(dnat_elem)
                dyn_d_trans = PANNatRuleExtractor.extract_dynamic_destination_translation(dyn_dnat_elem)

                # Determine state
                if dyn_d_trans is not None:
                    # PAN-OS dynamic destination translation
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="nat_rules",
                        source_path=f"nat/rules/entry[@name='{n_name}']",
                        name=n_name,
                        status=ExtractionStatus.UNSUPPORTED,
                        requires_manual_review=True,
                        notes=["Dynamic destination translation is not supported."]
                    ))
                    continue

                nat_type = NATType.SOURCE
                if snat_elem is not None and dnat_elem is not None:
                    nat_type = NATType.TWICE
                elif dnat_elem is not None:
                    nat_type = NATType.DESTINATION
                
                trans_srcs = s_trans.translated_address if s_trans else []
                trans_dsts = [d_trans.translated_address] if (d_trans and d_trans.translated_address) else []
                trans_port = d_trans.translated_port if d_trans else None
                
                # Check for "interface" trans src
                trans_src = None
                trans_srcs_list = []
                if s_trans:
                    if s_trans.method == "dynamic-ip-and-port" and s_trans.interface_address:
                        trans_srcs_list = [s_trans.interface_address]
                        extraction.inventory_items.append(SourceInventoryItem(
                            domain="nat_rules",
                            source_path=f"nat/rules/entry[@name='{n_name}']",
                            name=n_name,
                            status=ExtractionStatus.PARTIALLY_NORMALIZED,
                            requires_manual_review=True,
                            notes=["Interface NAT fallback was mapped to the interface IP. Target generator may not fully support interface NAT semantics."]
                        ))
                    elif s_trans.translated_address:
                        trans_srcs_list = s_trans.translated_address

                if snat_elem is None and dnat_elem is None:
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain="nat_rules",
                        source_path=f"nat/rules/entry[@name='{n_name}']",
                        name=n_name,
                        status=ExtractionStatus.EXTRACT_ONLY,
                        requires_manual_review=True,
                        notes=["NAT rule has no source or destination translation configured."]
                    ))
                    # DO NOT CREATE IRNATRule FOR NO-NAT! (Wait, "NAT rules without SNAT/DNAT are not errors—preserve and classify them.")
                    # Yes, we preserve them in ExtractionResult as EXTRACT_ONLY, and do not create IRNATRule.
                    continue

                ir.nat_rules.append(IRNATRule(
                    name=n_name,
                    type=nat_type,
                    from_zone=from_z or [],
                    to_zone=to_z or [],
                    source=src or [],
                    destination=dst or [],
                    services=srv or [],
                    translated_sources=trans_srcs_list,
                    translated_destinations=trans_dsts,
                    translated_port=trans_port
                ))'''

content = re.sub(r'    def _parse_nat_rules\(self, scope: PANScope, search_root: ET\.Element, extraction: ExtractionResult\):.*?    def _parse_routes', new_nat_rules + "\n\n    def _parse_routes", content, flags=re.DOTALL)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Patched NAT rewrite")
