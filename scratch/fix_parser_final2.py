import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Find "    def parse("
parse_idx = content.find("    def parse(")

if parse_idx != -1:
    # 2. Extract everything before parse
    extract_body = content[:parse_idx]
    
    # 3. Clean up any trailing spaces or newlines before "def parse"
    extract_body = extract_body.rstrip()
    
    # 4. Remove any duplicate extraction.canonical_ir = ir at the end of extract_body
    if extract_body.endswith("return extraction"):
        extract_body = extract_body[:-17].rstrip()
    if extract_body.endswith("extraction.canonical_ir = ir"):
        extract_body = extract_body[:-28].rstrip()

    # 5. Add the routing and NAT logic
    routing_nat = """
        # 8. NAT Rules
        paths = ["./rulebase/nat/rules/entry", "./shared/pre-rulebase/nat/rules/entry", "./shared/post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in root.findall(path):
                n_name = n_entry.get("name")
                if not n_name: continue
                PANNatRuleExtractor.extract_nat_rule(n_entry, extraction, PANScope(kind="shared", name="shared"))

        # 9. Static Routes
        shared_scope = PANScope(kind="shared", name="shared")
        PANRouteExtractor.extract_static_routes(shared_scope, root, extraction)
        
        extraction.canonical_ir = ir
        return extraction
"""
    extract_body += "\n" + routing_nat + "\n\n"
    
    # 6. Re-add the parse method
    final_content = extract_body + "    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:\n        return self.extract(content, zone_mapping).canonical_ir\n"

    with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
        f.write(final_content)
    print("Fixed parser.py")
else:
    print("Could not find parse method")
