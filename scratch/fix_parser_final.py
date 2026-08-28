import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix the policy required fields check
content = content.replace("            if not from_zones or not to_zones or not sources or not destinations or not applications or not services:",
                          "            if not from_zones or not to_zones or not sources or not destinations:")

# Insert the routing and NAT calls before "extraction.canonical_ir = ir"
target = "        extraction.canonical_ir = ir"
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
"""
if "PANRouteExtractor.extract_static_routes" not in content:
    content = content.replace(target, routing_nat + "\n" + target)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Parser final fixed.")
