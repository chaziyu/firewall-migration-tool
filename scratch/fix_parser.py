import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# Fix policy action
content = content.replace('act_text = act_elem.text.strip().lower() if act_elem is not None and act_elem.text else "allow"',
                          'act_text = act_elem.text.strip().lower() if act_elem is not None and act_elem.text else None')

content = content.replace('action = PolicyAction.DENY if act_text in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else PolicyAction.ALLOW',
                          'action = PolicyAction.DENY if act_text in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else (PolicyAction.ALLOW if act_text else None)')

# Fix policy broadening
content = content.replace('from_zone=from_zones or ["any"]', 'from_zone=from_zones or []')
content = content.replace('to_zone=to_zones or ["any"]', 'to_zone=to_zones or []')
content = content.replace('source=sources or ["any"]', 'source=sources or []')
content = content.replace('destination=destinations or ["any"]', 'destination=destinations or []')
content = content.replace('applications=applications or ["any"]', 'applications=applications or []')
content = content.replace('service=services or ["any"]', 'service=services or []')

# Remove the old NAT Rules and Static Routes which start from "# 8. NAT Rules" until "extraction.canonical_ir = ir"
start_idx = content.find("        # 8. NAT Rules")
end_idx = content.find("        extraction.canonical_ir = ir")
if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + content[end_idx:]

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Parser fixed.")
