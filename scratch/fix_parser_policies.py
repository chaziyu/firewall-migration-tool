import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# I will replace the entire # 7. Security Policies block in parser.py

start_marker = "        # 7. Security Policies"
end_marker = "        extraction.canonical_ir = ir"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

new_policies_logic = """        # 7. Security Policies
        for p_entry in root.findall(".//rulebase/security/rules/entry"):
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

            if not from_zones or not to_zones or not sources or not destinations or not applications or not services:
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

"""
content = content[:start_idx] + new_policies_logic + content[end_idx:]

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Updated policies logic")
