import json

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source
from fwmigrate.vendors.cisco_asa.web_report import build_asa_preview


def test_preview_separates_source_relationship_and_derived_and_redacts_secrets():
    secret = "ASA_PREVIEW_SECRET_SENTINEL"
    result = extract_cisco_asa_source(
        "hostname asa\n"
        "interface Ethernet0/0\n nameif outside\n"
        "object network WEB\n host 192.0.2.10\n"
        "access-list OUT extended permit ip any any\n"
        "access-group OUT in interface outside\n"
        "nat (inside,outside) source static WEB interface\n"
        f"username admin password 0 {secret}\n"
    )
    preview = build_asa_preview(result)
    assert "interfaces" in preview["source"]
    assert "addresses" in preview["source"]
    assert "acl" in preview["relationships"]
    assert "nat" in preview["derived"]
    assert "inventory" in preview and "unsupported" in preview and "coverage" in preview
    assert preview["summary"]["objects"]["policies"] == len(result.config.access_rules)
    assert preview["summary"]["scopes"] == ["root"]
    assert {"interfaces", "addresses", "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2",
            "validation", "unresolved_references"} <= set(preview["sections"])
    acl_row = preview["sections"]["policies"][0]
    assert acl_row["acl_name"] == "OUT" and acl_row["interface"] == "outside"
    assert acl_row["source_order"] is not None
    assert secret not in json.dumps(preview)
