from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_identity_sources_and_access_roles_are_structured_and_withheld():
    result = extract_checkpoint_config(__import__("json").dumps({"responses": [
        {"command": "show-gateways-and-servers", "data": {"objects": [{"name": "gw", "identity-awareness": {"ad-query": {"enabled": True}}}]}},
        {"command": "show-access-roles", "data": {"objects": [{"uid": "role-1", "name": "Staff", "type": "access-role", "users": ["alice"], "user-groups": ["Employees"], "networks": ["inside"]}]}},
        {"command": "show-access-rulebase", "package": "P", "layer": "L", "data": {"rulebase": [{"uid": "r1", "rule-number": 1, "name": "identity", "source": ["role-1"], "destination": ["Any"], "service": ["Any"], "action": "Accept", "enabled": True}]}},
    ]}))
    ir = result.canonical_ir
    assert ir.checkpoint_identity_sources[0].source_type == "ad-query"
    assert ir.checkpoint_access_roles[0].user_groups == ["Employees"]
    assert not ir.policies
    access_item = next(item for item in result.inventory_items if item.source_id == "r1")
    assert "checkpoint-identity-condition" in access_item.notes
