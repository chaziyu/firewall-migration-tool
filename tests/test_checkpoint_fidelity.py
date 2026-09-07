import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def _bundle(responses, **root):
    payload = {"format": "checkpoint-export-v1", "responses": responses}
    payload.update(root)
    return json.dumps(payload)


def test_nat_origin_identity_order_and_automatic_object_relationships_are_preserved():
    result = extract_checkpoint_config(_bundle([
        {"command": "show-gateways-and-servers", "domain": "D", "data": {"objects": [
            {"uid": "gw1", "name": "GW", "type": "simple-gateway", "interfaces": []},
        ]}},
        {"command": "show-networks", "domain": "D", "data": {"objects": [
            {
                "uid": "auto-net", "name": "AutoNet", "type": "network",
                "subnet4": "10.0.0.0", "mask-length4": 24,
                "nat-settings": {
                    "auto-rule": True, "method": "hide", "hide-behind": "gateway",
                    "install-on": ["gw1"], "proxy-arp": False,
                },
            },
        ]}},
        {"command": "show-hosts", "domain": "D", "data": {"objects": [
            {"uid": "public", "name": "Public", "type": "host", "ipv4-address": "198.51.100.10"},
            {"uid": "private", "name": "Private", "type": "host", "ipv4-address": "10.0.0.10"},
        ]}},
        {
            "command": "show-nat-rulebase", "domain": "D", "package": "Standard",
            "from": 1, "to": 3, "total": 3,
            "data": {"rulebase": [
                {"type": "nat-section", "name": "Automatic Generated Rules", "rulebase": [
                    {"type": "nat-section", "name": "NAT Rules for AutoNet (1-2)", "rulebase": [
                        {
                            "uid": "nat-identity", "rule-number": 1, "name": "AutoNet_NoNAT",
                            "type": "nat-rule", "original-source": "auto-net",
                            "original-destination": "auto-net", "original-service": "Any",
                            "translated-source": "Original", "translated-destination": "Original",
                            "translated-service": "Original", "install-on": ["gw1"], "enabled": True,
                        },
                        {
                            "uid": "nat-auto-hide", "rule-number": 2, "name": "AutoNet_Hide",
                            "type": "nat-rule", "original-source": "auto-net",
                            "original-destination": "Any", "original-service": "Any",
                            "translated-source": "Any", "translated-destination": "Original",
                            "translated-service": "Original", "method": "hide",
                            "hide-behind": "gateway", "install-on": ["gw1"], "enabled": True,
                        },
                    ]},
                ]},
                {"type": "nat-section", "name": "Manual Lower Rules", "rulebase": [
                    {
                        "uid": "nat-manual", "rule-number": 3, "name": "Manual_DNAT",
                        "type": "nat-rule", "original-source": "Any",
                        "original-destination": "public", "original-service": "Any",
                        "translated-source": "Original", "translated-destination": "private",
                        "translated-service": "Original", "install-on": ["gw1"], "enabled": True,
                    },
                ]},
            ]},
        },
    ], domain="D", gateway="GW", selected_domain="D", selected_package="Standard", selected_gateway="GW"))

    automatic_object = next(item for item in result.inventory_items if item.source_id == "auto-net")
    auto_nat = automatic_object.source_attributes["checkpoint-automatic-nat"]
    assert auto_nat["automatic_nat_enabled"] is True
    assert auto_nat["method"] == "hide"
    assert auto_nat["hide_behind_gateway"] is True
    assert auto_nat["install_on"] == ["gw1"]
    assert auto_nat["proxy_arp"] is False

    identity = next(item for item in result.inventory_items if item.source_id == "nat-identity")
    assert identity.source_attributes["checkpoint-nat-origin"] == "automatic"
    assert identity.source_attributes["checkpoint-nat-semantic"] == "identity"
    assert identity.source_attributes["checkpoint-ordering-barrier"] is True
    assert identity.source_attributes["checkpoint-enforcement-mode"] == "automatic-combinable"

    auto_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "AutoNet_Hide")
    assert auto_rule.source_origin == "automatic"
    assert auto_rule.source_context == "D/Standard"
    assert auto_rule.source_attributes["checkpoint-rule-uid"] == "nat-auto-hide"
    assert auto_rule.source_attributes["checkpoint-install-on"] == ["gw1"]
    assert auto_rule.source_attributes["checkpoint-automatic-nat-object-refs"] == ["auto-net"]
    assert auto_rule.source_attributes["checkpoint-preceding-identity-rules"] == [
        {"uid": "nat-identity", "name": "AutoNet_NoNAT", "sequence": 1}
    ]
    assert auto_rule.requires_manual_review is True
    assert "checkpoint-identity-nat-precedence" in auto_rule.review_reasons

    manual_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.name == "Manual_DNAT")
    assert manual_rule.source_origin == "manual"
    assert manual_rule.source_attributes["checkpoint-enforcement-mode"] == "manual-first-match"
    assert result.generation_safe is False
    assert "checkpoint-identity-nat-ordering-requires-manual-review" in result.blocking_reasons


def test_policy_package_retains_ordered_and_inline_layer_relationships():
    result = extract_checkpoint_config(_bundle([
        {"command": "show-packages", "domain": "D", "data": {"objects": [
            {"uid": "pkg", "name": "Standard", "access-layers": [
                {"uid": "ordered-b", "name": "Ordered B"},
                {"uid": "ordered-a", "name": "Ordered A"},
                {"uid": "child", "name": "Child"},
            ], "installation-targets": ["gw1"]},
        ]}},
        {"command": "show-access-layers", "domain": "D", "data": {"objects": [
            {"uid": "ordered-b", "name": "Ordered B"},
            {"uid": "ordered-a", "name": "Ordered A"},
            {"uid": "child", "name": "Child"},
        ]}},
        {
            "command": "show-access-rulebase", "domain": "D", "package": "Standard",
            "package_uid": "pkg", "layer": "Ordered B", "layer_uid": "ordered-b",
            "data": {"rulebase": [{
                "uid": "parent-rule", "rule-number": 10, "name": "Parent",
                "type": "access-rule", "inline-layer": {"uid": "child", "name": "Child"},
            }]},
        },
        {
            "command": "show-access-rulebase", "domain": "D", "package": "Standard",
            "package_uid": "pkg", "layer": "Ordered A", "layer_uid": "ordered-a",
            "data": {"rulebase": []},
        },
        {
            "command": "show-access-rulebase", "domain": "D", "package": "Standard",
            "package_uid": "pkg", "layer": "Child", "layer_uid": "child",
            "parent_layer": "Ordered B", "parent_layer_uid": "ordered-b",
            "parent_rule_uid": "parent-rule", "data": {"rulebase": []},
        },
    ], domain="D", selected_domain="D", selected_package="Standard"))

    package = next(item for item in result.canonical_ir.checkpoint_policy_packages if item.uid == "pkg")
    order = package.source_attributes["checkpoint-access-layer-order"]
    assert [entry["uid"] for entry in order] == ["ordered-b", "ordered-a", "child"]
    assert [entry["position"] for entry in order] == [1, 2, 3]

    child = next(item for item in result.canonical_ir.checkpoint_access_layers if item.uid == "child")
    assert child.inline is True
    assert child.parent_layer_uid == "ordered-b"
    assert child.parent_rule_uid == "parent-rule"
    assert package.source_attributes["checkpoint-inline-layers"] == [{
        "uid": "child",
        "name": "Child",
        "parent_layer_uid": "ordered-b",
        "parent_layer_name": "Ordered B",
        "parent_rule_uid": "parent-rule",
        "parent_rule_number": 10,
        "rule_uids": [],
    }]

    ordered_b = next(item for item in result.canonical_ir.checkpoint_access_layers if item.uid == "ordered-b")
    assert ordered_b.source_attributes["checkpoint-ordered-layer-position"] == 1
    assert ordered_b.source_attributes["checkpoint-package-uid"] == "pkg"

    package_inventory = next(
        item for item in result.inventory_items
        if item.source_path == "checkpoint/show-packages" and item.source_id == "pkg"
    )
    assert package_inventory.source_attributes["checkpoint-access-layer-order"] == order
