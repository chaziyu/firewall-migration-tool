import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.model import FGPolicyRoute
from fwmigrate.ir.core import IRFortiGatePolicyRoute


def _source_attributes(result):
    assert len(result.canonical_ir.policy_routes) == 1
    return result.canonical_ir.policy_routes[0].source_attributes


def test_ipv4_policy_route_preserves_all_multi_value_fields_as_ordered_lists():
    result = extract_fortigate_config(
        """config router policy
    edit 10
        set input-device "port1" "port2"
        set src "10.10.0.0/16" "10.20.0.0/16"
        set srcaddr "SRC-GROUP-1" "SRC-GROUP-2"
        set dst "0.0.0.0/0" "192.0.2.0/24"
        set dstaddr "DST-GROUP-1" "DST-GROUP-2"
        set internet-service-custom "CUSTOM-IS-1" "CUSTOM-IS-2"
        set internet-service-id 65646 65647
        set protocol 6
        set start-port 443
        set end-port 443
        set gateway 192.0.2.1
        set output-device "wan1"
    next
end
"""
    )

    rule = result.canonical_ir.policy_routes[0]
    assert isinstance(rule, IRFortiGatePolicyRoute)
    assert rule.family == "policy-route-ipv4"
    assert rule.source_id == "10"
    assert rule.address_family == "ipv4"
    assert rule.input_devices == ["port1", "port2"]
    assert rule.source_networks == ["10.10.0.0/16", "10.20.0.0/16"]
    assert rule.source_addresses == ["SRC-GROUP-1", "SRC-GROUP-2"]
    assert rule.destination_networks == ["0.0.0.0/0", "192.0.2.0/24"]
    assert rule.destination_addresses == ["DST-GROUP-1", "DST-GROUP-2"]
    assert rule.internet_service_custom == ["CUSTOM-IS-1", "CUSTOM-IS-2"]
    assert rule.internet_service_ids == [65646, 65647]
    assert rule.protocol == 6
    assert rule.destination_port_start == 443
    assert rule.destination_port_end == 443
    assert rule.gateway == "192.0.2.1"
    assert rule.output_device == "wan1"
    assert rule.source_attributes == {
        "input_device": ["port1", "port2"],
        "src": ["10.10.0.0/16", "10.20.0.0/16"],
        "srcaddr": ["SRC-GROUP-1", "SRC-GROUP-2"],
        "dst": ["0.0.0.0/0", "192.0.2.0/24"],
        "dstaddr": ["DST-GROUP-1", "DST-GROUP-2"],
        "internet_service_custom": ["CUSTOM-IS-1", "CUSTOM-IS-2"],
        "internet_service_id": ["65646", "65647"],
        "protocol": "6",
        "start_port": "443",
        "end_port": "443",
        "gateway": "192.0.2.1",
        "output_device": "wan1",
    }
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == "router policy" and item.source_id == "10"
    )
    assert item.requires_manual_review is True
    assert next(command for command in item.commands if command.key == "input-device").values == [
        "port1",
        "port2",
    ]
    assert next(command for command in item.commands if command.key == "src").values == [
        "10.10.0.0/16",
        "10.20.0.0/16",
    ]


def test_ipv6_policy_route_preserves_all_multi_value_fields_as_ordered_lists():
    result = extract_fortigate_config(
        """config router policy6
    edit 20
        set input-device "port3" "port4"
        set src "2001:db8:10::/64" "2001:db8:20::/64"
        set srcaddr "SRC6-GROUP-1" "SRC6-GROUP-2"
        set dst "2001:db8:100::/64" "2001:db8:200::/64"
        set dstaddr "DST6-GROUP-1" "DST6-GROUP-2"
        set internet-service-custom "CUSTOM6-IS-1" "CUSTOM6-IS-2"
        set internet-service-id 70001 70002
        set protocol 6
        set start-port 443
        set end-port 443
        set gateway 2001:db8::1
        set output-device "wan2"
    next
end
"""
    )

    attributes = _source_attributes(result)
    rule = result.canonical_ir.policy_routes[0]
    assert isinstance(rule, IRFortiGatePolicyRoute)
    assert rule.family == "policy-route-ipv6"
    assert rule.address_family == "ipv6"
    assert rule.input_devices == ["port3", "port4"]
    assert rule.source_networks == ["2001:db8:10::/64", "2001:db8:20::/64"]
    assert rule.destination_networks == ["2001:db8:100::/64", "2001:db8:200::/64"]
    assert rule.internet_service_ids == [70001, 70002]
    assert attributes["input_device"] == ["port3", "port4"]
    assert attributes["src"] == ["2001:db8:10::/64", "2001:db8:20::/64"]
    assert attributes["srcaddr"] == ["SRC6-GROUP-1", "SRC6-GROUP-2"]
    assert attributes["dst"] == ["2001:db8:100::/64", "2001:db8:200::/64"]
    assert attributes["dstaddr"] == ["DST6-GROUP-1", "DST6-GROUP-2"]
    assert attributes["internet_service_custom"] == [
        "CUSTOM6-IS-1",
        "CUSTOM6-IS-2",
    ]
    assert attributes["internet_service_id"] == ["70001", "70002"]
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert result.generation_safe is False


def test_single_value_policy_route_list_fields_remain_one_element_lists():
    result = extract_fortigate_config(
        """config router policy
    edit 30
        set input-device "port1"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set internet-service-custom "CUSTOM-IS-1"
        set internet-service-id 65646
    next
end
"""
    )

    attributes = _source_attributes(result)
    assert attributes["input_device"] == ["port1"]
    assert attributes["src"] == ["10.0.0.0/24"]
    assert attributes["dst"] == ["0.0.0.0/0"]
    assert attributes["internet_service_custom"] == ["CUSTOM-IS-1"]
    assert attributes["internet_service_id"] == ["65646"]


def test_policy_route_list_field_order_is_preserved():
    result = extract_fortigate_config(
        """config router policy
    edit 40
        set input-device "port3" "port1" "port2"
        set src "10.30.0.0/24" "10.10.0.0/24" "10.20.0.0/24"
        set dst "203.0.113.0/24" "198.51.100.0/24"
    next
end
"""
    )

    attributes = _source_attributes(result)
    assert attributes["input_device"] == ["port3", "port1", "port2"]
    assert attributes["src"] == [
        "10.30.0.0/24",
        "10.10.0.0/24",
        "10.20.0.0/24",
    ]
    assert attributes["dst"] == ["203.0.113.0/24", "198.51.100.0/24"]


@pytest.mark.parametrize(
    ("section", "family", "rule_id", "input_device", "src", "dst", "gateway", "output_device"),
    [
        (
            "router policy",
            "policy-route-ipv4",
            101,
            "lan",
            "10.0.0.0/24",
            "0.0.0.0/0",
            "192.0.2.1",
            "wan",
        ),
        (
            "router policy6",
            "policy-route-ipv6",
            102,
            "lan6",
            "2001:db8:10::/64",
            "::/0",
            "2001:db8::1",
            "wan6",
        ),
    ],
)
def test_policy_route_omitted_status_defaults_enabled_without_source_synthesis(
    section,
    family,
    rule_id,
    input_device,
    src,
    dst,
    gateway,
    output_device,
):
    result = extract_fortigate_config(
        f'''config {section}
    edit {rule_id}
        set input-device "{input_device}"
        set src "{src}"
        set dst "{dst}"
        set gateway {gateway}
        set output-device "{output_device}"
    next
end
'''
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.family == family
    assert rule.enabled is True
    assert "status" not in rule.source_attributes
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == section and item.source_id == str(rule_id)
    )
    assert all(command.key != "status" for command in item.commands)


@pytest.mark.parametrize(
    ("section", "family", "src", "dst", "gateway", "input_device", "output_device"),
    [
        (
            "router policy",
            "policy-route-ipv4",
            "10.0.0.0/24",
            "0.0.0.0/0",
            "192.0.2.1",
            "lan",
            "wan",
        ),
        (
            "router policy6",
            "policy-route-ipv6",
            "2001:db8:10::/64",
            "::/0",
            "2001:db8::1",
            "lan6",
            "wan6",
        ),
    ],
)
@pytest.mark.parametrize("status, expected_enabled", [("enable", True), ("disable", False)])
def test_policy_route_explicit_status_overrides_family_default(
    section,
    family,
    src,
    dst,
    gateway,
    input_device,
    output_device,
    status,
    expected_enabled,
):
    result = extract_fortigate_config(
        f'''config {section}
    edit 103
        set status {status}
        set input-device "{input_device}"
        set src "{src}"
        set dst "{dst}"
        set gateway {gateway}
        set output-device "{output_device}"
    next
end
'''
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.family == family
    assert rule.enabled is expected_enabled
    assert rule.source_attributes["status"] == status
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == section and item.source_id == "103"
    )
    status_command = next(command for command in item.commands if command.key == "status")
    assert status_command.values == [status]


def test_policy_route_unknown_status_does_not_become_enabled():
    result = extract_fortigate_config(
        """config router policy
    edit 104
        set status unexpected
        set input-device "lan"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set gateway 192.0.2.1
        set output-device "wan"
    next
end
"""
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.enabled is None
    assert rule.source_attributes["status"] == "unexpected"


@pytest.mark.parametrize(
    ("section", "family", "action", "expected_effective_action"),
    [
        ("router policy", "policy-route-ipv4", None, "permit"),
        ("router policy", "policy-route-ipv4", "permit", "permit"),
        ("router policy", "policy-route-ipv4", "deny", "deny"),
        ("router policy6", "policy-route-ipv6", None, "permit"),
        ("router policy6", "policy-route-ipv6", "permit", "permit"),
        ("router policy6", "policy-route-ipv6", "deny", "deny"),
    ],
)
def test_policy_route_effective_action_matrix_preserves_source_provenance(
    section,
    family,
    action,
    expected_effective_action,
):
    action_line = f"        set action {action}\n" if action else ""
    result = extract_fortigate_config(
        f'''config {section}
    edit 200
        set input-device "lan"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set gateway 192.0.2.1
        set output-device "wan"
{action_line}    next
end
'''
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.family == family
    assert rule.effective_action == expected_effective_action
    assert result.model_dump()["canonical_ir"]["policy_routes"][0]["effective_action"] == expected_effective_action
    item = next(
        item for item in result.inventory_items
        if item.source_path == section and item.source_id == "200"
    )
    if action is None:
        assert "action" not in rule.source_attributes
        assert all(command.key != "action" for command in item.commands)
    else:
        assert rule.source_attributes["action"] == action
        action_command = next(command for command in item.commands if command.key == "action")
        assert action_command.values == [action]
    assert rule.enabled is True
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies == []
    assert result.generation_safe is False


def test_policy_route_unknown_action_is_not_defaulted():
    result = extract_fortigate_config(
        """config router policy
    edit 201
        set input-device "lan"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set action unexpected
    next
end
"""
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.effective_action is None
    assert rule.source_attributes["action"] == "unexpected"


def test_policy_route_action_and_status_are_independent():
    result = extract_fortigate_config(
        """config router policy
    edit 202
        set status disable
        set input-device "lan"
        set src "10.0.0.0/24"
        set dst "0.0.0.0/0"
        set action permit
    next
end
"""
    )

    rule = result.canonical_ir.policy_routes[0]
    assert rule.effective_action == "permit"
    assert rule.enabled is False


def test_policy_route_all_scalar_fields_are_typed_without_boolean_coercion():
    result = extract_fortigate_config(
        """config router policy
    edit 300
        set action deny
        set comments "review this route"
        set dst-negate disable
        set end-source-port 2000
        set input-device-negate enable
        set src-negate disable
        set start-source-port 1000
        set status disable
        set tos 0x10
        set tos-mask 0xff
    next
end
"""
    )
    parsed = parse_fortigate_config(
        """config router policy
    edit 300
        set action deny
        set comments "review this route"
        set dst-negate disable
        set end-source-port 2000
        set input-device-negate enable
        set src-negate disable
        set start-source-port 1000
        set status disable
        set tos 0x10
        set tos-mask 0xff
    next
end
"""
    )
    source = parsed.policy_routes[0]
    rule = result.canonical_ir.policy_routes[0]
    assert isinstance(source, FGPolicyRoute)
    assert isinstance(rule, IRFortiGatePolicyRoute)
    expected = {
        "action": "deny", "comments": "review this route", "dst_negate": "disable",
        "end_source_port": 2000, "input_device_negate": "enable", "src_negate": "disable",
        "start_source_port": 1000, "status": "disable", "tos": "0x10", "tos_mask": "0xff",
    }
    for key, value in expected.items():
        assert getattr(source, key) == value
    assert rule.source_action == "deny"
    assert rule.source_status == "disable"
    assert rule.effective_action == "deny"
    assert rule.enabled is False
    assert rule.destination_negate == "disable"
    assert rule.source_port_start == 1000
    assert rule.source_port_end == 2000
    assert rule.tos == "0x10"
    assert rule.tos_mask == "0xff"


def test_policy_route_set_append_unset_keeps_final_state_and_inventory_history():
    result = extract_fortigate_config(
        """config router policy
    edit 301
        set input-device "port1"
        append input-device "port2"
        set srcaddr "A"
        append srcaddr "B"
        set internet-service-id 1
        append internet-service-id 2
        set gateway 192.0.2.1
        set protocol 6
        unset srcaddr
        unset gateway
        unset protocol
    next
end
"""
    )
    rule = result.canonical_ir.policy_routes[0]
    assert rule.input_devices == ["port1", "port2"]
    assert rule.source_addresses == []
    assert rule.internet_service_ids == [1, 2]
    assert rule.gateway is None
    assert rule.protocol is None
    item = next(item for item in result.inventory_items if item.source_path == "router policy")
    assert [(command.operation, command.key) for command in item.commands] == [
        ("set", "input-device"), ("append", "input-device"),
        ("set", "srcaddr"), ("append", "srcaddr"),
        ("set", "internet-service-id"), ("append", "internet-service-id"),
        ("set", "gateway"), ("set", "protocol"),
        ("unset", "srcaddr"), ("unset", "gateway"), ("unset", "protocol"),
    ]


def test_policy_route_malformed_numeric_values_are_retained_without_parse_failure():
    config = """config router policy
    edit 302
        set protocol invalid-protocol
        set start-port invalid-start
        set end-port invalid-end
        set start-source-port invalid-source-start
        set end-source-port invalid-source-end
        set internet-service-id 65646 invalid-id 65647
    next
end
"""
    result = extract_fortigate_config(config)
    source = parse_fortigate_config(config).policy_routes[0]
    rule = result.canonical_ir.policy_routes[0]
    assert rule.protocol is None
    assert rule.destination_port_start is None
    assert rule.destination_port_end is None
    assert rule.source_port_start is None
    assert rule.source_port_end is None
    assert rule.internet_service_ids == [65646, 65647]
    for key in (
        "unparsed_protocol", "unparsed_start_port", "unparsed_end_port",
        "unparsed_start_source_port", "unparsed_end_source_port",
    ):
        assert key in rule.source_attributes
    assert rule.source_attributes["internet_service_id"] == ["65646", "invalid-id", "65647"]
    assert rule.source_attributes["unparsed_internet_service_id"] == ["invalid-id"]
    assert source.extra_settings["unparsed_internet_service_id"] == ["invalid-id"]
    assert result.generation_safe is False
    assert result.migration_complete is False


def test_policy_route_range_validation_requires_review_without_repairing_values():
    result = extract_fortigate_config(
        """config router policy
    edit 303
        set protocol 256
        set start-port 2000
        set end-port 1000
    next
end
"""
    )
    rule = result.canonical_ir.policy_routes[0]
    assert rule.protocol == 256
    assert rule.destination_port_start == 2000
    assert rule.destination_port_end == 1000
    assert any("outside the valid range" in reason for reason in rule.review_reasons)
    assert any("inverted" in reason for reason in rule.review_reasons)


def test_policy_route_identity_is_scoped_by_vdom_and_family():
    result = extract_fortigate_config(
        """config vdom
    edit vdom-a
        config router policy
            edit 10
                set src "10.0.0.0/24"
            next
        end
    next
    edit vdom-b
        config router policy
            edit 10
                set src "10.0.1.0/24"
            next
        end
    next
end
config router policy6
    edit 10
        set src "2001:db8::/64"
    next
end
"""
    )
    assert [(rule.source_context, rule.family, rule.source_id) for rule in result.canonical_ir.policy_routes] == [
        ("vdom-a", "policy-route-ipv4", "10"),
        ("vdom-b", "policy-route-ipv4", "10"),
        ("root", "policy-route-ipv6", "10"),
    ]
    assert result.canonical_ir.policy_routes[0].source_networks == ["10.0.0.0/24"]
    assert result.canonical_ir.policy_routes[1].source_networks == ["10.0.1.0/24"]


def test_policy_route_source_order_is_not_numeric_id_order():
    result = extract_fortigate_config(
        """config router policy
    edit 30
    next
    edit 10
    next
    edit 20
    next
end
"""
    )
    assert [rule.source_id for rule in result.canonical_ir.policy_routes] == ["30", "10", "20"]
    assert [rule.source_order for rule in result.canonical_ir.policy_routes] == sorted(
        rule.source_order for rule in result.canonical_ir.policy_routes
    )


def test_policy_route_coverage_counts_ipv4_and_ipv6_families_separately():
    result = extract_fortigate_config(
        """config router policy
    edit 1
    next
end
config router policy6
    edit 2
    next
end
"""
    )
    sections = {section.path: section for section in result.source_sections}
    for path, family in (("router policy", "policy-route-ipv4"), ("router policy6", "policy-route-ipv6")):
        section = sections[path]
        assert section.status.value == "EXTRACT_ONLY"
        assert section.object_count_parsed == 1
        assert section.object_count_normalized == 1
        assert "Semantic support level: TYPED_EXTRACT_ONLY." in section.notes
        assert family in {rule.family for rule in result.canonical_ir.policy_routes}
    assert result.generation_safe is False
    assert result.migration_complete is False
    assert result.canonical_ir.policy_routes[0].requires_manual_review is True
