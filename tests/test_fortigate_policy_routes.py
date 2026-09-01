import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


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
    assert rule.family == "policy-route-ipv4"
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
    assert result.canonical_ir.policy_routes[0].family == "policy-route-ipv6"
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
