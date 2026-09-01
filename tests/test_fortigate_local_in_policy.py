import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_ipv4_local_in_multi_value_fields_preserve_lists_and_source_inventory():
    result = extract_fortigate_config(
        '''config firewall local-in-policy
    edit 10
        set intf "wan3" "wan1" "wan2"
        set srcaddr "ADMIN-NET-1" "ADMIN-NET-2"
        set dstaddr "FGT-IP-1" "FGT-IP-2"
        set service "SSH" "HTTPS" "PING"
        set internet-service-src enable
        set internet-service-src-custom "CUSTOM-IS-1" "CUSTOM-IS-2"
        set internet-service-src-custom-group "CUSTOM-GROUP-1" "CUSTOM-GROUP-2"
        set internet-service-src-group "IS-GROUP-1" "IS-GROUP-2"
        set internet-service-src-name "IS-NAME-1" "IS-NAME-2"
        set srcaddr-negate enable
        set dstaddr-negate enable
        set service-negate enable
        set internet-service-src-negate enable
        set action accept
        set schedule "always"
    next
end
'''
    )

    assert len(result.canonical_ir.local_in_policies) == 1
    rule = result.canonical_ir.local_in_policies[0]
    assert rule.family == "local-in-policy-ipv4"
    assert rule.source_attributes == {
        "intf": ["wan3", "wan1", "wan2"],
        "srcaddr": ["ADMIN-NET-1", "ADMIN-NET-2"],
        "dstaddr": ["FGT-IP-1", "FGT-IP-2"],
        "service": ["SSH", "HTTPS", "PING"],
        "internet_service_src": "enable",
        "internet_service_src_custom": ["CUSTOM-IS-1", "CUSTOM-IS-2"],
        "internet_service_src_custom_group": [
            "CUSTOM-GROUP-1",
            "CUSTOM-GROUP-2",
        ],
        "internet_service_src_group": ["IS-GROUP-1", "IS-GROUP-2"],
        "internet_service_src_name": ["IS-NAME-1", "IS-NAME-2"],
        "srcaddr_negate": "enable",
        "dstaddr_negate": "enable",
        "service_negate": "enable",
        "internet_service_src_negate": "enable",
        "action": "accept",
        "schedule": "always",
    }

    assert result.canonical_ir.policies == []
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.nat_rules == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == "firewall local-in-policy"
        and item.source_id == "10"
    )
    commands = {command.key: command for command in item.commands}
    assert commands["intf"].values == ["wan3", "wan1", "wan2"]
    assert commands["internet-service-src-custom"].values == [
        "CUSTOM-IS-1",
        "CUSTOM-IS-2",
    ]


def test_ipv6_local_in_multi_value_fields_preserve_lists_and_family_names():
    result = extract_fortigate_config(
        '''config firewall local-in-policy6
    edit 20
        set intf "wan3" "wan4"
        set srcaddr "ADMIN6-NET-1" "ADMIN6-NET-2"
        set dstaddr "FGT6-IP-1" "FGT6-IP-2"
        set service "HTTPS" "SSH"
        set internet-service6-src enable
        set internet-service6-src-custom "CUSTOM6-IS-1" "CUSTOM6-IS-2"
        set internet-service6-src-custom-group "CUSTOM6-GROUP-1" "CUSTOM6-GROUP-2"
        set internet-service6-src-group "IS6-GROUP-1" "IS6-GROUP-2"
        set internet-service6-src-name "IS6-NAME-1" "IS6-NAME-2"
        set internet-service6-src-negate enable
        set srcaddr-negate enable
        set dstaddr-negate enable
        set service-negate enable
        set action accept
        set schedule "always"
    next
end
'''
    )

    assert len(result.canonical_ir.local_in_policies) == 1
    rule = result.canonical_ir.local_in_policies[0]
    assert rule.family == "local-in-policy-ipv6"
    assert rule.source_attributes["intf"] == ["wan3", "wan4"]
    assert rule.source_attributes["srcaddr"] == [
        "ADMIN6-NET-1",
        "ADMIN6-NET-2",
    ]
    assert rule.source_attributes["dstaddr"] == ["FGT6-IP-1", "FGT6-IP-2"]
    assert rule.source_attributes["service"] == ["HTTPS", "SSH"]
    assert rule.source_attributes["internet_service6_src_custom"] == [
        "CUSTOM6-IS-1",
        "CUSTOM6-IS-2",
    ]
    assert rule.source_attributes["internet_service6_src_custom_group"] == [
        "CUSTOM6-GROUP-1",
        "CUSTOM6-GROUP-2",
    ]
    assert rule.source_attributes["internet_service6_src_group"] == [
        "IS6-GROUP-1",
        "IS6-GROUP-2",
    ]
    assert rule.source_attributes["internet_service6_src_name"] == [
        "IS6-NAME-1",
        "IS6-NAME-2",
    ]
    assert rule.source_attributes["internet_service6_src"] == "enable"
    assert "internet_service_src" not in rule.source_attributes
    assert rule.source_attributes["internet_service6_src_negate"] == "enable"
    assert rule.source_attributes["srcaddr_negate"] == "enable"
    assert rule.source_attributes["dstaddr_negate"] == "enable"
    assert rule.source_attributes["service_negate"] == "enable"


def test_local_in_official_list_fields_are_lists_for_single_values():
    result = extract_fortigate_config(
        '''config firewall local-in-policy
    edit 30
        set intf "wan1"
        set srcaddr "ADMIN-NET"
        set dstaddr "all"
        set service "HTTPS"
        set internet-service-src-custom "CUSTOM-IS-1"
    next
end
'''
    )

    attributes = result.canonical_ir.local_in_policies[0].source_attributes
    assert attributes["intf"] == ["wan1"]
    assert attributes["srcaddr"] == ["ADMIN-NET"]
    assert attributes["dstaddr"] == ["all"]
    assert attributes["service"] == ["HTTPS"]
    assert attributes["internet_service_src_custom"] == ["CUSTOM-IS-1"]


@pytest.mark.parametrize(
    ("section", "family", "rule_id", "interface", "srcaddr", "dstaddr"),
    [
        (
            "firewall local-in-policy",
            "local-in-policy-ipv4",
            201,
            "wan",
            "ADMIN-NET",
            "all",
        ),
        (
            "firewall local-in-policy6",
            "local-in-policy-ipv6",
            202,
            "wan6",
            "ADMIN6-NET",
            "all",
        ),
    ],
)
def test_local_in_omitted_status_defaults_enabled_without_source_synthesis(
    section,
    family,
    rule_id,
    interface,
    srcaddr,
    dstaddr,
):
    result = extract_fortigate_config(
        f'''config {section}
    edit {rule_id}
        set intf "{interface}"
        set srcaddr "{srcaddr}"
        set dstaddr "{dstaddr}"
        set service "HTTPS"
        set action accept
        set schedule "always"
    next
end
'''
    )

    rule = result.canonical_ir.local_in_policies[0]
    assert rule.family == family
    assert rule.enabled is True
    assert "status" not in rule.source_attributes
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.nat_rules == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == section and item.source_id == str(rule_id)
    )
    assert all(command.key != "status" for command in item.commands)


@pytest.mark.parametrize(
    ("section", "family", "interface", "srcaddr", "dstaddr"),
    [
        (
            "firewall local-in-policy",
            "local-in-policy-ipv4",
            "wan",
            "ADMIN-NET",
            "all",
        ),
        (
            "firewall local-in-policy6",
            "local-in-policy-ipv6",
            "wan6",
            "ADMIN6-NET",
            "all",
        ),
    ],
)
@pytest.mark.parametrize("status, expected_enabled", [("enable", True), ("disable", False)])
def test_local_in_explicit_status_overrides_family_default(
    section,
    family,
    interface,
    srcaddr,
    dstaddr,
    status,
    expected_enabled,
):
    result = extract_fortigate_config(
        f'''config {section}
    edit 203
        set status {status}
        set intf "{interface}"
        set srcaddr "{srcaddr}"
        set dstaddr "{dstaddr}"
        set service "HTTPS"
        set action accept
        set schedule "always"
    next
end
'''
    )

    rule = result.canonical_ir.local_in_policies[0]
    assert rule.family == family
    assert rule.enabled is expected_enabled
    assert rule.source_attributes["status"] == status
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.nat_rules == []
    assert result.generation_safe is False
    assert result.migration_complete is False

    item = next(
        item
        for item in result.inventory_items
        if item.source_path == section and item.source_id == "203"
    )
    status_command = next(command for command in item.commands if command.key == "status")
    assert status_command.values == [status]
