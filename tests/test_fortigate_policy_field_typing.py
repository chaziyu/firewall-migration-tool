import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import (
    SECTION_LIST_FIELDS,
    parse_fortigate_config,
)


def _policy_value(policy, key):
    if key in type(policy).model_fields:
        return getattr(policy, key)
    return policy.extra_settings[key]


def _source_commands(result, section):
    item = next(item for item in result.inventory_items if item.source_path == section)
    return {command.key: command.values for command in item.commands}


PBR_LIST_FIELDS = {
    "dst",
    "dstaddr",
    "input_device",
    "internet_service_custom",
    "internet_service_id",
    "src",
    "srcaddr",
}

LOCAL_IN_IPV4_LIST_FIELDS = {
    "dstaddr",
    "internet_service_src_custom",
    "internet_service_src_custom_group",
    "internet_service_src_group",
    "internet_service_src_name",
    "intf",
    "service",
    "srcaddr",
}

LOCAL_IN_IPV6_LIST_FIELDS = {
    "dstaddr",
    "internet_service6_src_custom",
    "internet_service6_src_custom_group",
    "internet_service6_src_group",
    "internet_service6_src_name",
    "intf",
    "service",
    "srcaddr",
}

FIREWALL_POLICY_LIST_FIELDS = {
    "custom_log_fields",
    "dstaddr",
    "dstaddr6",
    "dstintf",
    "fsso_groups",
    "groups",
    "internet_service_custom",
    "internet_service_custom_group",
    "internet_service_group",
    "internet_service_name",
    "internet_service_src_custom",
    "internet_service_src_custom_group",
    "internet_service_src_group",
    "internet_service_src_name",
    "internet_service6_custom",
    "internet_service6_custom_group",
    "internet_service6_group",
    "internet_service6_name",
    "internet_service6_src_custom",
    "internet_service6_src_custom_group",
    "internet_service6_src_group",
    "internet_service6_src_name",
    "network_service_dynamic",
    "network_service_src_dynamic",
    "ntlm_enabled_browsers",
    "pcp_poolname",
    "poolname",
    "poolname6",
    "rtp_addr",
    "service",
    "sgt",
    "src_vendor_mac",
    "srcaddr",
    "srcaddr6",
    "srcintf",
    "users",
    "ztna_ems_tag",
    "ztna_ems_tag_secondary",
    "ztna_geo_tag",
}


def test_policy_list_metadata_is_complete_and_normalized():
    assert PBR_LIST_FIELDS <= SECTION_LIST_FIELDS["router policy"]
    assert PBR_LIST_FIELDS <= SECTION_LIST_FIELDS["router policy6"]
    assert LOCAL_IN_IPV4_LIST_FIELDS <= SECTION_LIST_FIELDS["firewall local-in-policy"]
    assert LOCAL_IN_IPV6_LIST_FIELDS <= SECTION_LIST_FIELDS["firewall local-in-policy6"]
    assert FIREWALL_POLICY_LIST_FIELDS <= SECTION_LIST_FIELDS["firewall policy"]
    assert all("-" not in field for fields in SECTION_LIST_FIELDS.values() for field in fields)


@pytest.mark.parametrize("section", ["router policy", "router policy6"])
def test_pbr_every_verified_list_field_preserves_type_order_and_source_tokens(section):
    values = {
        "dst": ("DST-C", "DST-A"),
        "dstaddr": ("DSTADDR-C", "DSTADDR-A"),
        "input-device": ("port3", "port1"),
        "internet-service-custom": ("CUSTOM-C", "CUSTOM-A"),
        "internet-service-id": ("65646", "65647"),
        "src": ("SRC-C", "SRC-A"),
        "srcaddr": ("SRCADDR-C", "SRCADDR-A"),
    }
    config = "\n".join(
        [
            f"config {section}",
            "    edit 1",
            *[
                f'        set {key} "{first}" "{second}"'
                for key, (first, second) in values.items()
            ],
            "    next",
            "end",
        ]
    )

    result = extract_fortigate_config(config)
    attributes = result.canonical_ir.policy_routes[0].source_attributes
    expected = {key.replace("-", "_"): list(pair) for key, pair in values.items()}
    assert all(isinstance(attributes[key], list) for key in expected)
    assert {key: attributes[key] for key in expected} == expected
    commands = _source_commands(result, section)
    assert {key: commands[key] for key in values} == {
        key: list(pair) for key, pair in values.items()
    }


def test_pbr_single_value_list_and_scalar_neighbors_remain_structurally_distinct():
    result = extract_fortigate_config(
        """config router policy
    edit 1
        set dst "DST-ONE"
        set action permit
        set gateway 192.0.2.1
        set output-device "wan1"
        set protocol 6
        set start-port 443
        set end-port 8443
        set status disable
        set src-negate enable
        set dst-negate disable
        set input-device-negate enable
    next
end
"""
    )
    attributes = result.canonical_ir.policy_routes[0].source_attributes
    assert attributes["dst"] == ["DST-ONE"]
    for key in (
        "action",
        "gateway",
        "output_device",
        "protocol",
        "start_port",
        "end_port",
        "status",
        "src_negate",
        "dst_negate",
        "input_device_negate",
    ):
        assert isinstance(attributes[key], str)


@pytest.mark.parametrize(
    ("section", "fields", "family", "prefix"),
    [
        (
            "firewall local-in-policy",
            LOCAL_IN_IPV4_LIST_FIELDS,
            "local-in-policy-ipv4",
            "internet-service-src",
        ),
        (
            "firewall local-in-policy6",
            LOCAL_IN_IPV6_LIST_FIELDS,
            "local-in-policy-ipv6",
            "internet-service6-src",
        ),
    ],
)
def test_local_in_every_verified_list_field_preserves_type_order_and_family_names(
    section, fields, family, prefix
):
    keys = {
        "dstaddr": ("DST-C", "DST-A"),
        f"{prefix}-custom": ("CUSTOM-C", "CUSTOM-A"),
        f"{prefix}-custom-group": ("CUSTOM-GROUP-C", "CUSTOM-GROUP-A"),
        f"{prefix}-group": ("GROUP-C", "GROUP-A"),
        f"{prefix}-name": ("NAME-C", "NAME-A"),
        "intf": ("wan3", "wan1"),
        "service": ("HTTPS", "SSH"),
        "srcaddr": ("SRC-C", "SRC-A"),
    }
    config = "\n".join(
        [
            f"config {section}",
            "    edit 1",
            *[
                f'        set {key} "{first}" "{second}"'
                for key, (first, second) in keys.items()
            ],
            "        set action accept",
            "        set schedule \"always\"",
            "        set status disable",
            "        set srcaddr-negate enable",
            "        set dstaddr-negate disable",
            "        set service-negate enable",
            "    next",
            "end",
        ]
    )

    result = extract_fortigate_config(config)
    rule = result.canonical_ir.local_in_policies[0]
    assert rule.family == family
    expected = {key.replace("-", "_"): list(pair) for key, pair in keys.items()}
    assert set(expected) == fields
    assert all(isinstance(rule.source_attributes[key], list) for key in expected)
    assert {key: rule.source_attributes[key] for key in expected} == expected
    family_status = (
        "internet_service6_src"
        if prefix.startswith("internet-service6")
        else "internet_service_src"
    )
    assert family_status not in rule.source_attributes
    for key in (
        "action",
        "schedule",
        "status",
        "srcaddr_negate",
        "dstaddr_negate",
        "service_negate",
    ):
        assert isinstance(rule.source_attributes[key], str)


def test_firewall_policy_all_verified_list_fields_are_explicit_ordered_lists():
    values = {
        field: (f"{field}-C", f"{field}-A") for field in FIREWALL_POLICY_LIST_FIELDS
    }
    config = "\n".join(
        [
            "config firewall policy",
            "    edit 1",
            *[
                f'        set {key.replace("_", "-")} "{first}" "{second}"'
                for key, (first, second) in values.items()
            ],
            "    next",
            "end",
        ]
    )

    policy = parse_fortigate_config(config).policies[0]
    for key, pair in values.items():
        value = _policy_value(policy, key)
        assert isinstance(value, list), key
        assert value == list(pair)


def test_firewall_policy_single_value_lists_and_scalar_neighbors_remain_typed():
    policy = parse_fortigate_config(
        """config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "SRC"
        set dstaddr "DST"
        set service "HTTPS"
        set groups "GROUP"
        set users "alice"
        set poolname "POOL"
        set action accept
        set status enable
        set schedule "always"
        set comments "comment"
        set nat enable
        set ippool enable
        set inspection-mode flow
        set logtraffic all
        set srcaddr-negate disable
        set dstaddr-negate disable
        set service-negate disable
        set internet-service enable
        set internet-service-src disable
    next
end
"""
    ).policies[0]

    for key in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service", "groups", "users", "poolname"):
        value = _policy_value(policy, key)
        assert isinstance(value, list)
        assert len(value) == 1
    for key in (
        "action",
        "status",
        "schedule",
        "comments",
        "nat",
        "ippool",
        "inspection_mode",
        "logtraffic",
        "srcaddr_negate",
        "dstaddr_negate",
        "service_negate",
        "internet_service",
        "internet_service_src",
    ):
        assert isinstance(getattr(policy, key), str)


def test_firewall_policy_append_extends_an_explicit_list_and_preserves_inventory():
    result = extract_fortigate_config(
        """config firewall policy
    edit 1
        set srcaddr "A"
        append srcaddr "B" "C"
    next
end
"""
    )
    policy = result.canonical_ir.policies[0]
    assert policy.source_address_references == ["A", "B", "C"]
    item = next(item for item in result.inventory_items if item.source_path == "firewall policy")
    assert [(command.operation, command.key, command.values) for command in item.commands] == [
        ("set", "srcaddr", ["A"]),
        ("append", "srcaddr", ["B", "C"]),
    ]


def test_section_metadata_does_not_change_router_static_dstaddr_to_a_list():
    parsed = parse_fortigate_config(
        """config router policy
    edit 1
        set dstaddr "PBR-A" "PBR-B"
    next
end
config router static
    edit 1
        set dstaddr "STATIC-A" "STATIC-B"
    next
end
"""
    )
    assert parsed.policy_routes[0].settings["dstaddr"] == ["PBR-A", "PBR-B"]
    assert parsed.static_routes[0].dstaddr == "STATIC-A STATIC-B"


def test_unknown_firewall_policy_settings_remain_preserved_as_scalars_and_raw_commands():
    result = extract_fortigate_config(
        """config firewall policy
    edit 1
        set timeout-send-rst enable
        set future-traffic-setting "one" "two"
    next
end
"""
    )
    policy = result.canonical_ir.policies[0]
    assert policy.source_extra_settings["timeout_send_rst"] == "enable"
    assert policy.source_extra_settings["future_traffic_setting"] == "one two"
    commands = _source_commands(result, "firewall policy")
    assert commands["future-traffic-setting"] == ["one", "two"]
