import pytest

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _interface_ir(config: str):
    parsed = parse_fortigate_config(config)
    return FGToIRTransformer(parsed).transform().interfaces[0]


def _interface_config(extra: str = "") -> str:
    return f"""
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set type physical
        set role lan
{extra}
    next
end
"""


def test_simple_interface_is_fully_normalized():
    interface = _interface_ir(_interface_config())

    assert interface.migration_status == "NORMALIZED"
    assert interface.requires_manual_review is False
    assert interface.review_reasons == []


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("bandwidth-ingress", "1000"),
    ],
)
def test_unmodeled_top_level_interface_setting_requires_review(setting, value):
    interface = _interface_ir(_interface_config(f"        set {setting} {value}"))

    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert any(setting.replace("-", "_") in reason for reason in interface.review_reasons)
    assert interface.source_attributes[setting.replace("-", "_")] == value


def test_monitor_bandwidth_does_not_add_review_reason():
    interface = _interface_ir(
        _interface_config("        set monitor-bandwidth enable")
    )

    assert not any("monitor" in reason.lower() for reason in interface.review_reasons)


def test_dns_server_override_does_not_add_review_reason():
    interface = _interface_ir(
        _interface_config("        set dns-server-override enable")
    )

    assert interface.source_dns_server_override is True
    assert interface.source_attributes["dns_server_override"] == "enable"
    assert not any("dns" in reason.lower() for reason in interface.review_reasons)


def test_dedicated_to_management_has_specific_review_reason():
    interface = _interface_ir(
        _interface_config("        set dedicated-to management")
    )

    assert interface.source_dedicated_to == "management"
    assert interface.requires_manual_review is True
    assert any(
        "management" in reason.lower() and "dedicated" in reason.lower()
        for reason in interface.review_reasons
    )
    assert not any(
        "unmodeled top-level interface setting 'dedicated-to'" in reason.lower()
        for reason in interface.review_reasons
    )


@pytest.mark.parametrize(
    ("nested_name", "nested_body", "expected_reason"),
    [
        (
            "ipv6",
            "            config ip6-prefix-list\n"
            "                edit 2001:db8::/64\n"
            "                    set autonomous-flag enable\n"
            "                next\n"
            "            end",
            "source-specific behavior",
        ),
        (
            "vrrp",
            "            set vrip 10.0.0.254",
            "VRRP interface semantics",
        ),
        (
            "tagging",
            "            set tags \"HQ\"",
            "Interface tagging semantics",
        ),
    ],
)
def test_nested_interface_semantics_require_review(
    nested_name,
    nested_body,
    expected_reason,
):
    if nested_name == "ipv6":
        nested = (
            "        config ipv6\n"
            f"{nested_body}\n"
            "        end"
        )
    else:
        nested = (
            f"        config {nested_name}\n"
            "            edit 1\n"
            f"{nested_body}\n"
            "            next\n"
            "        end"
        )

    interface = _interface_ir(_interface_config(nested))

    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert any(expected_reason in reason for reason in interface.review_reasons)


def test_other_nested_interface_block_requires_review_and_is_retained():
    interface = _interface_ir(
        _interface_config(
            """        config l2tp-client-settings
            set peer-host \"vpn.example.com\"
        end"""
        )
    )

    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert any(
        "L2TP client interface settings" in reason
        for reason in interface.review_reasons
    )
    assert [node.name for node in interface.nested_source_configs] == [
        "l2tp-client-settings"
    ]


def test_typed_and_low_risk_interface_settings_do_not_trigger_review():
    interface = _interface_ir(
        _interface_config(
            """        set alias \"LAN\"
        set description \"Office LAN\"
        set status up
        set mode static
        set color 3
        set comment \"presentation only\"
        set snmp-index 7"""
        )
    )

    assert interface.migration_status == "NORMALIZED"
    assert interface.requires_manual_review is False
    assert interface.review_reasons == []


def test_extractor_reports_partial_interface_coverage():
    result = extract_fortigate_config(
        _interface_config("        set dedicated-to lan")
    )

    interface_section = next(
        section
        for section in result.source_sections
        if section.path == "system interface"
    )

    assert interface_section.status.value == "PARTIALLY_NORMALIZED"
    assert any("interface(s) require manual review" in note for note in interface_section.notes)
