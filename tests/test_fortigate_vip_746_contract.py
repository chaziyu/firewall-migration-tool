from fwmigrate.parsers.fortigate.firewall_vip_746 import (
    FORTIOS_746_VIP_FIELDS,
    FORTIOS_746_VIP_NESTED_SECTIONS,
    effective_vip_settings_746,
    validate_vip_746,
)
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _parse(body: str, name: str = "VIP_CONTRACT"):
    return parse_fortigate_config(
        f'''config firewall vip
    edit "{name}"
{body}
    next
end
'''
    )


def test_vip_746_contract_covers_reviewed_top_level_and_nested_fields():
    assert {
        "add_nat46_route",
        "arp_reply",
        "extaddr",
        "extintf",
        "extip",
        "extport",
        "mapped_addr",
        "mappedip",
        "mappedport",
        "nat_source_vip",
        "nat44",
        "nat46",
        "portforward",
        "portmapping_type",
        "protocol",
        "service",
        "src_filter",
        "src_vip_filter",
        "srcintf_filter",
        "status",
        "type",
        "uuid",
    }.issubset(FORTIOS_746_VIP_FIELDS)
    assert FORTIOS_746_VIP_NESTED_SECTIONS == {
        "gslb-public-ips",
        "quic",
        "realservers",
        "ssl-cipher-suites",
        "ssl-server-cipher-suites",
    }


def test_basic_static_vip_matches_contract_and_keeps_effective_defaults_separate():
    parsed = _parse(
        """        set extip 203.0.113.10
        set mappedip 10.0.0.10
"""
    )
    source = parsed.vips[0]

    assert source.source_explicit_fields == {"extip", "mappedip"}
    assert validate_vip_746(source) == []

    effective = effective_vip_settings_746(source)
    assert effective["type"] == "static-nat"
    assert effective["protocol"] == "tcp"
    assert effective["portmapping_type"] == "1-to-1"
    assert effective["nat44"] == "enable"
    assert effective["nat46"] == "disable"
    assert effective["add_nat46_route"] == "enable"

    vip = FGToIRTransformer(parsed).transform().virtual_ips[0]
    assert vip.migration_status == "NORMALIZED"
    assert vip.requires_manual_review is False
    assert vip.source_explicit_fields == ["extip", "mappedip"]


def test_unknown_vip_setting_is_preserved_and_gets_contract_review_reason():
    parsed = _parse(
        """        set extip 203.0.113.11
        set mappedip 10.0.0.11
        set future-setting keep-me
""",
        name="VIP_UNKNOWN",
    )
    source = parsed.vips[0]
    reasons = validate_vip_746(source)

    assert source.extra_settings["future_setting"] == "keep-me"
    assert any("unmodeled source setting 'future_setting'" in reason for reason in reasons)

    vip = FGToIRTransformer(parsed).transform().virtual_ips[0]
    assert vip.migration_status == "PARTIALLY_NORMALIZED"
    assert vip.requires_manual_review is True
    assert vip.extra_settings["future_setting"] == "keep-me"
    assert "unmodeled source setting 'future_setting'" in (vip.audit_note or "")


def test_src_vip_filter_is_in_contract_but_remains_review_gated():
    parsed = _parse(
        """        set extip 203.0.113.12
        set mappedip 10.0.0.12
        set src-vip-filter enable
""",
        name="VIP_SRC_FILTER",
    )
    source = parsed.vips[0]

    assert "src_vip_filter" in source.source_explicit_fields
    assert validate_vip_746(source) == []

    vip = FGToIRTransformer(parsed).transform().virtual_ips[0]
    assert vip.extra_settings["src_vip_filter"] == "enable"
    assert vip.extra_settings["src_vip_filter_enabled"] is True
    assert vip.migration_status == "PARTIALLY_NORMALIZED"
    assert vip.requires_manual_review is True
    assert "reverse-SNAT source filtering" in (vip.audit_note or "")
