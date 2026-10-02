from .helpers import assert_source_unchanged, snapshot_source

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.validation import validate_asa_config

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views

from fwmigrate.vendors.cisco_asa.model.interface import CiscoInterface

from fwmigrate.vendors.cisco_asa.model.source import CiscoASAConfig
from fwmigrate.vendors.cisco_asa.model.nat import CiscoNATRule
from fwmigrate.vendors.cisco_asa.model.address import CiscoNetworkObject

from fwmigrate.vendors.cisco_asa.model.vpn import CiscoGroupPolicy, CiscoVPNAddressPool

from fwmigrate.vendors.cisco_asa.model.zone import CiscoTrafficZone

def test_validation_is_repeatable_and_does_not_change_extraction_status():
    result = extract_cisco_asa_source("crypto map VPN 10 match address MISSING\n")
    snapshot = snapshot_source(result.config)

    first = validate_asa_config(result.config, result.derived)
    second = validate_asa_config(result.config, result.derived)

    assert first == second
    assert_source_unchanged(result.config, snapshot)
    assert any(issue.category == "parse" for issue in first.issues) == bool(result.config.diagnostics)

def test_unresolved_relationship_does_not_change_extracted_source_status():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n nameif outside\n"
        "access-group MISSING in interface outside\n"
    )
    binding = result.config.acl_bindings[0]

    assert binding.extraction_status == "EXTRACTED"
    assert not result.config.diagnostics
    assert any(issue.reference_name == "MISSING" and not issue.resolved for issue in result.derived.relationship_issues)
    assert any(issue.category == "acl" and "Unresolved" in issue.message for issue in result.validation.issues)

def test_zone_validation_checks_members_count_levels_and_single_zone_ownership():
    interfaces = [CiscoInterface(name=f"Ethernet0/{index}", security_level=100 if index < 2 else 50,
                                 traffic_zone_members=["Z1", "Z2"] if index == 0 else [])
                  for index in range(9)]
    first = CiscoTrafficZone(name="Z1", members=[f"Ethernet0/{index}" for index in range(9)])
    second = CiscoTrafficZone(name="Z2", members=["Ethernet0/0"])
    config = CiscoASAConfig(interfaces=interfaces, traffic_zones=[first, second])

    result = validate_asa_config(config, build_asa_derived_views(config))

    messages = [issue.message for issue in result.issues if issue.category == "zone"]
    assert "Interface belongs to more than one traffic zone" in messages

def test_zone_validation_uses_interface_zone_member_relationships():
    source = "zone EDGE\n"
    for index in range(9):
        management_only = "management-only\n" if index == 8 else ""
        source += (
            f"interface Ethernet0/{index}\n"
            f" nameif edge{index}\n"
            f" security-level {100 if index < 8 else 90}\n"
            f" {management_only} zone-member EDGE\n"
        )
    result = extract_cisco_asa_source(source)
    messages = [issue.message for issue in result.validation.issues if issue.category == "zone"]
    assert "Traffic zone exceeds the eight-interface limit" in messages
    assert "Traffic zone members have different security levels" in messages
    assert "Traffic zone contains an unsupported interface member" in messages

def test_group_policy_inheritance_cycle_is_reported_without_mutation():
    config = CiscoASAConfig(group_policies=[
        CiscoGroupPolicy(name="A", parent="B"), CiscoGroupPolicy(name="B", parent="A")
    ])
    snapshot = snapshot_source(config)

    result = validate_asa_config(config, build_asa_derived_views(config))

    assert any(issue.category == "vpn" and issue.message == "Group-policy inheritance cycle" for issue in result.issues)
    assert_source_unchanged(config, snapshot)

def test_partial_diagnostic_remains_warning_in_validation():
    result = extract_cisco_asa_source(
        "object service APP\n"
        " service tcp destination eq 443\n"
        " service udp destination eq 53\n"
    )

    issue = next(
        item for item in result.validation.issues
        if item.category == "parse" and "Multiple service specifications" in item.message
    )
    assert issue.severity == "warning"


def test_legacy_crypto_algorithms_are_reported_without_rewriting_source():
    result = extract_cisco_asa_source(
        "crypto ikev1 policy 10\n"
        " encryption 3des\n"
        " hash md5\n"
    )

    messages = [item.message for item in result.validation.issues if item.category == "crypto"]
    assert any("3des" in message for message in messages)
    assert any("md5" in message for message in messages)
    assert result.config.ike_policies[0].encryption == "3des"
    assert result.config.ike_policies[0].hash_algorithm == "md5"


def test_translated_nat_value_conflicts_with_interface_and_vpn_pool_are_reported():
    config = CiscoASAConfig(
        interfaces=[CiscoInterface(name="Ethernet0/0", ip="203.0.113.10")],
        network_objects=[
            CiscoNetworkObject(name="MAPPED", type="host", value="203.0.113.10")
        ],
        vpn_address_pools=[
            CiscoVPNAddressPool(name="RA", start="203.0.113.1", end="203.0.113.20")
        ],
        nat_rules=[
            CiscoNATRule(name="nat:1", mapped_source="MAPPED")
        ],
    )

    result = validate_asa_config(config, build_asa_derived_views(config))
    messages = [item.message for item in result.issues if item.category == "nat"]
    assert any("overlaps interface address" in message for message in messages)
    assert any("overlaps VPN address pool RA" in message for message in messages)

