import pytest
import fwmigrate.generators  # noqa: F401 - register built-in target generators
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir.core import IRConfig, IRPolicy, IRSecurityProfileGroup, IRMetadata
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from tests.fixture_paths import VENDOR_FIXTURES

SOURCE_VENDORS = ["fortigate", "palo_alto", "cisco_asa", "checkpoint", "juniper_srx"]
TARGET_VENDORS = ["palo_alto", "fortigate", "checkpoint", "juniper_srx", "cisco_asa"]

GOLDEN_INPUTS = VENDOR_FIXTURES

@pytest.mark.parametrize("source_vendor", SOURCE_VENDORS)
@pytest.mark.parametrize("target_vendor", TARGET_VENDORS)
def test_any_to_any_vendor_matrix_conversion(source_vendor, target_vendor):
    """Test every possible source-to-target migration permutation (M x N matrix)."""
    input_file = GOLDEN_INPUTS[source_vendor]
    assert input_file.exists(), f"Missing example input for {source_vendor}"

    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Ingest via Source Parser
    parser = PluginRegistry.get_parser(source_vendor)
    ir = parser.parse(content)
    assert ir is not None
    assert len(ir.addresses) > 0 or len(ir.policies) > 0

    # 2. Optimize
    optimizer = RuleOptimizer(ir)
    pruned_ir = optimizer.prune_unused_objects()
    assert pruned_ir is not None

    # 3. Generate via Target Generator
    generator = PluginRegistry.get_generator(target_vendor)
    
    # Test all supported formats for this generator
    target_meta = next(t for t in PluginRegistry.list_target_vendors() if t['vendor_id'] == target_vendor)
    for fmt in target_meta['supported_formats']:
        artifacts = generator.generate(pruned_ir, format=fmt)
        assert len(artifacts) >= 1
        for art in artifacts:
            assert len(art.content) > 0
            assert art.filename is not None

def test_fortigate_to_palo_alto_utm_profile_names_are_not_treated_as_equivalent():
    """FortiGate UTM names must not synthesize semantically unproven PAN-OS profiles."""
    input_file = GOLDEN_INPUTS["fortigate"]
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    ir = FGToIRTransformer(
        parse_fortigate_config(content),
        zone_mapping={
            "port1": "LAN_ZONE",
            "port2": "WAN_ZONE",
            "port3": "DMZ_ZONE",
        },
    ).transform()

    # Verify IR extracted security profile groups
    assert len(ir.security_profile_groups) >= 1
    spg = ir.security_profile_groups[0]
    assert spg.name.startswith("SPG_") or spg.name == "Migrated_Profiles"
    assert spg.requires_manual_review is True
    assert spg.migration_status == "PARTIALLY_NORMALIZED"

    # Generate Palo Alto XML
    pa_gen = PluginRegistry.get_generator("palo_alto")
    artifacts = pa_gen.generate(ir, format="xml")
    xml_content = artifacts[0].content

    assert f'<entry name="{spg.name}">' not in xml_content
    assert f"<member>{spg.name}</member>" not in xml_content
    assert any(
        entry.confidence.value == "manual"
        and "source-specific" in entry.message
        for entry in ir.audit_entries
    )

def test_palo_alto_to_fortigate_utm_profile_group_synthesis():
    """Verify PAN-OS profile settings synthesize FortiGate profile-group CLI."""
    input_file = GOLDEN_INPUTS["palo_alto"]
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("palo_alto")
    ir = parser.parse(content)

    assert len(ir.security_profile_groups) >= 1
    assert any(p.security_profile_group for p in ir.policies)

    # Generate FortiGate CLI
    fg_gen = PluginRegistry.get_generator("fortigate")
    artifacts = fg_gen.generate(ir, format="cli")
    conf_content = artifacts[0].content

    assert "config firewall profile-group" in conf_content
    assert "set utm-status enable" in conf_content
    assert 'set profile-group "SPG_Corporate"' in conf_content


def test_palo_alto_generator_applies_target_defaults_for_partial_ir_profiles():
    """Verify that IR with partial profiles receives target-required defaults from PAN-OS transformer."""
    ir = IRConfig(
        metadata=IRMetadata(hostname="HQ-FW", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="Allow_Web",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["any"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.ALLOW,
                security_profile_group="SPG_IPS_default",
                ips_sensor="default",
                antivirus=None,
                webfilter=None,
            )
        ],
        security_profile_groups=[
            IRSecurityProfileGroup(
                name="SPG_IPS_default",
                vulnerability="default",
                antivirus=None,
                anti_spyware=None,
                url_filtering=None,
                file_blocking=None,
                wildfire=None,
                ssl_decryption="certificate-inspection",
            )
        ],
    )

    pa_gen = PluginRegistry.get_generator("palo_alto")
    artifacts = pa_gen.generate(ir, format="xml")
    xml_content = artifacts[0].content


def test_palo_alto_to_fortigate_utm_profile_group_synthesis():
    """Verify PAN-OS profile settings synthesize FortiGate profile-group CLI."""
    input_file = GOLDEN_INPUTS["palo_alto"]
    with open(input_file, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("palo_alto")
    ir = parser.parse(content)

    assert len(ir.security_profile_groups) >= 1
    assert any(p.security_profile_group for p in ir.policies)

    # Generate FortiGate CLI
    fg_gen = PluginRegistry.get_generator("fortigate")
    artifacts = fg_gen.generate(ir, format="cli")
    conf_content = artifacts[0].content

    assert "config firewall profile-group" in conf_content
    assert "set utm-status enable" in conf_content
    assert 'set profile-group "SPG_Corporate"' in conf_content


def test_palo_alto_generator_applies_target_defaults_for_partial_ir_profiles():
    """Verify that IR with partial profiles receives target-required defaults from PAN-OS transformer."""
    ir = IRConfig(
        metadata=IRMetadata(hostname="HQ-FW", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="Allow_Web",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["any"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.ALLOW,
                security_profile_group="SPG_IPS_default",
                ips_sensor="default",
                antivirus=None,
                webfilter=None,
            )
        ],
        security_profile_groups=[
            IRSecurityProfileGroup(
                name="SPG_IPS_default",
                vulnerability="default",
                antivirus=None,
                anti_spyware=None,
                url_filtering=None,
                file_blocking=None,
                wildfire=None,
                ssl_decryption="certificate-inspection",
            )
        ],
    )

    pa_gen = PluginRegistry.get_generator("palo_alto")
    artifacts = pa_gen.generate(ir, format="xml")
    xml_content = artifacts[0].content

    # Profile group XML contains target defaults for unset IR fields
    assert '<entry name="SPG_IPS_default">' in xml_content
    assert "<vulnerability>" in xml_content
    assert "<virus>" in xml_content
    assert "<spyware>" in xml_content
    assert "<file-blocking>" in xml_content
    assert "<wildfire-analysis>" in xml_content
    assert "<member>basic-file-blocking</member>" in xml_content


def test_any_ipv4_and_any_ipv6_handling_across_all_target_generators():
    """Verify that any-ipv4 and any-ipv6 canonical keywords generate valid, safe target syntax without non-existent object references."""
    ir = IRConfig(
        schema_version="1.14",
        metadata=IRMetadata(hostname="Test-Dual-Any"),
        policies=[
            IRPolicy(
                name="Allow_IPv4_All",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["any-ipv4"],
                destination=["any-ipv4"],
                service=["any"],
                action=PolicyAction.ALLOW,
            ),
            IRPolicy(
                name="Allow_IPv6_All",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["any-ipv6"],
                destination=["any-ipv6"],
                service=["any"],
                action=PolicyAction.ALLOW,
            ),
        ],
    )

    # 1. FortiGate CLI
    fg_gen = PluginRegistry.get_generator("fortigate")
    fg_art = fg_gen.generate(ir, format="cli")
    fg_cli = fg_art[0].content
    assert 'set srcaddr "all"' in fg_cli
    assert 'set dstaddr "all"' in fg_cli

    # 2. Cisco ASA CLI
    asa_gen = PluginRegistry.get_generator("cisco_asa")
    asa_art = asa_gen.generate(ir, format="cli")
    asa_cli = asa_art[0].content
    assert "access-list trust_access_in extended permit ip any any" in asa_cli
    assert "object any-ipv4" not in asa_cli
    assert "object-group any-ipv4" not in asa_cli

    # 3. Check Point CLI
    cp_gen = PluginRegistry.get_generator("checkpoint")
    cp_art = cp_gen.generate(ir, format="cli")
    cp_cli = cp_art[0].content
    assert 'source "Any" destination "Any"' in cp_cli
    assert '"any-ipv4"' not in cp_cli

    # 4. Palo Alto XML
    pa_gen = PluginRegistry.get_generator("palo_alto")
    pa_art = pa_gen.generate(ir, format="xml")
    pa_xml = pa_art[0].content
    assert "<member>any</member>" in pa_xml
    assert "<member>any-ipv4</member>" not in pa_xml

    # 5. Juniper SRX CLI
    junos_gen = PluginRegistry.get_generator("juniper_srx")
    junos_art = junos_gen.generate(ir, format="cli")
    junos_cli = junos_art[0].content
    assert "match source-address any-ipv4" in junos_cli
    assert "match destination-address any-ipv4" in junos_cli
