import pytest
from fwmigrate.core.stubs import create_unsupported_stub, DEFAULT_STUB_IP, DEFAULT_STUB_TAG
from fwmigrate.ir.core import IRConfig, IRMetadata, IRAddress, IRAddressGroup, IRPolicy, PolicyAction
from fwmigrate.ir.enums import AddressType, MigrationConfidence
from fwmigrate.parsers.fortigate.model import FGConfig, FGAddress, FGAddressGroup, FGPolicy
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator

def test_create_unsupported_stub():
    stub = create_unsupported_stub(
        name="ipad 1",
        original_type="mac",
        original_value="00:11:22:33:44:55",
        description="CEO iPad MAC Address"
    )
    assert stub.name == "ipad 1"
    assert stub.type == AddressType.STUB_UNSUPPORTED
    assert stub.value == "192.0.2.254/32"
    assert stub.original_type == "mac"
    assert stub.original_value == "00:11:22:33:44:55"
    assert stub.requires_manual_review is True
    assert "MANUAL_REVIEW_REQUIRED" in stub.tags
    assert "UNSUPPORTED_MAC" in stub.tags
    assert "192.0.2.254/32" in stub.audit_note

def test_fortigate_mac_addresses_and_address_groups():
    fg = FGConfig()
    fg.addresses.append(FGAddress(name="ipad 1", type="mac", macaddr="00:11:22:33:44:55", comment="Test MAC 1"))
    fg.addresses.append(FGAddress(name="ipad 2", type="mac", macaddr="00:11:22:33:44:66", comment="Test MAC 2"))
    fg.addresses.append(FGAddress(name="web_server", type="ipmask", subnet="10.0.0.10 255.255.255.255"))
    fg.address_groups.append(FGAddressGroup(
        name="exclude QUIC",
        member=["ipad 1", "ipad 2"],
        comment="Group with MAC members"
    ))
    fg.address_groups.append(FGAddressGroup(
        name="mixed_group",
        member=["ipad 1", "web_server"],
        comment="Mixed Group"
    ))

    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    # Verify IR addresses
    stub_1 = next((a for a in ir.addresses if a.name == "ipad 1"), None)
    stub_2 = next((a for a in ir.addresses if a.name == "ipad 2"), None)
    assert stub_1 is not None
    assert stub_1.type == AddressType.STUB_UNSUPPORTED
    assert stub_1.value == "192.0.2.254/32"
    assert stub_2 is not None
    assert stub_2.type == AddressType.STUB_UNSUPPORTED

    # Verify IR address groups did NOT lose members
    exclude_quic = next((g for g in ir.address_groups if g.name == "exclude QUIC"), None)
    assert exclude_quic is not None
    assert exclude_quic.members == ["ipad 1", "ipad 2"]

    mixed_group = next((g for g in ir.address_groups if g.name == "mixed_group"), None)
    assert mixed_group is not None
    assert mixed_group.members == ["ipad 1", "web_server"]

    # Verify audit entries
    mac_audits = [e for e in ir.audit_entries if e.category == "Address" and "Unsupported source object type 'mac'" in e.message]
    assert len(mac_audits) == 2

def test_panos_xml_generator_with_stubs():
    ir = IRConfig(metadata=IRMetadata(hostname="fw-panos", source_vendor="fortigate"))
    stub = create_unsupported_stub("ipad 1", "mac", "00:11:22:33:44:55")
    ir.addresses.append(stub)
    ir.address_groups.append(IRAddressGroup(name="exclude QUIC", members=["ipad 1"]))

    generator = PANOSXMLGenerator()
    artifacts = generator.generate(ir)
    xml_content = artifacts[0].content

    # Check tag inventory definition in XML
    assert '<tag>' in xml_content
    assert '<entry name="MANUAL_REVIEW_REQUIRED">' in xml_content
    assert '<color>color3</color>' in xml_content

    # Check address object mapped to ip-netmask RFC 5737 dummy IP
    assert '<entry name="ipad 1">' in xml_content
    assert '<ip-netmask>192.0.2.254/32</ip-netmask>' in xml_content
    assert '<tag>' in xml_content
    assert '<member>MANUAL_REVIEW_REQUIRED</member>' in xml_content

    # Check address group retained member
    assert '<entry name="exclude QUIC">' in xml_content
    assert '<member>ipad 1</member>' in xml_content

def test_panos_terraform_generator_with_stubs():
    ir = IRConfig(metadata=IRMetadata(hostname="fw-panos", source_vendor="fortigate"))
    stub = create_unsupported_stub("ipad 1", "mac", "00:11:22:33:44:55")
    ir.addresses.append(stub)
    ir.address_groups.append(IRAddressGroup(name="exclude QUIC", members=["ipad 1"]))

    generator = PANOSTerraformGenerator()
    artifacts = generator.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    # Check administrative tag definition
    assert 'resource "panos_administrative_tag" "tag_manual_review_required"' in main_tf
    assert 'name     = "MANUAL_REVIEW_REQUIRED"' in main_tf
    assert 'color    = "color3"' in main_tf

    # Check address object
    assert 'resource "panos_address_object" "addr_ipad_1"' in main_tf
    assert 'value       = "192.0.2.254/32"' in main_tf
    assert 'type        = "ip-netmask"' in main_tf
    assert 'tags        = ["MANUAL_REVIEW_REQUIRED"]' in main_tf
    assert 'depends_on  = [panos_administrative_tag.tag_manual_review_required]' in main_tf

    # Check address group contains member reference without being dropped
    assert 'resource "panos_address_group" "grp_exclude_QUIC"' in main_tf
    assert 'panos_address_object.addr_ipad_1.name' in main_tf

def test_cli_generators_ip_fallback():
    ir = IRConfig(metadata=IRMetadata(hostname="test-fw"))
    stub = create_unsupported_stub("ipad 1", "mac", "00:11:22:33:44:55")
    ir.addresses.append(stub)
    ir.address_groups.append(IRAddressGroup(name="exclude QUIC", members=["ipad 1"]))

    # Cisco ASA
    cisco_gen = CiscoASACLIGenerator()
    cisco_cli = cisco_gen.generate(ir)
    assert "object network ipad 1" in cisco_cli
    assert "host 192.0.2.254" in cisco_cli

    # Juniper SRX
    juniper_gen = JuniperSRXCLIGenerator()
    juniper_cli = juniper_gen.generate(ir)
    assert "set security address-book global address ipad 1 192.0.2.254/32" in juniper_cli

    # Check Point
    cp_gen = CheckPointCLIGenerator()
    cp_cli = cp_gen.generate(ir)
    assert 'mgmt_cli add host name "ipad 1" ip-address "192.0.2.254"' in cp_cli

    # FortiGate
    fg_gen = FortiGateCLIGenerator()
    fg_artifacts = fg_gen.generate(ir)
    fg_cli = fg_artifacts[0].content
    assert 'set subnet 192.0.2.254 255.255.255.255' in fg_cli
