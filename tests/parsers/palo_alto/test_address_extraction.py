from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANAddress, PANAddressGroup
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_address_and_group_variants_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "objects.xml").read_text())
    addresses = {item.name: item for item in config.addresses}
    groups = {item.name: item for item in config.address_groups}

    assert addresses["IPv4-Host"].ip_netmask == "10.10.10.50/32"
    assert addresses["External-FQDN"].fqdn == "Api.Example.test"
    assert addresses["Missing-Type"].ip_netmask is None
    assert addresses["Has-Unknown"].raw_extra["future-field"] == "retain-me"
    assert groups["Static-Group"].static_members == ["IPv4-Host"]
    assert groups["Dynamic-Group"].dynamic_filter == "'production' and 'internet-facing'"


def test_address_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "address-secret-value"
    config = build_panos_config(
        f"""<config><shared>
          <address>
            <entry name='explicit'><ip-netmask>192.0.2.1/32</ip-netmask><description>no</description><future-field>keep</future-field><future-password>{secret}</future-password></entry>
            <entry name='missing'/>
          </address>
          <address-group><entry name='group'><static><member>explicit</member><future-nested>keep-nested</future-nested></static><future-toggle>no</future-toggle></entry></address-group>
        </shared></config>"""
    )
    explicit, missing = config.addresses
    group = config.address_groups[0]

    assert isinstance(explicit, PANAddress)
    assert isinstance(group, PANAddressGroup)
    assert explicit.ip_netmask == "192.0.2.1/32"
    assert explicit.description == "no"
    assert missing.ip_netmask is None
    assert explicit.raw_extra["future-field"] == "keep"
    assert group.raw_extra["future-toggle"] == "no"
    assert group.raw_extra["nested"]["static"]["future-nested"] == "keep-nested"
    assert explicit.scope.kind == group.scope.kind == "shared"
    assert_source_contract(explicit, config)
    assert_source_contract(group, config)
    assert secret not in str(config.model_dump())
