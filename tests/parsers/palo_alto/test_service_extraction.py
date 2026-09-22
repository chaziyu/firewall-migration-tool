from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANService, PANServiceGroup
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_service_and_group_variants_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "services.xml").read_text())
    services = {item.name: item for item in config.services}
    groups = {item.name: item for item in config.service_groups}

    assert services["TCP-Source"].tcp.port == "8443"
    assert services["TCP-Source"].tcp.source_port == "1024-65535"
    assert services["Both-Protocols"].tcp.port == "80"
    assert services["Both-Protocols"].udp.port == "80"
    assert services["Missing-Port"].tcp.port is None
    assert groups["Basic-Services"].members == ["TCP-443", "UDP-53"]


def test_service_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "service-secret-value"
    config = build_panos_config(
        f"""<config><shared>
          <service>
            <entry name='explicit'><protocol><tcp><port>443</port><future-protocol>keep-nested</future-protocol><future-password>{secret}</future-password></tcp></protocol><description>no</description><future-setting>keep</future-setting></entry>
            <entry name='missing'><protocol><tcp/></protocol></entry>
          </service>
          <service-group><entry name='group'><members><member>explicit</member></members><future-toggle>no</future-toggle></entry></service-group>
        </shared></config>"""
    )
    explicit, missing = config.services
    group = config.service_groups[0]

    assert isinstance(explicit, PANService)
    assert isinstance(group, PANServiceGroup)
    assert explicit.tcp.port == "443"
    assert explicit.description == "no"
    assert missing.tcp.port is None
    assert explicit.raw_extra["future-setting"] == "keep"
    assert explicit.tcp.raw_extra["future-protocol"] == "keep-nested"
    assert "future-protocol" not in explicit.raw_extra
    assert group.raw_extra["future-toggle"] == "no"
    assert explicit.scope.kind == group.scope.kind == "shared"
    assert_source_contract(explicit, config)
    assert_source_contract(group, config)
    assert secret not in str(config.model_dump())
