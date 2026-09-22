from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANVirtualRouter
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_virtual_logical_and_dynamic_routing_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "dynamic_routing.xml").read_text())
    routers = {item.name: item for item in config.virtual_routers}

    assert routers["vr-a"].bgp.router_id == "10.0.0.1"
    assert routers["vr-a"].bgp.peer_groups[0].peers[0].peer_as == "65002"
    assert routers["vr-a"].ospf.areas[0].interfaces[0].metric == "10"
    assert routers["vr-a"].rip.interfaces[0].name == "ethernet1/4"
    assert routers["vr-b"].bgp.enable is None
    assert config.logical_routers[0].vrfs[0].routing_protocol["bgp"]["router-id"] == "10.255.0.1"

    integrated = build_panos_config((FIXTURES / "integrated_firewall.xml").read_text())
    assert integrated.virtual_routers[0].static_routes[0].destination == "0.0.0.0/0"


def test_routing_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "routing-secret-value"
    config = build_panos_config(
        f"""<config><devices><entry name='fw'><network><virtual-router>
          <entry name='explicit'><interface><member>ethernet1/1</member></interface><protocol><bgp><enable>no</enable><peer-group><entry name='group'><peer><entry name='peer'><peer-as>65002</peer-as><future-nested>keep-nested</future-nested><future-password>{secret}</future-password></entry></peer></entry></peer-group></bgp></protocol><future-field>keep</future-field></entry>
          <entry name='missing'/>
        </virtual-router></network></entry></devices></config>"""
    )
    explicit, missing = config.virtual_routers
    peer = explicit.bgp.peer_groups[0].peers[0]

    assert isinstance(explicit, PANVirtualRouter)
    assert explicit.interfaces == ["ethernet1/1"]
    assert explicit.bgp.enable == "no"
    assert missing.interfaces is None
    assert missing.bgp is None
    assert explicit.raw_extra["future-field"] == "keep"
    assert peer.raw_extra["future-nested"] == "keep-nested"
    assert "future-nested" not in explicit.bgp.raw_extra
    assert explicit.scope.kind == "device"
    assert_source_contract(explicit, config)
    assert secret not in str(config.model_dump())
