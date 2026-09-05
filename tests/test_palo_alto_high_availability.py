from fwmigrate.parsers.palo_alto import PANOSSourceParser
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures/palo_alto/phase94_production.xml"

def test_pan_ha_preserves_configured_interface_values():
    xml = '<config><devices><entry name="fw"><deviceconfig><high-availability><enabled>yes</enabled><group><group-id>1</group-id><peer-ip>1.1.1.2</peer-ip></group><interface><ha1><ip-address>1.1.1.1</ip-address><netmask>255.255.255.0</netmask></ha1><ha3/></interface></high-availability></deviceconfig></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_high_availability.enabled is True
    assert ir.pan_high_availability.interfaces[0].ip_address == "1.1.1.1"
    assert ir.pan_high_availability.interfaces[1].ip_address is None

def test_pan_ha_production_hierarchy():
    xml = '<config><devices><entry name="fw"><deviceconfig><high-availability><enabled>yes</enabled><group><group-id>1</group-id><description>SBG-HA</description><peer-ip>1.1.1.2</peer-ip></group><election-option><preemptive>no</preemptive><timers><recommended/></timers></election-option><state-synchronization><ha2-keep-alive><enabled>yes</enabled></ha2-keep-alive></state-synchronization><monitoring><link-monitoring><enabled>yes</enabled><failure-condition>all</failure-condition><link-group><entry name="Port Monitoring"><enabled>yes</enabled><failure-condition>all</failure-condition><interface><member>ha1</member></interface></entry></link-group></link-monitoring><path-monitoring><enabled>yes</enabled><failure-condition>all</failure-condition><path-group><virtual-router><entry name="default"><destination-ip><member>10.1.4.1</member></destination-ip><failure-condition>all</failure-condition><ping-interval>3000</ping-interval></entry></virtual-router></path-group></path-monitoring></monitoring></high-availability></deviceconfig></entry></devices></config>'
    ha = PANOSSourceParser().parse(xml).pan_high_availability
    assert ha.description == "SBG-HA" and ha.recommended_timers is True
    assert ha.link_groups[0].name == "Port Monitoring"
    assert ha.path_groups[0].routing_instance == "default"
    assert ha.path_groups[0].ping_interval_ms == 3000
    assert ha.link_groups[0].resolved_interfaces == []
    assert ha.path_groups[0].routing_instance_resolved is False

def test_pan_ha_unknown_nested_child_is_unsupported():
    result = PANOSSourceParser().extract('<config><devices><entry name="fw"><deviceconfig><high-availability><future-ha-option><x>1</x></future-ha-option></high-availability></deviceconfig></entry></devices></config>')
    assert any(item.status.value == "UNSUPPORTED" and "future-ha-option" in item.source_path for item in result.inventory_items)


def test_phase94_ha_exact_values_and_resolutions():
    ha = PANOSSourceParser().parse(FIXTURE.read_text()).pan_high_availability
    assert (ha.enabled, ha.group_id, ha.description, ha.peer_ip, ha.preemptive, ha.recommended_timers, ha.ha2_keep_alive_enabled) == (True, 1, "SBG-HA", "1.1.1.2", False, True, True)
    link = ha.link_groups[0]
    assert (link.name, link.interfaces, link.resolved_interfaces, link.unresolved_interfaces) == ("Port Monitoring", ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/8"], ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/8"], [])
    path = ha.path_groups[0]
    assert (path.routing_instance, path.destination_ips, path.failure_condition, path.ping_interval_ms) == ("default", [f"10.1.4.{i}" for i in range(1, 6)], "all", 3000)
    assert [i.ip_address for i in ha.interfaces[:2]] == ["1.1.1.1", "2.2.2.1"]


def test_phase94_malformed_ha_group_id_is_reviewed():
    result = PANOSSourceParser().extract(FIXTURE.read_text().replace("<group-id>1</group-id>", "<group-id>bad</group-id>"))
    ha = result.canonical_ir.pan_high_availability
    assert ha.group_id is None and any("Invalid integer" in reason for reason in ha.review_reasons)
