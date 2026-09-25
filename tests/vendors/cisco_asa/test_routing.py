from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

from .helpers import assert_source_unchanged, snapshot_source

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule

from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule

from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec

from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships

from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships

from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships

from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind

from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index

from copy import deepcopy

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

def test_null0_route_keeps_gateway_absent():
    route = extract_cisco_asa_source("route null0 192.168.2.0 255.255.255.0\n").config.static_routes[0]
    assert (route.interface, route.destination, route.mask, route.gateway) == (
        "null0", "192.168.2.0", "255.255.255.0", None
    )
    assert "gateway" not in route.explicit_fields

def test_policy_route_cost_and_path_monitor_are_separate_from_sla_track():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 policy-route cost 25
 policy-route path-monitoring 192.0.2.1
""").parse_raw()
    interface = config.interfaces[0]
    assert interface.policy_route_cost == "25"
    monitor = interface.policy_route_path_monitors[0]
    assert (monitor.mode, monitor.peer, monitor.source_order) == ("peer", "192.0.2.1", 3)
    assert config.tracks == [] and config.sla_monitors == []

def test_routing_keeps_route_track_sla_edges_context_scoped():
    route = SimpleNamespace(source_context="ctx", raw_line="route inside", interface="inside", track_id=1)
    track = SimpleNamespace(name="track:1", source_context="ctx", track_id=1, sla_id=5)
    sla = SimpleNamespace(name="sla:5", source_context="ctx", sla_id=5, interface=None)
    config = SimpleNamespace(static_routes=[route], tracks=[track], sla_monitors=[sla], route_maps=[], interfaces=[])
    interface = SimpleNamespace(name="inside"); track_ref = SimpleNamespace(track_id=1); sla_ref = SimpleNamespace(sla_id=5)
    refs = ASAReferenceIndex()
    refs.register("ctx", ASAReferenceKind.INTERFACE, "inside", interface)
    refs.register("ctx", ASAReferenceKind.TRACK, "1", track_ref)
    refs.register("ctx", ASAReferenceKind.SLA_MONITOR, "5", sla_ref)

    graph = build_routing_relationships(config, refs)

    assert graph.static_routes[0].interface is interface and graph.static_routes[0].track is track_ref
    assert graph.tracks[0].sla_monitor is sla_ref
    assert not graph.issues

def test_path_monitor_is_source_only():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif inside
 policy-route path-monitoring auto
""").parse_raw()
    result = build_routing_relationships(config, build_asa_reference_index(config))
    assert result.path_monitors[0].status == "SOURCE_ONLY"

def test_route_transform_separates_configured_and_effective_values():
    result = extract_cisco_asa_source("route outside 192.0.2.0 255.255.255.0 192.0.2.1\n"
                                     "ipv6 route outside 2001:db8::1/64 2001:db8::2 10\n")
    ipv4, ipv6 = result.derived.routes.routes
    assert (ipv4.configured_administrative_distance, ipv4.effective_administrative_distance) == (None, 1)
    assert ipv4.normalized_destination == "192.0.2.0/24"
    assert (ipv6.configured_administrative_distance, ipv6.effective_administrative_distance) == (10, 10)
    assert ipv6.normalized_destination == "2001:db8::/64"
    assert ipv6.source_route.destination == "2001:db8::1/64"

def test_gateway_absent_routes_and_null0_distance_are_parsed_structurally():
    result = extract_cisco_asa_source(
        "route inside 192.0.2.0 255.255.255.0\n"
        "route null0 198.51.100.0 255.255.255.0 250\n"
    )
    absent, null_route = result.config.static_routes
    assert absent.gateway is None and absent.extraction_status == "PARTIAL"
    assert null_route.gateway is None and null_route.administrative_distance == 250
