from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _transform(config: str):
    return FGToIRTransformer(parse_fortigate_config(config)).transform()


def test_route_source_model_preserves_distinct_known_fields():
    fg = parse_fortigate_config("""
config router static
    edit 10
        set dst 10.0.0.0 255.0.0.0
        set gateway 192.0.2.1
        set device "wan1"
        set distance 5
        set priority 20
        set blackhole disable
    next
    edit 11
        set dst 192.0.2.0 255.255.255.0
    next
end
""")

    assert fg.static_routes[0].distance == 5
    assert fg.static_routes[0].priority == 20
    assert fg.static_routes[0].blackhole == "disable"
    assert fg.static_routes[1].distance is None
    assert fg.static_routes[1].priority is None


def test_fortigate_distance_maps_to_administrative_distance_not_metric():
    route = _transform("""
config router static
    edit 10
        set dst 10.10.0.0 255.255.0.0
        set gateway 192.0.2.1
        set device "wan1"
        set distance 5
        set priority 10
    next
end
""").routes[0]

    assert route.source_route_id == 10
    assert route.destination == "10.10.0.0/16"
    assert route.source_destination == "10.10.0.0 255.255.0.0"
    assert route.next_hop == "192.0.2.1"
    assert route.interface == "wan1"
    assert route.administrative_distance == 5
    assert route.metric is None
    assert route.priority == 10
    assert route.migration_status == "NORMALIZED"
    assert route.requires_manual_review is False


def test_blackhole_sdwan_and_explicit_status_are_preserved_independently():
    ir = _transform("""
config router static
    edit 5
        set dst 203.0.113.0 255.255.255.0
        set blackhole enable
        set status disable
    next
    edit 10
        set dst 0.0.0.0 0.0.0.0
        set sdwan-zone "virtual-wan-link"
        set distance 1
    next
end
""")
    blackhole, sdwan = ir.routes

    assert blackhole.blackhole is True
    assert blackhole.next_hop is None
    assert blackhole.interface is None
    assert blackhole.enabled is False
    assert sdwan.sdwan_zone == "virtual-wan-link"
    assert sdwan.interface is None
    assert sdwan.administrative_distance == 1
    assert sdwan.enabled is None


def test_unknown_route_settings_are_preserved_and_require_review():
    result = extract_fortigate_config("""
config router static
    edit 22
        set dst 198.51.100.0 255.255.255.0
        set dynamic-gateway enable
        set link-monitor-exempt enable
    next
end
""")
    route = result.canonical_ir.routes[0]
    section = next(
        section for section in result.source_sections
        if section.path == "router static"
    )

    assert route.source_attributes == {
        "dynamic_gateway": "enable",
        "link_monitor_exempt": "enable",
    }
    assert route.migration_status == "PARTIALLY_NORMALIZED"
    assert route.requires_manual_review is True
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "unmodeled or invalid" in " ".join(section.notes)


def test_full_fortigate_fixture_route_counts_and_semantics_match_source():
    fixture = Path(__file__).parent / "fixtures" / "example_fortigate.conf"
    config = fixture.read_text(encoding="utf-8")
    result = extract_fortigate_config(config)
    section = next(
        section for section in result.source_sections
        if section.path == "router static"
    )

    assert section.object_count_source == len(result.canonical_ir.routes)
    assert section.object_count_parsed == len(result.canonical_ir.routes)
    route = result.canonical_ir.routes[0]
    assert route.source_route_id == 1
    assert route.destination == "0.0.0.0/0"
    assert route.next_hop == "203.0.113.1"
    assert route.interface == "port2"
    assert route.administrative_distance == 10
    assert route.metric is None
