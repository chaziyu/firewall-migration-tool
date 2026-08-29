from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_routes_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "routes.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Verify no fake VPN addresses were synthesized from routes!
    assert not any("vpn_subnet" in a.name for a in ir.addresses)

    r_def = next(r for r in ir.routes if r.destination == "0.0.0.0/0")
    assert r_def.next_hop == "198.51.100.254"

    # Discard route
    r_disc = next(r for r in ir.routes if r.destination == "172.16.0.0/12")
    assert r_disc.blackhole is True

    # Routing instance route
    r_vrf = next(r for r in ir.routes if r.destination == "10.200.0.0/16")
    assert r_vrf.source_attributes.get("junos_routing_instance") == "VRF_CUSTOMER_A"
    assert r_vrf.requires_manual_review is True
    assert r_vrf.migration_status == "PARTIALLY_NORMALIZED"
    assert any("routing-instance" in reason for reason in r_vrf.review_reasons)

    assert_no_silent_loss(res, total_input_commands=9)
