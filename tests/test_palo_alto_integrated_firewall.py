from collections import Counter
from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def test_integrated_firewall_terminal_completeness_and_no_contradictions():
    result = _result()
    domains = Counter(item.domain for item in result.inventory_items)
    assert domains["policies"] == 1
    assert domains["nat"] == 1
    assert domains["routes"] == 1
    assert domains["dynamic_routing:bgp"] == 1
    assert domains["dynamic_routing:bgp_peer"] == 1
    assert domains["dynamic_routing:ospf"] == 1
    assert domains["profile_groups"] == 1
    assert len({item.source_record_id for item in result.inventory_items}) == len(result.inventory_items)


def test_integrated_firewall_unsupported_and_unknown_material_remain_inventoried():
    result = _result()
    future_policy = next(item for item in result.inventory_items if item.domain == "policy:future-policy")
    future_network = next(item for item in result.inventory_items if item.source_path == "network/future-network")
    assert future_policy.status == future_network.status == ExtractionStatus.UNSUPPORTED
    assert "retain-policy-evidence" in str(future_policy.source_attributes)
    assert "retain-network-evidence" in str(future_network.source_attributes)


def test_integrated_firewall_does_not_invent_policy_or_route_values():
    result = _result()
    policy = next(policy for policy in result.canonical_ir.policies if policy.name == "allow-web")
    route = next(route for route in result.canonical_ir.routes if route.name == "default")
    assert policy.source == ["inside-group"] and policy.destination == ["public"]
    assert policy.action.value == "allow"
    assert route.metric == 10 and route.administrative_distance is None
    assert route.source_attributes["pan_admin_distance_explicit"] is False


def test_integrated_firewall_rulebase_and_vsys_associations_are_preserved():
    result = _result()
    policy = next(item for item in result.inventory_items if item.domain == "policies")
    peer = next(item for item in result.inventory_items if item.domain == "dynamic_routing:bgp_peer")
    assert policy.source_attributes["pan_rulebase_position"] == "local"
    assert peer.source_attributes["pan_vsys"] == "vsys1"
