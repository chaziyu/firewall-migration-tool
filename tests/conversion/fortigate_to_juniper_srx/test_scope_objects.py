import hashlib
import json

from fwmigrate.conversion.fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner


def _settings(item):
    return dict(item.settings)


def test_actual_fortigate_source_plans_scoped_ipv4_objects_and_tcp_udp_services(explicit_analysis, complete_options):
    config = explicit_analysis.extracted.config
    before = hashlib.sha256(json.dumps(config.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()

    plan = FortiGateToJuniperSRXPlanner().plan(config, explicit_analysis.derived, complete_options)
    after = hashlib.sha256(json.dumps(config.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()

    assert before == after
    addresses = {item.source_name: item for item in plan.items if item.family == "address"}
    assert _settings(addresses["client-net"])["value"] == "10.10.0.0/24"
    assert _settings(addresses["app-host"])["value"] == "10.10.0.10/32"
    assert _settings(addresses["client-range"])["range_start"] == "10.10.0.20"
    assert _settings(addresses["client-range"])["range_end"] == "10.10.0.30"
    assert addresses["future-address"].disposition == "BLOCK"
    assert "ADDRESS_HAS_UNSUPPORTED_SOURCE_SETTINGS" in addresses["future-address"].blockers

    groups = {item.source_name: item for item in plan.items if item.family == "address_group"}
    assert _settings(groups["trusted-clients"])["members"] == (addresses["client-net"].target_name,)
    assert addresses["client-net"].key in groups["trusted-clients"].dependencies

    services = {item.source_name: item for item in plan.items if item.family == "service"}
    assert _settings(services["tcp-app"])["protocol"] == "tcp"
    assert _settings(services["tcp-app"])["destination_port"] == "8443"
    assert _settings(services["udp-dns"])["protocol"] == "udp"
    assert "comment" not in _settings(services["tcp-app"])
    assert "comment" not in _settings(addresses["app-host"])
    service_groups = {item.source_name: item for item in plan.items if item.family == "service_group"}
    assert len(_settings(service_groups["application-services"])["members"]) == 2


def test_object_names_are_stable_and_vdom_names_do_not_alias(explicit_analysis, blocker_analysis, complete_options):
    planner = FortiGateToJuniperSRXPlanner()
    config = explicit_analysis.extracted.config
    first = planner.plan(config, explicit_analysis.derived, complete_options)
    second = planner.plan(config, explicit_analysis.derived, complete_options)
    assert [item.target_name for item in first.items] == [item.target_name for item in second.items]

    other = planner.plan(
        blocker_analysis.extracted.config,
        blocker_analysis.derived,
        {"source_vdom": "tenant-a", "target_context": "root", "target_version": "25.2R1",
         "target_mode": "standalone", "routing_table": "inet.0"},
    )
    scoped = [item for item in other.items if item.family == "address" and item.source_name == "shared-name"]
    assert len(scoped) == 1
    assert scoped[0].source_vdom == "tenant-a"


def test_address_group_cycles_and_unknown_references_block(blocker_analysis, complete_options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        blocker_analysis.extracted.config, blocker_analysis.derived, complete_options
    )
    groups = {item.source_name: item for item in plan.items if item.family == "address_group"}

    assert "ADDRESS_GROUP_CYCLE" in groups["cycle-a"].blockers
    assert "ADDRESS_GROUP_MEMBER_UNRESOLVED_OR_PREDEFINED" in groups["missing-member"].blockers

    services = {item.source_name: item for item in plan.items if item.family == "service"}
    assert "SERVICE_PROTOCOL_UNSUPPORTED" in services["sctp-only"].blockers
    service_groups = {item.source_name: item for item in plan.items if item.family == "service_group"}
    assert "SERVICE_GROUP_CYCLE" in service_groups["service-cycle-a"].blockers
