from copy import deepcopy

from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config


def test_apbr_objects_remain_separate_and_references_are_read_only():
    config = JuniperSRXParser("\n".join([
        "set routing-instances WAN instance-type virtual-router",
        "set applications application WEB protocol tcp",
        "set security advance-policy-based-routing metrics-profile MET jitter 25",
        "set security advance-policy-based-routing active-probe-params ACT probe-interval 5",
        "set security advance-policy-based-routing passive-probe-params PAS sample-window 10",
        "set security advance-policy-based-routing overlay-path PATH interface ge-0/0/0.0",
        "set security advance-policy-based-routing destination-path-group DPG probe-routing-instance WAN",
        "set security advance-policy-based-routing destination-path-group DPG overlay-path PATH",
        "set security advance-policy-based-routing multipath-rule MP application WEB",
        "set security advance-policy-based-routing sla-rule SLA metrics-profile MISSING",
        "set security advance-policy-based-routing sla-rule SLA active-probe-params ACT",
        "set security advance-policy-based-routing sla-rule SLA passive-probe-params PAS",
        "set security advance-policy-based-routing sla-rule SLA multipath-rule MP",
        "set security advance-policy-based-routing sla-rule SLA switch-idle-time 30",
        "set security advance-policy-based-routing sla-rule SLA current-jitter 99",
    ])).extract_source()
    context = next(iter(config.iter_contexts()))
    assert list(context.apbr.metrics_profiles) == ["MET"]
    assert context.apbr.metrics_profiles["MET"].jitter == "25"
    assert context.apbr.sla_rules["SLA"].metrics_profile == "MISSING"
    assert context.apbr.destination_path_groups["DPG"].overlay_paths == ["PATH"]
    assert "current_jitter" not in context.apbr.sla_rules["SLA"].model_dump()
    before = deepcopy(config)
    derived = build_juniper_derived_views(config)
    validation = validate_juniper_config(config, derived)
    assert config == before
    assert any(issue.category == "reference" and "MISSING" in issue.message for issue in validation.issues)


def test_apbr_graph_reports_resolved_and_unresolved_native_edges():
    config = JuniperSRXParser("\n".join([
        "set applications application WEB protocol tcp",
        "set applications application-set WEB-SET application WEB",
        "set security advance-policy-based-routing metrics-profile MET jitter 25",
        "set security advance-policy-based-routing active-probe-params ACT probe-interval 5",
        "set security advance-policy-based-routing overlay-path PATH interface ge-0/0/0.0",
        "set security advance-policy-based-routing destination-path-group DPG probe-routing-instance MISSING-RI",
        "set security advance-policy-based-routing destination-path-group DPG overlay-path PATH",
        "set security advance-policy-based-routing multipath-rule MP application WEB",
        "set security advance-policy-based-routing multipath-rule MP application-group WEB-SET",
        "set security advance-policy-based-routing sla-rule SLA metrics-profile MET",
        "set security advance-policy-based-routing sla-rule SLA active-probe-params ACT",
        "set security advance-policy-based-routing sla-rule SLA multipath-rule MP",
    ])).extract_source()
    graph = build_juniper_derived_views(config).apbr_graph
    statuses = {(edge["relationship"], edge["target_name"]): edge["resolved"] for edge in graph}
    assert statuses[("OVERLAY_PATH", "PATH")] is True
    assert statuses[("PROBE_ROUTING_INSTANCE", "MISSING-RI")] is False
    assert statuses[("APPLICATION", "WEB")] is True
    assert statuses[("APPLICATION_SET", "WEB-SET")] is True
    assert statuses[("METRICS_PROFILE", "MET")] is True
    assert statuses[("ACTIVE_PROBE_PARAMS", "ACT")] is True
    assert statuses[("MULTIPATH_RULE", "MP")] is True
    assert not any(any(term in str(value).lower() for term in ("sdwan", "fortigate", "health-check"))
                   for edge in graph for value in edge.values())


def test_apbr_resolution_stays_inside_logical_system_context():
    config = JuniperSRXParser("\n".join([
        "set applications application WEB protocol tcp",
        "set logical-systems L1 security advance-policy-based-routing multipath-rule MP application WEB",
    ])).extract_source()
    edge = next(item for item in build_juniper_derived_views(config).apbr_graph
                if item["source_name"] == "MP" and item["relationship"] == "APPLICATION")
    assert edge["context"] == "logical-system L1"
    assert edge["resolved"] is False
