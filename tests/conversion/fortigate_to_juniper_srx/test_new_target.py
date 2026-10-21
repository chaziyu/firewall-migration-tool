from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import approve_design, build_artifact, build_review
from fwmigrate.conversion.fortigate_to_juniper_srx.design.deterministic import options_mapping
from fwmigrate.conversion.fortigate_to_juniper_srx.options import SRXInterfaceMapping, SRXMigrationOptions
from fwmigrate.conversion.fortigate_to_juniper_srx.recommendations.target_mapping import propose_new_target
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


SOURCE = '''#config-version=FG100E-7.2.13-FW-build1762-260128
config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
set snmp-index 1
next
edit wan
set type physical
set ip 198.51.100.1 255.255.255.0
next
end
config firewall address
edit clients
set uuid 00000000-0000-0000-0000-000000000001
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall policy
edit 1
set uuid 00000000-0000-0000-0000-000000000002
set srcintf lan
set dstintf wan
set srcaddr clients
set dstaddr all
set service ALL
set schedule always
set action accept
set logtraffic all
next
edit 2
set srcintf lan
set dstintf wan
set srcaddr all
set dstaddr all
set service ALL
set schedule always
next
end
'''


def test_new_device_proposals_preserve_source_and_require_exact_approval():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    before = analysis.extracted.config.model_dump(mode="json")
    proposed = propose_new_target(analysis.extracted.config, analysis.derived, {})
    assert proposed.interfaces["root"]["lan"] == SRXInterfaceMapping("ge-0/0/0", 0)
    assert proposed.interfaces["root"]["wan"] == SRXInterfaceMapping("ge-0/0/1", 0)
    assert len(set(proposed.interface_zones["root"].values())) == 2
    assert analysis.extracted.config.model_dump(mode="json") == before
    review = build_review(analysis, options_mapping(proposed), "source")
    assert all(not item["blockers"] for item in review["report"]["items"])
    policies = [item for item in review["report"]["items"] if item["family"] == "policy"]
    assert policies[0]["key"] in policies[1]["dependencies"]
    with pytest.raises(ValueError, match="approval"):
        build_artifact(analysis, options_mapping(proposed), "source", None)
    approval = approve_design(review, review["draft"], [policies[-1]["key"]])
    artifact = build_artifact(analysis, options_mapping(proposed), "source", approval)
    text = artifact["command_text"]
    assert " then permit" in text and " then deny" in text
    assert text.index(" then permit") < text.index(" then deny")
    parsed = JuniperSRXSourceReporter().analyze_source(text)
    assert not parsed.config.unsupported_commands
    assert not parsed.validation.issues
    root = parsed.config.get_context("root")
    assert len(root.zones) == 2
    assert len(root.policies) == 2
    changed = replace(proposed, interface_zones={"root": {"lan": "different-zone", "wan": proposed.interface_zones["root"]["wan"]}})
    with pytest.raises(ValueError, match="different pair, source or design"):
        build_artifact(analysis, options_mapping(changed), "source", approval)


def test_proposals_keep_engineer_values_and_avoid_allocated_ports():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    options = SRXMigrationOptions(source_vdom="root", interfaces={"root": {"lan": SRXInterfaceMapping("ge-0/0/0", 0)}},
        interface_zones={"root": {"lan": "trusted"}})
    proposed = propose_new_target(analysis.extracted.config, analysis.derived, options)
    assert proposed.interface_zones["root"]["lan"] == "trusted"
    assert proposed.interfaces["root"]["wan"].target_interface == "ge-0/0/1"
    assert options.interfaces["root"] == {"lan": SRXInterfaceMapping("ge-0/0/0", 0)}


def test_unzoned_interface_placement_does_not_merge_or_invent_source_zones():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    proposed = propose_new_target(analysis.extracted.config, analysis.derived, {})
    merged = replace(proposed, interface_zones={"root": {"lan": "shared", "wan": "shared"}})
    review = build_review(analysis, merged, "source")
    assert all(item["render_disposition"] == "BLOCK" for item in review["report"]["items"] if item["family"] in {"zone", "policy"})
    assert not analysis.extracted.config.zones


def test_api_proposals_are_not_approval_and_reject_existing_target_evidence():
    from fwmigrate.web import create_app
    client = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": "s" * 32}).test_client()
    prefix = "/api/migration/fortigate_to_juniper_srx"
    payload = {"source": {"vendor": "fortigate", "source_text": SOURCE}, "options": {}}
    response = client.post(prefix + "/proposals", json=payload)
    assert response.status_code == 200
    assert response.json["approval_required"] is True
    assert response.json["hardware_verified"] is False
    assert "approval" not in response.json
    assert client.post(prefix + "/proposals", json={**payload, "target_source": {"vendor": "juniper_srx", "source_text": ""}}).status_code == 400
    assert client.post(prefix + "/build", json={**payload, "options": response.json["options"]}).status_code == 400


def test_explicit_builtin_names_keep_their_source_definition():
    source = SOURCE.replace("set service ALL", "set service HTTP", 1) + '''config firewall service custom
edit HTTP
set tcp-portrange 9443
next
end
config firewall address
edit all
set subnet 203.0.113.0 255.255.255.0
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    options = propose_new_target(analysis.extracted.config, analysis.derived, {})
    review = build_review(analysis, options, "source")
    items = review["report"]["items"]
    http = next(row for row in items if row["family"] == "service" and row["source_name"] == "HTTP")
    address = next(row for row in items if row["family"] == "address" and row["source_name"] == "all")
    policy = next(row for row in items if row["family"] == "policy")
    assert policy["settings"]["applications"] == (http["target_name"],)
    assert policy["settings"]["destination_addresses"] == (address["target_name"],)
    assert http["key"] in policy["dependencies"] and address["key"] in policy["dependencies"]


def test_unrestricted_explicit_ip_service_requires_versioned_source_proof():
    text = SOURCE + '''config firewall service custom
edit ALL
set protocol IP
next
end
'''
    for source, supported in ((text, True), (text.replace("7.2.13", "7.4.6"), False)):
        analysis = FortiGateSourceReporter().analyze_source(source)
        options = propose_new_target(analysis.extracted.config, analysis.derived, {})
        review = build_review(analysis, options, "source")
        policy = next(row for row in review["report"]["items"] if row["family"] == "policy")
        assert (policy["settings"]["applications"] == ("any",)) is supported
    constrained = text.replace("set protocol IP", "set protocol TCP/UDP/SCTP\nset tcp-portrange 443")
    analysis = FortiGateSourceReporter().analyze_source(constrained)
    options = propose_new_target(analysis.extracted.config, analysis.derived, {})
    review = build_review(analysis, options, "source")
    assert all(row["settings"]["applications"] != ("any",) for row in review["report"]["items"] if row["family"] == "policy")


def test_numeric_protocol_and_explicit_icmp_selectors_round_trip():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall service custom
edit gre
set protocol IP
set protocol-number 47
next
edit echo
set protocol ICMP
set icmptype 8
set icmpcode 0
next
edit unknown-icmp
set protocol ICMP
set icmptype 8
next
end
''')
    options = SRXMigrationOptions(source_vdom="root", target_context="root", target_version="25.2R1", target_mode="standalone", routing_table="inet.0")
    review = build_review(analysis, options, "source")
    ready = [row["key"] for row in review["report"]["items"] if not row["blockers"]]
    assert len(ready) == 2
    approval = approve_design(review, review["draft"], ready)
    artifact = build_artifact(analysis, options, "source", approval)
    parsed = JuniperSRXSourceReporter().analyze_source(artifact["command_text"])
    assert not parsed.config.unsupported_commands and not parsed.validation.issues
    assert " protocol 47\n" in artifact["command_text"]
    assert " icmp-type 8\n" in artifact["command_text"]
    assert " icmp-code 0\n" in artifact["command_text"]


def test_management_access_is_reported_separately_and_enables_no_admin_services():
    source = SOURCE.replace("set snmp-index 1", "set snmp-index 1\nset allowaccess ping ssh https\nset device-identification enable")
    analysis = FortiGateSourceReporter().analyze_source(source)
    options = propose_new_target(analysis.extracted.config, analysis.derived, {})
    review = build_review(analysis, options, "source")
    control = next(row for row in review["report"]["items"] if row["family"] == "interface_control_plane")
    assert control["render_disposition"] == "BLOCK"
    assert control["settings"]["source_allowaccess"] == ("ping", "ssh", "https")
    ready = [row["key"] for row in review["report"]["items"] if row["render_disposition"] == "CREATE"]
    approval = approve_design(review, review["draft"], ready)
    artifact = build_artifact(analysis, options, "source", approval)
    assert "family inet address 192.0.2.1/24" in artifact["command_text"]
    assert "host-inbound" not in artifact["command_text"]
    assert "set system services" not in artifact["command_text"]
    assert artifact["report"]["plan_status"] == "READY_WITH_MANUAL_WORK"
