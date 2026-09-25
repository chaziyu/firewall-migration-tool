from dataclasses import FrozenInstanceError
import pytest
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.address import CPAddressRange, CPHost, CPNetwork
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway
from fwmigrate.vendors.checkpoint.model.policy import CPAutoNATRule, CPNATRule
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def test_automatic_nat_stays_on_the_owner_object():
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-hosts",
        "data": {"objects": [{"type": "host", "name": "Web", "nat-settings": {"auto-rule": True}}]},
    }]}))

    host = result.config.hosts[0]
    assert type(host) is CPHost
    assert host.nat_settings == {"auto-rule": True}
    assert not result.config.nat_rules

def test_manual_nat_keeps_source_references_order_and_resolved_metadata():
    source = CPHost(uid="src", name="inside")
    rule = CPNATRule(
        uid="rule", name="manual", order=7, enabled=True,
        original_source=["inside"], original_destination=["service-vip"], original_service=["https"],
        translated_source=["public"], translated_destination=["public-vip"], translated_service=["https-translated"],
        method="static", install_on=["gw"],
    )
    returned_auto = CPAutoNATRule(uid="auto", name="automatic", order=8, automatic=True)
    config = CheckPointConfig(
        hosts=[source], services=[], gateways=[CPGateway(uid="gateway", name="gw")],
        nat_rules=[rule, returned_auto],
    )

    result = build_checkpoint_derived_views(config)
    view = result.nat.views[0]

    assert view.source_kind == "manual_rule"
    assert view.source_uid == rule.uid and view.source_name == rule.name
    assert view.rule_order == 7
    assert view.original_source[0].reference == "inside"
    assert view.original_source[0].resolved_uid == "src"
    assert view.original_destination[0].reference == "service-vip"
    assert view.original_service[0].reference == "https"
    assert view.translated_source[0].reference == "public"
    assert view.translated_destination[0].reference == "public-vip"
    assert view.translated_service[0].reference == "https-translated"
    assert view.translation_method == "static"
    assert view.install_on[0].reference == "gw"
    assert len(view.install_on) == 1
    assert result.nat.views[1].source_kind == "returned_automatic_rule"
    assert result.nat.views[1].owner_uid is None
    with pytest.raises(FrozenInstanceError):
        view.rule_order = 8

def test_automatic_nat_settings_are_traceable_and_unknown_when_incomplete():
    host = CPHost(uid="host", name="Web", nat_settings={"auto-rule": True})
    config = CheckPointConfig(hosts=[host])
    before = config.model_dump()

    result = build_checkpoint_derived_views(config)
    view = result.nat.views[0]

    assert view.source_kind == "automatic_object_settings"
    assert (view.owner_uid, view.owner_name) == ("host", "Web")
    assert view.translated_source is None
    assert view.issues == result.nat.issues
    assert "not explicit" in result.nat.issues[0].message
    assert config.model_dump() == before
    assert view.owner_kind == "CPHost"

@pytest.mark.parametrize("owner", [
    CPHost(uid="host", name="host-auto", nat_settings={"auto-rule": True, "method": "static", "ipv4-address": "192.0.2.10"}),
    CPNetwork(uid="network", name="network-auto", nat_settings={"auto-rule": True, "method": "hide", "ipv4-address": "192.0.2.20"}),
    CPAddressRange(uid="range", name="range-auto", nat_settings={"auto-rule": True, "method": "static", "ipv4-address": "192.0.2.30"}),
])
def test_automatic_nat_is_derived_from_host_network_and_range_owners(owner):
    config = CheckPointConfig(hosts=[owner] if isinstance(owner, CPHost) else [],
                              networks=[owner] if isinstance(owner, CPNetwork) else [],
                              address_ranges=[owner] if isinstance(owner, CPAddressRange) else [])
    before = config.model_dump()

    result = build_checkpoint_derived_views(config)
    view = result.nat.views[0]

    assert view.source_kind == "automatic_object_settings"
    assert view.owner_uid == owner.uid
    assert view.owner_kind == type(owner).__name__
    assert view.translated_source[0].reference == owner.nat_settings["ipv4-address"]
    assert config.model_dump() == before
    assert not hasattr(config, "ip_pools")
    assert not hasattr(config, "vips")

@pytest.mark.parametrize("settings, expected_issue", [
    ({"auto-rule": True, "method": "hide"}, "address"),
    ({"auto-rule": True, "ipv4-address": "192.0.2.40"}, "method"),
])
def test_partial_automatic_nat_preserves_known_values_and_reports_unknown(settings, expected_issue):
    owner = CPNetwork(uid="network", name="partial", nat_settings=settings)
    config = CheckPointConfig(networks=[owner])
    before = config.model_dump()

    view = build_checkpoint_derived_views(config).nat.views[0]

    assert view.owner_uid == owner.uid
    if expected_issue == "address":
        assert view.translated_source is None
    else:
        assert view.translated_source[0].reference == "192.0.2.40"
    assert any(expected_issue in issue.message.lower() for issue in view.issues)
    assert config.model_dump() == before

def test_nat_unresolved_references_are_attached_to_view_and_result():
    rule = CPNATRule(uid="rule", name="manual", original_source=["missing"])
    result = build_checkpoint_derived_views(CheckPointConfig(nat_rules=[rule]))

    issue = result.nat.views[0].issues[0]
    assert issue.source_uid == "rule"
    assert issue.source_field == "original_source"
    assert issue.reference == "missing"
    assert issue.relationship_status == "missing"
    assert issue in result.nat.issues

def test_manual_nat_preserves_multiple_install_targets():
    rule = CPNATRule(uid="rule", name="manual", install_on=["gw-a", "gw-b"])
    config = CheckPointConfig(gateways=[CPGateway(name="gw-a"), CPGateway(name="gw-b")], nat_rules=[rule])

    view = build_checkpoint_derived_views(config).nat.views[0]

    assert [item.resolved_name for item in view.install_on] == ["gw-a", "gw-b"]
    assert not view.issues
