from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle
from fwmigrate.vendors.checkpoint.validation import validate_checkpoint_config


def _extract(responses):
    bundle = CheckPointExportBundle.model_validate({"responses": responses})
    before = bundle.model_dump()
    result = extract_checkpoint_config(bundle)
    assert bundle.model_dump() == before
    return result


def test_access_layer_inventory_and_rulebase_observation_reconcile():
    result = _extract([
        {"command": "show-access-layers", "data": {"objects": [
            {"uid": "layer-1", "name": "Shared", "type": "access-layer"},
        ]}},
        {"command": "show-access-rulebase", "data": {
            "uid": "layer-1", "name": "Shared", "rulebase": [],
        }},
    ])

    assert len(result.config.access_layers) == 1
    layer = result.config.access_layers[0]
    assert layer.command == "show-access-layers"
    assert layer.package is None and layer.parent_rule_uid is None and layer.parent_layer_uid is None
    assert build_checkpoint_derived_views(result.config).references.by_uid["layer-1"] is layer


def test_gateway_api_observations_union_compatible_explicit_fields():
    result = _extract([
        {"command": "show-gateways-and-servers", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "address": "192.0.2.1"},
        ]}},
        {"command": "show-simple-gateways", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "interfaces": [{"name": "eth0"}],
             "nat-settings": {"auto-rule": True}},
        ]}},
    ])

    assert len(result.config.gateways) == 1
    gateway = result.config.gateways[0]
    assert gateway.command == "show-simple-gateways"
    assert gateway.address == "192.0.2.1"
    assert gateway.interfaces[0].name == "eth0"
    assert gateway.nat_settings == {"auto-rule": True}
    assert build_checkpoint_derived_views(result.config).references.by_uid["g1"] is gateway


def test_conflicting_or_weak_identity_observations_stay_separate():
    conflict = _extract([
        {"command": "show-gateways-and-servers", "domain": "A", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "address": "192.0.2.1"},
        ]}},
        {"command": "show-simple-gateways", "domain": "A", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "address": "192.0.2.2"},
        ]}},
    ])
    assert [item.address for item in conflict.config.gateways] == ["192.0.2.1", "192.0.2.2"]
    derived = build_checkpoint_derived_views(conflict.config)
    assert any(item.code == "duplicate_uid" for item in validate_checkpoint_config(conflict.config, derived).issues)

    weak_identity = _extract([
        {"command": "show-simple-gateways", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway"},
            {"uid": "g2", "name": "GW", "type": "gateway"},
        ]}},
        {"command": "show-gateways-and-servers", "domain": "Other", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway"},
        ]}},
    ])
    assert len(weak_identity.config.gateways) == 3
    assert {item.uid for item in weak_identity.config.gateways} == {"g1", "g2"}


def test_raw_extra_conflicts_and_concrete_type_differences_are_not_merged():
    result = _extract([
        {"command": "show-gateways-and-servers", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "future-setting": "one"},
        ]}},
        {"command": "show-simple-gateways", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "gateway", "future-setting": "two"},
        ]}},
        {"command": "show-simple-clusters", "data": {"objects": [
            {"uid": "g1", "name": "GW", "type": "cluster"},
        ]}},
    ])

    assert len(result.config.gateways) == 2
    assert len(result.config.clusters) == 1
    assert {item.raw_extra["future-setting"] for item in result.config.gateways} == {"one", "two"}
    before = result.config.model_dump()
    build_checkpoint_derived_views(result.config)
    assert result.config.model_dump() == before
