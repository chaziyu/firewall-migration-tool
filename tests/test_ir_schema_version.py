import pytest

from fwmigrate.ir import IRConfig
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_json, load_ir_payload


def _payload():
    return {"metadata": {"hostname": "FW", "source_vendor": "fortigate"}}


def test_ir_config_has_no_schema_version():
    ir = IRConfig.model_validate(_payload())

    assert ir.schema_version == 2
    assert '"schema_version":2' in dump_ir_json(ir)


def test_unversioned_ir_json_migrates_and_round_trips_as_v2():
    ir = load_ir_json(dump_ir_json(load_ir_payload(_payload())))

    assert ir.metadata.hostname == "FW"
    assert ir.schema_version == 2


def test_legacy_payload_keeps_historical_source_vendor_default():
    ir = load_ir_payload({"metadata": {"hostname": "FW"}})

    assert ir.metadata.source_vendor == "fortinet"


@pytest.mark.parametrize("version", [0, 3, "2", True])
def test_unsupported_or_malformed_schema_version_is_rejected(version):
    with pytest.raises(IRSchemaError):
        load_ir_payload({**_payload(), "schema_version": version})


def test_v2_requires_an_explicit_source_vendor():
    with pytest.raises(ValueError):
        load_ir_payload({"schema_version": 2, "metadata": {"hostname": "FW"}})


def test_typed_vendor_extensions_round_trip():
    ir = load_ir_json(dump_ir_json(load_ir_payload(_payload())))

    assert ir.vendor_extensions.fortios.security_policies == []
    assert ir.vendor_extensions.cisco_ftd.model_dump() == {}


def test_legacy_central_nat_loads_as_source_nat_with_rulebase_provenance():
    ir = load_ir_payload({
        **_payload(),
        "nat_rules": [{"name": "central-1", "type": "central"}],
    })

    assert ir.nat_rules[0].type.value == "source"
    assert ir.nat_rules[0].source_origin == "central-snat-map"
    assert ir.nat_rules[0].is_central_rulebase


def test_legacy_policy_roots_migrate_without_ambiguity():
    ir = load_ir_payload({
        **_payload(),
        "policies": [{"name": "portable"}],
        "security_policies": [{"family": "firewall security-policy"}],
    })

    assert ir.security_policies[0].name == "portable"
    assert ir.policies is ir.security_policies
    assert ir.vendor_extensions.fortios.security_policies[0].family == "firewall security-policy"


def test_non_object_serialized_ir_is_rejected():
    with pytest.raises(IRSchemaError):
        load_ir_json("[]")
