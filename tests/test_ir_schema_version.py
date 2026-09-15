import pytest

from fwmigrate.ir import IRConfig
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_json, load_ir_payload


def _payload():
    return {"metadata": {"hostname": "FW", "source_vendor": "fortigate"}}


def test_ir_config_has_no_schema_version():
    ir = IRConfig.model_validate(_payload())

    assert "schema_version" not in ir.model_dump()
    assert "schema_version" not in dump_ir_json(ir)


def test_ir_json_round_trips_without_schema_version():
    ir = load_ir_json(dump_ir_json(load_ir_payload(_payload())))

    assert ir.metadata.hostname == "FW"
    assert "schema_version" not in ir.model_dump()


def test_non_object_serialized_ir_is_rejected():
    with pytest.raises(IRSchemaError):
        load_ir_json("[]")
