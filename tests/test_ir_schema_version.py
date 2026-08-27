import logging

import pytest

from fwmigrate.ir import IR_SCHEMA_VERSION
from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.ir.errors import IRSchemaError, UnsupportedIRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_json, load_ir_payload
from fwmigrate.ir.version import (
    parse_schema_version,
    validate_supported_schema_version,
)


def _metadata(source_version=None):
    return IRMetadata(
        hostname="FW01",
        source_vendor="fortigate",
        source_version=source_version,
    )


def test_ir_config_defaults_to_current_schema_version():
    ir = IRConfig(metadata=_metadata(source_version="7.4.5"))

    assert IR_SCHEMA_VERSION == "1.3"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.metadata.source_version == "7.4.5"


def test_explicit_current_version_serialization_and_deep_copy():
    ir = IRConfig(schema_version=IR_SCHEMA_VERSION, metadata=_metadata())

    assert ir.model_dump()["schema_version"] == IR_SCHEMA_VERSION
    assert f'"schema_version":"{IR_SCHEMA_VERSION}"' in (
        ir.model_dump_json().replace(" ", "")
    )
    assert dump_ir_json(ir) == ir.model_dump_json()
    assert ir.model_copy(deep=True).schema_version == ir.schema_version


@pytest.mark.parametrize(
    "value",
    ["abc", "1", "1.x", "v1", "1.0-beta", "", None, 1.0],
)
def test_malformed_schema_versions_are_rejected(value):
    with pytest.raises(IRSchemaError):
        parse_schema_version(value)
    with pytest.raises(IRSchemaError):
        load_ir_payload({
            "schema_version": value,
            "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
        })


@pytest.mark.parametrize("value", ["0.9", "1.4", "2.0"])
def test_unsupported_schema_versions_are_rejected(value):
    with pytest.raises(UnsupportedIRSchemaError):
        validate_supported_schema_version(value)
    with pytest.raises(UnsupportedIRSchemaError):
        load_ir_payload({
            "schema_version": value,
            "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
        })


def test_current_version_payload_and_json_load_successfully():
    payload = {
        "schema_version": IR_SCHEMA_VERSION,
        "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
    }

    assert load_ir_payload(payload).schema_version == IR_SCHEMA_VERSION
    assert load_ir_json(dump_ir_json(load_ir_payload(payload))).metadata.hostname == "FW"


def test_unversioned_legacy_payload_uses_explicit_migration_and_warns(caplog):
    payload = {
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "routes": [],
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert "schema_version" not in payload
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded unversioned legacy IR" in caplog.text


def test_schema_1_0_payload_adds_empty_phase2_inventory(caplog):
    payload = {
        "schema_version": "1.0",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.0"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.vpn_phase2 == []
    assert ir.fsso_providers == []
    assert ir.fsso_ad_groups == []
    assert "Loaded IR schema 1.0" in caplog.text


def test_schema_1_1_payload_adds_empty_fsso_inventory(caplog):
    payload = {
        "schema_version": "1.1",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.1"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.fsso_providers == []
    assert ir.fsso_ad_groups == []
    assert "Loaded IR schema 1.1" in caplog.text


def test_schema_1_2_payload_uses_explicit_additive_migration(caplog):
    payload = {
        "schema_version": "1.2",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.2"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded IR schema 1.2" in caplog.text


def test_non_object_serialized_ir_is_rejected():
    with pytest.raises(IRSchemaError):
        load_ir_json("[]")
