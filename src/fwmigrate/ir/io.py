from __future__ import annotations

import json
from typing import Any

from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.migrations import migrate_ir_payload
from fwmigrate.ir.version import validate_supported_schema_version


def load_ir_payload(payload: dict[str, Any]) -> IRConfig:
    if not isinstance(payload, dict):
        raise IRSchemaError("Serialized IR payload must be a JSON object.")

    migrated = migrate_ir_payload(payload)
    validate_supported_schema_version(migrated.get("schema_version"))
    return IRConfig.model_validate(migrated)


def load_ir_json(payload: str) -> IRConfig:
    raw = json.loads(payload)
    return load_ir_payload(raw)


def dump_ir_json(ir_config: IRConfig, **kwargs: Any) -> str:
    return ir_config.model_dump_json(**kwargs)
