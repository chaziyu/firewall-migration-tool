from __future__ import annotations

import json
from typing import Any

from fwmigrate.ir import IRConfig
from fwmigrate.ir.errors import IRSchemaError


def load_ir_payload(payload: dict[str, Any]) -> IRConfig:
    if not isinstance(payload, dict):
        raise IRSchemaError("Serialized IR payload must be a JSON object.")

    return IRConfig.model_validate(payload)


def load_ir_json(payload: str) -> IRConfig:
    raw = json.loads(payload)
    return load_ir_payload(raw)


def dump_ir_json(ir_config: IRConfig, **kwargs: Any) -> str:
    return ir_config.model_dump_json(**kwargs)
